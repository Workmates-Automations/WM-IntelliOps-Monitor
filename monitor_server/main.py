"""
IntelliOps EC2 Monitor Server
Standalone FastAPI server that monitors the IntelliOps platform itself.

Routes:
  GET  /api/product-monitoring        — Lambda / API GW / DynamoDB health
  GET  /api/ai-monitoring             — AI agent event metrics from S3
  POST /api/ai-monitoring/log         — Log an AI agent event
  GET  /api/cloudwatch-dashboards     — List CW dashboards for an account
  POST /api/chat                      — Ollama-powered assistant (cross-account aware)
  GET  /health                        — Server health + Ollama status

Cross-account: uses CWMSessionRole via STS AssumeRole (same pattern as portal).
"""

from __future__ import annotations

import json
import logging
import os
import sys
import time
from typing import Any, Dict, List, Optional

import boto3
import httpx
from botocore.exceptions import ClientError
from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

# ── make sibling packages importable ──────────────────────────────────────────
_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
logger = logging.getLogger("Monitor")

# ── Config ────────────────────────────────────────────────────────────────────

_OLLAMA_URL   = os.environ.get("OLLAMA_URL",   "http://localhost:11434")
_OLLAMA_MODEL = os.environ.get("OLLAMA_MODEL", "llama3.2")
_HOME_REGION  = os.environ.get("AWS_REGION",   "ap-south-1")
_HOME_ACCOUNT = os.environ.get("HOME_ACCOUNT_ID", "036160411876")
_ROLE_NAME    = os.environ.get("CROSS_ACCOUNT_ROLE_NAME", "CWMSessionRole")

# S3 bucket that stores AI monitoring events
_AI_BUCKET = os.environ.get("INTELLIOPS_STRANDS_JOBS_BUCKET", "intelliops-websiterca")

# Lambda names / tables to monitor (comma-separated in env)
_LAMBDAS = [x.strip() for x in os.environ.get("MONITOR_LAMBDAS", "").split(",") if x.strip()]
_DYNAMO_TABLES = [
    x.strip() for x in
    os.environ.get("MONITOR_DYNAMO_TABLES", "IntelliOps-Tickets,IntelliOps-Alarms,IntelliOps-Sessions").split(",")
    if x.strip()
]

# ── FastAPI app ────────────────────────────────────────────────────────────────

app = FastAPI(
    title="IntelliOps Monitor",
    description="EC2-hosted monitoring dashboard for IntelliOps platform",
    version="1.0.0",
    docs_url="/docs",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── AWS helpers ───────────────────────────────────────────────────────────────

def _session(account_id: str = "", region: str = _HOME_REGION) -> boto3.session.Session:
    """Return a boto3 session, assuming cross-account role when needed."""
    if not account_id or account_id == _HOME_ACCOUNT:
        return boto3.session.Session(region_name=region)
    sts = boto3.client("sts", region_name=_HOME_REGION)
    role_arn = f"arn:aws:iam::{account_id}:role/{_ROLE_NAME}"
    try:
        creds = sts.assume_role(
            RoleArn=role_arn,
            RoleSessionName="IntelliOps-Monitor",
            DurationSeconds=900,
        )["Credentials"]
        return boto3.session.Session(
            aws_access_key_id=creds["AccessKeyId"],
            aws_secret_access_key=creds["SecretAccessKey"],
            aws_session_token=creds["SessionToken"],
            region_name=region,
        )
    except ClientError as exc:
        logger.warning("AssumeRole %s failed: %s", account_id, exc)
        raise HTTPException(status_code=502, detail=f"Cross-account role assumption failed: {exc}")


def _cw(account_id: str = "", region: str = _HOME_REGION):
    return _session(account_id, region).client("cloudwatch", region_name=region)


def _s3():
    return boto3.client("s3", region_name=_HOME_REGION)


# ── Product monitoring helpers ────────────────────────────────────────────────

from datetime import datetime, timedelta, timezone

def _metric_sum(cw_client, namespace: str, metric: str, dims: list, minutes: int = 60) -> float:
    end = datetime.now(timezone.utc)
    start = end - timedelta(minutes=minutes)
    try:
        pts = cw_client.get_metric_statistics(
            Namespace=namespace, MetricName=metric, Dimensions=dims,
            StartTime=start, EndTime=end, Period=minutes * 60, Statistics=["Sum"],
        ).get("Datapoints", [])
        return sum(p.get("Sum", 0) for p in pts)
    except Exception:
        return 0.0


def _metric_avg(cw_client, namespace: str, metric: str, dims: list, minutes: int = 60) -> float:
    end = datetime.now(timezone.utc)
    start = end - timedelta(minutes=minutes)
    try:
        pts = cw_client.get_metric_statistics(
            Namespace=namespace, MetricName=metric, Dimensions=dims,
            StartTime=start, EndTime=end, Period=minutes * 60, Statistics=["Average"],
        ).get("Datapoints", [])
        vals = [p.get("Average", 0) for p in pts]
        return sum(vals) / len(vals) if vals else 0.0
    except Exception:
        return 0.0


def _lambda_stats(cw_client, fn_name: str) -> Dict:
    dims = [{"Name": "FunctionName", "Value": fn_name}]
    inv = _metric_sum(cw_client, "AWS/Lambda", "Invocations", dims)
    err = _metric_sum(cw_client, "AWS/Lambda", "Errors", dims)
    thr = _metric_sum(cw_client, "AWS/Lambda", "Throttles", dims)
    dur = _metric_avg(cw_client, "AWS/Lambda", "Duration", dims)
    rate = round(err / inv * 100, 2) if inv > 0 else 0.0
    return {
        "name": fn_name,
        "invocations": int(inv),
        "errors": int(err),
        "throttles": int(thr),
        "avg_duration_ms": round(dur),
        "error_rate": rate,
        "health": "healthy" if rate < 5 else ("warning" if rate < 20 else "critical"),
    }


def _apigw_stats(cw_client) -> Dict:
    count = _metric_sum(cw_client, "AWS/ApiGateway", "Count", [])
    e5xx  = _metric_sum(cw_client, "AWS/ApiGateway", "5XXError", [])
    e4xx  = _metric_sum(cw_client, "AWS/ApiGateway", "4XXError", [])
    lat   = _metric_avg(cw_client, "AWS/ApiGateway", "Latency", [])
    return {
        "request_count": int(count),
        "error_5xx": int(e5xx),
        "error_4xx": int(e4xx),
        "avg_latency_ms": round(lat),
        "error_rate": round((e5xx + e4xx) / count * 100, 2) if count else 0,
        "health": "healthy" if e5xx == 0 else ("warning" if e5xx < 5 else "critical"),
    }


def _dynamo_stats(cw_client, table: str) -> Dict:
    dims = [{"Name": "TableName", "Value": table}]
    read  = _metric_sum(cw_client, "AWS/DynamoDB", "ConsumedReadCapacityUnits",  dims)
    write = _metric_sum(cw_client, "AWS/DynamoDB", "ConsumedWriteCapacityUnits", dims)
    rthr  = _metric_sum(cw_client, "AWS/DynamoDB", "ReadThrottleEvents",  dims)
    wthr  = _metric_sum(cw_client, "AWS/DynamoDB", "WriteThrottleEvents", dims)
    lat   = _metric_avg(cw_client, "AWS/DynamoDB", "SuccessfulRequestLatency", dims)
    return {
        "name": table,
        "consumed_read": round(read),
        "consumed_write": round(write),
        "read_throttles": int(rthr),
        "write_throttles": int(wthr),
        "avg_latency_ms": round(lat, 2),
        "health": "healthy" if rthr == 0 and wthr == 0 else "warning",
    }


def _active_alarms(cw_client) -> List[Dict]:
    try:
        alarms = []
        for page in cw_client.get_paginator("describe_alarms").paginate(StateValue="ALARM", MaxRecords=30):
            for a in page.get("MetricAlarms", []):
                alarms.append({
                    "name": a.get("AlarmName"),
                    "metric": a.get("MetricName"),
                    "namespace": a.get("Namespace"),
                    "reason": a.get("StateReason", "")[:200],
                    "updated_at": str(a.get("StateUpdatedTimestamp", "")),
                })
        return alarms[:20]
    except Exception:
        return []


# ── AI monitoring helpers ─────────────────────────────────────────────────────

_AI_PREFIX = "ai-monitoring/events/"


def _list_date_prefixes(days: int = 2) -> List[str]:
    return [
        f"{_AI_PREFIX}{(datetime.now(timezone.utc) - timedelta(days=d)).strftime('%Y/%m/%d')}/"
        for d in range(days)
    ]


def _read_ai_events(days: int = 2, limit: int = 100) -> List[Dict]:
    s3 = _s3()
    keys: List[str] = []
    for prefix in _list_date_prefixes(days):
        try:
            for page in s3.get_paginator("list_objects_v2").paginate(Bucket=_AI_BUCKET, Prefix=prefix, MaxKeys=200):
                for obj in page.get("Contents", []):
                    keys.append(obj["Key"])
        except Exception:
            pass
    keys = sorted(keys, reverse=True)[:limit]
    events: List[Dict] = []
    for k in keys:
        try:
            body = s3.get_object(Bucket=_AI_BUCKET, Key=k)["Body"].read()
            events.append(json.loads(body))
        except Exception:
            pass
    events.sort(key=lambda e: e.get("timestamp", 0), reverse=True)
    return events


def _ai_summary(events: List[Dict]) -> Dict:
    if not events:
        return {
            "total": 0, "valid": 0, "invalid": 0, "hallucinations": 0,
            "avg_latency_ms": 0, "avg_confidence": 0,
            "error_rate": 0, "success_rate": 0, "hallucination_rate": 0,
            "by_agent": {},
        }
    total    = len(events)
    valid    = sum(1 for e in events if e.get("validation", {}).get("is_valid"))
    halluc   = sum(1 for e in events if e.get("validation", {}).get("is_hallucination"))
    lats     = [e["latency_ms"] for e in events if e.get("latency_ms")]
    confs    = [e.get("validation", {}).get("confidence", 0) for e in events]
    by_agent: Dict[str, Dict] = {}
    for e in events:
        at = e.get("agent_type", "unknown")
        s  = by_agent.setdefault(at, {"total": 0, "valid": 0, "invalid": 0, "hallucinations": 0, "latencies": [], "last_seen": 0})
        s["total"]    += 1
        s["last_seen"] = max(s["last_seen"], e.get("timestamp", 0))
        if e.get("validation", {}).get("is_valid"):   s["valid"]   += 1
        else:                                          s["invalid"] += 1
        if e.get("validation", {}).get("is_hallucination"): s["hallucinations"] += 1
        if e.get("latency_ms"):                        s["latencies"].append(e["latency_ms"])
    for at, s in by_agent.items():
        llist = s.pop("latencies", [])
        s["avg_latency_ms"] = round(sum(llist) / len(llist)) if llist else 0
        s["success_rate"]   = round(s["valid"] / s["total"] * 100, 1) if s["total"] else 0
    return {
        "total": total, "valid": valid, "invalid": total - valid, "hallucinations": halluc,
        "avg_latency_ms": round(sum(lats) / len(lats)) if lats else 0,
        "avg_confidence": round(sum(confs) / len(confs), 3) if confs else 0,
        "error_rate":  round((total - valid) / total * 100, 1) if total else 0,
        "success_rate": round(valid / total * 100, 1) if total else 0,
        "hallucination_rate": round(halluc / total * 100, 1) if total else 0,
        "by_agent": by_agent,
    }


def _ai_alerts(summary: Dict) -> List[Dict]:
    alerts = []
    now = time.time()
    if summary["error_rate"] > 20:
        alerts.append({"level": "critical", "title": f"High AI failure rate: {summary['error_rate']}%",
                        "detail": f"{summary['invalid']} of {summary['total']} responses failed", "ts": now})
    if summary["hallucination_rate"] > 5:
        alerts.append({"level": "warning", "title": f"Hallucination rate: {summary['hallucination_rate']}%",
                        "detail": "Review agent prompts and validation thresholds", "ts": now})
    if summary["avg_latency_ms"] > 30000:
        alerts.append({"level": "warning", "title": f"High latency: {summary['avg_latency_ms']}ms avg",
                        "detail": "AI agents responding slowly", "ts": now})
    return alerts


# ── Ollama helper ─────────────────────────────────────────────────────────────

async def _ollama_chat(prompt: str, system: str = "") -> str:
    messages = []
    if system:
        messages.append({"role": "system", "content": system})
    messages.append({"role": "user", "content": prompt})
    payload = {"model": _OLLAMA_MODEL, "messages": messages, "stream": False}
    try:
        async with httpx.AsyncClient(timeout=120) as client:
            r = await client.post(f"{_OLLAMA_URL}/api/chat", json=payload)
            r.raise_for_status()
            return r.json().get("message", {}).get("content", "")
    except Exception as exc:
        logger.warning("Ollama error: %s", exc)
        return f"Ollama unavailable: {exc}"


# ── Routes ─────────────────────────────────────────────────────────────────────

@app.get("/health")
async def health():
    ollama_ok = False
    try:
        async with httpx.AsyncClient(timeout=5) as client:
            r = await client.get(f"{_OLLAMA_URL}/api/tags")
            ollama_ok = r.status_code == 200
    except Exception:
        pass
    return {
        "status": "ok",
        "ollama": "online" if ollama_ok else "offline",
        "ollama_model": _OLLAMA_MODEL,
        "region": _HOME_REGION,
        "home_account": _HOME_ACCOUNT,
        "ts": time.time(),
    }


@app.get("/api/product-monitoring")
def product_monitoring(account_id: str = Query(default="")):
    acc = account_id or _HOME_ACCOUNT
    cw  = _cw(acc)
    lambda_data = [_lambda_stats(cw, fn) for fn in _LAMBDAS] if _LAMBDAS else []
    api_data    = _apigw_stats(cw)
    dynamo_data = [_dynamo_stats(cw, t) for t in _DYNAMO_TABLES]
    alarms      = _active_alarms(cw)

    high_err     = [fn for fn in lambda_data if fn.get("error_rate", 0) > 20]
    throttled    = [t for t in dynamo_data if t.get("read_throttles", 0) + t.get("write_throttles", 0) > 0]
    score        = max(0, 100 - len(high_err) * 10 - len(throttled) * 5 - len(alarms) * 3
                       - (api_data.get("error_5xx", 0) > 0) * 20)
    health = {
        "score": round(score, 1),
        "status": "healthy" if score >= 80 else ("degraded" if score >= 50 else "critical"),
        "compute_ok": len(high_err) == 0,
        "api_ok": api_data.get("error_5xx", 0) == 0,
        "database_ok": len(throttled) == 0,
        "issues": (
            [f"{len(high_err)} Lambda(s) with high error rate"] if high_err else []
        ) + (
            [f"API Gateway {api_data.get('error_5xx', 0)} 5xx errors"] if api_data.get("error_5xx") else []
        ) + (
            [f"{len(throttled)} DynamoDB table(s) throttling"] if throttled else []
        ) + (
            [f"{len(alarms)} alarm(s) in ALARM state"] if alarms else []
        ),
    }
    return {
        "service_health": health,
        "lambda_metrics": lambda_data,
        "api_gateway":    api_data,
        "dynamo_db":      dynamo_data,
        "active_alarms":  alarms,
        "window_minutes": 60,
        "generated_at":   time.time(),
    }


@app.get("/api/ai-monitoring")
def ai_monitoring(days: int = Query(default=2, le=7), limit: int = Query(default=100, le=200)):
    events  = _read_ai_events(days=days, limit=limit)
    summary = _ai_summary(events)
    alerts  = _ai_alerts(summary)
    return {
        "summary": summary,
        "alerts":  alerts,
        "events":  events[:limit],
        "generatedAt": time.time(),
        "daysScanned": days,
    }


@app.get("/api/cloudwatch-dashboards")
def cw_dashboards(
    account_id: str = Query(default=""),
    region: str     = Query(default=""),
):
    acc = account_id or _HOME_ACCOUNT
    reg = region     or _HOME_REGION
    sess = _session(acc, reg)
    cw   = sess.client("cloudwatch", region_name=reg)
    dashboards = []
    try:
        for page in cw.get_paginator("list_dashboards").paginate():
            for d in page.get("DashboardEntries", []):
                dashboards.append({
                    "name":          d.get("DashboardName"),
                    "arn":           d.get("DashboardArn"),
                    "last_modified": str(d.get("LastModified", "")),
                    "size_bytes":    d.get("Size", 0),
                    "account_id":    acc,
                    "region":        reg,
                    "console_url": (
                        f"https://{reg}.console.aws.amazon.com/cloudwatch/home"
                        f"?region={reg}#dashboards:name={d.get('DashboardName')}"
                    ),
                })
    except Exception as exc:
        logger.warning("list_dashboards: %s", exc)
    return {"account_id": acc, "region": reg, "dashboards": dashboards, "count": len(dashboards)}


class ChatRequest(BaseModel):
    prompt: str
    context: str = ""
    account_id: str = ""


@app.post("/api/chat")
async def chat(req: ChatRequest):
    system = (
        "You are IntelliOps Monitor Assistant — an AI that helps analyze AWS infrastructure "
        "and IntelliOps platform health metrics. Be concise, actionable, and specific. "
        "Use bullet points and **bold** for key findings."
    )
    if req.context:
        system += f"\n\nCurrent monitoring context:\n{req.context}"
    if req.account_id:
        system += f"\nAWS Account: {req.account_id}"
    reply = await _ollama_chat(req.prompt, system)
    return {"response": reply, "model": _OLLAMA_MODEL, "ts": time.time()}


# ── Dashboard HTML (served at root) ───────────────────────────────────────────

_HTML = open(os.path.join(os.path.dirname(__file__), "dashboard.html")).read() \
    if os.path.exists(os.path.join(os.path.dirname(__file__), "dashboard.html")) else "<h1>IntelliOps Monitor</h1>"


@app.get("/", response_class=HTMLResponse)
async def root():
    return HTMLResponse(_HTML)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=False)
