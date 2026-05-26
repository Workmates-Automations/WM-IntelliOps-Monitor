"""
IntelliOps EC2 Monitor Server
Standalone FastAPI server that monitors the IntelliOps platform itself.

Routes:
  GET  /api/application-monitoring    — Lambda / API GW / DynamoDB / EC2 / RDS health
  GET  /api/product-monitoring        — (alias for backward compat)
  GET  /api/ai-monitoring             — AI agent event metrics from S3
  POST /api/ai-monitoring/log         — Log an AI agent event to S3
  GET  /api/ai-monitoring/agent-status — Live per-agent status overview
  POST /api/ai-monitoring/llm-judge   — LLM-as-a-judge evaluation (Langfuse-style)
  GET  /api/cloudwatch-dashboards     — List CW dashboards (cross-account aware)
  GET  /api/service-uptime            — Service uptime and SLA summary
  POST /api/chat                      — Ollama-powered assistant (cross-account aware)
  GET  /health                        — Server health + Ollama status

Open-source monitoring integrations:
  - Grafana: connect to CloudWatch datasource for Lambda/API GW dashboards
  - Loki Stack: ship application logs via Promtail → Loki → Grafana
  - EFK: Fluent Bit → Elasticsearch → Kibana for structured log search

Cross-account: uses CWMSessionRole via STS AssumeRole (same pattern as portal).
"""

from __future__ import annotations

import json
import logging
import os
import sys
import time
import uuid
from typing import Any, Dict, List, Optional

import boto3
import httpx
from botocore.exceptions import ClientError
from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel

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

_AI_BUCKET   = os.environ.get("INTELLIOPS_STRANDS_JOBS_BUCKET", "intelliops-websiterca")
_AI_PREFIX   = "ai-monitoring/events/"

_LAMBDAS = [x.strip() for x in os.environ.get("MONITOR_LAMBDAS", "").split(",") if x.strip()]
_DYNAMO_TABLES = [
    x.strip() for x in
    os.environ.get("MONITOR_DYNAMO_TABLES", "IntelliOps-Tickets,IntelliOps-Alarms,IntelliOps-Sessions").split(",")
    if x.strip()
]

# Known AI agents to track — fallback if none in S3
_KNOWN_AGENTS = ["nexus_agent", "strands_agent", "devops_agent", "rca_agent", "security_agent"]

# ── FastAPI app ────────────────────────────────────────────────────────────────

app = FastAPI(
    title="IntelliOps Monitor",
    description="EC2-hosted monitoring dashboard for IntelliOps platform",
    version="2.0.0",
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


def _ec2_client(account_id: str = "", region: str = _HOME_REGION):
    return _session(account_id, region).client("ec2", region_name=region)


def _rds_client(account_id: str = "", region: str = _HOME_REGION):
    return _session(account_id, region).client("rds", region_name=region)


def _lambda_client(account_id: str = "", region: str = _HOME_REGION):
    return _session(account_id, region).client("lambda", region_name=region)


# ── Time helpers ───────────────────────────────────────────────────────────────

from datetime import datetime, timedelta, timezone


# ── CloudWatch metric helpers ─────────────────────────────────────────────────

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


def _metric_max(cw_client, namespace: str, metric: str, dims: list, minutes: int = 60) -> float:
    end = datetime.now(timezone.utc)
    start = end - timedelta(minutes=minutes)
    try:
        pts = cw_client.get_metric_statistics(
            Namespace=namespace, MetricName=metric, Dimensions=dims,
            StartTime=start, EndTime=end, Period=minutes * 60, Statistics=["Maximum"],
        ).get("Datapoints", [])
        return max((p.get("Maximum", 0) for p in pts), default=0.0)
    except Exception:
        return 0.0


# ── Lambda auto-discovery ─────────────────────────────────────────────────────

def _lambda_list(account_id: str = "", region: str = _HOME_REGION) -> List[str]:
    """Return all Lambda function names; falls back to env-var list if set."""
    if _LAMBDAS:
        return _LAMBDAS
    try:
        client = _lambda_client(account_id, region)
        names: List[str] = []
        for page in client.get_paginator("list_functions").paginate():
            for fn in page.get("Functions", []):
                names.append(fn["FunctionName"])
        return names
    except Exception as exc:
        logger.warning("lambda_list: %s", exc)
        return []


# ── Lambda stats ──────────────────────────────────────────────────────────────

def _lambda_stats(cw_client, fn_name: str) -> Dict:
    dims = [{"Name": "FunctionName", "Value": fn_name}]
    inv = _metric_sum(cw_client, "AWS/Lambda", "Invocations", dims)
    err = _metric_sum(cw_client, "AWS/Lambda", "Errors", dims)
    thr = _metric_sum(cw_client, "AWS/Lambda", "Throttles", dims)
    dur = _metric_avg(cw_client, "AWS/Lambda", "Duration", dims)
    conc = _metric_max(cw_client, "AWS/Lambda", "ConcurrentExecutions", dims)
    rate = round(err / inv * 100, 2) if inv > 0 else 0.0
    return {
        "name": fn_name,
        "invocations": int(inv),
        "errors": int(err),
        "throttles": int(thr),
        "avg_duration_ms": round(dur),
        "max_concurrent": round(conc),
        "error_rate": rate,
        "health": "healthy" if rate < 5 else ("warning" if rate < 20 else "critical"),
    }


def _apigw_stats(cw_client) -> Dict:
    count = _metric_sum(cw_client, "AWS/ApiGateway", "Count", [])
    e5xx  = _metric_sum(cw_client, "AWS/ApiGateway", "5XXError", [])
    e4xx  = _metric_sum(cw_client, "AWS/ApiGateway", "4XXError", [])
    lat   = _metric_avg(cw_client, "AWS/ApiGateway", "Latency", [])
    p99   = _metric_max(cw_client, "AWS/ApiGateway", "Latency", [])
    return {
        "request_count": int(count),
        "error_5xx": int(e5xx),
        "error_4xx": int(e4xx),
        "avg_latency_ms": round(lat),
        "p99_latency_ms": round(p99),
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
    sys_errs = _metric_sum(cw_client, "AWS/DynamoDB", "SystemErrors", dims)
    return {
        "name": table,
        "consumed_read": round(read),
        "consumed_write": round(write),
        "read_throttles": int(rthr),
        "write_throttles": int(wthr),
        "avg_latency_ms": round(lat, 2),
        "system_errors": int(sys_errs),
        "health": "healthy" if rthr == 0 and wthr == 0 else "warning",
    }


def _ec2_health_stats(account_id: str = "", region: str = _HOME_REGION) -> List[Dict]:
    """Return CPU/status-check metrics for running EC2 instances."""
    try:
        ec2 = _ec2_client(account_id, region)
        cw  = _cw(account_id, region)
        instances = []
        paginator = ec2.get_paginator("describe_instances")
        for page in paginator.paginate(Filters=[{"Name": "instance-state-name", "Values": ["running"]}]):
            for res in page.get("Reservations", []):
                for inst in res.get("Instances", []):
                    iid  = inst.get("InstanceId", "")
                    name = next((t["Value"] for t in inst.get("Tags", []) if t["Key"] == "Name"), iid)
                    dims = [{"Name": "InstanceId", "Value": iid}]
                    cpu  = _metric_avg(cw, "AWS/EC2", "CPUUtilization", dims, minutes=15)
                    net_in  = _metric_sum(cw, "AWS/EC2", "NetworkIn", dims, minutes=15)
                    net_out = _metric_sum(cw, "AWS/EC2", "NetworkOut", dims, minutes=15)
                    # Status checks
                    sc_fail = _metric_sum(cw, "AWS/EC2", "StatusCheckFailed", dims, minutes=15)
                    instances.append({
                        "instance_id": iid,
                        "name": name,
                        "type": inst.get("InstanceType", ""),
                        "cpu_pct": round(cpu, 1),
                        "net_in_mb": round(net_in / 1024 / 1024, 2),
                        "net_out_mb": round(net_out / 1024 / 1024, 2),
                        "status_check_failed": int(sc_fail) > 0,
                        "health": "critical" if int(sc_fail) > 0 else ("warning" if cpu > 80 else "healthy"),
                    })
        return instances
    except Exception as exc:
        logger.warning("ec2_health_stats: %s", exc)
        return []


def _rds_health_stats(account_id: str = "", region: str = _HOME_REGION) -> List[Dict]:
    """Return CPU/connections/freeable-memory for RDS instances."""
    try:
        rds_client = _rds_client(account_id, region)
        cw  = _cw(account_id, region)
        instances = []
        paginator = rds_client.get_paginator("describe_db_instances")
        for page in paginator.paginate():
            for db in page.get("DBInstances", []):
                dbid   = db.get("DBInstanceIdentifier", "")
                engine = db.get("Engine", "")
                status = db.get("DBInstanceStatus", "")
                dims = [{"Name": "DBInstanceIdentifier", "Value": dbid}]
                cpu  = _metric_avg(cw, "AWS/RDS", "CPUUtilization", dims, minutes=15)
                conn = _metric_avg(cw, "AWS/RDS", "DatabaseConnections", dims, minutes=15)
                free_mem = _metric_avg(cw, "AWS/RDS", "FreeableMemory", dims, minutes=15)
                free_storage = _metric_avg(cw, "AWS/RDS", "FreeStorageSpace", dims, minutes=15)
                instances.append({
                    "db_id": dbid,
                    "engine": engine,
                    "status": status,
                    "cpu_pct": round(cpu, 1),
                    "connections": round(conn),
                    "freeable_memory_gb": round(free_mem / 1024**3, 2),
                    "free_storage_gb": round(free_storage / 1024**3, 2),
                    "health": "critical" if status != "available" else ("warning" if cpu > 80 else "healthy"),
                })
        return instances
    except Exception as exc:
        logger.warning("rds_health_stats: %s", exc)
        return []


# ── Bedrock helpers ───────────────────────────────────────────────────────────

_BEDROCK_AGENT_HEALTH = {
    "PREPARED":    "healthy",
    "NOT_PREPARED": "warning",
    "PREPARING":   "warning",
    "CREATING":    "warning",
    "VERSIONING":  "warning",
    "FAILED":      "critical",
    "DELETING":    "critical",
}


def _bedrock_agents(account_id: str = "", region: str = _HOME_REGION) -> List[Dict]:
    """List all Bedrock Agents with status + last-24h CloudWatch metrics."""
    try:
        sess = _session(account_id, region)
        ba   = sess.client("bedrock-agent", region_name=region)
        cw   = _cw(account_id, region)
        agents: List[Dict] = []
        for page in ba.get_paginator("list_agents").paginate():
            for a in page.get("agentSummaries", []):
                aid        = a.get("agentId", "")
                raw_status = a.get("agentStatus", "UNKNOWN")
                # Correct AWS/Bedrock metric names — dimension AgentId for per-agent data
                dims = [{"Name": "AgentId", "Value": aid}]
                invocations   = _metric_sum(cw, "AWS/Bedrock", "Invocations",            dims, minutes=1440)
                latency       = _metric_avg(cw, "AWS/Bedrock", "InvocationLatency",      dims, minutes=1440)
                client_errors = _metric_sum(cw, "AWS/Bedrock", "InvocationClientErrors", dims, minutes=1440)
                server_errors = _metric_sum(cw, "AWS/Bedrock", "InvocationServerErrors", dims, minutes=1440)
                throttles     = _metric_sum(cw, "AWS/Bedrock", "InvocationThrottles",    dims, minutes=1440)
                success_pct   = (
                    round((invocations - client_errors - server_errors) / invocations * 100, 1)
                    if invocations > 0 else 0
                )
                agents.append({
                    "agent_id":          aid,
                    "agent_name":        a.get("agentName", aid),
                    "agent_status":      raw_status,
                    "description":       (a.get("description") or "")[:120],
                    "latest_version":    a.get("latestAgentVersion", ""),
                    "updated_at":        str(a.get("updatedAt", "")),
                    "health":            _BEDROCK_AGENT_HEALTH.get(raw_status, "unknown"),
                    "invocations_24h":   int(invocations),
                    "success_rate":      success_pct,
                    "avg_latency_ms":    round(latency) if latency else 0,
                    "user_errors_24h":   int(client_errors),
                    "server_errors_24h": int(server_errors),
                    "throttles_24h":     int(throttles),
                })
        agents.sort(key=lambda x: x["agent_name"].lower())
        return agents
    except Exception as exc:
        logger.warning("bedrock_agents: %s", exc)
        return []


def _bedrock_model_metrics(account_id: str = "", region: str = _HOME_REGION) -> Dict:
    """Aggregate Bedrock model-invocation metrics from CloudWatch (last 24h)."""
    try:
        cw = _cw(account_id, region)
        # No dimension = aggregate across all models in the account/region
        return {
            "total_invocations_24h": int(_metric_sum(cw, "AWS/Bedrock", "Invocations",            [], minutes=1440)),
            "avg_latency_ms":        round(_metric_avg(cw, "AWS/Bedrock", "InvocationLatency",      [], minutes=1440)),
            "client_errors_24h":     int(_metric_sum(cw, "AWS/Bedrock", "InvocationClientErrors",  [], minutes=1440)),
            "server_errors_24h":     int(_metric_sum(cw, "AWS/Bedrock", "InvocationServerErrors",  [], minutes=1440)),
            "throttles_24h":         int(_metric_sum(cw, "AWS/Bedrock", "InvocationThrottles",      [], minutes=1440)),
        }
    except Exception as exc:
        logger.warning("bedrock_model_metrics: %s", exc)
        return {}


def _bedrock_logging_status(account_id: str = "", region: str = _HOME_REGION) -> Dict:
    """Check whether Bedrock model-invocation logging is enabled."""
    try:
        bedrock = _session(account_id, region).client("bedrock", region_name=region)
        lc = bedrock.get_model_invocation_logging_configuration().get("loggingConfig", {})
        return {
            "enabled":             bool(lc.get("cloudWatchConfig") or lc.get("s3Config")),
            "cloudwatch_enabled":  bool(lc.get("cloudWatchConfig")),
            "s3_enabled":          bool(lc.get("s3Config")),
            "log_group":           (lc.get("cloudWatchConfig") or {}).get("logGroupName", ""),
        }
    except Exception as exc:
        logger.warning("bedrock_logging_status: %s", exc)
        return {"enabled": False, "cloudwatch_enabled": False, "s3_enabled": False, "log_group": ""}


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

def _list_date_prefixes(days: int = 2) -> List[str]:
    return [
        f"{_AI_PREFIX}{(datetime.now(timezone.utc) - timedelta(days=d)).strftime('%Y/%m/%d')}/"
        for d in range(days)
    ]


def _job_record_to_event(rec: Dict, agent_type: str) -> Optional[Dict]:
    """Convert a Strands / Ollama job record to the AI monitoring event schema."""
    status      = rec.get("status", "")
    completed   = rec.get("completedAt") or 0
    started     = rec.get("startedAt")   or 0
    if not completed:
        return None  # still running

    is_valid    = status in ("completed", "requires_approval")
    latency_ms  = int((completed - started) * 1000) if started else 0
    confidence  = 0.85 if status == "completed" else (0.70 if status == "requires_approval" else 0.0)
    response    = rec.get("response", "") or ""
    error_msg   = rec.get("error") if not is_valid else None

    return {
        "timestamp":       int(completed * 1000),
        "agent_type":      agent_type,
        "job_id":          rec.get("jobId", ""),
        "latency_ms":      latency_ms,
        "response_length": len(response),
        "error":           error_msg,
        "validation": {
            "is_valid":        is_valid,
            "is_hallucination": False,
            "confidence":      confidence,
        },
        "_source": "job_store",
    }


def _read_job_stores(days: int = 2, limit: int = 150) -> List[Dict]:
    """
    Read Strands + Ollama job stores as a fallback when ai-monitoring/events/ is empty.
    Uses timestamp-prefix StartAfter to skip records older than `days` days.
    """
    s3         = _s3()
    cutoff_ts  = int(time.time() - days * 86400)
    results: List[Dict] = []

    sources = [
        ("strands-jobs/", "strands-jobs/strands-", "strands_agent"),
        ("ollama-jobs/",  "ollama-jobs/ollama-",   "ollama_executor"),
    ]
    for prefix_dir, start_key_prefix, agent_type in sources:
        start_after = f"{start_key_prefix}{cutoff_ts}"
        try:
            paginator = s3.get_paginator("list_objects_v2")
            for page in paginator.paginate(
                Bucket=_AI_BUCKET,
                Prefix=prefix_dir,
                StartAfter=start_after,
                MaxKeys=min(limit, 300),
            ):
                for obj in page.get("Contents", []):
                    try:
                        body = s3.get_object(Bucket=_AI_BUCKET, Key=obj["Key"])["Body"].read()
                        rec  = json.loads(body)
                        ev   = _job_record_to_event(rec, agent_type)
                        if ev:
                            results.append(ev)
                    except Exception:
                        pass
        except Exception as exc:
            logger.debug("_read_job_stores %s: %s", prefix_dir, exc)

    results.sort(key=lambda e: e.get("timestamp", 0), reverse=True)
    return results[:limit]


def _read_ai_events(days: int = 2, limit: int = 200) -> List[Dict]:
    s3 = _s3()
    keys: List[str] = []
    for prefix in _list_date_prefixes(days):
        try:
            for page in s3.get_paginator("list_objects_v2").paginate(Bucket=_AI_BUCKET, Prefix=prefix, MaxKeys=300):
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

    # If no dedicated event-log entries exist yet, fall back to job stores
    if not events:
        events = _read_job_stores(days=days, limit=limit)

    return events


def _agent_display_name(agent_type: str) -> str:
    names = {
        "nexus_agent":    "Nexus AI Agent",
        "strands_agent":  "Strands Agent",
        "devops_agent":   "DevOps Agent",
        "rca_agent":      "RCA Agent",
        "security_agent": "Security Agent",
        "judge_agent":    "Judge Agent",
        "compliance_agent": "Compliance Agent",
        "healing_agent":  "Healing Agent",
    }
    return names.get(agent_type, agent_type.replace("_", " ").title())


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
        s  = by_agent.setdefault(at, {
            "total": 0, "valid": 0, "invalid": 0, "hallucinations": 0,
            "latencies": [], "last_seen": 0, "errors": [],
            "confidence_scores": [],
        })
        s["total"]   += 1
        s["last_seen"] = max(s["last_seen"], e.get("timestamp", 0))
        v = e.get("validation", {})
        if v.get("is_valid"):    s["valid"]   += 1
        else:                    s["invalid"] += 1
        if v.get("is_hallucination"): s["hallucinations"] += 1
        if e.get("latency_ms"): s["latencies"].append(e["latency_ms"])
        if v.get("confidence") is not None: s["confidence_scores"].append(v["confidence"])
        if e.get("error"):      s["errors"].append(str(e["error"])[:200])

    for at, s in by_agent.items():
        llist = s.pop("latencies", [])
        clist = s.pop("confidence_scores", [])
        errs  = s.pop("errors", [])
        s["avg_latency_ms"]   = round(sum(llist) / len(llist)) if llist else 0
        s["max_latency_ms"]   = round(max(llist)) if llist else 0
        s["avg_confidence"]   = round(sum(clist) / len(clist), 3) if clist else 0
        s["success_rate"]     = round(s["valid"] / s["total"] * 100, 1) if s["total"] else 0
        s["error_rate"]       = round(s["invalid"] / s["total"] * 100, 1) if s["total"] else 0
        s["hallucination_rate"] = round(s["hallucinations"] / s["total"] * 100, 1) if s["total"] else 0
        s["recent_errors"]    = errs[-3:]
        s["display_name"]     = _agent_display_name(at)
        s["last_seen_iso"]    = datetime.fromtimestamp(s["last_seen"], tz=timezone.utc).isoformat() if s["last_seen"] else None
        s["status"] = (
            "critical" if s["error_rate"] > 20 or s["hallucination_rate"] > 10 else
            "warning"  if s["error_rate"] > 5  or s["avg_latency_ms"] > 15000 else
            "healthy"
        )

    return {
        "total": total,
        "valid": valid,
        "invalid": total - valid,
        "hallucinations": halluc,
        "avg_latency_ms": round(sum(lats) / len(lats)) if lats else 0,
        "max_latency_ms": round(max(lats)) if lats else 0,
        "avg_confidence": round(sum(confs) / len(confs), 3) if confs else 0,
        "error_rate":       round((total - valid) / total * 100, 1) if total else 0,
        "success_rate":     round(valid / total * 100, 1) if total else 0,
        "hallucination_rate": round(halluc / total * 100, 1) if total else 0,
        "by_agent": by_agent,
    }


def _ai_alerts(summary: Dict) -> List[Dict]:
    alerts = []
    now = time.time()
    if summary["error_rate"] > 20:
        alerts.append({
            "level": "critical",
            "title": f"High AI failure rate: {summary['error_rate']}%",
            "detail": f"{summary['invalid']} of {summary['total']} responses failed",
            "ts": now,
        })
    if summary["hallucination_rate"] > 5:
        alerts.append({
            "level": "warning",
            "title": f"Hallucination rate elevated: {summary['hallucination_rate']}%",
            "detail": "Review agent prompts and validation thresholds",
            "ts": now,
        })
    if summary["avg_latency_ms"] > 30000:
        alerts.append({
            "level": "warning",
            "title": f"High AI latency: {summary['avg_latency_ms']} ms avg",
            "detail": "AI agents responding slowly — check Ollama/Bedrock availability",
            "ts": now,
        })
    for agent_type, agent_data in summary.get("by_agent", {}).items():
        if agent_data.get("error_rate", 0) > 30:
            alerts.append({
                "level": "critical",
                "title": f"{agent_data['display_name']} — critical failure rate {agent_data['error_rate']}%",
                "detail": f"Last errors: {'; '.join(agent_data.get('recent_errors', [])[:2])}",
                "ts": now,
            })
        if agent_data.get("hallucination_rate", 0) > 10:
            alerts.append({
                "level": "warning",
                "title": f"{agent_data['display_name']} — hallucination spike {agent_data['hallucination_rate']}%",
                "detail": "Increase validation strictness or review model context window",
                "ts": now,
            })
    return alerts


# ── Service uptime tracker ─────────────────────────────────────────────────────

def _check_service_endpoints() -> List[Dict]:
    """HTTP health checks against key IntelliOps services."""
    services = [
        {"name": "IntelliOps Portal", "url": "https://portal.wmintelliops.com"},
        {"name": "Monitor Server",    "url": "http://localhost:8000/health"},
        {"name": "Ollama",            "url": f"{_OLLAMA_URL}/api/tags"},
    ]
    results = []
    import urllib.request
    for svc in services:
        start = time.time()
        try:
            req = urllib.request.Request(svc["url"], headers={"User-Agent": "IntelliOps-Monitor/2.0"})
            with urllib.request.urlopen(req, timeout=5) as resp:
                latency_ms = round((time.time() - start) * 1000)
                results.append({
                    "name": svc["name"],
                    "url": svc["url"],
                    "status": "up",
                    "status_code": resp.status,
                    "latency_ms": latency_ms,
                    "checked_at": time.time(),
                })
        except Exception as exc:
            results.append({
                "name": svc["name"],
                "url": svc["url"],
                "status": "down",
                "error": str(exc)[:120],
                "latency_ms": None,
                "checked_at": time.time(),
            })
    return results


# ── Ollama helper ─────────────────────────────────────────────────────────────

async def _ollama_chat(prompt: str, system: str = "") -> str:
    # Discover available models so we can fall back gracefully
    available_models: List[str] = []
    try:
        async with httpx.AsyncClient(timeout=5) as client:
            r = await client.get(f"{_OLLAMA_URL}/api/tags")
            if r.status_code == 200:
                available_models = [m.get("name", "") for m in r.json().get("models", [])]
    except Exception:
        pass

    model = _OLLAMA_MODEL
    if available_models:
        base = model.split(":")[0]
        matches = [m for m in available_models if m == model or m.startswith(base)]
        model = matches[0] if matches else available_models[0]

    messages = []
    if system:
        messages.append({"role": "system", "content": system})
    messages.append({"role": "user", "content": prompt})
    payload = {"model": model, "messages": messages, "stream": False}
    # 300s timeout — llama3.2 on CPU-only EC2 can take 3-4 minutes for long prompts
    _timeout = httpx.Timeout(connect=10.0, read=300.0, write=30.0, pool=10.0)
    try:
        async with httpx.AsyncClient(timeout=_timeout) as client:
            r = await client.post(f"{_OLLAMA_URL}/api/chat", json=payload)
            if r.status_code == 404:
                # Older Ollama or model not pulled — fallback to /api/generate
                gen_payload = {
                    "model": model,
                    "prompt": (f"System: {system}\n\n" if system else "") + f"User: {prompt}\nAssistant:",
                    "stream": False,
                }
                r = await client.post(f"{_OLLAMA_URL}/api/generate", json=gen_payload)
                r.raise_for_status()
                return r.json().get("response", "")
            r.raise_for_status()
            return r.json().get("message", {}).get("content", "")
    except Exception as exc:
        exc_detail = f"{type(exc).__name__}: {exc}" if str(exc) else type(exc).__name__
        logger.warning("Ollama error: %s", exc_detail)
        hint = f" (available: {', '.join(available_models[:3])})" if available_models else " (no models loaded — run: docker compose exec ollama ollama pull llama3.2)"
        return f"Ollama error{hint}: {exc_detail}"


# ── Routes ────────────────────────────────────────────────────────────────────

@app.get("/health")
async def health():
    ollama_ok = False
    ollama_models: List[str] = []
    try:
        async with httpx.AsyncClient(timeout=5) as client:
            r = await client.get(f"{_OLLAMA_URL}/api/tags")
            if r.status_code == 200:
                ollama_ok = True
                ollama_models = [m.get("name", "") for m in r.json().get("models", [])]
    except Exception:
        pass
    return {
        "status": "ok",
        "ollama": "online" if ollama_ok else "offline",
        "ollama_model": _OLLAMA_MODEL,
        "ollama_available_models": ollama_models,
        "region": _HOME_REGION,
        "home_account": _HOME_ACCOUNT,
        "ts": time.time(),
    }


@app.get("/api/application-monitoring")
def application_monitoring(
    account_id: str = Query(default=""),
    region:     str = Query(default=""),
    include_ec2: bool = Query(default=True),
    include_rds: bool = Query(default=True),
):
    acc = account_id or _HOME_ACCOUNT
    reg = region or _HOME_REGION
    cw  = _cw(acc, reg)

    lambda_names = _lambda_list(acc, reg)
    lambda_data  = [_lambda_stats(cw, fn) for fn in lambda_names]
    api_data     = _apigw_stats(cw)
    dynamo_data  = [_dynamo_stats(cw, t) for t in _DYNAMO_TABLES]
    alarms       = _active_alarms(cw)
    ec2_data     = _ec2_health_stats(acc, reg) if include_ec2 else []
    rds_data     = _rds_health_stats(acc, reg) if include_rds else []

    # Service endpoint checks
    service_uptime = _check_service_endpoints()

    # Score calculation
    high_err    = [fn for fn in lambda_data if fn.get("error_rate", 0) > 20]
    throttled   = [t for t in dynamo_data if t.get("read_throttles", 0) + t.get("write_throttles", 0) > 0]
    ec2_issues  = [e for e in ec2_data if e.get("health") != "healthy"]
    rds_issues  = [r for r in rds_data if r.get("health") != "healthy"]
    svc_down    = [s for s in service_uptime if s.get("status") == "down"]

    score = max(0, 100
        - len(high_err) * 10
        - len(throttled) * 5
        - len(alarms) * 3
        - (api_data.get("error_5xx", 0) > 0) * 20
        - len(ec2_issues) * 8
        - len(rds_issues) * 8
        - len(svc_down) * 15
    )

    issues = (
        [f"{len(high_err)} Lambda(s) with high error rate"]             if high_err   else []
    ) + (
        [f"API Gateway — {api_data.get('error_5xx', 0)} 5xx errors"]   if api_data.get("error_5xx") else []
    ) + (
        [f"{len(throttled)} DynamoDB table(s) throttling"]              if throttled  else []
    ) + (
        [f"{len(alarms)} CloudWatch alarm(s) in ALARM state"]           if alarms     else []
    ) + (
        [f"{len(ec2_issues)} EC2 instance(s) with issues"]              if ec2_issues else []
    ) + (
        [f"{len(rds_issues)} RDS instance(s) with issues"]              if rds_issues else []
    ) + (
        [f"{len(svc_down)} service(s) unreachable"]                     if svc_down   else []
    )

    health_status = {
        "score": round(score, 1),
        "status": "healthy" if score >= 80 else ("degraded" if score >= 50 else "critical"),
        "compute_ok":  len(high_err) == 0,
        "api_ok":      api_data.get("error_5xx", 0) == 0,
        "database_ok": len(throttled) == 0,
        "ec2_ok":      len(ec2_issues) == 0,
        "rds_ok":      len(rds_issues) == 0,
        "services_ok": len(svc_down) == 0,
        "issues": issues,
    }

    return {
        "service_health":  health_status,
        "lambda_metrics":  lambda_data,
        "api_gateway":     api_data,
        "dynamo_db":       dynamo_data,
        "ec2_instances":   ec2_data,
        "rds_instances":   rds_data,
        "active_alarms":   alarms,
        "service_uptime":  service_uptime,
        "window_minutes":  60,
        "account_id":      acc,
        "region":          reg,
        "generated_at":    time.time(),
        "open_source_integrations": {
            "grafana": {
                "description": "Grafana with CloudWatch datasource for Lambda/API GW dashboards",
                "datasource": "cloudwatch",
                "docs": "https://grafana.com/docs/grafana/latest/datasources/aws-cloudwatch/",
            },
            "loki_stack": {
                "description": "Loki + Promtail + Grafana for application log aggregation",
                "shipper": "Promtail / Fluent Bit",
                "docs": "https://grafana.com/docs/loki/latest/",
            },
            "efk": {
                "description": "Elasticsearch + Fluent Bit + Kibana for structured log search",
                "shipper": "Fluent Bit",
                "docs": "https://www.elastic.co/guide/en/elastic-stack-get-started/current/get-started-docker.html",
            },
        },
    }


# Backward-compat alias
app.get("/api/product-monitoring")(application_monitoring)


class LLMJudgeRequest(BaseModel):
    prompt:   str
    response: str
    context:  Optional[str] = None
    criteria: Optional[List[str]] = None


@app.post("/api/ai-monitoring/llm-judge")
async def llm_judge(req: LLMJudgeRequest):
    """
    LLM-as-a-judge evaluation (Langfuse-style).
    Uses the local Ollama model to score an AI response on:
      accuracy, relevance, groundedness, hallucination_risk, helpfulness
    Returns scores 1-5 and brief reasoning for each criterion.
    """
    default_criteria = ["accuracy", "relevance", "groundedness", "hallucination_risk", "helpfulness"]
    criteria = req.criteria or default_criteria

    judge_prompt = (
        "You are an expert AI evaluator. Score the following AI response on each criterion from 1 (poor) to 5 (excellent).\n\n"
        f"Original Prompt:\n{req.prompt[:1000]}\n\n"
        + (f"Context:\n{req.context[:500]}\n\n" if req.context else "")
        + f"AI Response:\n{req.response[:1500]}\n\n"
        "Evaluate on these criteria:\n"
        + "\n".join(f"- {c}" for c in criteria)
        + "\n\nRespond ONLY with a JSON object like:\n"
        '{"accuracy":4,"relevance":5,"groundedness":3,"hallucination_risk":2,"helpfulness":4,'
        '"reasoning":"Brief 1-2 sentence explanation","overall_score":3.6}'
    )
    try:
        _timeout = httpx.Timeout(connect=10.0, read=120.0, write=30.0, pool=10.0)
        async with httpx.AsyncClient(timeout=_timeout) as client:
            r = await client.post(
                f"{_OLLAMA_URL}/api/generate",
                json={"model": _OLLAMA_MODEL, "prompt": judge_prompt, "stream": False},
            )
        r.raise_for_status()
        raw = r.json().get("response", "")
        # Strip markdown fences
        import re as _re
        raw = _re.sub(r'^```(?:json)?\s*|\s*```$', '', raw.strip(), flags=_re.MULTILINE).strip()
        # Find first { ... }
        m = _re.search(r'\{.*\}', raw, _re.DOTALL)
        scores = json.loads(m.group(0)) if m else {}
        if not any(c in scores for c in criteria):
            raise ValueError("No criterion scores in response")
        # Compute overall if not present
        if "overall_score" not in scores:
            vals = [float(scores[c]) for c in criteria if c in scores]
            scores["overall_score"] = round(sum(vals) / len(vals), 2) if vals else 0.0
        return {"success": True, "scores": scores, "criteria": criteria, "model": _OLLAMA_MODEL}
    except Exception as exc:
        logger.warning("LLM judge failed: %s", exc)
        return JSONResponse(
            status_code=500,
            content={"success": False, "error": f"{type(exc).__name__}: {exc}"},
        )


@app.get("/api/ai-monitoring")
def ai_monitoring(
    days:  int = Query(default=2, le=7),
    limit: int = Query(default=200, le=500),
):
    events  = _read_ai_events(days=days, limit=limit)
    summary = _ai_summary(events)
    alerts  = _ai_alerts(summary)

    # Validation quality breakdown
    validation_breakdown = {
        "accuracy_distribution": {},
        "confidence_distribution": {"high": 0, "medium": 0, "low": 0},
    }
    for e in events:
        v = e.get("validation", {})
        conf = v.get("confidence", 0)
        if conf >= 0.8:   validation_breakdown["confidence_distribution"]["high"]   += 1
        elif conf >= 0.5: validation_breakdown["confidence_distribution"]["medium"] += 1
        else:             validation_breakdown["confidence_distribution"]["low"]    += 1

    # Hourly event trend (last 24h)
    hourly: Dict[int, int] = {h: 0 for h in range(24)}
    cutoff = time.time() - 86400
    for e in events:
        ts = e.get("timestamp", 0)
        if ts > cutoff:
            hour = datetime.fromtimestamp(ts / 1000 if ts > 1e12 else ts, tz=timezone.utc).hour
            hourly[hour] = hourly.get(hour, 0) + 1

    return {
        "summary":              summary,
        "alerts":               alerts,
        "events":               events[:50],
        "validation_breakdown": validation_breakdown,
        "hourly_trend":         [{"hour": h, "count": hourly[h]} for h in range(24)],
        "generatedAt":          time.time(),
        "daysScanned":          days,
    }


@app.get("/api/ai-monitoring/agent-status")
def ai_agent_status():
    """Live status overview for each known AI agent."""
    events = _read_ai_events(days=1, limit=200)
    summary = _ai_summary(events)
    by_agent = summary.get("by_agent", {})

    statuses = []
    for agent_type in _KNOWN_AGENTS:
        data = by_agent.get(agent_type, {})
        statuses.append({
            "agent_type":   agent_type,
            "display_name": _agent_display_name(agent_type),
            "status":       data.get("status", "unknown"),
            "total":        data.get("total", 0),
            "success_rate": data.get("success_rate", 0),
            "error_rate":   data.get("error_rate", 0),
            "hallucination_rate": data.get("hallucination_rate", 0),
            "avg_latency_ms": data.get("avg_latency_ms", 0),
            "avg_confidence": data.get("avg_confidence", 0),
            "last_seen_iso":  data.get("last_seen_iso"),
            "recent_errors":  data.get("recent_errors", []),
        })

    # Also add any agents seen in S3 that aren't in known list
    for agent_type, data in by_agent.items():
        if agent_type not in _KNOWN_AGENTS:
            statuses.append({
                "agent_type":   agent_type,
                "display_name": _agent_display_name(agent_type),
                "status":       data.get("status", "unknown"),
                "total":        data.get("total", 0),
                "success_rate": data.get("success_rate", 0),
                "error_rate":   data.get("error_rate", 0),
                "hallucination_rate": data.get("hallucination_rate", 0),
                "avg_latency_ms": data.get("avg_latency_ms", 0),
                "avg_confidence": data.get("avg_confidence", 0),
                "last_seen_iso":  data.get("last_seen_iso"),
                "recent_errors":  data.get("recent_errors", []),
            })

    return {
        "agents":       statuses,
        "total_agents": len(statuses),
        "healthy":      sum(1 for a in statuses if a["status"] == "healthy"),
        "warning":      sum(1 for a in statuses if a["status"] == "warning"),
        "critical":     sum(1 for a in statuses if a["status"] == "critical"),
        "unknown":      sum(1 for a in statuses if a["status"] == "unknown"),
        "generated_at": time.time(),
    }


class AIEventLog(BaseModel):
    agent_type:    str
    latency_ms:    Optional[float] = None
    error:         Optional[str]   = None
    prompt_tokens: Optional[int]   = None
    output_tokens: Optional[int]   = None
    model:         Optional[str]   = None
    validation:    Optional[Dict]  = None
    metadata:      Optional[Dict]  = None


@app.post("/api/ai-monitoring/log")
def log_ai_event(event: AIEventLog):
    """Write a single AI agent event to S3 for aggregation."""
    try:
        s3  = _s3()
        now = datetime.now(timezone.utc)
        key = f"{_AI_PREFIX}{now.strftime('%Y/%m/%d')}/{event.agent_type}_{int(time.time() * 1000)}_{uuid.uuid4().hex[:8]}.json"
        payload = {
            "timestamp":    int(time.time() * 1000),
            "agent_type":   event.agent_type,
            "latency_ms":   event.latency_ms,
            "error":        event.error,
            "prompt_tokens": event.prompt_tokens,
            "output_tokens": event.output_tokens,
            "model":        event.model or _OLLAMA_MODEL,
            "validation":   event.validation or {},
            "metadata":     event.metadata or {},
        }
        s3.put_object(
            Bucket=_AI_BUCKET,
            Key=key,
            Body=json.dumps(payload).encode(),
            ContentType="application/json",
        )
        return {"ok": True, "key": key}
    except Exception as exc:
        logger.error("log_ai_event: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc))


@app.get("/api/service-uptime")
def service_uptime():
    """Check HTTP health of IntelliOps services."""
    results = _check_service_endpoints()
    up   = [r for r in results if r.get("status") == "up"]
    down = [r for r in results if r.get("status") == "down"]
    return {
        "services":   results,
        "total":      len(results),
        "up":         len(up),
        "down":       len(down),
        "uptime_pct": round(len(up) / len(results) * 100, 1) if results else 0,
        "checked_at": time.time(),
    }


@app.get("/api/cloudwatch-dashboards")
def cw_dashboards(
    account_id: str = Query(default=""),
    region:     str = Query(default=""),
):
    acc = account_id or _HOME_ACCOUNT
    reg = region or _HOME_REGION
    sess = _session(acc, reg)
    cw   = sess.client("cloudwatch", region_name=reg)
    dashboards = []
    try:
        for page in cw.get_paginator("list_dashboards").paginate():
            for d in page.get("DashboardEntries", []):
                name = d.get("DashboardName", "")
                dashboards.append({
                    "name":          name,
                    "arn":           d.get("DashboardArn"),
                    "last_modified": str(d.get("LastModified", "")),
                    "size_bytes":    d.get("Size", 0),
                    "account_id":    acc,
                    "region":        reg,
                    "console_url": (
                        f"https://{reg}.console.aws.amazon.com/cloudwatch/home"
                        f"?region={reg}#dashboards:name={name}"
                    ),
                })
    except Exception as exc:
        logger.warning("list_dashboards: %s", exc)
    return {"account_id": acc, "region": reg, "dashboards": dashboards, "count": len(dashboards)}


@app.get("/api/bedrock-agents")
def bedrock_agents_route(
    account_id: str = Query(default=""),
    region:     str = Query(default=""),
):
    """List all Bedrock Agents with deployment status and 24h CloudWatch metrics."""
    acc = account_id or _HOME_ACCOUNT
    reg = region or _HOME_REGION
    agents  = _bedrock_agents(acc, reg)
    metrics = _bedrock_model_metrics(acc, reg)
    logging_status = _bedrock_logging_status(acc, reg)
    healthy  = sum(1 for a in agents if a["health"] == "healthy")
    warning  = sum(1 for a in agents if a["health"] == "warning")
    critical = sum(1 for a in agents if a["health"] == "critical")
    unknown  = sum(1 for a in agents if a["health"] == "unknown")
    return {
        "agents":          agents,
        "total_agents":    len(agents),
        "healthy":         healthy,
        "warning":         warning,
        "critical":        critical,
        "unknown":         unknown,
        "bedrock_metrics": metrics,
        "logging_status":  logging_status,
        "account_id":      acc,
        "region":          reg,
        "generated_at":    time.time(),
    }


class ChatRequest(BaseModel):
    prompt:     str
    context:    str  = ""
    account_id: str  = ""


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


# ── Dashboard HTML ────────────────────────────────────────────────────────────

_HTML_PATH = os.path.join(os.path.dirname(__file__), "dashboard.html")
_HTML = open(_HTML_PATH).read() if os.path.exists(_HTML_PATH) else "<h1>IntelliOps Monitor</h1>"


@app.get("/", response_class=HTMLResponse)
async def root():
    return HTMLResponse(_HTML)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=False)
