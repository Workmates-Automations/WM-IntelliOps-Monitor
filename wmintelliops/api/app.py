"""
IntelliOps Multi-Agent API
FastAPI application that exposes the multi-agent PoC as REST endpoints.

Run:
    uvicorn wmintelliops.api.app:app --host 0.0.0.0 --port 8001 --reload

Endpoints:
  POST /agent/security          — Run SecurityAgent for account/region
  POST /agent/rca               — Run RCAAgent for incident
  POST /agent/compliance        — Run ComplianceAgent for account/region
  POST /agent/healing           — Run HealingAgent (dry_run by default)
  POST /workflow/security       — Run full SecurityWorkflow (all agents in sequence)
  GET  /workflow/{id}           — Poll workflow result by ID
  GET  /agent/status            — Current agent status from memory
  POST /rag/ingest              — Ingest documents into a named namespace
  GET  /rag/search              — Semantic search across a namespace
  GET  /memory/{agent}/{key}    — Retrieve agent memory by key
  GET  /health                  — API health
"""
from __future__ import annotations

import logging
import os
import time
from typing import Any, Dict, List, Optional

from fastapi import BackgroundTasks, FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

logger = logging.getLogger(__name__)

_OLLAMA_URL   = os.environ.get("OLLAMA_URL",   "http://localhost:11434")
_OLLAMA_MODEL = os.environ.get("OLLAMA_MODEL", "llama3.2")
_MONITOR_URL  = os.environ.get("MONITOR_URL",  "http://localhost:8000")
_DRY_RUN      = os.environ.get("HEALING_DRY_RUN", "true").lower() == "true"

app = FastAPI(
    title="IntelliOps Multi-Agent API",
    description="Ollama-powered multi-agent security & operations platform",
    version="1.0.0",
    docs_url="/docs",
)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])


# ── Request / Response models ─────────────────────────────────────────────────

class AccountRequest(BaseModel):
    account_id: str
    region: str = "ap-south-1"
    context: Optional[Dict] = None

class RCARequest(BaseModel):
    incident_id: str
    account_id: str
    region: str = "ap-south-1"
    incident_text: str
    signals: Optional[Dict] = None

class WorkflowRequest(BaseModel):
    account_id: str
    region: str = "ap-south-1"
    incident_id: Optional[str] = None
    incident_text: Optional[str] = None
    context: Optional[Dict] = None
    dry_run: bool = True

class RAGIngestRequest(BaseModel):
    namespace: str
    items: List[Dict]  # [{"text": "...", "metadata": {...}}]

class HealingRequest(BaseModel):
    incident_id: str
    account_id: str
    region: str = "ap-south-1"
    incident_text: str
    signals: Optional[Dict] = None
    dry_run: bool = True

class ValidateRequest(BaseModel):
    agent_type: str
    output: Any
    ground_truth: Optional[Dict] = None
    latency_ms: Optional[float] = None


# ── In-memory workflow result store (use MemoryStore for persistence) ─────────

_workflow_results: Dict[str, Dict] = {}


# ── Helper ────────────────────────────────────────────────────────────────────

def _agent_kwargs():
    return {"ollama_url": _OLLAMA_URL, "model": _OLLAMA_MODEL}


# ── Routes ────────────────────────────────────────────────────────────────────

@app.get("/health")
def health():
    return {"status": "ok", "model": _OLLAMA_MODEL, "ts": time.time()}


@app.post("/agent/security")
def run_security_agent(req: AccountRequest):
    from wmintelliops.agents.security_agent import SecurityAgent
    agent  = SecurityAgent(**_agent_kwargs())
    report = agent.run(req.account_id, req.region, context=req.context)
    return report.to_dict()


@app.post("/agent/rca")
def run_rca_agent(req: RCARequest):
    from wmintelliops.agents.rca_agent import RCAAgent
    agent  = RCAAgent(**_agent_kwargs())
    report = agent.run(req.incident_id, req.account_id, req.region, req.incident_text, req.signals)
    return report.to_dict()


@app.post("/agent/compliance")
def run_compliance_agent(req: AccountRequest):
    from wmintelliops.agents.compliance_agent import ComplianceAgent
    agent  = ComplianceAgent(**_agent_kwargs())
    report = agent.run(req.account_id, req.region)
    return report.to_dict()


@app.post("/agent/healing")
def run_healing_agent(req: HealingRequest):
    from wmintelliops.agents.healing_agent import HealingAgent
    agent = HealingAgent(**_agent_kwargs(), dry_run=req.dry_run)
    plan  = agent.run(req.incident_id, req.account_id, req.region, req.incident_text, req.signals)
    return plan.to_dict()


@app.post("/agent/validate")
def validate_agent_output(req: ValidateRequest):
    from wmintelliops.agents.judge_agent import JudgeAgent
    judge  = JudgeAgent(**_agent_kwargs(), monitor_url=_MONITOR_URL)
    result = judge.validate(req.agent_type, req.output, req.ground_truth, req.latency_ms)
    return result.to_dict()


@app.post("/workflow/security")
def run_security_workflow(req: WorkflowRequest, background_tasks: BackgroundTasks):
    from wmintelliops.workflows.security_workflow import SecurityWorkflow

    def _run():
        wf     = SecurityWorkflow(ollama_url=_OLLAMA_URL, model=_OLLAMA_MODEL,
                                   monitor_url=_MONITOR_URL, dry_run=req.dry_run)
        result = wf.run(req.account_id, req.region, req.incident_id, req.incident_text, req.context)
        _workflow_results[result.workflow_id] = result.to_dict()

    import uuid as _uuid
    wid = f"wf-{_uuid.uuid4().hex[:12]}"
    _workflow_results[wid] = {"workflow_id": wid, "status": "queued", "started_at": time.time()}
    background_tasks.add_task(_run)
    return {"workflow_id": wid, "status": "queued", "message": "Workflow started in background"}


@app.get("/workflow/{workflow_id}")
def get_workflow_result(workflow_id: str):
    result = _workflow_results.get(workflow_id)
    if not result:
        # Try memory store
        try:
            from wmintelliops.memory.postgres_memory import MemoryStore
            result = MemoryStore().get("security_workflow", workflow_id)
        except Exception:
            pass
    if not result:
        raise HTTPException(status_code=404, detail="Workflow not found")
    return result


@app.post("/rag/ingest")
def rag_ingest(req: RAGIngestRequest):
    from wmintelliops.rag.retrieval import Retriever
    r = Retriever()
    items = [(item.get("text", ""), item.get("metadata", {})) for item in req.items]
    ids   = r.ingest(req.namespace, items)
    return {"ingested": len(ids), "ids": ids, "namespace": req.namespace}


@app.get("/rag/search")
def rag_search(
    q:         str = Query(..., description="Search query"),
    namespace: str = Query(default="incidents"),
    top_k:     int = Query(default=5, le=20),
):
    from wmintelliops.rag.retrieval import Retriever
    results = Retriever().search(q, namespace=namespace, top_k=top_k)
    return {"query": q, "namespace": namespace, "results": results, "count": len(results)}


@app.get("/memory/{agent_type}/{key:path}")
def get_memory(agent_type: str, key: str):
    from wmintelliops.memory.postgres_memory import MemoryStore
    value = MemoryStore().get(agent_type, key)
    if value is None:
        raise HTTPException(status_code=404, detail="Memory key not found")
    return {"agent_type": agent_type, "key": key, "value": value}


@app.get("/memory/{agent_type}")
def list_memory(agent_type: str, limit: int = Query(default=20, le=100)):
    from wmintelliops.memory.postgres_memory import MemoryStore
    return {"agent_type": agent_type, "records": MemoryStore().list(agent_type, limit=limit)}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("wmintelliops.api.app:app", host="0.0.0.0", port=8001, reload=True)
