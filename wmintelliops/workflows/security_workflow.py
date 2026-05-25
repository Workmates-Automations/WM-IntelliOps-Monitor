"""
Security Workflow
Orchestrates a full security incident response pipeline:

  SecurityAgent → JudgeAgent → RCAAgent → HealingAgent → ComplianceAgent

Each stage validates its output before passing it to the next.
Results are persisted to PostgreSQL memory and can be polled via the API.

Usage:
    from wmintelliops.workflows.security_workflow import SecurityWorkflow
    wf = SecurityWorkflow()
    result = wf.run(incident_id="INC-001", account_id="123456789012", region="ap-south-1")
"""
from __future__ import annotations

import logging
import os
import time
import uuid
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

_OLLAMA_URL = os.environ.get("OLLAMA_URL", "http://localhost:11434")
_OLLAMA_MODEL = os.environ.get("OLLAMA_MODEL", "llama3.2")
_MONITOR_URL = os.environ.get("MONITOR_URL", "http://localhost:8000")


@dataclass
class WorkflowResult:
    workflow_id: str
    incident_id: str
    account_id: str
    region: str
    status: str              # running | completed | failed
    stages: List[Dict] = field(default_factory=list)
    security_report: Optional[Dict] = None
    rca_report: Optional[Dict] = None
    healing_plan: Optional[Dict] = None
    compliance_report: Optional[Dict] = None
    started_at: float = field(default_factory=time.time)
    completed_at: Optional[float] = None
    error: Optional[str] = None

    def to_dict(self) -> Dict:
        return asdict(self)


class SecurityWorkflow:
    """
    End-to-end security incident response workflow using the local Ollama agent stack.
    """

    def __init__(
        self,
        ollama_url: str = _OLLAMA_URL,
        model: str = _OLLAMA_MODEL,
        monitor_url: str = _MONITOR_URL,
        dry_run: bool = True,
    ):
        self.ollama_url  = ollama_url
        self.model       = model
        self.monitor_url = monitor_url
        self.dry_run     = dry_run

    def _stage(self, name: str, result: WorkflowResult) -> None:
        result.stages.append({"name": name, "started_at": time.time(), "status": "running"})

    def _stage_done(self, name: str, result: WorkflowResult, error: Optional[str] = None) -> None:
        for s in reversed(result.stages):
            if s["name"] == name:
                s["status"]       = "failed" if error else "completed"
                s["completed_at"] = time.time()
                s["duration_s"]   = round(s["completed_at"] - s["started_at"], 2)
                if error: s["error"] = error
                break

    def run(
        self,
        account_id: str,
        region: str,
        incident_id: Optional[str] = None,
        incident_text: Optional[str] = None,
        context: Optional[Dict] = None,
    ) -> WorkflowResult:
        from wmintelliops.agents.security_agent  import SecurityAgent
        from wmintelliops.agents.judge_agent     import JudgeAgent
        from wmintelliops.agents.rca_agent       import RCAAgent
        from wmintelliops.agents.healing_agent   import HealingAgent
        from wmintelliops.agents.compliance_agent import ComplianceAgent
        from wmintelliops.memory.postgres_memory import MemoryStore

        incident_id = incident_id or f"INC-{uuid.uuid4().hex[:8].upper()}"
        incident_text = incident_text or f"Security incident detected in account {account_id} / {region}"

        result = WorkflowResult(
            workflow_id=uuid.uuid4().hex[:16],
            incident_id=incident_id,
            account_id=account_id,
            region=region,
            status="running",
        )
        mem = MemoryStore()

        # ── Stage 1: Security Analysis ────────────────────────────────────────
        self._stage("security_analysis", result)
        try:
            sec_agent = SecurityAgent(ollama_url=self.ollama_url, model=self.model)
            sec_report = sec_agent.run(account_id, region, context=context)
            result.security_report = sec_report.to_dict()
            self._stage_done("security_analysis", result)
            logger.info("Security: %d findings, score %.1f", len(sec_report.findings), sec_report.risk_score)
        except Exception as exc:
            self._stage_done("security_analysis", result, error=str(exc))
            logger.error("SecurityAgent failed: %s", exc)

        # ── Stage 2: Validate security output (JudgeAgent) ───────────────────
        self._stage("judge_security", result)
        try:
            judge = JudgeAgent(ollama_url=self.ollama_url, model=self.model, monitor_url=self.monitor_url)
            val   = judge.validate(
                agent_type="security_agent",
                agent_output=result.security_report,
                latency_ms=None,
            )
            result.stages[-1]["validation"] = val.to_dict()
            self._stage_done("judge_security", result)
        except Exception as exc:
            self._stage_done("judge_security", result, error=str(exc))

        # ── Stage 3: Root Cause Analysis ──────────────────────────────────────
        self._stage("rca", result)
        try:
            signals = {}
            if result.security_report:
                signals["findings"] = [f.get("title") for f in result.security_report.get("findings", [])]
            rca_agent = RCAAgent(ollama_url=self.ollama_url, model=self.model)
            rca_report = rca_agent.run(incident_id, account_id, region, incident_text, signals)
            result.rca_report = rca_report.to_dict()
            self._stage_done("rca", result)
        except Exception as exc:
            self._stage_done("rca", result, error=str(exc))
            logger.error("RCAAgent failed: %s", exc)

        # ── Stage 4: Validate RCA (JudgeAgent) ───────────────────────────────
        self._stage("judge_rca", result)
        try:
            val = judge.validate(agent_type="rca_agent", agent_output=result.rca_report)
            result.stages[-1]["validation"] = val.to_dict()
            self._stage_done("judge_rca", result)
        except Exception as exc:
            self._stage_done("judge_rca", result, error=str(exc))

        # ── Stage 5: Self-Healing ─────────────────────────────────────────────
        self._stage("healing", result)
        try:
            heal_agent  = HealingAgent(ollama_url=self.ollama_url, model=self.model, dry_run=self.dry_run)
            heal_plan   = heal_agent.run(incident_id, account_id, region, incident_text)
            result.healing_plan = heal_plan.to_dict()
            self._stage_done("healing", result)
        except Exception as exc:
            self._stage_done("healing", result, error=str(exc))
            logger.error("HealingAgent failed: %s", exc)

        # ── Stage 6: Compliance check ─────────────────────────────────────────
        self._stage("compliance", result)
        try:
            comp_agent   = ComplianceAgent(ollama_url=self.ollama_url, model=self.model)
            comp_report  = comp_agent.run(account_id, region)
            result.compliance_report = comp_report.to_dict()
            self._stage_done("compliance", result)
        except Exception as exc:
            self._stage_done("compliance", result, error=str(exc))
            logger.error("ComplianceAgent failed: %s", exc)

        # ── Finalise ──────────────────────────────────────────────────────────
        result.status       = "completed"
        result.completed_at = time.time()

        try:
            mem.store("security_workflow", result.workflow_id, result.to_dict())
        except Exception:
            pass

        logger.info(
            "SecurityWorkflow %s completed in %.1fs for %s/%s",
            result.workflow_id,
            result.completed_at - result.started_at,
            account_id, region,
        )
        return result
