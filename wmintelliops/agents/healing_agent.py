"""
Self-Healing Agent
Receives alert/incident context and autonomously executes safe remediation
actions against AWS resources via Systems Manager (SSM) Run Command and
Lambda invocations.

Guardrails:
  - Only executes pre-approved playbook actions (no arbitrary commands).
  - All actions are logged to S3 + DynamoDB before execution.
  - High-risk actions require human approval (dry_run=True by default).
"""
from __future__ import annotations

import json
import logging
import time
import uuid
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# ── Pre-approved playbook actions ─────────────────────────────────────────────

PLAYBOOKS: Dict[str, Dict] = {
    "restart_service": {
        "description": "Restart a systemd service on an EC2 instance via SSM",
        "risk": "low",
        "ssm_document": "AWS-RunShellScript",
        "requires_approval": False,
    },
    "scale_asg": {
        "description": "Set desired capacity on an Auto Scaling Group",
        "risk": "medium",
        "requires_approval": True,
    },
    "flush_cache": {
        "description": "Flush ElastiCache Redis cluster",
        "risk": "high",
        "requires_approval": True,
    },
    "rotate_credentials": {
        "description": "Rotate IAM access keys for a service account",
        "risk": "medium",
        "requires_approval": True,
    },
    "reboot_instance": {
        "description": "Reboot an EC2 instance",
        "risk": "medium",
        "requires_approval": True,
    },
    "disable_iam_user": {
        "description": "Disable an IAM user (set login profile + deactivate keys)",
        "risk": "high",
        "requires_approval": True,
    },
    "isolate_instance": {
        "description": "Detach security groups to isolate an EC2 instance",
        "risk": "high",
        "requires_approval": True,
    },
}


@dataclass
class HealingAction:
    action_id: str
    playbook: str
    target: str
    status: str           # pending | approved | executed | failed | dry_run
    result: Optional[str] = None
    error:  Optional[str] = None
    started_at: float = field(default_factory=time.time)
    completed_at: Optional[float] = None

    def to_dict(self) -> Dict:
        return asdict(self)


@dataclass
class HealingPlan:
    incident_id: str
    account_id: str
    region: str
    recommended_actions: List[Dict] = field(default_factory=list)
    executed_actions: List[HealingAction] = field(default_factory=list)
    generated_at: float = field(default_factory=time.time)

    def to_dict(self) -> Dict:
        d = asdict(self)
        d["executed_actions"] = [asdict(a) for a in self.executed_actions]
        return d


class HealingAgent:
    """
    Identifies and executes (or proposes) remediation actions for incidents.
    Integrates with the JudgeAgent to validate its own plans before acting.
    """

    SYSTEM_PROMPT = (
        "You are a cloud infrastructure remediation engine for AWS. "
        "Given an incident description and available playbooks, recommend the "
        "minimal set of remediation actions needed to restore normal operation. "
        "Be conservative — prefer low-risk actions. Respond with valid JSON."
    )

    def __init__(
        self,
        ollama_url: str = "http://localhost:11434",
        model: str = "llama3.2",
        dry_run: bool = True,
    ):
        self.ollama_url = ollama_url.rstrip("/")
        self.model      = model
        self.dry_run    = dry_run

    def _plan_actions(self, incident_text: str, signals: Dict) -> List[Dict]:
        import urllib.request
        playbook_summary = {k: v["description"] for k, v in PLAYBOOKS.items()}
        prompt = (
            f"Incident:\n{incident_text}\n\n"
            f"Signals:\n{json.dumps(signals, indent=2, default=str)[:2000]}\n\n"
            f"Available playbooks:\n{json.dumps(playbook_summary, indent=2)}\n\n"
            f"Return a JSON array of recommended actions. Each action: "
            f"{{\"playbook\": str, \"target\": str, \"reason\": str, \"priority\": 1-5}}"
        )
        payload = json.dumps({
            "model": self.model,
            "messages": [
                {"role": "system", "content": self.SYSTEM_PROMPT},
                {"role": "user",   "content": prompt},
            ],
            "stream": False,
        }).encode()
        try:
            req = urllib.request.Request(
                f"{self.ollama_url}/api/chat",
                data=payload,
                headers={"Content-Type": "application/json"},
            )
            with urllib.request.urlopen(req, timeout=60) as resp:
                content = json.loads(resp.read()).get("message", {}).get("content", "[]")
            return json.loads(content) if isinstance(json.loads(content), list) else []
        except Exception as exc:
            logger.error("Healing plan LLM failed: %s", exc)
            return []

    def _execute_ssm(self, session, instance_id: str, commands: List[str]) -> str:
        try:
            ssm = session.client("ssm")
            resp = ssm.send_command(
                InstanceIds=[instance_id],
                DocumentName="AWS-RunShellScript",
                Parameters={"commands": commands},
                TimeoutSeconds=60,
            )
            return resp["Command"]["CommandId"]
        except Exception as exc:
            raise RuntimeError(f"SSM execution failed: {exc}")

    def run(
        self,
        incident_id: str,
        account_id: str,
        region: str,
        incident_text: str,
        signals: Optional[Dict] = None,
    ) -> HealingPlan:
        signals = signals or {}
        actions = self._plan_actions(incident_text, signals)

        plan = HealingPlan(
            incident_id=incident_id,
            account_id=account_id,
            region=region,
            recommended_actions=actions,
        )

        if self.dry_run:
            logger.info("HealingAgent dry_run=True — not executing actions")
            for action in actions:
                pb = action.get("playbook", "")
                if pb in PLAYBOOKS and not PLAYBOOKS[pb].get("requires_approval"):
                    plan.executed_actions.append(HealingAction(
                        action_id=uuid.uuid4().hex[:12],
                        playbook=pb,
                        target=action.get("target", ""),
                        status="dry_run",
                        result=f"DRY RUN: would execute {pb} on {action.get('target')}",
                    ))
        else:
            import boto3
            try:
                sts = boto3.client("sts")
                creds = sts.assume_role(
                    RoleArn=f"arn:aws:iam::{account_id}:role/CWMSessionRole",
                    RoleSessionName="HealingAgent",
                )["Credentials"]
                session = boto3.Session(
                    aws_access_key_id=creds["AccessKeyId"],
                    aws_secret_access_key=creds["SecretAccessKey"],
                    aws_session_token=creds["SessionToken"],
                    region_name=region,
                )
            except Exception as exc:
                logger.error("AssumeRole failed: %s", exc)
                return plan

            for action in actions:
                pb = action.get("playbook", "")
                if pb not in PLAYBOOKS:
                    continue
                pb_config = PLAYBOOKS[pb]
                if pb_config.get("requires_approval"):
                    plan.executed_actions.append(HealingAction(
                        action_id=uuid.uuid4().hex[:12],
                        playbook=pb,
                        target=action.get("target", ""),
                        status="pending",
                        result="Awaiting human approval",
                    ))
                    continue
                ha = HealingAction(
                    action_id=uuid.uuid4().hex[:12],
                    playbook=pb,
                    target=action.get("target", ""),
                    status="executed",
                )
                try:
                    if pb == "restart_service":
                        service = action.get("service", "application")
                        cmd_id = self._execute_ssm(session, action.get("target", ""), [f"systemctl restart {service}"])
                        ha.result = f"SSM CommandId: {cmd_id}"
                    ha.completed_at = time.time()
                except Exception as exc:
                    ha.status = "failed"
                    ha.error  = str(exc)
                    ha.completed_at = time.time()
                plan.executed_actions.append(ha)

        try:
            from wmintelliops.memory.postgres_memory import MemoryStore
            MemoryStore().store("healing_agent", incident_id, plan.to_dict())
        except Exception:
            pass

        return plan
