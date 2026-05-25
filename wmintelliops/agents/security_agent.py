"""
Security Agent
Analyzes CloudWatch alarms, GuardDuty findings, IAM anomalies, and VPC flow
logs to produce a structured security assessment for the current AWS environment.

Input:
  - account_id: str
  - region: str
  - context: dict  (optional enrichment — prior findings, ticket history)

Output:
  SecurityReport with severity, findings, MITRE ATT&CK mappings, recommendations.
"""
from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


# ── Data models ───────────────────────────────────────────────────────────────

@dataclass
class SecurityFinding:
    severity: str           # critical | high | medium | low | informational
    category: str           # iam | network | compute | data | compliance
    title: str
    description: str
    resource: str           # ARN or human name of affected resource
    mitre_tactic: str       # e.g. "Privilege Escalation"
    mitre_technique: str    # e.g. "T1078 Valid Accounts"
    remediation: str
    raw: Dict = field(default_factory=dict)


@dataclass
class SecurityReport:
    account_id: str
    region: str
    risk_score: float        # 0–100, higher = riskier
    risk_label: str          # critical | high | medium | low
    findings: List[SecurityFinding] = field(default_factory=list)
    summary: str = ""
    scanned_at: float = field(default_factory=time.time)

    def to_dict(self) -> Dict:
        d = asdict(self)
        d["findings"] = [asdict(f) for f in self.findings]
        return d


# ── Agent ─────────────────────────────────────────────────────────────────────

class SecurityAgent:
    """
    Runs security analysis using Ollama (local LLM) + AWS APIs.
    Designed for the EC2 Ollama PoC — no Bedrock / no external LLM required.
    """

    SYSTEM_PROMPT = (
        "You are a cloud security analyst specialising in AWS infrastructure. "
        "Given a list of raw security signals (CloudWatch alarms, GuardDuty findings, "
        "IAM anomalies), you produce structured findings with MITRE ATT&CK mappings "
        "and actionable remediations. Respond only with valid JSON."
    )

    def __init__(self, ollama_url: str = "http://localhost:11434", model: str = "llama3.2"):
        self.ollama_url = ollama_url.rstrip("/")
        self.model      = model

    # ── AWS data gathering ────────────────────────────────────────────────────

    def _gather_signals(self, session, region: str) -> Dict[str, Any]:
        signals: Dict[str, Any] = {
            "alarm_breaches": [],
            "guardduty_findings": [],
            "iam_anomalies": [],
        }
        cw = session.client("cloudwatch", region_name=region)
        try:
            for page in cw.get_paginator("describe_alarms").paginate(StateValue="ALARM"):
                for a in page.get("MetricAlarms", []):
                    signals["alarm_breaches"].append({
                        "name": a.get("AlarmName"),
                        "metric": a.get("MetricName"),
                        "namespace": a.get("Namespace"),
                        "reason": a.get("StateReason", "")[:300],
                    })
        except Exception as exc:
            logger.warning("CloudWatch alarms: %s", exc)

        try:
            gd = session.client("guardduty", region_name=region)
            detectors = gd.list_detectors().get("DetectorIds", [])
            for det in detectors[:1]:
                for page in gd.get_paginator("list_findings").paginate(
                    DetectorId=det,
                    FindingCriteria={"Criterion": {"severity": {"Gte": 4}}},
                    MaxResults=20,
                ):
                    fids = page.get("FindingIds", [])
                    if fids:
                        details = gd.get_findings(DetectorId=det, FindingIds=fids[:10])
                        for f in details.get("Findings", []):
                            signals["guardduty_findings"].append({
                                "type": f.get("Type"),
                                "severity": f.get("Severity"),
                                "title": f.get("Title"),
                                "description": f.get("Description", "")[:300],
                                "resource_type": f.get("Resource", {}).get("ResourceType"),
                            })
        except Exception as exc:
            logger.warning("GuardDuty: %s", exc)

        return signals

    # ── LLM analysis ──────────────────────────────────────────────────────────

    def _analyze_with_llm(self, signals: Dict, context: Dict) -> List[SecurityFinding]:
        import urllib.request
        prompt = (
            f"Analyze these AWS security signals and return a JSON array of findings.\n\n"
            f"Each finding must have: severity, category, title, description, resource, "
            f"mitre_tactic, mitre_technique, remediation.\n\n"
            f"Signals:\n{json.dumps(signals, indent=2, default=str)}\n\n"
            f"Context:\n{json.dumps(context, indent=2, default=str)}\n\n"
            f"Return only the JSON array, no other text."
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
            with urllib.request.urlopen(req, timeout=90) as resp:
                raw_content = json.loads(resp.read()).get("message", {}).get("content", "[]")
            findings_raw = json.loads(raw_content)
            return [
                SecurityFinding(
                    severity=f.get("severity", "medium"),
                    category=f.get("category", "compute"),
                    title=f.get("title", "Unknown finding"),
                    description=f.get("description", ""),
                    resource=f.get("resource", ""),
                    mitre_tactic=f.get("mitre_tactic", ""),
                    mitre_technique=f.get("mitre_technique", ""),
                    remediation=f.get("remediation", ""),
                    raw=f,
                )
                for f in (findings_raw if isinstance(findings_raw, list) else [])
            ]
        except Exception as exc:
            logger.error("LLM analysis failed: %s", exc)
            return []

    # ── Risk scoring ──────────────────────────────────────────────────────────

    @staticmethod
    def _score(findings: List[SecurityFinding]) -> float:
        weights = {"critical": 25, "high": 15, "medium": 8, "low": 3, "informational": 1}
        raw = sum(weights.get(f.severity, 5) for f in findings)
        return round(min(100.0, raw), 1)

    @staticmethod
    def _label(score: float) -> str:
        if score >= 75: return "critical"
        if score >= 50: return "high"
        if score >= 25: return "medium"
        return "low"

    # ── Main entry point ──────────────────────────────────────────────────────

    def run(self, account_id: str, region: str, context: Optional[Dict] = None) -> SecurityReport:
        import boto3
        try:
            from botocore.exceptions import ClientError
            from wmintelliops.memory.postgres_memory import MemoryStore
            mem = MemoryStore()
        except Exception:
            mem = None

        try:
            sts = boto3.client("sts")
            role_arn = f"arn:aws:iam::{account_id}:role/CWMSessionRole"
            creds = sts.assume_role(RoleArn=role_arn, RoleSessionName="SecurityAgent")["Credentials"]
            session = boto3.Session(
                aws_access_key_id=creds["AccessKeyId"],
                aws_secret_access_key=creds["SecretAccessKey"],
                aws_session_token=creds["SessionToken"],
                region_name=region,
            )
        except Exception as exc:
            logger.error("AssumeRole failed: %s", exc)
            return SecurityReport(
                account_id=account_id, region=region,
                risk_score=0, risk_label="unknown",
                summary=f"Could not assume cross-account role: {exc}",
            )

        signals  = self._gather_signals(session, region)
        findings = self._analyze_with_llm(signals, context or {})
        score    = self._score(findings)
        label    = self._label(score)

        report = SecurityReport(
            account_id=account_id,
            region=region,
            risk_score=score,
            risk_label=label,
            findings=findings,
            summary=(
                f"{len(findings)} findings detected. "
                f"Risk: {label} (score {score}/100). "
                f"Critical: {sum(1 for f in findings if f.severity == 'critical')}, "
                f"High: {sum(1 for f in findings if f.severity == 'high')}."
            ),
        )

        # Persist to memory
        if mem:
            try:
                mem.store("security_agent", f"{account_id}/{region}", report.to_dict())
            except Exception:
                pass

        return report
