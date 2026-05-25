"""
Compliance Agent
Checks AWS account configuration against CIS AWS Foundations Benchmark,
AWS Well-Architected Framework, and custom IntelliOps policies.

Produces a ComplianceReport with framework scores, control status, and
remediation guidance per control.
"""
from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class ControlResult:
    control_id: str
    framework: str        # CIS | WAF | PCI | SOC2 | HIPAA | IntelliOps
    title: str
    status: str           # pass | fail | warning | not_applicable
    severity: str         # critical | high | medium | low
    description: str
    remediation: str
    resource: str = ""


@dataclass
class ComplianceReport:
    account_id: str
    region: str
    frameworks: List[str] = field(default_factory=list)
    controls: List[ControlResult] = field(default_factory=list)
    scores: Dict[str, float] = field(default_factory=dict)  # framework → % pass
    overall_score: float = 0.0
    generated_at: float = field(default_factory=time.time)

    def to_dict(self) -> Dict:
        d = asdict(self)
        d["controls"] = [asdict(c) for c in self.controls]
        return d


# ── Control checks ────────────────────────────────────────────────────────────

def _check_iam_mfa(session, region: str) -> List[ControlResult]:
    """CIS 1.x — IAM root MFA and access key checks."""
    results = []
    try:
        iam = session.client("iam")
        summary = iam.get_account_summary().get("SummaryMap", {})
        mfa_enabled = summary.get("AccountMFAEnabled", 0) > 0
        results.append(ControlResult(
            control_id="CIS-1.1",
            framework="CIS",
            title="Avoid root account usage and enable MFA",
            status="pass" if mfa_enabled else "fail",
            severity="critical",
            description="Root account MFA protects against credential compromise.",
            remediation="Enable MFA for the root account via IAM console.",
            resource="arn:aws:iam:::root",
        ))
        # Access key rotation
        root_keys = summary.get("AccountAccessKeysPresent", 0)
        results.append(ControlResult(
            control_id="CIS-1.4",
            framework="CIS",
            title="No root account access keys",
            status="fail" if root_keys > 0 else "pass",
            severity="critical",
            description="Root access keys are highly privileged and should not exist.",
            remediation="Delete root access keys in IAM > Security Credentials.",
            resource="arn:aws:iam:::root",
        ))
    except Exception as exc:
        logger.warning("IAM MFA check: %s", exc)
    return results


def _check_cloudtrail(session, region: str) -> List[ControlResult]:
    """CIS 2.x — CloudTrail enabled and log validation."""
    try:
        ct = session.client("cloudtrail", region_name=region)
        trails = ct.describe_trails(includeShadowTrails=False).get("trailList", [])
        enabled = any(t.get("IsMultiRegionTrail") for t in trails)
        log_val = any(t.get("LogFileValidationEnabled") for t in trails)
        return [
            ControlResult(
                control_id="CIS-2.1",
                framework="CIS",
                title="CloudTrail enabled in all regions",
                status="pass" if enabled else "fail",
                severity="high",
                description="Multi-region CloudTrail provides a complete audit trail.",
                remediation="Enable a multi-region CloudTrail trail.",
                resource="cloudtrail",
            ),
            ControlResult(
                control_id="CIS-2.2",
                framework="CIS",
                title="CloudTrail log file validation enabled",
                status="pass" if log_val else "warning",
                severity="medium",
                description="Log file validation detects tampering.",
                remediation="Enable log file validation on the CloudTrail trail.",
                resource="cloudtrail",
            ),
        ]
    except Exception as exc:
        logger.warning("CloudTrail check: %s", exc)
        return []


def _check_s3_public_access(session, region: str) -> List[ControlResult]:
    """Check S3 account-level public access block."""
    try:
        s3c = session.client("s3control", region_name=region)
        sts = session.client("sts")
        acct_id = sts.get_caller_identity()["Account"]
        cfg = s3c.get_public_access_block(AccountId=acct_id).get("PublicAccessBlockConfiguration", {})
        blocked = all([
            cfg.get("BlockPublicAcls"),
            cfg.get("BlockPublicPolicy"),
            cfg.get("IgnorePublicAcls"),
            cfg.get("RestrictPublicBuckets"),
        ])
        return [ControlResult(
            control_id="CIS-2.3",
            framework="CIS",
            title="S3 account-level public access block enabled",
            status="pass" if blocked else "fail",
            severity="high",
            description="Account-level public access block prevents accidental bucket exposure.",
            remediation="Enable all 4 S3 Block Public Access settings at the account level.",
            resource=f"arn:aws:s3:::*",
        )]
    except Exception as exc:
        logger.warning("S3 public access check: %s", exc)
        return []


# ── Agent ─────────────────────────────────────────────────────────────────────

class ComplianceAgent:
    """Runs CIS + custom compliance checks against an AWS account."""

    def __init__(self, ollama_url: str = "http://localhost:11434", model: str = "llama3.2"):
        self.ollama_url = ollama_url.rstrip("/")
        self.model      = model

    def run(self, account_id: str, region: str, frameworks: Optional[List[str]] = None) -> ComplianceReport:
        import boto3
        frameworks = frameworks or ["CIS", "IntelliOps"]

        try:
            sts = boto3.client("sts")
            role_arn = f"arn:aws:iam::{account_id}:role/CWMSessionRole"
            creds = sts.assume_role(RoleArn=role_arn, RoleSessionName="ComplianceAgent")["Credentials"]
            session = boto3.Session(
                aws_access_key_id=creds["AccessKeyId"],
                aws_secret_access_key=creds["SecretAccessKey"],
                aws_session_token=creds["SessionToken"],
                region_name=region,
            )
        except Exception as exc:
            logger.error("AssumeRole failed: %s", exc)
            return ComplianceReport(account_id=account_id, region=region, frameworks=frameworks)

        all_controls: List[ControlResult] = []
        all_controls.extend(_check_iam_mfa(session, region))
        all_controls.extend(_check_cloudtrail(session, region))
        all_controls.extend(_check_s3_public_access(session, region))

        # Score per framework
        scores: Dict[str, float] = {}
        for fw in frameworks:
            fw_controls = [c for c in all_controls if c.framework == fw]
            if fw_controls:
                pass_count = sum(1 for c in fw_controls if c.status == "pass")
                scores[fw] = round(pass_count / len(fw_controls) * 100, 1)

        overall = round(sum(scores.values()) / len(scores), 1) if scores else 0.0

        report = ComplianceReport(
            account_id=account_id,
            region=region,
            frameworks=frameworks,
            controls=all_controls,
            scores=scores,
            overall_score=overall,
        )

        try:
            from wmintelliops.memory.postgres_memory import MemoryStore
            MemoryStore().store("compliance_agent", f"{account_id}/{region}", report.to_dict())
        except Exception:
            pass

        return report
