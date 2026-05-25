"""
Judge Agent
Validates outputs from other agents for accuracy, hallucination, and consistency.
Acts as the LLM-as-a-judge layer to score and filter agent responses before
they are surfaced to users or stored.

Produces a ValidationResult with: is_valid, is_hallucination, confidence, issues.
"""
from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class ValidationResult:
    agent_type: str
    is_valid: bool
    is_hallucination: bool
    confidence: float          # 0.0–1.0
    issues: List[str] = field(default_factory=list)
    score: float = 0.0         # 0–100 quality score
    validated_at: float = field(default_factory=time.time)

    def to_dict(self) -> Dict:
        return asdict(self)

    def as_monitoring_event(self, latency_ms: Optional[float] = None, error: Optional[str] = None) -> Dict:
        """Format as an event compatible with /api/ai-monitoring/log."""
        return {
            "agent_type": self.agent_type,
            "latency_ms": latency_ms,
            "error": error,
            "validation": {
                "is_valid":        self.is_valid,
                "is_hallucination": self.is_hallucination,
                "confidence":      self.confidence,
                "issues":          self.issues,
                "score":           self.score,
            },
        }


class JudgeAgent:
    """
    LLM-as-a-Judge: evaluates agent outputs for quality, factual accuracy,
    and hallucination using the local Ollama model.

    Also integrates with the monitor server's /api/ai-monitoring/log endpoint
    to provide real-time observability for all agent executions.
    """

    SYSTEM_PROMPT = (
        "You are a strict quality judge evaluating AI agent outputs for an AWS cloud platform. "
        "Given an agent output and (optionally) ground-truth context, assess: "
        "1) Is the output factually valid (no obvious errors)? "
        "2) Does it contain hallucinations (facts not in the context)? "
        "3) What is your confidence in the output quality (0.0–1.0)? "
        "4) What specific issues exist (list)? "
        "5) What is the overall quality score (0–100)? "
        "Respond only with valid JSON."
    )

    def __init__(
        self,
        ollama_url: str = "http://localhost:11434",
        model: str = "llama3.2",
        monitor_url: str = "http://localhost:8000",
    ):
        self.ollama_url  = ollama_url.rstrip("/")
        self.model       = model
        self.monitor_url = monitor_url.rstrip("/")

    # ── Core validation logic ─────────────────────────────────────────────────

    def validate(
        self,
        agent_type: str,
        agent_output: Any,
        ground_truth: Optional[Dict] = None,
        latency_ms: Optional[float] = None,
    ) -> ValidationResult:
        """
        Validate an agent output.
        Automatically logs the result to the monitor server.
        """
        result = self._judge_with_llm(agent_type, agent_output, ground_truth)
        self._log_to_monitor(result, latency_ms=latency_ms)
        return result

    def _judge_with_llm(
        self,
        agent_type: str,
        output: Any,
        ground_truth: Optional[Dict],
    ) -> ValidationResult:
        import urllib.request
        prompt = (
            f"Agent type: {agent_type}\n\n"
            f"Agent output:\n{json.dumps(output, indent=2, default=str)[:3000]}\n\n"
        )
        if ground_truth:
            prompt += f"Ground truth / expected context:\n{json.dumps(ground_truth, indent=2, default=str)[:2000]}\n\n"
        prompt += (
            "Return JSON with keys: is_valid (bool), is_hallucination (bool), "
            "confidence (float 0-1), issues (list of strings), score (float 0-100)."
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
                content = json.loads(resp.read()).get("message", {}).get("content", "{}")
            parsed = json.loads(content)
            return ValidationResult(
                agent_type=agent_type,
                is_valid=bool(parsed.get("is_valid", True)),
                is_hallucination=bool(parsed.get("is_hallucination", False)),
                confidence=float(parsed.get("confidence", 0.7)),
                issues=parsed.get("issues", []),
                score=float(parsed.get("score", 70.0)),
            )
        except Exception as exc:
            logger.error("Judge LLM failed: %s", exc)
            return ValidationResult(
                agent_type=agent_type,
                is_valid=True,
                is_hallucination=False,
                confidence=0.5,
                issues=[f"Judge LLM unavailable: {exc}"],
                score=50.0,
            )

    # ── Monitor integration ───────────────────────────────────────────────────

    def _log_to_monitor(self, result: ValidationResult, latency_ms: Optional[float] = None):
        """POST validation event to the monitor server for observability."""
        import urllib.request
        payload = json.dumps(result.as_monitoring_event(latency_ms=latency_ms)).encode()
        try:
            req = urllib.request.Request(
                f"{self.monitor_url}/api/ai-monitoring/log",
                data=payload,
                headers={"Content-Type": "application/json"},
            )
            with urllib.request.urlopen(req, timeout=5):
                pass
        except Exception as exc:
            logger.warning("Monitor log failed: %s", exc)

    # ── Batch validation ──────────────────────────────────────────────────────

    def validate_batch(
        self,
        items: List[Dict],
    ) -> List[ValidationResult]:
        """
        Validate a batch of agent outputs.
        Each item: {"agent_type": str, "output": Any, "ground_truth": dict|None,
                    "latency_ms": float|None}
        """
        return [
            self.validate(
                agent_type=item.get("agent_type", "unknown"),
                agent_output=item.get("output"),
                ground_truth=item.get("ground_truth"),
                latency_ms=item.get("latency_ms"),
            )
            for item in items
        ]
