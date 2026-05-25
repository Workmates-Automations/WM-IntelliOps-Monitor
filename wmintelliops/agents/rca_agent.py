"""
Root Cause Analysis (RCA) Agent
Given an incident description + AWS signals, produces a structured RCA report
with timeline, probable root cause, contributing factors, and fix actions.

Uses: Ollama (local LLM) + RAG retrieval from historical incidents.
"""
from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class RCAReport:
    incident_id: str
    account_id: str
    region: str
    probable_cause: str
    contributing_factors: List[str] = field(default_factory=list)
    timeline: List[Dict] = field(default_factory=list)
    fix_actions: List[str] = field(default_factory=list)
    prevention_actions: List[str] = field(default_factory=list)
    confidence: float = 0.0
    generated_at: float = field(default_factory=time.time)

    def to_dict(self) -> Dict:
        return asdict(self)


class RCAAgent:
    """
    Performs root cause analysis on AWS incidents using local Ollama LLM.
    Enriches with RAG-retrieved similar historical incidents for better accuracy.
    """

    SYSTEM_PROMPT = (
        "You are a senior site reliability engineer specialising in AWS incident RCA. "
        "Given incident signals and historical context, identify the root cause, "
        "contributing factors, and fix actions. Respond with valid JSON only."
    )

    def __init__(self, ollama_url: str = "http://localhost:11434", model: str = "llama3.2"):
        self.ollama_url = ollama_url.rstrip("/")
        self.model      = model

    def _retrieve_similar(self, incident_text: str) -> List[Dict]:
        """Retrieve similar past incidents via RAG."""
        try:
            from wmintelliops.rag.retrieval import Retriever
            retriever = Retriever()
            return retriever.search(incident_text, top_k=3)
        except Exception:
            return []

    def _build_timeline(self, signals: Dict) -> List[Dict]:
        """Reconstruct event timeline from alarm state changes."""
        events = []
        for alarm in signals.get("alarm_breaches", []):
            events.append({
                "ts": alarm.get("updated_at", ""),
                "event": f"Alarm BREACH: {alarm.get('name')} — {alarm.get('reason', '')[:150]}",
            })
        events.sort(key=lambda e: e.get("ts", ""))
        return events

    def _call_llm(self, incident_text: str, signals: Dict, similar: List[Dict]) -> Dict:
        import urllib.request
        prompt = (
            f"Incident description:\n{incident_text}\n\n"
            f"AWS signals:\n{json.dumps(signals, indent=2, default=str)[:3000]}\n\n"
            f"Similar historical incidents:\n{json.dumps(similar, indent=2, default=str)[:2000]}\n\n"
            f"Return JSON with keys: probable_cause, contributing_factors (list), "
            f"fix_actions (list), prevention_actions (list), confidence (0.0-1.0)."
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
                content = json.loads(resp.read()).get("message", {}).get("content", "{}")
            return json.loads(content)
        except Exception as exc:
            logger.error("RCA LLM call failed: %s", exc)
            return {
                "probable_cause": f"LLM unavailable: {exc}",
                "contributing_factors": [],
                "fix_actions": [],
                "prevention_actions": [],
                "confidence": 0.0,
            }

    def run(
        self,
        incident_id: str,
        account_id: str,
        region: str,
        incident_text: str,
        signals: Optional[Dict] = None,
    ) -> RCAReport:
        signals   = signals or {}
        similar   = self._retrieve_similar(incident_text)
        timeline  = self._build_timeline(signals)
        result    = self._call_llm(incident_text, signals, similar)

        report = RCAReport(
            incident_id=incident_id,
            account_id=account_id,
            region=region,
            probable_cause=result.get("probable_cause", "Unknown"),
            contributing_factors=result.get("contributing_factors", []),
            timeline=timeline,
            fix_actions=result.get("fix_actions", []),
            prevention_actions=result.get("prevention_actions", []),
            confidence=float(result.get("confidence", 0.5)),
        )

        try:
            from wmintelliops.memory.postgres_memory import MemoryStore
            MemoryStore().store("rca_agent", incident_id, report.to_dict())
        except Exception:
            pass

        return report
