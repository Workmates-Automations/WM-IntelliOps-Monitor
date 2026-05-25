"""
Retrieval module
Wraps VectorStore with domain-specific namespacing for IntelliOps:
  - incidents  — historical incident reports + RCA outputs
  - playbooks  — remediation playbook descriptions
  - knowledge  — AWS docs, runbooks, SOPs

Usage:
    from wmintelliops.rag.retrieval import Retriever
    r = Retriever()
    r.ingest("incidents", [("Lambda cold start timeout at 12:00 UTC", {"severity": "high"})])
    results = r.search("Lambda function error", namespace="incidents")
"""
from __future__ import annotations

import logging
import os
from typing import Any, Dict, List, Optional, Tuple

from wmintelliops.rag.vectorstore import VectorStore

logger = logging.getLogger(__name__)

_BASE_PATH = os.environ.get("VECTORSTORE_BASE_PATH", "/tmp/intelliops_vs")


class Retriever:
    """
    Namespaced retrieval layer on top of VectorStore.
    Each namespace gets its own store file to keep data separated.
    """

    _stores: Dict[str, VectorStore] = {}

    def _store(self, namespace: str) -> VectorStore:
        if namespace not in self._stores:
            path = f"{_BASE_PATH}_{namespace}.json"
            os.makedirs(os.path.dirname(path) if os.path.dirname(path) else ".", exist_ok=True)
            self._stores[namespace] = VectorStore(path=path)
        return self._stores[namespace]

    def ingest(self, namespace: str, items: List[Tuple[str, Dict]]) -> List[str]:
        """Add (text, metadata) pairs to a namespace."""
        return self._store(namespace).add_batch(items)

    def search(
        self,
        query: str,
        namespace: str = "incidents",
        top_k: int = 5,
        min_score: float = 0.1,
    ) -> List[Dict]:
        """Retrieve top-k relevant documents from a namespace."""
        return self._store(namespace).search(query, top_k=top_k, min_score=min_score)

    def ingest_incident(self, text: str, metadata: Optional[Dict] = None) -> str:
        return self._store("incidents").add(text, metadata)

    def ingest_playbook(self, text: str, metadata: Optional[Dict] = None) -> str:
        return self._store("playbooks").add(text, metadata)

    def ingest_knowledge(self, text: str, metadata: Optional[Dict] = None) -> str:
        return self._store("knowledge").add(text, metadata)

    def stats(self) -> Dict[str, int]:
        return {ns: store.count() for ns, store in self._stores.items()}
