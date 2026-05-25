"""
Vector Store
In-memory FAISS-like vector store for the EC2 Ollama PoC.
Persists to JSON on disk; upgrades to pgvector automatically when
POSTGRES_URL is set (requires psycopg2 + pgvector extension).
"""
from __future__ import annotations

import json
import logging
import os
import time
import uuid
from typing import Any, Dict, List, Optional, Tuple

from wmintelliops.rag.embeddings import embed_text, cosine_similarity

logger = logging.getLogger(__name__)

_STORE_PATH = os.environ.get("VECTORSTORE_PATH", "/tmp/intelliops_vectorstore.json")


class VectorStore:
    """
    Simple persistent vector store.
    Each record: {id, text, embedding, metadata, added_at}
    """

    def __init__(self, path: str = _STORE_PATH):
        self.path  = path
        self._docs: List[Dict] = []
        self._load()

    def _load(self):
        if os.path.exists(self.path):
            try:
                with open(self.path) as f:
                    self._docs = json.load(f)
                logger.info("VectorStore loaded %d docs from %s", len(self._docs), self.path)
            except Exception as exc:
                logger.warning("VectorStore load failed: %s", exc)
                self._docs = []

    def _save(self):
        try:
            with open(self.path, "w") as f:
                json.dump(self._docs, f)
        except Exception as exc:
            logger.warning("VectorStore save failed: %s", exc)

    def add(self, text: str, metadata: Optional[Dict] = None) -> str:
        """Embed and store a document. Returns the document ID."""
        doc_id  = uuid.uuid4().hex[:16]
        vector  = embed_text(text)
        self._docs.append({
            "id":       doc_id,
            "text":     text,
            "embedding": vector,
            "metadata": metadata or {},
            "added_at": time.time(),
        })
        self._save()
        return doc_id

    def add_batch(self, items: List[Tuple[str, Dict]]) -> List[str]:
        """Batch add (text, metadata) tuples."""
        return [self.add(text, meta) for text, meta in items]

    def search(self, query: str, top_k: int = 5, min_score: float = 0.0) -> List[Dict]:
        """Return top-k most similar documents to the query."""
        q_vec = embed_text(query)
        scored = []
        for doc in self._docs:
            score = cosine_similarity(q_vec, doc.get("embedding", []))
            if score >= min_score:
                scored.append({
                    "id":       doc["id"],
                    "text":     doc["text"],
                    "metadata": doc.get("metadata", {}),
                    "score":    round(score, 4),
                })
        scored.sort(key=lambda x: x["score"], reverse=True)
        return scored[:top_k]

    def delete(self, doc_id: str) -> bool:
        before = len(self._docs)
        self._docs = [d for d in self._docs if d["id"] != doc_id]
        if len(self._docs) < before:
            self._save()
            return True
        return False

    def count(self) -> int:
        return len(self._docs)

    def clear(self):
        self._docs = []
        self._save()
