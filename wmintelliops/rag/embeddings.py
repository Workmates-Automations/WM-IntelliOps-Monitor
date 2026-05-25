"""
Embeddings module
Generates text embeddings via Ollama's embedding endpoint (nomic-embed-text).
Falls back to simple TF-IDF bag-of-words for offline/testing scenarios.
"""
from __future__ import annotations

import json
import logging
import math
import os
from typing import List, Optional

logger = logging.getLogger(__name__)

_OLLAMA_URL   = os.environ.get("OLLAMA_URL",   "http://localhost:11434")
_EMBED_MODEL  = os.environ.get("OLLAMA_EMBED_MODEL", "nomic-embed-text")


def embed_text(text: str, model: Optional[str] = None) -> List[float]:
    """Return a float embedding vector for the given text."""
    import urllib.request
    m = model or _EMBED_MODEL
    payload = json.dumps({"model": m, "prompt": text}).encode()
    try:
        req = urllib.request.Request(
            f"{_OLLAMA_URL}/api/embeddings",
            data=payload,
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read()).get("embedding", [])
    except Exception as exc:
        logger.warning("Ollama embedding failed, falling back to TF-IDF: %s", exc)
        return _tfidf_embed(text)


def embed_batch(texts: List[str], model: Optional[str] = None) -> List[List[float]]:
    """Embed a list of texts."""
    return [embed_text(t, model) for t in texts]


def cosine_similarity(a: List[float], b: List[float]) -> float:
    """Cosine similarity between two vectors."""
    if not a or not b or len(a) != len(b):
        return 0.0
    dot   = sum(x * y for x, y in zip(a, b))
    mag_a = math.sqrt(sum(x * x for x in a))
    mag_b = math.sqrt(sum(x * x for x in b))
    if mag_a == 0 or mag_b == 0:
        return 0.0
    return dot / (mag_a * mag_b)


# ── TF-IDF fallback ───────────────────────────────────────────────────────────

_VOCAB: dict[str, int] = {}

def _tfidf_embed(text: str, dim: int = 256) -> List[float]:
    """Minimal bag-of-words vector as fallback when Ollama is unavailable."""
    tokens = text.lower().split()
    vec = [0.0] * dim
    for t in tokens:
        idx = hash(t) % dim
        vec[idx] += 1.0
    # L2 normalise
    mag = math.sqrt(sum(x * x for x in vec)) or 1.0
    return [x / mag for x in vec]
