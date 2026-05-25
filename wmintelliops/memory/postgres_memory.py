"""
PostgreSQL-based Memory Store
Persists agent execution state, conversation history, and audit trail.

When POSTGRES_URL is not set, falls back to SQLite for local PoC testing.

Schema:
  agent_memory (
    id         SERIAL PRIMARY KEY,
    agent_type VARCHAR(64),
    key        VARCHAR(256),
    value      JSONB,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
  )

  agent_conversations (
    id         SERIAL PRIMARY KEY,
    session_id VARCHAR(64),
    role       VARCHAR(16),   -- user | assistant | system
    content    TEXT,
    metadata   JSONB,
    created_at TIMESTAMPTZ DEFAULT NOW()
  )
"""
from __future__ import annotations

import json
import logging
import os
import sqlite3
import time
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

_POSTGRES_URL = os.environ.get("POSTGRES_URL", "")
_SQLITE_PATH  = os.environ.get("SQLITE_PATH", "/tmp/intelliops_memory.db")


# ── SQLite backend (local PoC) ─────────────────────────────────────────────────

def _sqlite_conn():
    conn = sqlite3.connect(_SQLITE_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def _ensure_sqlite_schema():
    conn = _sqlite_conn()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS agent_memory (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            agent_type  TEXT NOT NULL,
            key         TEXT NOT NULL,
            value       TEXT NOT NULL,
            created_at  REAL NOT NULL,
            updated_at  REAL NOT NULL
        );
        CREATE UNIQUE INDEX IF NOT EXISTS idx_agent_key ON agent_memory(agent_type, key);

        CREATE TABLE IF NOT EXISTS agent_conversations (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id  TEXT NOT NULL,
            role        TEXT NOT NULL,
            content     TEXT NOT NULL,
            metadata    TEXT DEFAULT '{}',
            created_at  REAL NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_session ON agent_conversations(session_id);
    """)
    conn.commit()
    conn.close()


_ensure_sqlite_schema()


# ── PostgreSQL backend ────────────────────────────────────────────────────────

def _ensure_pg_schema(conn):
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS agent_memory (
            id          SERIAL PRIMARY KEY,
            agent_type  VARCHAR(64) NOT NULL,
            key         VARCHAR(256) NOT NULL,
            value       JSONB NOT NULL,
            created_at  TIMESTAMPTZ DEFAULT NOW(),
            updated_at  TIMESTAMPTZ DEFAULT NOW(),
            UNIQUE (agent_type, key)
        );
        CREATE TABLE IF NOT EXISTS agent_conversations (
            id          SERIAL PRIMARY KEY,
            session_id  VARCHAR(64) NOT NULL,
            role        VARCHAR(16) NOT NULL,
            content     TEXT NOT NULL,
            metadata    JSONB DEFAULT '{}',
            created_at  TIMESTAMPTZ DEFAULT NOW()
        );
        CREATE INDEX IF NOT EXISTS idx_agent_key_pg ON agent_memory(agent_type, key);
        CREATE INDEX IF NOT EXISTS idx_session_pg ON agent_conversations(session_id);
    """)
    conn.commit()


def _pg_conn():
    try:
        import psycopg2
        conn = psycopg2.connect(_POSTGRES_URL)
        _ensure_pg_schema(conn)
        return conn
    except Exception as exc:
        logger.warning("PostgreSQL unavailable (%s), using SQLite fallback", exc)
        return None


# ── Unified MemoryStore ───────────────────────────────────────────────────────

class MemoryStore:
    """
    Unified agent memory store.
    Automatically uses PostgreSQL if POSTGRES_URL is set, else SQLite.
    """

    def __init__(self):
        self._use_pg = bool(_POSTGRES_URL)

    def store(self, agent_type: str, key: str, value: Any) -> bool:
        """Upsert a value for (agent_type, key)."""
        serialized = json.dumps(value, default=str)
        now = time.time()
        try:
            if self._use_pg:
                conn = _pg_conn()
                if conn:
                    cur = conn.cursor()
                    cur.execute("""
                        INSERT INTO agent_memory (agent_type, key, value, created_at, updated_at)
                        VALUES (%s, %s, %s::jsonb, NOW(), NOW())
                        ON CONFLICT (agent_type, key) DO UPDATE
                        SET value = EXCLUDED.value, updated_at = NOW()
                    """, (agent_type, key, serialized))
                    conn.commit()
                    conn.close()
                    return True
            # SQLite fallback
            conn = _sqlite_conn()
            conn.execute("""
                INSERT INTO agent_memory (agent_type, key, value, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(agent_type, key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at
            """, (agent_type, key, serialized, now, now))
            conn.commit()
            conn.close()
            return True
        except Exception as exc:
            logger.error("MemoryStore.store failed: %s", exc)
            return False

    def get(self, agent_type: str, key: str) -> Optional[Any]:
        """Retrieve a value for (agent_type, key)."""
        try:
            if self._use_pg:
                conn = _pg_conn()
                if conn:
                    cur = conn.cursor()
                    cur.execute("SELECT value FROM agent_memory WHERE agent_type=%s AND key=%s", (agent_type, key))
                    row = cur.fetchone()
                    conn.close()
                    return row[0] if row else None
            conn = _sqlite_conn()
            row = conn.execute(
                "SELECT value FROM agent_memory WHERE agent_type=? AND key=?", (agent_type, key)
            ).fetchone()
            conn.close()
            return json.loads(row["value"]) if row else None
        except Exception as exc:
            logger.error("MemoryStore.get failed: %s", exc)
            return None

    def list(self, agent_type: str, limit: int = 50) -> List[Dict]:
        """List recent entries for an agent_type."""
        try:
            if self._use_pg:
                conn = _pg_conn()
                if conn:
                    cur = conn.cursor()
                    cur.execute(
                        "SELECT key, value, updated_at FROM agent_memory WHERE agent_type=%s ORDER BY updated_at DESC LIMIT %s",
                        (agent_type, limit)
                    )
                    rows = cur.fetchall()
                    conn.close()
                    return [{"key": r[0], "value": r[1], "updated_at": str(r[2])} for r in rows]
            conn = _sqlite_conn()
            rows = conn.execute(
                "SELECT key, value, updated_at FROM agent_memory WHERE agent_type=? ORDER BY updated_at DESC LIMIT ?",
                (agent_type, limit)
            ).fetchall()
            conn.close()
            return [{"key": r["key"], "value": json.loads(r["value"]), "updated_at": r["updated_at"]} for r in rows]
        except Exception as exc:
            logger.error("MemoryStore.list failed: %s", exc)
            return []

    # ── Conversation memory ───────────────────────────────────────────────────

    def add_message(self, session_id: str, role: str, content: str, metadata: Optional[Dict] = None) -> bool:
        meta_str = json.dumps(metadata or {}, default=str)
        now = time.time()
        try:
            if self._use_pg:
                conn = _pg_conn()
                if conn:
                    cur = conn.cursor()
                    cur.execute(
                        "INSERT INTO agent_conversations (session_id, role, content, metadata, created_at) VALUES (%s,%s,%s,%s::jsonb,NOW())",
                        (session_id, role, content, meta_str)
                    )
                    conn.commit()
                    conn.close()
                    return True
            conn = _sqlite_conn()
            conn.execute(
                "INSERT INTO agent_conversations (session_id, role, content, metadata, created_at) VALUES (?,?,?,?,?)",
                (session_id, role, content, meta_str, now)
            )
            conn.commit()
            conn.close()
            return True
        except Exception as exc:
            logger.error("add_message failed: %s", exc)
            return False

    def get_conversation(self, session_id: str, limit: int = 20) -> List[Dict]:
        try:
            if self._use_pg:
                conn = _pg_conn()
                if conn:
                    cur = conn.cursor()
                    cur.execute(
                        "SELECT role, content, metadata, created_at FROM agent_conversations WHERE session_id=%s ORDER BY created_at DESC LIMIT %s",
                        (session_id, limit)
                    )
                    rows = cur.fetchall()
                    conn.close()
                    return [{"role": r[0], "content": r[1], "metadata": r[2], "created_at": str(r[3])} for r in reversed(rows)]
            conn = _sqlite_conn()
            rows = conn.execute(
                "SELECT role, content, metadata, created_at FROM agent_conversations WHERE session_id=? ORDER BY created_at DESC LIMIT ?",
                (session_id, limit)
            ).fetchall()
            conn.close()
            return [{"role": r["role"], "content": r["content"], "metadata": json.loads(r["metadata"]), "created_at": r["created_at"]} for r in reversed(rows)]
        except Exception as exc:
            logger.error("get_conversation failed: %s", exc)
            return []
