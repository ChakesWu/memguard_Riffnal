"""
Audited memory store with hash chain and Ed25519 signing.
Every memory operation is recorded with cryptographic integrity guarantees.
"""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from memguard.core.memory_entry import MemoryEntry, MemoryStatus, Provenance, SourceType
from memguard.crypto.hash_chain import HashChain
from memguard.crypto.signing import Signer


class MemoryStore:
    """SQLite-backed memory store with hash chain and signing.
    
    Every write is:
    1. Chained (SHA-256 hash includes previous hash)
    2. Signed (Ed25519)
    3. Versioned (updates create new versions, old versions preserved)
    """

    def __init__(
        self,
        db_path: str = "./memguard_data/memories.db",
        signer: Optional[Signer] = None,
        tenant_id: str = "default",
    ):
        self._db_path = Path(db_path)
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._signer = signer
        self._tenant_id = tenant_id
        self._chain = HashChain()
        self._conn: Optional[sqlite3.Connection] = None
        self._init_db()
        self._restore_chain()

    def _init_db(self) -> None:
        self._conn = sqlite3.connect(str(self._db_path))
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.executescript("""
            CREATE TABLE IF NOT EXISTS memories (
                id TEXT PRIMARY KEY,
                tenant_id TEXT NOT NULL DEFAULT 'default',
                key TEXT NOT NULL,
                content TEXT NOT NULL,
                content_hash TEXT NOT NULL,
                provenance TEXT NOT NULL,
                trust_score REAL NOT NULL,
                trust_decay_rate REAL NOT NULL DEFAULT 0.02,
                prev_hash TEXT NOT NULL,
                chain_hash TEXT NOT NULL,
                signature TEXT,
                version INTEGER NOT NULL DEFAULT 1,
                status TEXT NOT NULL DEFAULT 'active',
                quarantine_reason TEXT DEFAULT '',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                expires_at TEXT,
                tags TEXT DEFAULT '[]',
                UNIQUE(tenant_id, key, version)
            );
            CREATE INDEX IF NOT EXISTS idx_memories_tenant ON memories(tenant_id);
            CREATE INDEX IF NOT EXISTS idx_memories_tenant_key ON memories(tenant_id, key);
            CREATE INDEX IF NOT EXISTS idx_memories_status ON memories(status);
            CREATE INDEX IF NOT EXISTS idx_memories_tenant_key_version ON memories(tenant_id, key, version DESC);
        """)
        self._conn.commit()

    @property
    def tenant_id(self) -> str:
        return self._tenant_id

    def _restore_chain(self) -> None:
        cursor = self._conn.execute(
            "SELECT chain_hash FROM memories WHERE tenant_id = ? ORDER BY rowid DESC LIMIT 1",
            (self._tenant_id,),
        )
        row = cursor.fetchone()
        if row:
            self._chain.set_last_hash(row["chain_hash"])

    def put(self, entry: MemoryEntry) -> MemoryEntry:
        """Store a memory entry with chain hash and signature."""
        entry.prev_hash = self._chain.last_hash
        chain_data = {
            "id": entry.id,
            "key": entry.key,
            "content_hash": entry.content_hash,
            "version": entry.version,
            "created_at": entry.created_at.isoformat(),
        }
        chain_hash = self._chain.append(chain_data)

        if self._signer:
            sign_data = {
                "id": entry.id,
                "key": entry.key,
                "content_hash": entry.content_hash,
                "chain_hash": chain_hash,
                "prev_hash": entry.prev_hash,
            }
            entry.signature = self._signer.sign(sign_data)

        self._conn.execute(
            """INSERT INTO memories
               (id, tenant_id, key, content, content_hash, provenance, trust_score,
                trust_decay_rate, prev_hash, chain_hash, signature, version,
                status, quarantine_reason, created_at, updated_at, expires_at, tags)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                entry.id, self._tenant_id, entry.key,
                json.dumps(entry.content, default=str),
                entry.content_hash,
                json.dumps(entry.provenance.to_dict()),
                entry.trust_score, entry.trust_decay_rate,
                entry.prev_hash, chain_hash,
                entry.signature, entry.version,
                entry.status.value, entry.quarantine_reason,
                entry.created_at.isoformat(), entry.updated_at.isoformat(),
                entry.expires_at.isoformat() if entry.expires_at else None,
                json.dumps(entry.tags),
            ),
        )
        self._conn.commit()
        return entry

    def get(self, key: str, include_quarantined: bool = False) -> Optional[MemoryEntry]:
        """Get the latest active version of a memory by key (tenant-scoped)."""
        statuses = ["active"]
        if include_quarantined:
            statuses.extend(["quarantined", "under_review"])
        placeholders = ",".join("?" for _ in statuses)
        cursor = self._conn.execute(
            f"""SELECT * FROM memories
                WHERE tenant_id = ? AND key = ? AND status IN ({placeholders})
                ORDER BY version DESC LIMIT 1""",
            [self._tenant_id, key] + statuses,
        )
        row = cursor.fetchone()
        return self._row_to_entry(row) if row else None

    def get_history(self, key: str) -> list[MemoryEntry]:
        """Get all versions of a memory (for drift detection, tenant-scoped)."""
        cursor = self._conn.execute(
            "SELECT * FROM memories WHERE tenant_id = ? AND key = ? ORDER BY version ASC",
            (self._tenant_id, key),
        )
        return [self._row_to_entry(row) for row in cursor.fetchall()]

    def get_all_active(self) -> list[MemoryEntry]:
        """Get all active memories (for fragment assembly detection, tenant-scoped)."""
        cursor = self._conn.execute(
            "SELECT * FROM memories WHERE tenant_id = ? AND status = 'active' ORDER BY created_at DESC",
            (self._tenant_id,),
        )
        return [self._row_to_entry(row) for row in cursor.fetchall()]

    def get_by_status(self, status: MemoryStatus) -> list[MemoryEntry]:
        cursor = self._conn.execute(
            "SELECT * FROM memories WHERE tenant_id = ? AND status = ? ORDER BY updated_at DESC",
            (self._tenant_id, status.value),
        )
        return [self._row_to_entry(row) for row in cursor.fetchall()]

    def update_status(self, entry_id: str, status: MemoryStatus, reason: str = "") -> None:
        now = datetime.now(timezone.utc).isoformat()
        self._conn.execute(
            "UPDATE memories SET status = ?, quarantine_reason = ?, updated_at = ? WHERE id = ?",
            (status.value, reason, now, entry_id),
        )
        self._conn.commit()

    def get_next_version(self, key: str) -> int:
        cursor = self._conn.execute(
            "SELECT MAX(version) as max_ver FROM memories WHERE tenant_id = ? AND key = ?",
            (self._tenant_id, key),
        )
        row = cursor.fetchone()
        return (row["max_ver"] or 0) + 1

    def count(self, status: Optional[MemoryStatus] = None) -> int:
        if status:
            cursor = self._conn.execute(
                "SELECT COUNT(*) as cnt FROM memories WHERE tenant_id = ? AND status = ?",
                (self._tenant_id, status.value),
            )
        else:
            cursor = self._conn.execute(
                "SELECT COUNT(*) as cnt FROM memories WHERE tenant_id = ?",
                (self._tenant_id,),
            )
        return cursor.fetchone()["cnt"]

    def _row_to_entry(self, row: sqlite3.Row) -> MemoryEntry:
        prov_data = json.loads(row["provenance"])
        return MemoryEntry(
            id=row["id"],
            key=row["key"],
            content=json.loads(row["content"]),
            content_hash=row["content_hash"],
            provenance=Provenance.from_dict(prov_data),
            trust_score=row["trust_score"],
            trust_decay_rate=row["trust_decay_rate"],
            prev_hash=row["prev_hash"],
            signature=row["signature"],
            version=row["version"],
            status=MemoryStatus(row["status"]),
            quarantine_reason=row["quarantine_reason"] or "",
            created_at=datetime.fromisoformat(row["created_at"]),
            updated_at=datetime.fromisoformat(row["updated_at"]),
            expires_at=datetime.fromisoformat(row["expires_at"]) if row["expires_at"] else None,
            tags=json.loads(row["tags"]),
        )

    def close(self) -> None:
        if self._conn:
            self._conn.close()
