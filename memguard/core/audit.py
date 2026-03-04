"""
Immutable audit engine — append-only, signed, hash-chained log.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Optional

from memguard.crypto.hash_chain import HashChain
from memguard.crypto.signing import Signer


class AuditAction(Enum):
    WRITE = "write"
    READ = "read"
    UPDATE = "update"
    DELETE = "delete"
    QUARANTINE = "quarantine"
    RELEASE = "release"
    BLOCK = "block"
    DETECTION_TRIGGER = "detection_trigger"
    POLICY_VIOLATION = "policy_violation"


class AuditEngine:
    """Append-only audit log with Ed25519 signing + SHA-256 hash chain."""

    def __init__(
        self,
        audit_path: str = "./memguard_data/audit.jsonl",
        signer: Optional[Signer] = None,
        tenant_id: str = "default",
    ):
        self._path = Path(audit_path)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._signer = signer
        self._tenant_id = tenant_id
        self._chain = HashChain()
        self._restore_chain()

    def _restore_chain(self) -> None:
        if not self._path.exists():
            return
        last_line = ""
        with open(self._path, "r", encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    last_line = line.strip()
        if last_line:
            try:
                entry = json.loads(last_line)
                self._chain.set_last_hash(entry.get("chain_hash", HashChain.GENESIS_HASH))
            except json.JSONDecodeError:
                pass

    def log(
        self,
        action: AuditAction,
        memory_key: str = "",
        memory_id: str = "",
        agent_id: str = "",
        session_id: str = "",
        details: Optional[dict[str, Any]] = None,
    ) -> dict[str, Any]:
        """Append a signed, chained audit entry."""
        record = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "tenant_id": self._tenant_id,
            "action": action.value,
            "memory_key": memory_key,
            "memory_id": memory_id,
            "agent_id": agent_id,
            "session_id": session_id,
            "details": details or {},
        }
        chain_hash = self._chain.append(record)
        record["chain_hash"] = chain_hash
        if self._signer:
            record["signature"] = self._signer.sign(record)
        with open(self._path, "a", encoding="utf-8") as f:
            f.write(json.dumps(record, default=str) + "\n")
        return record

    def read_all(self, tenant_only: bool = True) -> list[dict[str, Any]]:
        """Read audit entries. If tenant_only=True, only returns this tenant's entries."""
        if not self._path.exists():
            return []
        entries = []
        with open(self._path, "r", encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    entry = json.loads(line)
                    if tenant_only and entry.get("tenant_id", "default") != self._tenant_id:
                        continue
                    entries.append(entry)
        return entries

    def query(self, memory_key: Optional[str] = None, action: Optional[AuditAction] = None) -> list[dict[str, Any]]:
        """Filter audit entries by key and/or action."""
        results = []
        for entry in self.read_all():
            if memory_key and entry.get("memory_key") != memory_key:
                continue
            if action and entry.get("action") != action.value:
                continue
            results.append(entry)
        return results
