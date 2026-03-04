"""
Quarantine manager — isolates suspicious memories for human review.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from memguard.core.memory_entry import MemoryEntry, MemoryStatus
from memguard.core.memory_store import MemoryStore
from memguard.core.audit import AuditEngine, AuditAction


class QuarantineManager:
    """Manages the quarantine zone for suspicious memories."""

    def __init__(self, store: MemoryStore, audit: AuditEngine):
        self._store = store
        self._audit = audit

    def quarantine(self, entry_id: str, reason: str, detector: str = "") -> None:
        """Move a memory to quarantine."""
        self._store.update_status(entry_id, MemoryStatus.QUARANTINED, reason)
        self._audit.log(
            action=AuditAction.QUARANTINE,
            memory_id=entry_id,
            details={"reason": reason, "detector": detector},
        )

    def release(self, entry_id: str, reviewer: str = "") -> None:
        """Release a memory from quarantine back to active."""
        self._store.update_status(entry_id, MemoryStatus.ACTIVE, "")
        self._audit.log(
            action=AuditAction.RELEASE,
            memory_id=entry_id,
            details={"reviewer": reviewer},
        )

    def confirm_malicious(self, entry_id: str, reviewer: str = "") -> None:
        """Confirm a quarantined memory as malicious."""
        self._store.update_status(
            entry_id, MemoryStatus.CONFIRMED_MALICIOUS, "confirmed by reviewer"
        )
        self._audit.log(
            action=AuditAction.QUARANTINE,
            memory_id=entry_id,
            details={"confirmed_malicious": True, "reviewer": reviewer},
        )

    def get_pending(self) -> list[MemoryEntry]:
        """Get all memories awaiting review."""
        return self._store.get_by_status(MemoryStatus.QUARANTINED)

    def get_stats(self) -> dict[str, int]:
        """Get quarantine statistics."""
        return {
            "quarantined": self._store.count(MemoryStatus.QUARANTINED),
            "under_review": self._store.count(MemoryStatus.UNDER_REVIEW),
            "confirmed_malicious": self._store.count(MemoryStatus.CONFIRMED_MALICIOUS),
            "total_active": self._store.count(MemoryStatus.ACTIVE),
        }
