"""
Generic adapter — for any key-value or document memory system.

Usage:
    from memguard.adapters.generic import SecureKVStore

    store = SecureKVStore(guard=MemGuard())
    store.set("user_email", "alice@corp.com", source_type="user_input")
    email = store.get("user_email")
"""

from __future__ import annotations

from typing import Any, Optional

from memguard.core.memory_proxy import MemGuard, WriteResult


class SecureKVStore:
    """MemGuard-protected key-value store wrapper."""

    def __init__(
        self,
        guard: Optional[MemGuard] = None,
        agent_id: str = "",
        session_id: str = "",
    ):
        self._guard = guard or MemGuard()
        self._agent_id = agent_id
        self._session_id = session_id

    def set(
        self,
        key: str,
        value: Any,
        source_type: str = "user_input",
        **kwargs: Any,
    ) -> WriteResult:
        """Set a value through MemGuard pipeline."""
        return self._guard.write(
            key=key,
            content=value,
            source_type=source_type,
            agent_id=self._agent_id,
            session_id=self._session_id,
            **kwargs,
        )

    def get(self, key: str) -> Any:
        """Get a value (only active, non-expired)."""
        return self._guard.read(
            key=key,
            agent_id=self._agent_id,
            session_id=self._session_id,
        )

    def delete(self, key: str) -> bool:
        """Soft-delete a value."""
        return self._guard.delete(
            key=key,
            agent_id=self._agent_id,
            session_id=self._session_id,
        )

    def get_quarantined(self):
        """Get all quarantined entries."""
        return self._guard.quarantine.get_pending()
