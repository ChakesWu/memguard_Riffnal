"""
Memory entry data model with provenance tracking.

Every memory in MemGuard is not raw data — it carries full security metadata:
who wrote it, where it came from, how trusted it is, and its integrity chain.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional


class MemoryStatus(Enum):
    """Lifecycle status of a memory entry."""
    ACTIVE = "active"
    QUARANTINED = "quarantined"
    UNDER_REVIEW = "under_review"
    RELEASED = "released"
    CONFIRMED_MALICIOUS = "confirmed_malicious"
    DELETED = "deleted"
    EXPIRED = "expired"


class SourceType(Enum):
    """Where the memory content originated."""
    USER_INPUT = "user_input"
    TOOL_OUTPUT = "tool_output"
    AGENT_INTERNAL = "agent_internal"
    EXTERNAL_CONTENT = "external_content"
    SKILL = "skill"
    SYSTEM = "system"


class WriteDecision(Enum):
    """Decision made by the security pipeline."""
    ALLOW = "allow"
    QUARANTINE = "quarantine"
    BLOCK = "block"


@dataclass
class Provenance:
    """Complete provenance chain for a memory entry.
    
    Tracks exactly who wrote what, from where, and through which path.
    This is the core of MemGuard's moat — once provenance data accumulates,
    migration cost is extremely high.
    """
    source_type: SourceType
    source_id: str = ""
    agent_id: str = ""
    session_id: str = ""
    channel: str = ""
    parent_memory_ids: list[str] = field(default_factory=list)
    trust_chain: list[str] = field(default_factory=list)
    agent_signature: str = ""
    agent_public_key: str = ""
    attestation: Optional[dict[str, Any]] = None
    
    def to_dict(self) -> dict[str, Any]:
        return {
            "source_type": self.source_type.value,
            "source_id": self.source_id,
            "agent_id": self.agent_id,
            "session_id": self.session_id,
            "channel": self.channel,
            "parent_memory_ids": self.parent_memory_ids,
            "trust_chain": self.trust_chain,
            "agent_signature": self.agent_signature,
            "agent_public_key": self.agent_public_key,
            "attestation": self.attestation,
        }
    
    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Provenance:
        data = dict(data)
        data["source_type"] = SourceType(data["source_type"])
        return cls(**data)


@dataclass
class MemoryEntry:
    """A single memory entry with full security metadata.
    
    Unlike raw memory stores (LangChain ConversationBufferMemory, OpenClaw JSONL),
    every MemGuard entry carries provenance, trust scoring, integrity chain,
    and lifecycle management.
    """
    # Identity
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    key: str = ""
    content: Any = None
    content_hash: str = ""
    
    # Provenance
    provenance: Provenance = field(default_factory=lambda: Provenance(source_type=SourceType.SYSTEM))
    
    # Trust
    trust_score: float = 0.5
    trust_decay_rate: float = 0.02
    
    # Integrity (hash chain)
    prev_hash: str = ""
    signature: Optional[str] = None
    version: int = 1
    
    # Lifecycle
    status: MemoryStatus = MemoryStatus.ACTIVE
    quarantine_reason: str = ""
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: Optional[datetime] = None
    
    # Graph
    tags: list[str] = field(default_factory=list)
    
    def __post_init__(self):
        if not self.content_hash and self.content is not None:
            self.content_hash = self.compute_content_hash()
    
    def compute_content_hash(self) -> str:
        """Compute SHA-256 hash of the content."""
        content_str = json.dumps(self.content, sort_keys=True, default=str)
        return hashlib.sha256(content_str.encode("utf-8")).hexdigest()
    
    def compute_chain_hash(self) -> str:
        """Compute hash for the hash chain (includes prev_hash)."""
        chain_data = {
            "id": self.id,
            "key": self.key,
            "content_hash": self.content_hash,
            "prev_hash": self.prev_hash,
            "version": self.version,
            "created_at": self.created_at.isoformat(),
        }
        chain_str = json.dumps(chain_data, sort_keys=True)
        return hashlib.sha256(chain_str.encode("utf-8")).hexdigest()
    
    def effective_trust(self) -> float:
        """Compute current trust score after time-based decay."""
        if self.trust_decay_rate <= 0:
            return self.trust_score
        
        age_days = (datetime.now(timezone.utc) - self.created_at).total_seconds() / 86400
        decayed = self.trust_score - (self.trust_decay_rate * age_days)
        return max(decayed, 0.0)
    
    def is_expired(self) -> bool:
        """Check if this memory has expired."""
        if self.expires_at is None:
            return False
        return datetime.now(timezone.utc) >= self.expires_at
    
    def to_dict(self) -> dict[str, Any]:
        """Serialize to dictionary for storage."""
        return {
            "id": self.id,
            "key": self.key,
            "content": self.content,
            "content_hash": self.content_hash,
            "provenance": self.provenance.to_dict(),
            "trust_score": self.trust_score,
            "trust_decay_rate": self.trust_decay_rate,
            "prev_hash": self.prev_hash,
            "signature": self.signature,
            "version": self.version,
            "status": self.status.value,
            "quarantine_reason": self.quarantine_reason,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "tags": self.tags,
        }
    
    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> MemoryEntry:
        """Deserialize from dictionary."""
        data = dict(data)
        data["provenance"] = Provenance.from_dict(data["provenance"])
        data["status"] = MemoryStatus(data["status"])
        data["created_at"] = datetime.fromisoformat(data["created_at"])
        data["updated_at"] = datetime.fromisoformat(data["updated_at"])
        if data.get("expires_at"):
            data["expires_at"] = datetime.fromisoformat(data["expires_at"])
        return cls(**data)
