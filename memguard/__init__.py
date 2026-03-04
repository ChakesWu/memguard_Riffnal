"""
SafePatch MemGuard — Agent Memory Security
State Firewall for AI Agents

Lakera protects the request. MemGuard protects the system state.
"""

__version__ = "0.1.0"

from memguard.core.memory_entry import MemoryEntry, Provenance, MemoryStatus
from memguard.core.memory_proxy import MemGuard
from memguard.core.policy_engine import PolicyEngine
from memguard.core.quarantine import QuarantineManager
from memguard.core.audit import AuditEngine
from memguard.core.memory_store import MemoryStore
from memguard.core.tenant_manager import TenantManager
from memguard.core.agent_registry import AgentRegistry
from memguard.crypto.agent_identity import AgentIdentity
from memguard.crypto.attestation import SourceAttestation, ToolAttestation, RAGAttestation
from memguard.config import MemGuardConfig

__all__ = [
    "MemGuard",
    "MemoryEntry",
    "Provenance",
    "MemoryStatus",
    "PolicyEngine",
    "QuarantineManager",
    "AuditEngine",
    "MemoryStore",
    "TenantManager",
    "AgentRegistry",
    "AgentIdentity",
    "SourceAttestation",
    "ToolAttestation",
    "RAGAttestation",
    "MemGuardConfig",
]
