"""
MemGuard Memory Proxy — the core interceptor.
All memory operations route through here for security checks.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Optional

from memguard.config import MemGuardConfig
from memguard.core.agent_registry import AgentRegistry, VerificationResult
from memguard.core.audit import AuditEngine, AuditAction
from memguard.core.memory_entry import (
    MemoryEntry, MemoryStatus, Provenance, SourceType, WriteDecision,
)
from memguard.core.memory_store import MemoryStore
from memguard.core.policy_engine import PolicyEngine
from memguard.core.quarantine import QuarantineManager
from memguard.crypto.agent_identity import AgentIdentity
from memguard.crypto.attestation import SourceAttestation
from memguard.crypto.signing import Signer
from memguard.detection.pipeline import DetectionPipeline
from memguard.graph.memory_graph import MemoryGraph


class WriteResult:
    """Result of a memory write operation."""

    def __init__(
        self,
        allowed: bool,
        decision: WriteDecision,
        entry: Optional[MemoryEntry] = None,
        reasons: list[str] = None,
    ):
        self.allowed = allowed
        self.decision = decision
        self.entry = entry
        self.reasons = reasons or []


class MemGuard:
    """Main entry point — secure memory proxy.
    
    Usage:
        guard = MemGuard(config=MemGuardConfig.preset("balanced"))
        
        result = guard.write("user_email", "alice@corp.com",
            source_type="user_input", agent_id="main")
        
        value = guard.read("user_email")
    """

    def __init__(self, config: Optional[MemGuardConfig] = None):
        self._config = config or MemGuardConfig()
        self._config.ensure_directories()

        # Crypto
        self._signer = (
            Signer.load_or_generate(self._config.key_path)
            if self._config.signing_enabled
            else None
        )

        self._tenant_id = self._config.tenant_id

        # Core components
        self._store = MemoryStore(
            db_path=self._config.db_path, signer=self._signer,
            tenant_id=self._tenant_id,
        )
        self._audit = AuditEngine(
            audit_path=self._config.audit_path, signer=self._signer,
            tenant_id=self._tenant_id,
        )
        self._policy = PolicyEngine(self._config)
        self._detection = DetectionPipeline(self._config)
        self._quarantine = QuarantineManager(self._store, self._audit)
        self._graph = MemoryGraph()
        self._agent_registry = AgentRegistry(
            enforce=self._config.agent_identity_required,
        )

    def register_agent(self, identity: AgentIdentity) -> None:
        """Register an agent identity for signature verification."""
        self._agent_registry.register(identity)

    def revoke_agent(self, agent_id: str) -> bool:
        """Revoke an agent's identity."""
        return self._agent_registry.revoke(agent_id)

    def write(
        self,
        key: str,
        content: Any,
        source_type: str = "user_input",
        agent_id: str = "",
        session_id: str = "",
        channel: str = "",
        source_id: str = "",
        parent_memory_ids: Optional[list[str]] = None,
        tags: Optional[list[str]] = None,
        trust_score: Optional[float] = None,
        agent_signature: str = "",
        attestation: Optional[SourceAttestation] = None,
    ) -> WriteResult:
        """Write a memory through the security pipeline.
        
        Pipeline: Identity → Provenance → Policy → Detection → Store/Quarantine/Block
        
        If agent_identity_required is True, agent_signature must be provided
        and must match the registered agent's public key.
        
        If attestation is provided, it will be verified by the policy engine
        and stored in the entry's provenance for later verification.
        """
        # Step 0: Agent identity verification
        agent_public_key = ""
        if self._agent_registry.enforce or agent_signature:
            sign_data = {
                "key": key,
                "content_hash": MemoryEntry(
                    key=key, content=content,
                ).compute_content_hash(),
                "agent_id": agent_id,
            }
            if agent_signature:
                vr = self._agent_registry.verify_agent(
                    agent_id, sign_data, agent_signature,
                )
                if not vr.verified:
                    self._audit.log(
                        AuditAction.BLOCK, memory_key=key, memory_id="",
                        agent_id=agent_id, session_id=session_id,
                        details={"reason": "agent_identity_verification_failed",
                                 "detail": vr.reason},
                    )
                    return WriteResult(
                        allowed=False, decision=WriteDecision.BLOCK,
                        reasons=[f"Agent identity verification failed: {vr.reason}"],
                    )
                agent_public_key = vr.public_key
            elif self._agent_registry.enforce:
                # No signature provided but enforcement is on
                self._audit.log(
                    AuditAction.BLOCK, memory_key=key, memory_id="",
                    agent_id=agent_id, session_id=session_id,
                    details={"reason": "missing_agent_signature"},
                )
                return WriteResult(
                    allowed=False, decision=WriteDecision.BLOCK,
                    reasons=["Agent signature required but not provided"],
                )

        # Build entry with provenance
        provenance = Provenance(
            source_type=SourceType(source_type),
            source_id=source_id,
            agent_id=agent_id,
            session_id=session_id,
            channel=channel,
            parent_memory_ids=parent_memory_ids or [],
            agent_signature=agent_signature,
            agent_public_key=agent_public_key,
            attestation=attestation.to_dict() if attestation else None,
        )
        version = self._store.get_next_version(key)
        entry = MemoryEntry(
            key=key,
            content=content,
            provenance=provenance,
            trust_score=trust_score if trust_score is not None else 0.5,
            trust_decay_rate=self._config.trust_decay.rate_per_day if self._config.trust_decay.enabled else 0.0,
            version=version,
            tags=tags or [],
        )
        entry.content_hash = entry.compute_content_hash()

        # Step 1: Policy check
        policy_result = self._policy.evaluate(entry)
        entry.trust_score = policy_result.adjusted_trust

        if policy_result.decision == WriteDecision.BLOCK:
            self._audit.log(
                AuditAction.BLOCK, memory_key=key, memory_id=entry.id,
                agent_id=agent_id, session_id=session_id,
                details={"reasons": policy_result.reasons},
            )
            return WriteResult(
                allowed=False, decision=WriteDecision.BLOCK,
                entry=entry, reasons=policy_result.reasons,
            )

        # Step 2: Detection pipeline
        history = self._store.get_history(key)
        all_active = self._store.get_all_active()
        det_results = self._detection.run(entry, history, all_active)

        if DetectionPipeline.should_quarantine(det_results):
            reason = DetectionPipeline.triggered_reasons(det_results)
            entry.status = MemoryStatus.QUARANTINED
            entry.quarantine_reason = reason
            self._store.put(entry)
            self._graph.add_memory(entry)
            self._audit.log(
                AuditAction.QUARANTINE, memory_key=key, memory_id=entry.id,
                agent_id=agent_id, session_id=session_id,
                details={"reason": reason, "detection_results": [
                    {"detector": r.detector_name, "score": r.score, "triggered": r.triggered}
                    for r in det_results
                ]},
            )
            return WriteResult(
                allowed=False, decision=WriteDecision.QUARANTINE,
                entry=entry, reasons=[reason],
            )

        # Step 3: Policy said quarantine (but not block)
        if policy_result.decision == WriteDecision.QUARANTINE:
            entry.status = MemoryStatus.QUARANTINED
            entry.quarantine_reason = "; ".join(policy_result.reasons)
            self._store.put(entry)
            self._graph.add_memory(entry)
            self._audit.log(
                AuditAction.QUARANTINE, memory_key=key, memory_id=entry.id,
                agent_id=agent_id, session_id=session_id,
                details={"reasons": policy_result.reasons},
            )
            return WriteResult(
                allowed=False, decision=WriteDecision.QUARANTINE,
                entry=entry, reasons=policy_result.reasons,
            )

        # Step 4: Allow — store
        entry.status = MemoryStatus.ACTIVE
        self._store.put(entry)
        self._graph.add_memory(entry)
        self._audit.log(
            AuditAction.WRITE, memory_key=key, memory_id=entry.id,
            agent_id=agent_id, session_id=session_id,
            details={"trust": entry.trust_score, "version": entry.version},
        )
        return WriteResult(
            allowed=True, decision=WriteDecision.ALLOW, entry=entry,
        )

    def read(self, key: str, agent_id: str = "", session_id: str = "") -> Any:
        """Read a memory (only returns active, non-expired entries)."""
        entry = self._store.get(key)
        if entry is None:
            return None
        if entry.is_expired():
            self._store.update_status(entry.id, MemoryStatus.EXPIRED)
            return None
        self._audit.log(
            AuditAction.READ, memory_key=key, memory_id=entry.id,
            agent_id=agent_id, session_id=session_id,
        )
        return entry.content

    def read_entry(self, key: str, agent_id: str = "", session_id: str = "") -> Optional[MemoryEntry]:
        """Read a memory entry with full provenance (for signature verification).
        
        Returns the full MemoryEntry including provenance.agent_signature
        and provenance.agent_public_key, so the caller can verify who wrote it.
        """
        entry = self._store.get(key)
        if entry is None:
            return None
        if entry.is_expired():
            self._store.update_status(entry.id, MemoryStatus.EXPIRED)
            return None
        self._audit.log(
            AuditAction.READ, memory_key=key, memory_id=entry.id,
            agent_id=agent_id, session_id=session_id,
            details={"read_type": "full_entry"},
        )
        return entry

    def verify_entry(self, entry: MemoryEntry) -> VerificationResult:
        """Verify the agent signature on a memory entry.
        
        Checks that the entry's provenance.agent_signature is valid
        for the claimed provenance.agent_id using the registered public key.
        """
        prov = entry.provenance
        if not prov.agent_signature:
            return VerificationResult(
                verified=False, agent_id=prov.agent_id,
                reason="No agent signature in entry provenance",
            )
        sign_data = {
            "key": entry.key,
            "content_hash": entry.content_hash,
            "agent_id": prov.agent_id,
        }
        return self._agent_registry.verify_agent(
            prov.agent_id, sign_data, prov.agent_signature,
        )

    def delete(self, key: str, agent_id: str = "", session_id: str = "") -> bool:
        """Soft-delete a memory (preserves audit trail)."""
        entry = self._store.get(key)
        if entry is None:
            return False
        self._store.update_status(entry.id, MemoryStatus.DELETED)
        self._audit.log(
            AuditAction.DELETE, memory_key=key, memory_id=entry.id,
            agent_id=agent_id, session_id=session_id,
        )
        return True

    @property
    def tenant_id(self) -> str:
        return self._tenant_id

    @property
    def agent_registry(self) -> AgentRegistry:
        return self._agent_registry

    @property
    def quarantine(self) -> QuarantineManager:
        return self._quarantine

    @property
    def store(self) -> MemoryStore:
        return self._store

    @property
    def audit(self) -> AuditEngine:
        return self._audit

    @property
    def graph(self) -> MemoryGraph:
        return self._graph

    def close(self) -> None:
        """Close all resources (DB connections, etc.)."""
        self._store.close()
