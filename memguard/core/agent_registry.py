"""
AgentRegistry — manages registered agent identities for a MemGuard instance.

Responsibilities:
- Register agents with their Ed25519 public keys
- Verify that a write request comes from a registered agent
- Enforce RBAC: check agent permissions before allowing operations
- Detect impersonation: reject writes from unregistered or mismatched agents

Usage:
    from memguard.crypto.agent_identity import AgentIdentity
    from memguard.core.agent_registry import AgentRegistry

    registry = AgentRegistry()

    # Register agents
    agent_a = AgentIdentity.generate("procurement_agent", role="writer")
    agent_b = AgentIdentity.generate("audit_agent", role="reader",
                                      permissions=["read"])
    registry.register(agent_a)
    registry.register(agent_b)

    # Verify a signed write
    data = {"key": "vendor_info", "content_hash": "abc123"}
    sig = agent_a.sign(data)
    assert registry.verify_signature("procurement_agent", data, sig)

    # Check permissions
    assert registry.check_permission("procurement_agent", "write")
    assert not registry.check_permission("audit_agent", "write")
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional

from memguard.crypto.agent_identity import AgentIdentity


@dataclass
class VerificationResult:
    """Result of an agent identity verification."""
    verified: bool
    agent_id: str
    reason: str = ""
    agent_role: str = ""
    public_key: str = ""

    def __bool__(self) -> bool:
        return self.verified


class AgentRegistry:
    """Registry of known agent identities.

    All agents must be registered before they can write to MemGuard.
    Unregistered agent_ids are rejected. Registered agents must provide
    a valid signature matching their registered public key.
    """

    def __init__(self, enforce: bool = True):
        """
        Args:
            enforce: If True, MemGuard will reject writes from unregistered
                     agents. If False, unregistered agents are allowed but
                     flagged in audit (useful for gradual rollout).
        """
        self._agents: dict[str, AgentIdentity] = {}
        self._enforce = enforce
        self._revoked: set[str] = set()

    @property
    def enforce(self) -> bool:
        return self._enforce

    def register(self, identity: AgentIdentity) -> None:
        """Register an agent identity.

        Args:
            identity: AgentIdentity with at least a public key.

        Raises:
            ValueError: If agent_id is already registered or revoked.
        """
        if identity.agent_id in self._revoked:
            raise ValueError(
                f"Agent '{identity.agent_id}' has been revoked and cannot be re-registered"
            )
        if identity.agent_id in self._agents:
            raise ValueError(
                f"Agent '{identity.agent_id}' is already registered. "
                "Revoke first to re-register."
            )
        self._agents[identity.agent_id] = identity

    def revoke(self, agent_id: str) -> bool:
        """Revoke an agent's identity. All future operations will be rejected.

        Args:
            agent_id: The agent to revoke.

        Returns:
            True if the agent was found and revoked, False if not found.
        """
        if agent_id in self._agents:
            del self._agents[agent_id]
            self._revoked.add(agent_id)
            return True
        return False

    def is_registered(self, agent_id: str) -> bool:
        return agent_id in self._agents

    def is_revoked(self, agent_id: str) -> bool:
        return agent_id in self._revoked

    def get_identity(self, agent_id: str) -> Optional[AgentIdentity]:
        return self._agents.get(agent_id)

    def verify_agent(
        self,
        agent_id: str,
        data: dict[str, Any],
        signature_hex: str,
    ) -> VerificationResult:
        """Verify that a signed operation comes from a registered agent.

        Checks:
        1. agent_id is registered (not revoked)
        2. Signature matches the registered public key
        3. Agent has not been revoked

        Args:
            agent_id: Claimed agent identity.
            data: The data that was signed.
            signature_hex: Hex-encoded Ed25519 signature.

        Returns:
            VerificationResult with verified=True/False and reason.
        """
        # Check revocation
        if agent_id in self._revoked:
            return VerificationResult(
                verified=False, agent_id=agent_id,
                reason=f"Agent '{agent_id}' has been revoked",
            )

        # Check registration
        if agent_id not in self._agents:
            if self._enforce:
                return VerificationResult(
                    verified=False, agent_id=agent_id,
                    reason=f"Agent '{agent_id}' is not registered",
                )
            else:
                return VerificationResult(
                    verified=True, agent_id=agent_id,
                    reason="unregistered_but_allowed (enforce=False)",
                )

        identity = self._agents[agent_id]

        # Verify signature
        if not identity.verify(data, signature_hex):
            return VerificationResult(
                verified=False, agent_id=agent_id,
                reason=f"Signature verification failed for agent '{agent_id}' — "
                       "possible impersonation",
                public_key=identity.public_key_hex,
            )

        return VerificationResult(
            verified=True, agent_id=agent_id,
            agent_role=identity.role,
            public_key=identity.public_key_hex,
        )

    def check_permission(self, agent_id: str, operation: str) -> bool:
        """Check if an agent has permission for an operation.

        Args:
            agent_id: The agent to check.
            operation: "read", "write", "delete", "admin", etc.

        Returns:
            True if allowed. False if not registered or lacks permission.
        """
        identity = self._agents.get(agent_id)
        if identity is None:
            return not self._enforce
        return identity.has_permission(operation)

    def list_agents(self) -> list[dict[str, Any]]:
        """List all registered agents (public info only)."""
        return [identity.to_dict() for identity in self._agents.values()]

    def list_revoked(self) -> list[str]:
        """List all revoked agent IDs."""
        return list(self._revoked)

    def agent_count(self) -> int:
        return len(self._agents)
