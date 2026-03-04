"""
Agent Identity — per-agent Ed25519 keypair for cryptographic identity.

Each agent gets its own keypair. When an agent writes to MemGuard,
the write is signed with the agent's private key. Any reader can
verify the signature using the agent's public key from the registry.

This prevents:
- Agent impersonation (attacker claims to be agent_id="admin")
- Unsigned state injection (memory entries without valid agent signature)
- Cross-agent tampering (AgentA modifies AgentB's data undetected)

Usage:
    identity = AgentIdentity.generate("procurement_agent")
    sig = identity.sign({"key": "vendor_info", "content_hash": "abc123"})
    assert identity.verify({"key": "vendor_info", "content_hash": "abc123"}, sig)
    
    # Other agents can verify using only the public key
    pub_hex = identity.public_key_hex
    assert AgentIdentity.verify_with_public_key(data, sig, pub_hex)
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from nacl.encoding import HexEncoder
from nacl.signing import SigningKey, VerifyKey


@dataclass
class AgentIdentity:
    """Cryptographic identity for a single agent.
    
    Each agent has:
    - agent_id: human-readable identifier
    - Ed25519 keypair: for signing memory writes
    - role: agent's role (for RBAC policy)
    - permissions: what keys/operations this agent can perform
    - created_at: when this identity was created
    """
    agent_id: str
    role: str = "default"
    permissions: list[str] = field(default_factory=lambda: ["read", "write"])
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    _signing_key: Optional[SigningKey] = field(default=None, repr=False)
    _verify_key: Optional[VerifyKey] = field(default=None, repr=False)

    @classmethod
    def generate(
        cls,
        agent_id: str,
        role: str = "default",
        permissions: Optional[list[str]] = None,
    ) -> AgentIdentity:
        """Generate a new agent identity with a fresh Ed25519 keypair."""
        sk = SigningKey.generate()
        return cls(
            agent_id=agent_id,
            role=role,
            permissions=permissions or ["read", "write"],
            _signing_key=sk,
            _verify_key=sk.verify_key,
        )

    @classmethod
    def from_public_key_hex(
        cls,
        agent_id: str,
        public_key_hex: str,
        role: str = "default",
        permissions: Optional[list[str]] = None,
    ) -> AgentIdentity:
        """Create a verify-only identity from a public key (no signing capability)."""
        vk = VerifyKey(bytes.fromhex(public_key_hex))
        return cls(
            agent_id=agent_id,
            role=role,
            permissions=permissions or ["read"],
            _signing_key=None,
            _verify_key=vk,
        )

    @property
    def public_key_hex(self) -> str:
        """Get hex-encoded public key."""
        if self._verify_key is None:
            raise ValueError(f"Agent '{self.agent_id}' has no key material")
        return self._verify_key.encode(HexEncoder).decode()

    @property
    def can_sign(self) -> bool:
        """Whether this identity has signing capability (has private key)."""
        return self._signing_key is not None

    def sign(self, data: dict[str, Any]) -> str:
        """Sign data with this agent's private key.
        
        Returns hex-encoded Ed25519 signature.
        Raises ValueError if this is a verify-only identity.
        """
        if self._signing_key is None:
            raise ValueError(
                f"Agent '{self.agent_id}' has no signing key "
                "(verify-only identity)"
            )
        message = json.dumps(data, sort_keys=True, default=str).encode("utf-8")
        signed = self._signing_key.sign(message, encoder=HexEncoder)
        return signed.signature.decode()

    def verify(self, data: dict[str, Any], signature_hex: str) -> bool:
        """Verify a signature against data using this agent's public key."""
        if self._verify_key is None:
            return False
        message = json.dumps(data, sort_keys=True, default=str).encode("utf-8")
        try:
            self._verify_key.verify(message, bytes.fromhex(signature_hex))
            return True
        except Exception:
            return False

    @staticmethod
    def verify_with_public_key(
        data: dict[str, Any], signature_hex: str, public_key_hex: str,
    ) -> bool:
        """Verify a signature using a raw public key hex string.
        
        Useful when the verifier only has the public key (e.g., from registry).
        """
        try:
            vk = VerifyKey(bytes.fromhex(public_key_hex))
            message = json.dumps(data, sort_keys=True, default=str).encode("utf-8")
            vk.verify(message, bytes.fromhex(signature_hex))
            return True
        except Exception:
            return False

    def has_permission(self, operation: str) -> bool:
        """Check if this agent has a specific permission."""
        return operation in self.permissions

    def save(self, key_dir: str | Path) -> None:
        """Save agent identity to disk."""
        key_dir = Path(key_dir)
        key_dir.mkdir(parents=True, exist_ok=True)

        meta = {
            "agent_id": self.agent_id,
            "role": self.role,
            "permissions": self.permissions,
            "public_key": self.public_key_hex,
            "created_at": self.created_at.isoformat(),
        }
        meta_path = key_dir / f"agent_{self.agent_id}.json"
        meta_path.write_text(json.dumps(meta, indent=2))

        if self._signing_key is not None:
            sk_path = key_dir / f"agent_{self.agent_id}.key"
            sk_path.write_text(self._signing_key.encode(HexEncoder).decode())

        pub_path = key_dir / f"agent_{self.agent_id}.pub"
        pub_path.write_text(self.public_key_hex)

    @classmethod
    def load(cls, key_dir: str | Path, agent_id: str) -> AgentIdentity:
        """Load agent identity from disk."""
        key_dir = Path(key_dir)

        meta_path = key_dir / f"agent_{agent_id}.json"
        if not meta_path.exists():
            raise FileNotFoundError(f"Agent identity not found: {agent_id}")

        meta = json.loads(meta_path.read_text())

        sk_path = key_dir / f"agent_{agent_id}.key"
        if sk_path.exists():
            sk = SigningKey(bytes.fromhex(sk_path.read_text().strip()))
            vk = sk.verify_key
        else:
            sk = None
            vk = VerifyKey(bytes.fromhex(meta["public_key"]))

        return cls(
            agent_id=meta["agent_id"],
            role=meta.get("role", "default"),
            permissions=meta.get("permissions", ["read", "write"]),
            created_at=datetime.fromisoformat(meta["created_at"]),
            _signing_key=sk,
            _verify_key=vk,
        )

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dict (public info only, no private key)."""
        return {
            "agent_id": self.agent_id,
            "role": self.role,
            "permissions": self.permissions,
            "public_key": self.public_key_hex,
            "can_sign": self.can_sign,
            "created_at": self.created_at.isoformat(),
        }
