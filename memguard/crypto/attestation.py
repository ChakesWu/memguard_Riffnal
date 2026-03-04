"""
Supply Chain Attestation — cryptographic proof of data origin.

Every tool output or RAG retrieval can carry an attestation:
a signed certificate proving that a specific source produced specific content.

This prevents:
- Tool output tampering (MITM between tool and agent memory)
- RAG poisoning (injected documents claiming to be from trusted sources)
- Unsigned data injection (content entering memory without provenance proof)

Usage:
    from memguard.crypto.attestation import ToolAttestation, RAGAttestation
    from memguard.crypto.agent_identity import AgentIdentity

    # Tool signs its own output
    tool_id = AgentIdentity.generate("search_tool")
    att = ToolAttestation.create(
        tool_id=tool_id,
        tool_name="web_search",
        output="Search results for 'vendor info'...",
    )

    # Verify attestation
    assert att.verify(tool_id.public_key_hex)

    # RAG source signs retrieval
    rag_id = AgentIdentity.generate("vector_store")
    att = RAGAttestation.create(
        source_id=rag_id,
        source_name="company_docs",
        query="vendor payment policy",
        documents=["Doc1: ...", "Doc2: ..."],
    )
    assert att.verify(rag_id.public_key_hex)
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional

from memguard.crypto.agent_identity import AgentIdentity


def _content_hash(content: Any) -> str:
    """Compute SHA-256 hash of arbitrary content."""
    content_str = json.dumps(content, sort_keys=True, default=str)
    return hashlib.sha256(content_str.encode("utf-8")).hexdigest()


@dataclass
class SourceAttestation:
    """Base attestation — cryptographic proof that a source produced content.

    Fields:
        source_name: human-readable name (e.g., "web_search", "company_docs")
        source_type: "tool" or "rag"
        content_hash: SHA-256 of the attested content
        signature: Ed25519 signature over the attestation payload
        public_key: hex-encoded public key of the signer
        timestamp: when the attestation was created
        metadata: optional extra info (tool version, query, etc.)
    """
    source_name: str
    source_type: str  # "tool" or "rag"
    content_hash: str
    signature: str = ""
    public_key: str = ""
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    metadata: dict[str, Any] = field(default_factory=dict)

    def _sign_payload(self) -> dict[str, Any]:
        """The canonical payload that gets signed."""
        return {
            "source_name": self.source_name,
            "source_type": self.source_type,
            "content_hash": self.content_hash,
            "timestamp": self.timestamp.isoformat(),
            "metadata": self.metadata,
        }

    def verify(self, expected_public_key: str = "") -> bool:
        """Verify this attestation's signature.

        Args:
            expected_public_key: If provided, also checks that the attestation
                                 was signed by this specific key.

        Returns:
            True if signature is valid (and key matches if specified).
        """
        if not self.signature or not self.public_key:
            return False
        if expected_public_key and self.public_key != expected_public_key:
            return False
        return AgentIdentity.verify_with_public_key(
            self._sign_payload(), self.signature, self.public_key,
        )

    def verify_content(self, content: Any) -> bool:
        """Verify that content matches the attested content_hash."""
        return _content_hash(content) == self.content_hash

    @property
    def is_signed(self) -> bool:
        return bool(self.signature) and bool(self.public_key)

    def to_dict(self) -> dict[str, Any]:
        return {
            "source_name": self.source_name,
            "source_type": self.source_type,
            "content_hash": self.content_hash,
            "signature": self.signature,
            "public_key": self.public_key,
            "timestamp": self.timestamp.isoformat(),
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> SourceAttestation:
        data = dict(data)
        data["timestamp"] = datetime.fromisoformat(data["timestamp"])
        return cls(**data)


@dataclass
class ToolAttestation(SourceAttestation):
    """Attestation for a tool's output.

    A tool signs its own output before it enters agent memory,
    proving the output was genuinely produced by that tool.
    """

    @classmethod
    def create(
        cls,
        tool_id: AgentIdentity,
        tool_name: str,
        output: Any,
        metadata: Optional[dict[str, Any]] = None,
    ) -> ToolAttestation:
        """Create a signed attestation for tool output.

        Args:
            tool_id: The tool's AgentIdentity (with signing key).
            tool_name: Human-readable tool name.
            output: The tool's output content.
            metadata: Optional extra info (tool version, params, etc.).
        """
        att = cls(
            source_name=tool_name,
            source_type="tool",
            content_hash=_content_hash(output),
            public_key=tool_id.public_key_hex,
            metadata=metadata or {},
        )
        att.signature = tool_id.sign(att._sign_payload())
        return att


@dataclass
class RAGAttestation(SourceAttestation):
    """Attestation for RAG retrieval results.

    A RAG source signs its retrieval results, proving the documents
    were genuinely retrieved from that source for a specific query.
    """

    @classmethod
    def create(
        cls,
        source_id: AgentIdentity,
        source_name: str,
        query: str,
        documents: list[Any],
        metadata: Optional[dict[str, Any]] = None,
    ) -> RAGAttestation:
        """Create a signed attestation for RAG retrieval.

        Args:
            source_id: The RAG source's AgentIdentity (with signing key).
            source_name: Human-readable source name (e.g., "company_docs").
            query: The query that produced these documents.
            documents: The retrieved documents.
            metadata: Optional extra info (top_k, similarity scores, etc.).
        """
        combined_content = {"query": query, "documents": documents}
        meta = metadata or {}
        meta["query"] = query
        meta["document_count"] = len(documents)

        att = cls(
            source_name=source_name,
            source_type="rag",
            content_hash=_content_hash(combined_content),
            public_key=source_id.public_key_hex,
            metadata=meta,
        )
        att.signature = source_id.sign(att._sign_payload())
        return att

    def verify_documents(self, query: str, documents: list[Any]) -> bool:
        """Verify that query + documents match the attested content."""
        combined = {"query": query, "documents": documents}
        return _content_hash(combined) == self.content_hash
