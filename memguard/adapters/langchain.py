"""
LangChain adapter — wraps any LangChain memory with MemGuard protection.

Integrates:
- Agent Identity: automatic Ed25519 signing on save_context()
- Supply Chain Attestation: tool output attestation support
- Provenance Verification: transparent verification on reads
- Full LangChain BaseMemory interface compatibility

Usage:
    from memguard.adapters.langchain import SecureMemory
    from langchain.memory import ConversationBufferMemory

    memory = SecureMemory(
        base_memory=ConversationBufferMemory(),
        guard=guard,
        agent_identity=agent_identity,  # Ed25519 keypair
    )
    agent = create_react_agent(llm, tools, memory=memory)
"""

from __future__ import annotations

from typing import Any, Optional

from memguard.core.audit import AuditAction
from memguard.core.memory_entry import MemoryEntry
from memguard.core.memory_proxy import MemGuard, WriteResult
from memguard.crypto.agent_identity import AgentIdentity
from memguard.crypto.attestation import ToolAttestation, SourceAttestation


class SecureMemory:
    """Drop-in wrapper for LangChain BaseMemory with MemGuard protection.

    Intercepts save_context() and load_memory_variables() to route
    all memory operations through the MemGuard security pipeline.

    Features:
    - Automatic agent signature on every write (if agent_identity provided)
    - Provenance verification on reads (optional)
    - Blocked/quarantined content never reaches the base memory
    - Full audit trail of all memory operations
    """

    def __init__(
        self,
        base_memory: Any,
        guard: Optional[MemGuard] = None,
        agent_identity: Optional[AgentIdentity] = None,
        agent_id: str = "",
        session_id: str = "",
        source_type: str = "agent_internal",
        verify_on_read: bool = False,
    ):
        """
        Args:
            base_memory: LangChain BaseMemory instance to wrap.
            guard: MemGuard instance. Created with defaults if not provided.
            agent_identity: AgentIdentity for automatic signing. If provided,
                            the agent is auto-registered with the guard.
            agent_id: Fallback agent_id if no identity provided.
            session_id: Session identifier for audit.
            source_type: Default source type for writes.
            verify_on_read: If True, verify provenance on every read.
        """
        self._base = base_memory
        self._guard = guard or MemGuard()
        self._identity = agent_identity
        self._agent_id = agent_identity.agent_id if agent_identity else agent_id
        self._session_id = session_id
        self._source_type = source_type
        self._verify_on_read = verify_on_read
        self._blocked_writes: list[WriteResult] = []

        # Auto-register agent identity
        if self._identity and not self._guard.agent_registry.is_registered(self._agent_id):
            self._guard.register_agent(self._identity)

    @property
    def memory_variables(self) -> list[str]:
        return self._base.memory_variables

    @property
    def guard(self) -> MemGuard:
        return self._guard

    @property
    def blocked_writes(self) -> list[WriteResult]:
        """Get list of writes that were blocked/quarantined."""
        return list(self._blocked_writes)

    def _sign_write(self, key: str, content: Any) -> str:
        """Compute agent signature for a write."""
        if not self._identity or not self._identity.can_sign:
            return ""
        entry_tmp = MemoryEntry(key=key, content=content)
        sign_data = {
            "key": key,
            "content_hash": entry_tmp.compute_content_hash(),
            "agent_id": self._agent_id,
        }
        return self._identity.sign(sign_data)

    def load_memory_variables(self, inputs: dict[str, Any]) -> dict[str, Any]:
        """Load memories — reads are audited and optionally verified."""
        result = self._base.load_memory_variables(inputs)
        for key in result:
            self._guard.audit.log(
                action=AuditAction.READ,
                memory_key=f"langchain.{key}",
                agent_id=self._agent_id,
                session_id=self._session_id,
            )
            if self._verify_on_read:
                entry = self._guard.read_entry(f"langchain.context.{key}")
                if entry is not None:
                    vr = self._guard.verify_entry(entry)
                    if not vr.verified:
                        self._guard.audit.log(
                            action=AuditAction.READ,
                            memory_key=f"langchain.{key}",
                            agent_id=self._agent_id,
                            session_id=self._session_id,
                            details={"warning": "provenance_verification_failed",
                                     "reason": vr.reason},
                        )
        return result

    def save_context(self, inputs: dict[str, Any], outputs: dict[str, str]) -> None:
        """Save context — writes go through MemGuard pipeline with agent signing."""
        for key, value in outputs.items():
            mem_key = f"langchain.context.{key}"
            sig = self._sign_write(mem_key, value)

            result = self._guard.write(
                key=mem_key,
                content=value,
                source_type=self._source_type,
                agent_id=self._agent_id,
                session_id=self._session_id,
                agent_signature=sig,
            )
            if not result.allowed:
                self._blocked_writes.append(result)
                return

        # All checks passed — save to underlying memory
        self._base.save_context(inputs, outputs)

    def save_tool_output(
        self,
        key: str,
        output: Any,
        tool_identity: Optional[AgentIdentity] = None,
        tool_name: str = "",
    ) -> WriteResult:
        """Save a tool's output with optional attestation.

        If tool_identity is provided, the output is signed with the tool's
        key (ToolAttestation) before entering the MemGuard pipeline.

        Args:
            key: Memory key for this tool output.
            output: The tool's output content.
            tool_identity: Tool's AgentIdentity for attestation signing.
            tool_name: Human-readable tool name.

        Returns:
            WriteResult from the MemGuard pipeline.
        """
        attestation = None
        if tool_identity:
            attestation = ToolAttestation.create(
                tool_id=tool_identity,
                tool_name=tool_name or tool_identity.agent_id,
                output=output,
            )

        mem_key = f"langchain.tool.{key}"
        sig = self._sign_write(mem_key, output)

        result = self._guard.write(
            key=mem_key,
            content=output,
            source_type="tool_output",
            agent_id=self._agent_id,
            session_id=self._session_id,
            agent_signature=sig,
            attestation=attestation,
        )
        if not result.allowed:
            self._blocked_writes.append(result)
        return result

    def read_verified(self, key: str) -> tuple[Any, bool]:
        """Read a memory value and verify its provenance.

        Returns:
            (content, verified) tuple. verified=True if the entry has
            a valid agent signature from a registered agent.
        """
        entry = self._guard.read_entry(
            f"langchain.context.{key}",
            agent_id=self._agent_id,
            session_id=self._session_id,
        )
        if entry is None:
            return None, False
        vr = self._guard.verify_entry(entry)
        return entry.content, vr.verified

    def clear(self) -> None:
        """Clear memory — audited as delete."""
        for var in self.memory_variables:
            self._guard.delete(
                key=f"langchain.{var}",
                agent_id=self._agent_id,
                session_id=self._session_id,
            )
        self._base.clear()
        self._blocked_writes.clear()


class SecureCallbackHandler:
    """LangChain callback handler that audits tool calls and LLM interactions.

    Automatically creates ToolAttestation for tool outputs if tool_identities
    are registered.

    Usage:
        from memguard.adapters.langchain import SecureCallbackHandler
        handler = SecureCallbackHandler(
            guard=guard, agent_id="my_agent",
            tool_identities={"web_search": search_tool_identity},
        )
        agent.invoke("...", config={"callbacks": [handler]})
    """

    def __init__(
        self,
        guard: MemGuard,
        agent_identity: Optional[AgentIdentity] = None,
        agent_id: str = "",
        session_id: str = "",
        tool_identities: Optional[dict[str, AgentIdentity]] = None,
    ):
        self._guard = guard
        self._identity = agent_identity
        self._agent_id = agent_identity.agent_id if agent_identity else agent_id
        self._session_id = session_id
        self._tool_identities = tool_identities or {}
        self._current_tool: str = ""

        if self._identity and not self._guard.agent_registry.is_registered(self._agent_id):
            self._guard.register_agent(self._identity)

    def _sign_write(self, key: str, content: Any) -> str:
        """Compute agent signature for a write."""
        if not self._identity or not self._identity.can_sign:
            return ""
        entry_tmp = MemoryEntry(key=key, content=content)
        sign_data = {
            "key": key,
            "content_hash": entry_tmp.compute_content_hash(),
            "agent_id": self._agent_id,
        }
        return self._identity.sign(sign_data)

    def on_tool_start(self, serialized: dict, input_str: str, **kwargs: Any) -> None:
        self._current_tool = serialized.get("name", "unknown")
        self._guard.audit.log(
            action=AuditAction.READ,
            memory_key=f"tool_call.{self._current_tool}",
            agent_id=self._agent_id,
            session_id=self._session_id,
            details={"tool": self._current_tool, "input": input_str[:500]},
        )

    def on_tool_end(self, output: str, **kwargs: Any) -> None:
        tool_name = self._current_tool or "unknown"
        attestation = None
        tool_id = self._tool_identities.get(tool_name)
        if tool_id:
            attestation = ToolAttestation.create(
                tool_id=tool_id,
                tool_name=tool_name,
                output=output[:1000],
            )

        mem_key = f"tool_output.{tool_name}"
        sig = self._sign_write(mem_key, output[:1000])
        src = "tool_output" if attestation else "agent_internal"

        self._guard.write(
            key=mem_key,
            content=output[:1000],
            source_type=src,
            agent_id=self._agent_id,
            session_id=self._session_id,
            agent_signature=sig,
            attestation=attestation,
        )
