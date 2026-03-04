"""
SecureTool — wraps any LangChain-style tool with automatic attestation.

Every tool output is signed with the tool's Ed25519 key before it enters
agent memory. This creates a cryptographic proof of origin that MemGuard's
policy engine can verify.

Usage:
    from memguard.adapters.secure_tool import SecureTool
    from memguard.crypto.agent_identity import AgentIdentity

    # Wrap an existing tool
    tool_identity = AgentIdentity.generate("web_search")
    secure_search = SecureTool(
        tool=my_search_tool,
        tool_identity=tool_identity,
    )

    # Use it — output is automatically attested
    result = secure_search.run("vendor info")
    # result.output = "..."
    # result.attestation = ToolAttestation(...)

    # Or use with SecureMemory
    memory.save_tool_output(
        "search_result", result.output,
        tool_identity=tool_identity,
        tool_name="web_search",
    )
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Optional

from memguard.crypto.agent_identity import AgentIdentity
from memguard.crypto.attestation import ToolAttestation


@dataclass
class SecureToolResult:
    """Result from a SecureTool invocation.

    Carries both the raw output and its cryptographic attestation.
    """
    output: Any
    attestation: Optional[ToolAttestation] = None
    tool_name: str = ""
    error: str = ""

    @property
    def is_attested(self) -> bool:
        return self.attestation is not None and self.attestation.is_signed

    @property
    def success(self) -> bool:
        return not self.error

    def verify(self, expected_public_key: str = "") -> bool:
        """Verify the attestation on this result."""
        if not self.attestation:
            return False
        if not self.attestation.verify(expected_public_key):
            return False
        return self.attestation.verify_content(self.output)


class SecureTool:
    """Wrapper that adds cryptographic attestation to any tool's output.

    The tool can be:
    - A LangChain BaseTool (has .run() or ._run())
    - Any callable (function or lambda)
    - An object with a __call__ method

    On every invocation, the output is signed with the tool's Ed25519 key,
    creating a ToolAttestation that proves the output was genuinely produced
    by this tool.
    """

    def __init__(
        self,
        tool: Any = None,
        func: Optional[Callable] = None,
        tool_identity: Optional[AgentIdentity] = None,
        tool_name: str = "",
        metadata: Optional[dict[str, Any]] = None,
    ):
        """
        Args:
            tool: A LangChain BaseTool or any object with .run() method.
            func: A callable to use as the tool function (alternative to tool).
            tool_identity: Ed25519 identity for signing outputs.
            tool_name: Human-readable name. Defaults to tool.name or func.__name__.
            metadata: Static metadata to include in every attestation.
        """
        self._tool = tool
        self._func = func
        self._identity = tool_identity
        self._metadata = metadata or {}

        # Resolve tool name
        if tool_name:
            self._name = tool_name
        elif tool and hasattr(tool, "name"):
            self._name = tool.name
        elif func and hasattr(func, "__name__"):
            self._name = func.__name__
        else:
            self._name = "unknown_tool"

    @property
    def name(self) -> str:
        return self._name

    @property
    def identity(self) -> Optional[AgentIdentity]:
        return self._identity

    @property
    def public_key_hex(self) -> str:
        if self._identity:
            return self._identity.public_key_hex
        return ""

    def run(self, input_str: str = "", **kwargs: Any) -> SecureToolResult:
        """Run the tool and return an attested result.

        Args:
            input_str: Input to the tool.
            **kwargs: Additional keyword arguments passed to the tool.

        Returns:
            SecureToolResult with output and attestation.
        """
        try:
            # Execute the underlying tool
            if self._func:
                output = self._func(input_str, **kwargs)
            elif self._tool:
                if hasattr(self._tool, "run"):
                    output = self._tool.run(input_str, **kwargs)
                elif hasattr(self._tool, "_run"):
                    output = self._tool._run(input_str, **kwargs)
                elif callable(self._tool):
                    output = self._tool(input_str, **kwargs)
                else:
                    return SecureToolResult(
                        output=None, tool_name=self._name,
                        error=f"Tool '{self._name}' has no run() method",
                    )
            else:
                return SecureToolResult(
                    output=None, tool_name=self._name,
                    error="No tool or func provided",
                )
        except Exception as e:
            return SecureToolResult(
                output=None, tool_name=self._name,
                error=str(e),
            )

        # Create attestation
        attestation = None
        if self._identity and self._identity.can_sign:
            meta = dict(self._metadata)
            meta["input"] = str(input_str)[:500]
            attestation = ToolAttestation.create(
                tool_id=self._identity,
                tool_name=self._name,
                output=output,
                metadata=meta,
            )

        return SecureToolResult(
            output=output,
            attestation=attestation,
            tool_name=self._name,
        )

    def __call__(self, input_str: str = "", **kwargs: Any) -> SecureToolResult:
        """Alias for run()."""
        return self.run(input_str, **kwargs)

    @classmethod
    def from_function(
        cls,
        func: Callable,
        tool_name: str = "",
        tool_identity: Optional[AgentIdentity] = None,
        metadata: Optional[dict[str, Any]] = None,
    ) -> SecureTool:
        """Create a SecureTool from a plain function.

        Usage:
            def search(query: str) -> str:
                return f"Results for: {query}"

            secure_search = SecureTool.from_function(
                search, tool_name="web_search",
                tool_identity=AgentIdentity.generate("web_search"),
            )
        """
        return cls(
            func=func,
            tool_identity=tool_identity,
            tool_name=tool_name or getattr(func, "__name__", "unknown"),
            metadata=metadata,
        )
