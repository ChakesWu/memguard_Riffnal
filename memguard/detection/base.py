"""
Base detector interface and shared data structures.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional

from memguard.core.memory_entry import MemoryEntry


class ThreatLevel(Enum):
    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class DetectionResult:
    """Result from a single detector."""
    detector_name: str
    threat_level: ThreatLevel = ThreatLevel.NONE
    triggered: bool = False
    score: float = 0.0
    reason: str = ""
    details: dict[str, Any] = field(default_factory=dict)

    @property
    def should_quarantine(self) -> bool:
        return self.threat_level in (ThreatLevel.HIGH, ThreatLevel.CRITICAL)


class BaseDetector(ABC):
    """Abstract base class for all memory detectors."""

    @property
    @abstractmethod
    def name(self) -> str:
        ...

    @abstractmethod
    def check_write(
        self,
        entry: MemoryEntry,
        history: list[MemoryEntry],
        all_active: list[MemoryEntry],
    ) -> DetectionResult:
        """Check a memory write operation.

        Args:
            entry: The new memory being written
            history: Previous versions of the same key
            all_active: All currently active memories
        """
        ...

    def check_batch(self, all_active: list[MemoryEntry]) -> list[DetectionResult]:
        """Periodic batch scan of all active memories.
        Override for detectors that need cross-memory analysis.
        """
        return []
