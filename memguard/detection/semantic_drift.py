"""
Semantic Drift Detector — detects gradual meaning changes in memory.

Example attack:
  Day 1: "Bob is an intern"
  Day 2: "Bob manages the team"
  Day 3: "Bob approves all payments"

Each update looks harmless alone, but cumulative drift = privilege escalation.
"""

from __future__ import annotations

from typing import Optional

from memguard.core.memory_entry import MemoryEntry
from memguard.detection.base import BaseDetector, DetectionResult, ThreatLevel


class SemanticDriftDetector(BaseDetector):
    """Detects gradual semantic drift across memory versions."""

    def __init__(self, threshold: float = 0.6, embedder: Optional[object] = None):
        self._threshold = threshold
        self._embedder = embedder  # sentence-transformers model, lazy loaded

    @property
    def name(self) -> str:
        return "semantic_drift"

    def check_write(
        self,
        entry: MemoryEntry,
        history: list[MemoryEntry],
        all_active: list[MemoryEntry],
    ) -> DetectionResult:
        if len(history) < 1:
            return DetectionResult(detector_name=self.name)

        # Compute cumulative drift between first version and new version
        first_content = str(history[0].content)
        new_content = str(entry.content)
        drift_score = self._compute_drift(first_content, new_content)

        if drift_score > self._threshold:
            return DetectionResult(
                detector_name=self.name,
                triggered=True,
                threat_level=ThreatLevel.CRITICAL if drift_score > 0.9 else ThreatLevel.HIGH,
                score=drift_score,
                reason=f"Semantic drift {drift_score:.2f} exceeds threshold {self._threshold}",
                details={
                    "original": first_content[:200],
                    "current": new_content[:200],
                    "versions_count": len(history),
                },
            )

        return DetectionResult(detector_name=self.name, score=drift_score)

    def _compute_drift(self, text_a: str, text_b: str) -> float:
        """Compute semantic distance between two texts.

        Returns 0.0 (identical) to 1.0 (completely different).
        Uses sentence-transformers if available, falls back to token overlap.
        """
        if self._embedder is not None:
            return self._compute_embedding_drift(text_a, text_b)
        return self._compute_token_drift(text_a, text_b)

    def _compute_embedding_drift(self, text_a: str, text_b: str) -> float:
        """Embedding-based semantic distance (requires sentence-transformers)."""
        try:
            embeddings = self._embedder.encode([text_a, text_b])
            import numpy as np
            cos_sim = np.dot(embeddings[0], embeddings[1]) / (
                np.linalg.norm(embeddings[0]) * np.linalg.norm(embeddings[1]) + 1e-8
            )
            return float(1.0 - cos_sim)
        except Exception:
            return self._compute_token_drift(text_a, text_b)

    @staticmethod
    def _compute_token_drift(text_a: str, text_b: str) -> float:
        """Simple token-overlap fallback when no embedder is available."""
        tokens_a = set(text_a.lower().split())
        tokens_b = set(text_b.lower().split())
        if not tokens_a and not tokens_b:
            return 0.0
        intersection = tokens_a & tokens_b
        union = tokens_a | tokens_b
        jaccard = len(intersection) / len(union) if union else 0.0
        return 1.0 - jaccard
