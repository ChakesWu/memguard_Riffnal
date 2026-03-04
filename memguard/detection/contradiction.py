"""
Contradiction Detector — detects new memories that contradict trusted existing ones.

Example:
  Trusted memory: "CFO is Alice"
  New memory:     "CFO is Bob"  ← contradiction, possible tampering
"""

from __future__ import annotations

from memguard.core.memory_entry import MemoryEntry
from memguard.detection.base import BaseDetector, DetectionResult, ThreatLevel


class ContradictionDetector(BaseDetector):
    """Detects contradictions between new and existing memories."""

    def __init__(self, similarity_threshold: float = 0.75):
        self._threshold = similarity_threshold

    @property
    def name(self) -> str:
        return "contradiction"

    def check_write(
        self,
        entry: MemoryEntry,
        history: list[MemoryEntry],
        all_active: list[MemoryEntry],
    ) -> DetectionResult:
        new_text = str(entry.content).lower()

        # Find semantically related active memories (same key = direct update,
        # similar content across keys = potential contradiction)
        for existing in all_active:
            if existing.key == entry.key:
                continue  # same key updates handled by drift detector

            sim = self._text_similarity(new_text, str(existing.content).lower())
            if sim < self._threshold:
                continue

            # High similarity but different content = potential contradiction
            if self._is_contradiction(entry, existing):
                trust_diff = existing.effective_trust() - entry.trust_score
                if trust_diff > 0:
                    # Existing memory is more trusted → quarantine new one
                    return DetectionResult(
                        detector_name=self.name,
                        triggered=True,
                        threat_level=ThreatLevel.HIGH,
                        score=sim,
                        reason=(
                            f"Contradicts trusted memory '{existing.key}' "
                            f"(trust {existing.effective_trust():.2f} vs {entry.trust_score:.2f})"
                        ),
                        details={
                            "conflicting_key": existing.key,
                            "conflicting_content": str(existing.content)[:200],
                            "new_content": str(entry.content)[:200],
                            "trust_gap": trust_diff,
                        },
                    )

        return DetectionResult(detector_name=self.name)

    def _is_contradiction(self, new: MemoryEntry, existing: MemoryEntry) -> bool:
        """Heuristic: same topic but different factual claims."""
        new_text = str(new.content).lower()
        existing_text = str(existing.content).lower()

        # Simple heuristic: high token overlap but some key tokens differ
        new_tokens = set(new_text.split())
        existing_tokens = set(existing_text.split())
        overlap = new_tokens & existing_tokens
        diff = (new_tokens | existing_tokens) - overlap

        if not overlap:
            return False

        overlap_ratio = len(overlap) / max(len(new_tokens | existing_tokens), 1)
        # If high overlap (same topic) but meaningful differences → contradiction
        return overlap_ratio > 0.3 and len(diff) > 0

    @staticmethod
    def _text_similarity(a: str, b: str) -> float:
        """Simple Jaccard similarity as fallback."""
        tokens_a = set(a.split())
        tokens_b = set(b.split())
        if not tokens_a or not tokens_b:
            return 0.0
        return len(tokens_a & tokens_b) / len(tokens_a | tokens_b)
