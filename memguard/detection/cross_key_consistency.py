"""
Cross-Key Consistency Checker — detects entity inconsistencies across related memory keys.

Inspired by A-MemGuard (NTU/Oxford/Max Planck, 2025) knowledge graph analysis (§5.8),
but implemented without LLM dependency using regex entity extraction.

Core idea: Related memory keys (e.g. vendor_info and vendor_account) should contain
consistent entities (same bank account, same email). If an attacker only modifies one
key, the cross-key check catches the inconsistency.

A-MemGuard found that benign vs malicious reasoning paths have < 1% structural overlap.
We exploit this by checking that extracted entities across related keys remain consistent.
"""

from __future__ import annotations

import re
from typing import Optional

from memguard.core.memory_entry import MemoryEntry
from memguard.detection.base import BaseDetector, DetectionResult, ThreatLevel


# Entity extraction patterns
ENTITY_PATTERNS = {
    "bank_account": re.compile(r'\b\d{3}[-\s]?\d{3}[-\s]?\d{4,6}\b'),
    "email": re.compile(r'[\w.+-]+@[\w-]+\.[\w.-]+'),
    "amount": re.compile(r'\$[\d,]+(?:\.\d{2})?'),
    "phone": re.compile(r'\+?\d[\d\s-]{7,}\d'),
    "iban": re.compile(r'\b[A-Z]{2}\d{2}[A-Z0-9]{4,30}\b'),
}


def _extract_entities(text: str) -> dict[str, set[str]]:
    """Extract all recognized entities from text."""
    entities: dict[str, set[str]] = {}
    for entity_type, pattern in ENTITY_PATTERNS.items():
        found = set(pattern.findall(text))
        if found:
            entities[entity_type] = found
    return entities


def _find_conflicts(
    entities_a: dict[str, set[str]],
    entities_b: dict[str, set[str]],
) -> list[str]:
    """Find entity conflicts between two entity sets.
    
    A conflict occurs when both sets have the same entity type
    but with different values.
    """
    conflicts = []
    for entity_type in entities_a:
        if entity_type in entities_b:
            vals_a = entities_a[entity_type]
            vals_b = entities_b[entity_type]
            if vals_a and vals_b and not vals_a.intersection(vals_b):
                conflicts.append(
                    f"{entity_type}: {vals_a} vs {vals_b}"
                )
    return conflicts


class CrossKeyConsistencyChecker(BaseDetector):
    """Detects entity inconsistencies across related memory keys.

    A-MemGuard analog: §5.8 Knowledge Graph Analysis
    - Instead of full knowledge graphs, we extract structured entities (regex)
    - Instead of graph overlap analysis, we check entity consistency across key groups
    - Key innovation: user-defined consistency_groups link related keys
    
    Usage:
        checker = CrossKeyConsistencyChecker(
            consistency_groups=[
                ["vendor_info", "vendor_account"],
                ["approval_rules", "employee_info"],
            ]
        )
    """

    def __init__(self, consistency_groups: Optional[list[list[str]]] = None):
        self._groups = consistency_groups or []

    @property
    def name(self) -> str:
        return "cross_key_consistency"

    def check_write(
        self,
        entry: MemoryEntry,
        history: list[MemoryEntry],
        all_active: list[MemoryEntry],
    ) -> DetectionResult:
        if not self._groups:
            return DetectionResult(detector_name=self.name)

        # Find which group this key belongs to
        group = self._find_group(entry.key)
        if not group:
            return DetectionResult(detector_name=self.name)

        # Extract entities from new content
        new_entities = _extract_entities(str(entry.content))
        if not new_entities:
            return DetectionResult(detector_name=self.name)

        # Check against other keys in the same group
        all_conflicts = []
        for other_key in group:
            if other_key == entry.key:
                continue
            other_entry = self._find_active_entry(other_key, all_active)
            if other_entry is None:
                continue
            other_entities = _extract_entities(str(other_entry.content))
            conflicts = _find_conflicts(new_entities, other_entities)
            if conflicts:
                all_conflicts.extend(
                    f"{entry.key} vs {other_key}: {c}" for c in conflicts
                )

        if all_conflicts:
            return DetectionResult(
                detector_name=self.name,
                triggered=True,
                threat_level=ThreatLevel.HIGH,
                score=min(len(all_conflicts) * 0.5, 1.0),
                reason=(
                    f"Cross-key entity inconsistency: "
                    + "; ".join(all_conflicts[:3])
                ),
                details={
                    "conflicts": all_conflicts,
                    "group": group,
                    "new_entities": {k: list(v) for k, v in new_entities.items()},
                },
            )

        return DetectionResult(detector_name=self.name)

    def _find_group(self, key: str) -> Optional[list[str]]:
        """Find the consistency group that contains this key."""
        for group in self._groups:
            if key in group:
                return group
        return None

    @staticmethod
    def _find_active_entry(
        key: str, all_active: list[MemoryEntry],
    ) -> Optional[MemoryEntry]:
        """Find the most recent active entry for a key."""
        matches = [e for e in all_active if e.key == key]
        if not matches:
            return None
        return max(matches, key=lambda e: e.version)
