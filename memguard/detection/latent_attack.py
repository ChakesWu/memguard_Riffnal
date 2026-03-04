"""
Latent Attack Detector — orchestrates F008 detection components.

Combines SemanticFingerprintChecker, CrossKeyConsistencyChecker, and LessonMemory
into a single BaseDetector that integrates into the existing DetectionPipeline.

Inspired by A-MemGuard (NTU/Oxford/Max Planck, 2025), but LLM-free.
"""

from __future__ import annotations

from typing import Optional

from memguard.core.memory_entry import MemoryEntry
from memguard.detection.base import BaseDetector, DetectionResult, ThreatLevel
from memguard.detection.semantic_fingerprint import SemanticFingerprintChecker
from memguard.detection.cross_key_consistency import CrossKeyConsistencyChecker
from memguard.detection.lesson_memory import LessonMemory


class LatentAttackDetector(BaseDetector):
    """Composite detector for latent adversarial memory attacks.

    Runs three sub-checks in order:
    1. LessonMemory — check against known attack patterns (fast path)
    2. SemanticFingerprintChecker — TF-IDF consensus vs new content
    3. CrossKeyConsistencyChecker — entity consistency across related keys

    If any sub-check triggers, the attack is also recorded as a lesson
    for future defense (dual-memory structure).
    """

    def __init__(
        self,
        cosine_threshold: float = 0.65,
        overlap_floor: float = 0.35,
        consistency_groups: Optional[list[list[str]]] = None,
        lesson_similarity_threshold: float = 0.80,
        lesson_persist_path: Optional[str] = None,
        enable_fingerprint: bool = True,
        enable_cross_key: bool = True,
        enable_lessons: bool = True,
    ):
        self._enable_fingerprint = enable_fingerprint
        self._enable_cross_key = enable_cross_key
        self._enable_lessons = enable_lessons

        self._fingerprint_checker = SemanticFingerprintChecker(
            cosine_threshold=cosine_threshold,
            overlap_floor=overlap_floor,
        )
        self._cross_key_checker = CrossKeyConsistencyChecker(
            consistency_groups=consistency_groups,
        )
        self._lesson_memory = LessonMemory(
            similarity_threshold=lesson_similarity_threshold,
            persist_path=lesson_persist_path,
        )

    @property
    def name(self) -> str:
        return "latent_attack"

    @property
    def lesson_memory(self) -> LessonMemory:
        return self._lesson_memory

    def check_write(
        self,
        entry: MemoryEntry,
        history: list[MemoryEntry],
        all_active: list[MemoryEntry],
    ) -> DetectionResult:
        # 1. Check against known attack patterns (LessonMemory — fast path)
        if self._enable_lessons:
            corpus = [str(h.content) for h in history]
            matched_lesson = self._lesson_memory.check_against_lessons(
                key=entry.key,
                content=str(entry.content),
                corpus=corpus,
            )
            if matched_lesson is not None:
                return DetectionResult(
                    detector_name=self.name,
                    triggered=True,
                    threat_level=ThreatLevel.HIGH,
                    score=0.9,
                    reason=(
                        f"Matches known attack pattern (lesson memory): "
                        f"type={matched_lesson.attack_type}, "
                        f"detector={matched_lesson.detector_name}, "
                        f"recorded={matched_lesson.timestamp[:19]}"
                    ),
                    details={
                        "lesson_key": matched_lesson.key,
                        "lesson_type": matched_lesson.attack_type,
                        "lesson_preview": matched_lesson.content_preview[:100],
                    },
                )

        # 2. Semantic fingerprint check
        if self._enable_fingerprint:
            fp_result = self._fingerprint_checker.check_write(entry, history, all_active)
            if fp_result.triggered:
                self._record_lesson(entry, history, "semantic_fingerprint", fp_result.detector_name)
                return DetectionResult(
                    detector_name=self.name,
                    triggered=True,
                    threat_level=fp_result.threat_level,
                    score=fp_result.score,
                    reason=fp_result.reason,
                    details=fp_result.details,
                )

        # 3. Cross-key consistency check
        if self._enable_cross_key:
            ck_result = self._cross_key_checker.check_write(entry, history, all_active)
            if ck_result.triggered:
                self._record_lesson(entry, history, "cross_key_inconsistency", ck_result.detector_name)
                return DetectionResult(
                    detector_name=self.name,
                    triggered=True,
                    threat_level=ck_result.threat_level,
                    score=ck_result.score,
                    reason=ck_result.reason,
                    details=ck_result.details,
                )

        return DetectionResult(detector_name=self.name)

    def _record_lesson(
        self,
        entry: MemoryEntry,
        history: list[MemoryEntry],
        attack_type: str,
        detector_name: str,
    ) -> None:
        """Record a detected attack as a lesson for future defense."""
        if not self._enable_lessons:
            return
        corpus = [str(h.content) for h in history]
        self._lesson_memory.record_lesson(
            key=entry.key,
            content=str(entry.content),
            attack_type=attack_type,
            detector_name=detector_name,
            corpus=corpus,
        )
