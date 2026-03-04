"""
Lesson Memory — dual-memory structure for learning from detected attacks.

Inspired by A-MemGuard (NTU/Oxford/Max Planck, 2025) §4.2 dual-memory structure.

Core idea: When an attack is detected, store its "fingerprint" (TF-IDF vector).
Future writes are checked against stored lessons. If a new write matches a known
attack pattern, it is immediately flagged — breaking the self-reinforcing error cycle.

A-MemGuard's ablation study (§5.6) showed removing LessonMemory caused ACC to drop
from 63.83 to 38.29 — it's critical for maintaining accuracy over time.
"""

from __future__ import annotations

import json
import math
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

from memguard.detection.semantic_fingerprint import (
    _tokenize, _term_freq, _idf, _tfidf_vector, _cosine_similarity,
)


@dataclass
class Lesson:
    """A recorded attack pattern."""
    key: str
    attack_type: str
    fingerprint: dict[str, float]
    content_preview: str
    detector_name: str
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> dict:
        return {
            "key": self.key,
            "attack_type": self.attack_type,
            "fingerprint": self.fingerprint,
            "content_preview": self.content_preview,
            "detector_name": self.detector_name,
            "timestamp": self.timestamp,
        }

    @classmethod
    def from_dict(cls, data: dict) -> Lesson:
        return cls(**data)


class LessonMemory:
    """Stores and retrieves attack pattern fingerprints.

    A-MemGuard analog: §4.2 Dual-Memory Structure
    - Main memory = MemGuard's MemoryStore (normal entries)
    - Lesson memory = this class (attack fingerprints)
    - On detection: extract fingerprint → store as lesson
    - On future write: check against lessons → early interception

    The lesson memory breaks the self-reinforcing error cycle:
    - Round 1: Attack detected by SemanticFingerprintChecker → lesson stored
    - Round 2: Similar attack → matched by LessonMemory → blocked immediately
    """

    def __init__(self, similarity_threshold: float = 0.80, persist_path: Optional[str] = None):
        self._lessons: list[Lesson] = []
        self._similarity_threshold = similarity_threshold
        self._persist_path = persist_path
        if persist_path and os.path.exists(persist_path):
            self._load()

    def record_lesson(
        self,
        key: str,
        content: str,
        attack_type: str,
        detector_name: str,
        corpus: Optional[list[str]] = None,
    ) -> Lesson:
        """Record a new attack lesson with its TF-IDF fingerprint."""
        corpus = corpus or []
        fingerprint = self._compute_fingerprint(content, corpus)
        lesson = Lesson(
            key=key,
            attack_type=attack_type,
            fingerprint=fingerprint,
            content_preview=content[:200],
            detector_name=detector_name,
        )
        self._lessons.append(lesson)
        if self._persist_path:
            self._save()
        return lesson

    def check_against_lessons(
        self,
        key: str,
        content: str,
        corpus: Optional[list[str]] = None,
    ) -> Optional[Lesson]:
        """Check if new content matches any known attack pattern.

        Returns the matching lesson if similarity exceeds threshold, else None.
        """
        if not self._lessons:
            return None

        corpus = corpus or []
        new_fp = self._compute_fingerprint(content, corpus)

        best_match: Optional[Lesson] = None
        best_sim = 0.0

        for lesson in self._lessons:
            sim = _cosine_similarity(new_fp, lesson.fingerprint)
            if sim > best_sim:
                best_sim = sim
                best_match = lesson

        if best_sim >= self._similarity_threshold and best_match is not None:
            return best_match
        return None

    @property
    def lessons(self) -> list[Lesson]:
        return list(self._lessons)

    @property
    def count(self) -> int:
        return len(self._lessons)

    def clear(self) -> None:
        """Clear all lessons."""
        self._lessons.clear()
        if self._persist_path:
            self._save()

    @staticmethod
    def _compute_fingerprint(text: str, corpus: list[str]) -> dict[str, float]:
        """Compute TF-IDF fingerprint for text given corpus context."""
        all_texts = corpus + [text]
        all_tfs = [_term_freq(_tokenize(t)) for t in all_texts]
        idf_vals = _idf(all_tfs)
        return _tfidf_vector(all_tfs[-1], idf_vals)

    def _save(self) -> None:
        """Persist lessons to disk."""
        if not self._persist_path:
            return
        os.makedirs(os.path.dirname(self._persist_path) or ".", exist_ok=True)
        with open(self._persist_path, "w", encoding="utf-8") as f:
            json.dump([l.to_dict() for l in self._lessons], f, ensure_ascii=False, indent=2)

    def _load(self) -> None:
        """Load lessons from disk."""
        if not self._persist_path or not os.path.exists(self._persist_path):
            return
        try:
            with open(self._persist_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            self._lessons = [Lesson.from_dict(d) for d in data]
        except (json.JSONDecodeError, KeyError):
            self._lessons = []
