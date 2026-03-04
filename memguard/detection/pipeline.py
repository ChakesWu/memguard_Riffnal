"""
Detection pipeline — orchestrates all detectors in sequence.
"""

from __future__ import annotations

from memguard.config import MemGuardConfig
from memguard.core.memory_entry import MemoryEntry
from memguard.detection.base import BaseDetector, DetectionResult, ThreatLevel
from memguard.detection.semantic_drift import SemanticDriftDetector
from memguard.detection.privilege_escalation import PrivilegeEscalationDetector
from memguard.detection.fragment_assembly import FragmentAssemblyDetector
from memguard.detection.contradiction import ContradictionDetector
from memguard.detection.latent_attack import LatentAttackDetector


class DetectionPipeline:
    """Runs all detectors and returns aggregated results.
    
    Order: semantic_drift → privilege_escalation → contradiction → fragment_assembly → latent_attack
    Any HIGH/CRITICAL result triggers quarantine.
    """

    def __init__(self, config: MemGuardConfig):
        self._detectors: list[BaseDetector] = []
        self._latent_detector: LatentAttackDetector | None = None
        det = config.detection

        self._detectors.append(
            SemanticDriftDetector(threshold=det.semantic_drift_threshold)
        )
        if det.privilege_escalation_enabled:
            self._detectors.append(PrivilegeEscalationDetector())
        if det.contradiction_enabled:
            self._detectors.append(
                ContradictionDetector(similarity_threshold=det.contradiction_similarity_threshold)
            )
        if det.fragment_assembly_enabled:
            self._detectors.append(
                FragmentAssemblyDetector(scan_interval=det.fragment_scan_interval_writes)
            )
        if det.latent_detection_enabled:
            self._latent_detector = LatentAttackDetector(
                cosine_threshold=det.fingerprint_cosine_threshold,
                overlap_floor=det.fingerprint_overlap_floor,
                consistency_groups=det.consistency_groups if det.cross_key_consistency_enabled else None,
                lesson_similarity_threshold=det.lesson_similarity_threshold,
                enable_fingerprint=True,
                enable_cross_key=det.cross_key_consistency_enabled,
                enable_lessons=det.lesson_memory_enabled,
            )
            self._detectors.append(self._latent_detector)

    def run(
        self,
        entry: MemoryEntry,
        history: list[MemoryEntry],
        all_active: list[MemoryEntry],
    ) -> list[DetectionResult]:
        """Run all detectors on a memory write.
        
        Returns list of all results (including non-triggered).
        """
        results = []
        for detector in self._detectors:
            result = detector.check_write(entry, history, all_active)
            results.append(result)
        return results

    def run_batch_scan(self, all_active: list[MemoryEntry]) -> list[DetectionResult]:
        """Periodic batch scan across all active memories."""
        results = []
        for detector in self._detectors:
            batch_results = detector.check_batch(all_active)
            results.extend(batch_results)
        return results

    @property
    def latent_detector(self) -> LatentAttackDetector | None:
        """Access the latent attack detector (for lesson memory inspection)."""
        return self._latent_detector

    @staticmethod
    def worst_threat(results: list[DetectionResult]) -> ThreatLevel:
        """Get the worst threat level from a list of results."""
        levels = [r.threat_level for r in results if r.triggered]
        if not levels:
            return ThreatLevel.NONE
        order = [ThreatLevel.NONE, ThreatLevel.LOW, ThreatLevel.MEDIUM,
                 ThreatLevel.HIGH, ThreatLevel.CRITICAL]
        return max(levels, key=lambda l: order.index(l))

    @staticmethod
    def should_quarantine(results: list[DetectionResult]) -> bool:
        """Check if any detector result warrants quarantine."""
        return any(r.should_quarantine for r in results)

    @staticmethod
    def triggered_reasons(results: list[DetectionResult]) -> str:
        """Aggregate all triggered detector reasons."""
        triggered = [r for r in results if r.triggered]
        if not triggered:
            return ""
        return " | ".join(f"[{r.detector_name}] {r.reason}" for r in triggered)
