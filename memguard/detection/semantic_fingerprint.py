"""
Semantic Fingerprint Checker — detects latent adversarial memory attacks.

Inspired by A-MemGuard (NTU/Oxford/Max Planck, 2025) consensus validation,
but implemented without LLM dependency using TF-IDF vectors.

Core idea: Build a "consensus vector" from all historical versions of a key.
If new content has high token overlap (looks similar) but low cosine similarity
(semantic direction changed), it's a latent attack signal.

This catches ATK-5 class attacks: semantic restructuring that preserves most
tokens but changes meaning — which bypasses simple Jaccard-based drift detection.
"""

from __future__ import annotations

import math
import re
from collections import Counter
from typing import Optional

from memguard.core.memory_entry import MemoryEntry
from memguard.detection.base import BaseDetector, DetectionResult, ThreatLevel


def _tokenize(text: str) -> list[str]:
    """Tokenizer that handles both English and CJK text.
    
    English: split on word boundaries (whitespace + punctuation).
    CJK: split into individual characters (character-level n-grams).
    This ensures Chinese text gets proper TF-IDF analysis instead of
    treating entire phrases as single tokens.
    """
    text = text.lower()
    # Match: ASCII words OR individual CJK characters
    return re.findall(r'[a-z0-9]+|[\u4e00-\u9fff\u3400-\u4dbf]', text)


def _term_freq(tokens: list[str]) -> dict[str, float]:
    """Compute term frequency vector."""
    counts = Counter(tokens)
    total = len(tokens) if tokens else 1
    return {t: c / total for t, c in counts.items()}


def _idf(doc_tfs: list[dict[str, float]]) -> dict[str, float]:
    """Compute inverse document frequency across documents."""
    n_docs = len(doc_tfs)
    if n_docs == 0:
        return {}
    df: dict[str, int] = {}
    for tf in doc_tfs:
        for term in tf:
            df[term] = df.get(term, 0) + 1
    return {term: math.log((n_docs + 1) / (count + 1)) + 1.0
            for term, count in df.items()}


def _tfidf_vector(tf: dict[str, float], idf: dict[str, float]) -> dict[str, float]:
    """Compute TF-IDF vector for a single document."""
    return {term: tf_val * idf.get(term, 0.0) for term, tf_val in tf.items()}


def _cosine_similarity(vec_a: dict[str, float], vec_b: dict[str, float]) -> float:
    """Cosine similarity between two sparse vectors."""
    all_terms = set(vec_a) | set(vec_b)
    if not all_terms:
        return 1.0
    dot = sum(vec_a.get(t, 0.0) * vec_b.get(t, 0.0) for t in all_terms)
    norm_a = math.sqrt(sum(v ** 2 for v in vec_a.values())) or 1e-8
    norm_b = math.sqrt(sum(v ** 2 for v in vec_b.values())) or 1e-8
    return dot / (norm_a * norm_b)


def _jaccard_overlap(tokens_a: set[str], tokens_b: set[str]) -> float:
    """Jaccard similarity between two token sets."""
    if not tokens_a and not tokens_b:
        return 1.0
    intersection = tokens_a & tokens_b
    union = tokens_a | tokens_b
    return len(intersection) / len(union) if union else 0.0


def _avg_vector(vectors: list[dict[str, float]]) -> dict[str, float]:
    """Average multiple sparse vectors into a consensus vector."""
    if not vectors:
        return {}
    all_terms: set[str] = set()
    for v in vectors:
        all_terms.update(v.keys())
    n = len(vectors)
    return {t: sum(v.get(t, 0.0) for v in vectors) / n for t in all_terms}


def _line_level_divergence(old_text: str, new_text: str) -> Optional[dict]:
    """Analyze line-by-line divergence between old and new content.
    
    Returns None if texts have no comparable line structure.
    Otherwise returns:
      - changed_ratio: fraction of lines that changed
      - changed_cosine: cosine similarity computed only on changed lines
    """
    old_lines = [l.strip() for l in old_text.split("\n") if l.strip()]
    new_lines = [l.strip() for l in new_text.split("\n") if l.strip()]
    
    if len(old_lines) < 2 or len(new_lines) < 2:
        return None
    
    # Find modified lines (both sides non-empty = true modification, not addition/deletion)
    max_lines = max(len(old_lines), len(new_lines))
    old_changed = []
    new_changed = []
    
    for i in range(max_lines):
        old_l = old_lines[i] if i < len(old_lines) else ""
        new_l = new_lines[i] if i < len(new_lines) else ""
        # Only count true modifications (both sides non-empty and different)
        if old_l and new_l and old_l != new_l:
            old_changed.append(old_l)
            new_changed.append(new_l)
    
    # Require at least 2 modified lines — single-line changes are likely benign edits
    if len(old_changed) < 2:
        return None
    
    changed_ratio = len(old_changed) / max_lines
    
    # Compute TF-IDF cosine only on the changed portions
    old_changed_text = " ".join(old_changed)
    new_changed_text = " ".join(new_changed)
    
    all_texts = [old_changed_text, new_changed_text]
    all_tfs = [_term_freq(_tokenize(t)) for t in all_texts]
    idf_vals = _idf(all_tfs)
    vecs = [_tfidf_vector(tf, idf_vals) for tf in all_tfs]
    
    changed_cosine = _cosine_similarity(vecs[0], vecs[1])
    
    return {
        "changed_ratio": changed_ratio,
        "changed_cosine": changed_cosine,
        "changed_lines": len(old_changed),
        "total_lines": max_lines,
    }


class SemanticFingerprintChecker(BaseDetector):
    """Detects latent semantic shifts using TF-IDF consensus vectors.

    A-MemGuard analog: §4.1 Consensus-based Validation
    - Instead of LLM reasoning paths, we use TF-IDF vectors of content
    - Instead of path divergence scoring, we use cosine similarity vs consensus
    - Key innovation: distinguish "high token overlap + low cosine" = latent attack
    """

    def __init__(
        self,
        cosine_threshold: float = 0.65,
        overlap_floor: float = 0.35,
    ):
        self._cosine_threshold = cosine_threshold
        self._overlap_floor = overlap_floor

    @property
    def name(self) -> str:
        return "semantic_fingerprint"

    def check_write(
        self,
        entry: MemoryEntry,
        history: list[MemoryEntry],
        all_active: list[MemoryEntry],
    ) -> DetectionResult:
        if len(history) < 1:
            return DetectionResult(detector_name=self.name)

        # Build corpus: all history versions + new entry
        history_texts = [str(h.content) for h in history]
        new_text = str(entry.content)
        all_texts = history_texts + [new_text]

        # Tokenize all documents
        all_token_lists = [_tokenize(t) for t in all_texts]
        all_tfs = [_term_freq(tl) for tl in all_token_lists]
        idf = _idf(all_tfs)

        # Compute TF-IDF vectors
        all_vecs = [_tfidf_vector(tf, idf) for tf in all_tfs]
        history_vecs = all_vecs[:-1]
        new_vec = all_vecs[-1]

        # Consensus vector = average of all history versions
        consensus = _avg_vector(history_vecs)

        # Cosine similarity: new vs consensus
        cosine_sim = _cosine_similarity(consensus, new_vec)

        # Token overlap (Jaccard): new vs first version
        first_tokens = set(all_token_lists[0])
        new_tokens = set(all_token_lists[-1])
        token_overlap = _jaccard_overlap(first_tokens, new_tokens)

        # Latent attack signal: looks similar (high overlap) but direction changed (low cosine)
        is_latent = (
            token_overlap > self._overlap_floor
            and cosine_sim < self._cosine_threshold
        )

        # Secondary check: line-level divergence for CJK-heavy content
        # When document-level cosine stays high (many shared lines), check
        # if individual modified lines show significant semantic change
        if not is_latent and token_overlap > self._overlap_floor:
            line_div = _line_level_divergence(history_texts[0], new_text)
            if line_div is not None and line_div["changed_ratio"] > 0.15:
                # Some lines changed — check if changed lines are semantically different
                if line_div["changed_cosine"] < self._cosine_threshold:
                    is_latent = True
                    cosine_sim = line_div["changed_cosine"]  # use line-level score

        if is_latent:
            return DetectionResult(
                detector_name=self.name,
                triggered=True,
                threat_level=ThreatLevel.HIGH,
                score=1.0 - cosine_sim,
                reason=(
                    f"Latent semantic shift: token overlap {token_overlap:.2f} "
                    f"(looks similar) but cosine similarity {cosine_sim:.2f} "
                    f"(direction changed) — possible semantic restructuring attack"
                ),
                details={
                    "cosine_similarity": round(cosine_sim, 4),
                    "token_overlap": round(token_overlap, 4),
                    "history_versions": len(history),
                    "cosine_threshold": self._cosine_threshold,
                    "overlap_floor": self._overlap_floor,
                },
            )

        return DetectionResult(
            detector_name=self.name,
            score=1.0 - cosine_sim,
            details={
                "cosine_similarity": round(cosine_sim, 4),
                "token_overlap": round(token_overlap, 4),
            },
        )

    def compute_fingerprint(self, text: str, corpus: list[str]) -> dict[str, float]:
        """Compute TF-IDF fingerprint for a text given a corpus context.
        Used by LessonMemory to store attack fingerprints.
        """
        all_texts = corpus + [text]
        all_tfs = [_term_freq(_tokenize(t)) for t in all_texts]
        idf = _idf(all_tfs)
        return _tfidf_vector(all_tfs[-1], idf)
