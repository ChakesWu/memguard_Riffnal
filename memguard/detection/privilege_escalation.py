"""
Privilege Escalation Detector — detects memory updates that grant higher privileges.

Example: "Bob can view reports" → "Bob can approve payments"
Example: "Send to team@corp.com" → "Send to attacker@evil.com"
"""

from __future__ import annotations

import re

from memguard.core.memory_entry import MemoryEntry
from memguard.detection.base import BaseDetector, DetectionResult, ThreatLevel

# High-risk semantic keywords indicating privilege or sensitive operations
PRIV_KEYWORDS = {
    "admin", "root", "sudo", "approve", "authorize", "payment", "transfer",
    "delete", "execute", "bypass", "override", "unlimited", "full_access",
    "superuser", "master", "owner", "all_permissions",
}

FINANCIAL_KEYWORDS = {
    "payment", "invoice", "transfer", "wire", "bank", "account_number",
    "routing", "swift", "iban", "credit_card", "billing",
}

EMAIL_PATTERN = re.compile(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+")
URL_PATTERN = re.compile(r"https?://[^\s]+")
# Bank account patterns: dash-separated (012-345-678901), IBAN-like, or 6+ digit sequences
BANK_ACCOUNT_PATTERN = re.compile(r"\b\d{3}[-\s]?\d{3}[-\s]?\d{6}\b|\b[A-Z]{2}\d{2}[A-Z0-9]{4,30}\b")
# Numeric value with optional unit (e.g., 5mg, $10,000, 500ml, 20%)
# Captures: (number_str, unit_str) — unit may be empty
NUMERIC_VALUE_PATTERN = re.compile(
    r'(?:[$￥¥])?(\d[\d,]*)(?:\.\d+)?\s*'
    r'(mg|ml|g|kg|lb|oz|mm|cm|m|km|%|万|億|萬|元|円|日|次|片|粒|瓶|支|包)?'
    r'(?:/[^\s,;]*)?',
    re.IGNORECASE,
)


def _extract_numeric_values(text: str) -> dict[str, float]:
    """Extract numeric values with their units/context from text.
    
    Returns dict mapping "value+unit" context key to numeric value.
    E.g., "Amlodipine 5mg/日" → {"5mg": 5.0}
    """
    results = {}
    for match in NUMERIC_VALUE_PATTERN.finditer(text):
        num_str = match.group(1).replace(",", "")
        unit = (match.group(2) or "").lower()
        try:
            value = float(num_str)
            if value == 0:
                continue
            # Use position context: surrounding text helps match old vs new
            start = max(0, match.start() - 20)
            end = min(len(text), match.end() + 20)
            context = text[start:end].strip()
            key = f"{num_str}{unit}@{context}"
            results[key] = value
        except ValueError:
            continue
    return results


def _detect_numeric_changes(
    old_nums: dict[str, float],
    new_nums: dict[str, float],
    ratio_threshold: float = 2.0,
) -> list[str]:
    """Detect significant numeric value changes between old and new content.
    
    Matches values by unit context and flags changes where the ratio exceeds
    threshold (default 2x, i.e., doubling or halving).
    """
    changes = []
    # Build unit-indexed lookup: extract unit from key
    old_by_unit: dict[str, list[tuple[str, float]]] = {}
    for key, val in old_nums.items():
        unit = key.split("@")[0]
        # strip digits to get unit suffix
        unit_suffix = "".join(c for c in unit if not c.isdigit() and c != ".")
        old_by_unit.setdefault(unit_suffix, []).append((key, val))

    new_by_unit: dict[str, list[tuple[str, float]]] = {}
    for key, val in new_nums.items():
        unit = key.split("@")[0]
        unit_suffix = "".join(c for c in unit if not c.isdigit() and c != ".")
        new_by_unit.setdefault(unit_suffix, []).append((key, val))

    # Compare values within same unit category (only when unit is non-empty)
    # Skip unitless numbers — they are too ambiguous (could be years, IDs, versions)
    for unit_suffix, old_items in old_by_unit.items():
        if not unit_suffix:
            continue  # skip bare numbers without units
        new_items = new_by_unit.get(unit_suffix, [])
        if not new_items:
            continue
        for old_key, old_val in old_items:
            for new_key, new_val in new_items:
                if old_val == new_val:
                    continue
                ratio = max(new_val / old_val, old_val / new_val) if min(old_val, new_val) > 0 else 999
                if ratio >= ratio_threshold:
                    old_display = old_key.split("@")[0]
                    new_display = new_key.split("@")[0]
                    changes.append(f"{old_display} → {new_display} ({ratio:.1f}x)")
    return changes


class PrivilegeEscalationDetector(BaseDetector):
    """Detects privilege escalation patterns in memory updates."""

    @property
    def name(self) -> str:
        return "privilege_escalation"

    def check_write(
        self,
        entry: MemoryEntry,
        history: list[MemoryEntry],
        all_active: list[MemoryEntry],
    ) -> DetectionResult:
        if not history:
            return DetectionResult(detector_name=self.name)

        prev = history[-1]
        old_text = str(prev.content).lower()
        new_text = str(entry.content).lower()

        score = 0.0
        reasons = []

        # Check privilege keyword escalation
        old_priv = PRIV_KEYWORDS & set(old_text.split())
        new_priv = PRIV_KEYWORDS & set(new_text.split())
        added_priv = new_priv - old_priv
        if added_priv:
            score += 0.4 * len(added_priv)
            reasons.append(f"New privilege keywords: {added_priv}")

        # Check financial keyword introduction
        old_fin = FINANCIAL_KEYWORDS & set(old_text.split())
        new_fin = FINANCIAL_KEYWORDS & set(new_text.split())
        added_fin = new_fin - old_fin
        if added_fin:
            score += 0.3 * len(added_fin)
            reasons.append(f"New financial keywords: {added_fin}")

        # Check contact replacement (email/URL swap)
        old_emails = set(EMAIL_PATTERN.findall(str(prev.content)))
        new_emails = set(EMAIL_PATTERN.findall(str(entry.content)))
        if old_emails and new_emails and old_emails != new_emails:
            score += 0.6
            reasons.append(f"Email changed: {old_emails} → {new_emails}")

        old_urls = set(URL_PATTERN.findall(str(prev.content)))
        new_urls = set(URL_PATTERN.findall(str(entry.content)))
        if old_urls and new_urls and old_urls != new_urls:
            score += 0.5
            reasons.append(f"URL changed: {old_urls} → {new_urls}")

        # Check bank account number changes
        old_accounts = set(BANK_ACCOUNT_PATTERN.findall(str(prev.content)))
        new_accounts = set(BANK_ACCOUNT_PATTERN.findall(str(entry.content)))
        if old_accounts and new_accounts and old_accounts != new_accounts:
            score += 0.7
            reasons.append(f"Bank account changed: {old_accounts} → {new_accounts}")

        # Check numeric value changes (dosage, limits, amounts)
        old_nums = _extract_numeric_values(str(prev.content))
        new_nums = _extract_numeric_values(str(entry.content))
        num_changes = _detect_numeric_changes(old_nums, new_nums)
        if num_changes:
            score += 0.6
            for ch in num_changes[:3]:  # report up to 3
                reasons.append(f"Numeric value changed: {ch}")

        score = min(score, 1.0)

        if score > 0.5:
            level = ThreatLevel.CRITICAL if score > 0.8 else ThreatLevel.HIGH
            return DetectionResult(
                detector_name=self.name,
                triggered=True,
                threat_level=level,
                score=score,
                reason="; ".join(reasons),
                details={"old_content": old_text[:200], "new_content": new_text[:200]},
            )

        return DetectionResult(detector_name=self.name, score=score)
