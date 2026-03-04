"""
SHA-256 hash chain for memory integrity.
Each entry's hash includes the previous entry's hash,
making any tampering with historical entries detectable.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any


class HashChain:
    """Append-only hash chain for memory and audit entries.
    
    Properties:
        - Each entry includes hash of previous entry
        - Tampering with any entry breaks the chain
        - Verification is O(n) from genesis
    """
    
    GENESIS_HASH = "0" * 64  # SHA-256 of empty genesis
    
    def __init__(self):
        self._last_hash: str = self.GENESIS_HASH
    
    @property
    def last_hash(self) -> str:
        return self._last_hash
    
    def append(self, data: dict[str, Any]) -> str:
        """Compute hash for new entry and advance the chain.
        
        Args:
            data: Dictionary to hash (will be JSON-serialized)
            
        Returns:
            The new hash (which includes prev_hash)
        """
        entry = {
            "prev_hash": self._last_hash,
            "data": data,
        }
        entry_str = json.dumps(entry, sort_keys=True, default=str)
        new_hash = hashlib.sha256(entry_str.encode("utf-8")).hexdigest()
        self._last_hash = new_hash
        return new_hash
    
    def set_last_hash(self, hash_value: str) -> None:
        """Resume chain from a known last hash (e.g., loaded from DB)."""
        self._last_hash = hash_value
    
    @staticmethod
    def verify_chain(entries: list[dict[str, Any]]) -> tuple[bool, int]:
        """Verify an entire chain of entries.
        
        Each entry must have 'chain_hash' and 'prev_hash' fields.
        
        Returns:
            (is_valid, first_broken_index)
            If valid, first_broken_index = -1
        """
        expected_prev = HashChain.GENESIS_HASH
        
        for i, entry in enumerate(entries):
            if entry.get("prev_hash") != expected_prev:
                return False, i
            
            # Recompute the hash
            verify_data = {
                "prev_hash": entry["prev_hash"],
                "data": entry.get("data", {}),
            }
            verify_str = json.dumps(verify_data, sort_keys=True, default=str)
            computed = hashlib.sha256(verify_str.encode("utf-8")).hexdigest()
            
            if computed != entry.get("chain_hash"):
                return False, i
            
            expected_prev = computed
        
        return True, -1
