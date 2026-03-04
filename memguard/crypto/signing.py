"""
Ed25519 signing for memory entries and audit logs.
Ensures integrity — any tampering is cryptographically detectable.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from nacl.encoding import HexEncoder
from nacl.signing import SigningKey, VerifyKey


class Signer:
    """Ed25519 signer for MemGuard entries.
    
    Usage:
        signer = Signer.generate()
        signer.save("./keys")
        
        sig = signer.sign({"key": "value"})
        assert signer.verify({"key": "value"}, sig)
    """
    
    def __init__(self, signing_key: SigningKey):
        self._signing_key = signing_key
        self._verify_key = signing_key.verify_key
    
    @classmethod
    def generate(cls) -> Signer:
        """Generate a new Ed25519 keypair."""
        return cls(SigningKey.generate())
    
    @classmethod
    def load(cls, key_dir: str | Path) -> Signer:
        """Load signing key from disk."""
        key_path = Path(key_dir) / "memguard_signing.key"
        if not key_path.exists():
            raise FileNotFoundError(f"Signing key not found at {key_path}")
        
        key_bytes = bytes.fromhex(key_path.read_text().strip())
        return cls(SigningKey(key_bytes))
    
    @classmethod
    def load_or_generate(cls, key_dir: str | Path) -> Signer:
        """Load existing key or generate a new one."""
        try:
            return cls.load(key_dir)
        except FileNotFoundError:
            signer = cls.generate()
            signer.save(key_dir)
            return signer
    
    def save(self, key_dir: str | Path) -> None:
        """Save signing key to disk."""
        key_dir = Path(key_dir)
        key_dir.mkdir(parents=True, exist_ok=True)
        
        key_path = key_dir / "memguard_signing.key"
        key_path.write_text(self._signing_key.encode(HexEncoder).decode())
        
        pub_path = key_dir / "memguard_verify.pub"
        pub_path.write_text(self._verify_key.encode(HexEncoder).decode())
    
    def sign(self, data: dict[str, Any]) -> str:
        """Sign a dictionary, return hex-encoded signature."""
        message = json.dumps(data, sort_keys=True, default=str).encode("utf-8")
        signed = self._signing_key.sign(message, encoder=HexEncoder)
        return signed.signature.decode()
    
    def verify(self, data: dict[str, Any], signature_hex: str) -> bool:
        """Verify a signature against data."""
        message = json.dumps(data, sort_keys=True, default=str).encode("utf-8")
        try:
            self._verify_key.verify(message, bytes.fromhex(signature_hex))
            return True
        except Exception:
            return False
    
    @property
    def public_key_hex(self) -> str:
        """Get the hex-encoded public key."""
        return self._verify_key.encode(HexEncoder).decode()
