"""
MemGuard configuration management.
Supports YAML config files and programmatic configuration.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

import yaml


@dataclass
class TrustRules:
    """Default trust scores by source type."""
    user_input: float = 0.8
    tool_output: float = 0.6
    agent_internal: float = 0.7
    external_content: float = 0.3
    skill: float = 0.4
    system: float = 0.9


@dataclass
class TrustDecayConfig:
    """Trust decay over time."""
    enabled: bool = True
    rate_per_day: float = 0.02
    minimum: float = 0.1


@dataclass
class RateLimitConfig:
    """Rate limits for memory writes."""
    max_writes_per_minute: int = 20
    max_writes_per_session: int = 200


@dataclass
class DetectionConfig:
    """Detection pipeline configuration."""
    semantic_drift_threshold: float = 0.6
    privilege_escalation_enabled: bool = True
    fragment_assembly_enabled: bool = True
    fragment_scan_interval_writes: int = 10
    contradiction_enabled: bool = True
    contradiction_similarity_threshold: float = 0.75
    embedding_model: str = "all-MiniLM-L6-v2"
    # F008: Latent adversarial memory detection
    latent_detection_enabled: bool = True
    fingerprint_cosine_threshold: float = 0.70
    fingerprint_overlap_floor: float = 0.35
    cross_key_consistency_enabled: bool = True
    consistency_groups: list[list[str]] = field(default_factory=list)
    lesson_memory_enabled: bool = True
    lesson_similarity_threshold: float = 0.80


@dataclass
class MemGuardConfig:
    """Main configuration for MemGuard."""
    
    # Tenant
    tenant_id: str = "default"
    
    # Storage
    db_path: str = "./memguard_data/memories.db"
    audit_path: str = "./memguard_data/audit.log"
    
    # Crypto
    signing_enabled: bool = True
    key_path: str = "./memguard_data/keys"
    
    # Trust
    trust_rules: TrustRules = field(default_factory=TrustRules)
    trust_decay: TrustDecayConfig = field(default_factory=TrustDecayConfig)
    
    # Rate limits
    rate_limits: RateLimitConfig = field(default_factory=RateLimitConfig)
    
    # Detection
    detection: DetectionConfig = field(default_factory=DetectionConfig)
    
    # Sensitive field patterns (block or quarantine)
    sensitive_patterns: list[str] = field(default_factory=lambda: [
        "api_key", "password", "secret", "token", "private_key",
        "ssh_key", "credential", "auth_token", "access_key",
    ])
    sensitive_action: str = "quarantine"  # "block" or "quarantine"
    
    # Agent identity
    agent_identity_required: bool = False  # If True, all writes must have valid agent signature
    
    # Supply chain attestation
    attestation_trust_penalty: float = 0.15  # Trust penalty for unattested tool/RAG output
    attestation_trust_bonus: float = 0.1     # Trust bonus for valid attestation
    
    # Source restrictions
    external_content_max_trust: float = 0.5
    external_content_require_review: bool = True
    
    @classmethod
    def from_yaml(cls, path: str | Path) -> MemGuardConfig:
        """Load configuration from a YAML file."""
        path = Path(path)
        if not path.exists():
            return cls()
        
        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
        
        return cls._from_dict(data)
    
    @classmethod
    def _from_dict(cls, data: dict[str, Any]) -> MemGuardConfig:
        """Build config from a dictionary."""
        config = cls()
        
        for key, value in data.items():
            if key == "trust_rules" and isinstance(value, dict):
                config.trust_rules = TrustRules(**value)
            elif key == "trust_decay" and isinstance(value, dict):
                config.trust_decay = TrustDecayConfig(**value)
            elif key == "rate_limits" and isinstance(value, dict):
                config.rate_limits = RateLimitConfig(**value)
            elif key == "detection" and isinstance(value, dict):
                config.detection = DetectionConfig(**value)
            elif hasattr(config, key):
                setattr(config, key, value)
        
        return config
    
    @classmethod
    def preset(cls, name: str) -> MemGuardConfig:
        """Load a preset configuration.
        
        Presets:
            - "strict": Maximum security, all detectors on, low thresholds
            - "balanced": Good defaults for most use cases
            - "permissive": Minimal friction, mainly logging
        """
        if name == "strict":
            return cls(
                sensitive_action="block",
                external_content_max_trust=0.3,
                external_content_require_review=True,
                detection=DetectionConfig(
                    semantic_drift_threshold=0.4,
                    fragment_scan_interval_writes=5,
                    contradiction_similarity_threshold=0.6,
                ),
            )
        elif name == "permissive":
            return cls(
                sensitive_action="quarantine",
                external_content_max_trust=0.7,
                external_content_require_review=False,
                detection=DetectionConfig(
                    semantic_drift_threshold=0.8,
                    fragment_scan_interval_writes=50,
                    contradiction_similarity_threshold=0.9,
                ),
            )
        else:  # balanced
            return cls()
    
    def ensure_directories(self) -> None:
        """Create necessary directories."""
        for path_str in [self.db_path, self.audit_path, self.key_path]:
            path = Path(path_str)
            path.parent.mkdir(parents=True, exist_ok=True)
