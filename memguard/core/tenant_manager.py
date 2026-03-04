"""
TenantManager — manages multiple isolated MemGuard instances per tenant.

Each tenant gets:
- Its own namespace in the shared SQLite DB (tenant_id column)
- Its own audit log entries (tenant_id field)
- Its own policy config (optional per-tenant overrides)
- Complete isolation: tenantA cannot read/write/query tenantB's data

Usage:
    from memguard.core.tenant_manager import TenantManager

    tm = TenantManager()
    guard_a = tm.get_guard("acme_corp")
    guard_b = tm.get_guard("globex_inc")

    # These are fully isolated — different tenant_id scopes
    guard_a.write("vendor_info", "Acme vendor data", agent_id="agent1")
    guard_b.write("vendor_info", "Globex vendor data", agent_id="agent1")

    # Each only sees its own data
    assert guard_a.read("vendor_info") == "Acme vendor data"
    assert guard_b.read("vendor_info") == "Globex vendor data"
"""

from __future__ import annotations

from copy import deepcopy
from typing import Optional

from memguard.config import MemGuardConfig
from memguard.core.memory_proxy import MemGuard


class TenantManager:
    """Manages isolated MemGuard instances for multiple tenants.

    All tenants share the same SQLite DB file and audit log file,
    but data is hard-isolated by the tenant_id column/field.
    Per-tenant policy overrides can be registered before first access.
    """

    def __init__(self, base_config: Optional[MemGuardConfig] = None):
        """
        Args:
            base_config: Base configuration used as template for all tenants.
                         Each tenant gets a copy with its tenant_id set.
        """
        self._base_config = base_config or MemGuardConfig()
        self._guards: dict[str, MemGuard] = {}
        self._tenant_configs: dict[str, MemGuardConfig] = {}

    def register_tenant(
        self,
        tenant_id: str,
        config_overrides: Optional[dict] = None,
    ) -> None:
        """Pre-register a tenant with optional config overrides.

        Overrides are applied on top of the base config.
        Must be called before get_guard() for that tenant if you want
        custom settings (e.g., stricter detection thresholds).

        Args:
            tenant_id: Unique tenant identifier.
            config_overrides: Dict of config fields to override.
                Example: {"sensitive_action": "block",
                          "external_content_max_trust": 0.2}
        """
        if tenant_id in self._guards:
            raise ValueError(
                f"Tenant '{tenant_id}' already has an active MemGuard instance. "
                "Cannot change config after initialization."
            )
        cfg = deepcopy(self._base_config)
        cfg.tenant_id = tenant_id
        if config_overrides:
            for k, v in config_overrides.items():
                if hasattr(cfg, k):
                    setattr(cfg, k, v)
        self._tenant_configs[tenant_id] = cfg

    def get_guard(self, tenant_id: str) -> MemGuard:
        """Get or create an isolated MemGuard instance for a tenant.

        If the tenant was pre-registered with register_tenant(), uses
        that config. Otherwise, creates one from the base config.

        Args:
            tenant_id: Unique tenant identifier.

        Returns:
            A MemGuard instance scoped to this tenant.
        """
        if tenant_id not in self._guards:
            if tenant_id in self._tenant_configs:
                cfg = self._tenant_configs[tenant_id]
            else:
                cfg = deepcopy(self._base_config)
                cfg.tenant_id = tenant_id
                self._tenant_configs[tenant_id] = cfg
            self._guards[tenant_id] = MemGuard(config=cfg)
        return self._guards[tenant_id]

    def list_tenants(self) -> list[str]:
        """List all registered/active tenant IDs."""
        return list(self._tenant_configs.keys())

    def has_tenant(self, tenant_id: str) -> bool:
        return tenant_id in self._guards

    def close(self, tenant_id: Optional[str] = None) -> None:
        """Close MemGuard instance(s).

        Args:
            tenant_id: If provided, close only that tenant.
                       If None, close all tenants.
        """
        if tenant_id:
            if tenant_id in self._guards:
                self._guards[tenant_id].close()
                del self._guards[tenant_id]
        else:
            for g in self._guards.values():
                g.close()
            self._guards.clear()
