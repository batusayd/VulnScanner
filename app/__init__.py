"""VulnScanner application package - exposes ready-to-use scan methods and module catalog."""
from .scanner.presets import (
    ACTIVE_MODULES,
    ALL_MODULES,
    MODULES_CATALOG,
    PASSIVE_MODULES,
    PRESETS,
    api_security_scan,
    auto_scan,
    full_audit,
    production_safe_scan,
    quick_scan,
    run_preset,
    run_preset_async,
    tls_dns_scan,
)

__all__ = [
    "ALL_MODULES",
    "PASSIVE_MODULES",
    "ACTIVE_MODULES",
    "MODULES_CATALOG",
    "PRESETS",
    "auto_scan",
    "quick_scan",
    "production_safe_scan",
    "full_audit",
    "api_security_scan",
    "tls_dns_scan",
    "run_preset",
    "run_preset_async",
]
