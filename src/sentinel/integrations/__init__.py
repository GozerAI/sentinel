"""Sentinel integrations package."""
from sentinel.integrations.base import (
    BaseIntegration,
    RouterIntegration,
    SwitchIntegration,
    HypervisorIntegration,
    StorageIntegration,
)

__all__ = [
    "BaseIntegration",
    "RouterIntegration",
    "SwitchIntegration",
    "HypervisorIntegration",
    "StorageIntegration",
]

# Lazy imports for submodules to avoid circular dependencies
def __getattr__(name: str):
    """Lazy import submodules."""
    if name == "WANManager":
        from sentinel.integrations.wan import WANManager
        return WANManager
    elif name == "ComputeClusterManager":
        from sentinel.integrations.compute import ComputeClusterManager
        return ComputeClusterManager
    elif name == "MikroTikIntegration":
        from sentinel.integrations.routers.mikrotik import MikroTikIntegration
        return MikroTikIntegration
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
