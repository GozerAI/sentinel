"""
Orchestration module for Sentinel.

Provides integration bridges and coordination between components:
- Discovery → Compute Cluster auto-registration
- Infrastructure → Integration auto-configuration
- Event-driven automation pipelines
"""
from sentinel.orchestration.bridges import (
    BridgeAction,
    IntegrationBridge,
    DiscoveryComputeBridge,
    InfrastructureIntegrationBridge,
)

__all__ = [
    "BridgeAction",
    "IntegrationBridge",
    "DiscoveryComputeBridge",
    "InfrastructureIntegrationBridge",
]
