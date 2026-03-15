"""Router integrations for Sentinel."""
from sentinel.integrations.routers.opnsense import OPNsenseIntegration
from sentinel.integrations.routers.mikrotik import MikroTikIntegration

__all__ = ["OPNsenseIntegration", "MikroTikIntegration"]
