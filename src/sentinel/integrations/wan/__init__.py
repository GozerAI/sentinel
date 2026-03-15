"""
WAN/ISP integrations for Sentinel.

Provides management of internet connectivity and ISP relationships:
- Multi-WAN failover and load balancing
- Bandwidth monitoring and enforcement
- ISP SLA tracking
- Speed testing and quality metrics
"""
from sentinel.integrations.wan.manager import WANManager
from sentinel.integrations.wan.connection import (
    WANConnection,
    ConnectionType,
    ConnectionStatus,
    BandwidthMetrics,
    ConnectionQuality,
)

__all__ = [
    "WANManager",
    "WANConnection",
    "ConnectionType",
    "ConnectionStatus",
    "BandwidthMetrics",
    "ConnectionQuality",
]
