"""
Sentinel Core Models Package.

This package contains all the data models used throughout the Sentinel platform.
"""

from sentinel.core.models.device import (
    Device,
    DeviceType,
    DeviceStatus,
    TrustLevel,
    NetworkInterface,
    DeviceFingerprint,
    DeviceGroup,
    DeviceInventory,
)
from sentinel.core.models.network import (
    VLAN,
    VLANPurpose,
    NetworkLink,
    LinkType,
    LinkStatus,
    TopologyNode,
    NetworkTopology,
    TrafficFlow,
    QoSPolicy,
    DNSRecord,
    DHCPLease,
)
from sentinel.core.models.policy import (
    PolicyAction,
    PolicyScope,
    PolicyPriority,
    FirewallRule,
    SegmentationPolicy,
    DevicePolicy,
    AutomationRule,
    SecurityZone,
    PolicySet,
)
from sentinel.core.models.event import (
    Event,
    EventSeverity,
    EventCategory,
    SecurityAlert,
    AgentAction,
    AgentDecision,
    MetricEvent,
    AuditLogEntry,
)

__all__ = [
    # Device models
    "Device",
    "DeviceType",
    "DeviceStatus",
    "TrustLevel",
    "NetworkInterface",
    "DeviceFingerprint",
    "DeviceGroup",
    "DeviceInventory",
    # Network models
    "VLAN",
    "VLANPurpose",
    "NetworkLink",
    "LinkType",
    "LinkStatus",
    "TopologyNode",
    "NetworkTopology",
    "TrafficFlow",
    "QoSPolicy",
    "DNSRecord",
    "DHCPLease",
    # Policy models
    "PolicyAction",
    "PolicyScope",
    "PolicyPriority",
    "FirewallRule",
    "SegmentationPolicy",
    "DevicePolicy",
    "AutomationRule",
    "SecurityZone",
    "PolicySet",
    # Event models
    "Event",
    "EventSeverity",
    "EventCategory",
    "SecurityAlert",
    "AgentAction",
    "AgentDecision",
    "MetricEvent",
    "AuditLogEntry",
]
