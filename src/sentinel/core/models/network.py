"""
Network topology and configuration models.

This module defines data structures for representing network infrastructure
including VLANs, topology, links, traffic flows, and QoS policies.
"""

from datetime import datetime, timezone
from enum import Enum
from typing import Optional, Any
from pydantic import BaseModel, Field
from uuid import UUID, uuid4


def _utc_now() -> datetime:
    """Get current UTC time (timezone-aware)."""
    return datetime.now(timezone.utc)


class VLANPurpose(str, Enum):
    """Predefined purposes for VLANs to guide policy application."""

    MANAGEMENT = "management"
    WORKSTATIONS = "workstations"
    SERVERS = "servers"
    STORAGE = "storage"
    IOT = "iot"
    GUEST = "guest"
    DMZ = "dmz"
    QUARANTINE = "quarantine"
    AI_COMPUTE = "ai_compute"
    CUSTOM = "custom"


class VLAN(BaseModel):
    """
    VLAN configuration and metadata.

    Attributes:
        id: 802.1Q VLAN ID (1-4094)
        name: Human-readable VLAN name
        purpose: Predefined purpose category
        subnet: Network subnet in CIDR notation
        gateway: Default gateway IP
        dns_zone: DNS zone for this VLAN
        dhcp_enabled: Whether DHCP is enabled
        dhcp_range_start: Start of DHCP range
        dhcp_range_end: End of DHCP range
        isolated: Whether this VLAN is isolated from others
        allowed_destinations: VLAN IDs this VLAN can reach
        auto_managed: Whether managed by Planner agent
        created_at: Creation timestamp
    """

    id: int = Field(ge=1, le=4094)
    name: str
    purpose: VLANPurpose = VLANPurpose.CUSTOM
    subnet: str  # CIDR notation
    gateway: str
    dns_zone: Optional[str] = None
    dhcp_enabled: bool = True
    dhcp_range_start: Optional[str] = None
    dhcp_range_end: Optional[str] = None

    # Security
    isolated: bool = False
    allowed_destinations: list[int] = Field(default_factory=list)  # Other VLAN IDs

    # Metadata
    auto_managed: bool = False
    created_at: datetime = Field(default_factory=_utc_now)

    @property
    def network_address(self) -> str:
        """Extract network address from CIDR."""
        return self.subnet.split("/")[0]

    @property
    def prefix_length(self) -> int:
        """Extract prefix length from CIDR."""
        return int(self.subnet.split("/")[1])


class LinkType(str, Enum):
    """Types of network links."""

    ETHERNET = "ethernet"
    WIFI = "wifi"
    AGGREGATE = "aggregate"
    VIRTUAL = "virtual"
    VPN = "vpn"


class LinkStatus(str, Enum):
    """Operational status of a network link."""

    UP = "up"
    DOWN = "down"
    DEGRADED = "degraded"


class NetworkLink(BaseModel):
    """
    Represents a network connection between two nodes.

    Attributes:
        id: Unique link identifier (string for flexibility with LLDP-derived IDs)
        source_node_id: Source node ID (string to support LLDP-based topology)
        source_device_id: Source device UUID (optional, for device-linked topology)
        source_port: Source port name/number
        target_node_id: Target node ID (string to support LLDP-based topology)
        target_device_id: Target device UUID (optional, for device-linked topology)
        target_port: Target port name/number
        link_type: Physical or logical link type
        status: Current operational status
        speed_mbps: Negotiated link speed
        duplex: Duplex mode (full/half)
        utilization_percent: Current utilization
        bytes_in/out: Traffic counters
        errors_in/out: Error counters
        discovered_via: How the link was discovered (lldp, cdp, manual)
        last_updated: Last metrics update
    """

    id: str = Field(default_factory=lambda: str(uuid4()))
    source_node_id: Optional[str] = None
    source_device_id: Optional[UUID] = None
    source_port: Optional[str] = None
    target_node_id: Optional[str] = None
    target_device_id: Optional[UUID] = None
    target_port: Optional[str] = None

    link_type: str = "ethernet"  # ethernet, wifi, aggregate, virtual, vpn
    status: LinkStatus = LinkStatus.UP

    speed_mbps: Optional[int] = None
    duplex: Optional[str] = None

    # Traffic metrics
    utilization_percent: float = 0.0
    bytes_in: int = 0
    bytes_out: int = 0
    errors_in: int = 0
    errors_out: int = 0

    # Discovery metadata
    discovered_via: Optional[str] = None  # lldp, cdp, manual, scan

    last_updated: datetime = Field(default_factory=_utc_now)

    @property
    def is_healthy(self) -> bool:
        """Check if link is healthy."""
        return (
            self.status == LinkStatus.UP
            and self.errors_in == 0
            and self.errors_out == 0
            and self.utilization_percent < 90
        )


class TopologyNode(BaseModel):
    """
    Node in the network topology graph.

    Attributes:
        id: Unique node identifier (string for flexibility with LLDP-derived IDs)
        name: Human-readable node name
        device_id: Reference to Device UUID (optional)
        node_type: Type of node (router, switch, endpoint)
        layer: Network layer (1=core, 2=distribution, 3=access, 4=endpoint)
        ip_address: Node IP address
        mac_address: Node MAC address (for matching to devices)
        vendor: Device vendor from OUI lookup
        position: XY coordinates for visualization
        children: Child node IDs
        parent: Parent node ID
        metadata: Additional node-specific data
    """

    id: str = Field(default_factory=lambda: str(uuid4()))
    name: str = "Unknown"
    device_id: Optional[UUID] = None
    node_type: str = "endpoint"  # router, switch, access_point, endpoint, etc.
    layer: int = 4  # Network layer (core=1, distribution=2, access=3, endpoint=4)
    ip_address: Optional[str] = None
    mac_address: Optional[str] = None
    vendor: Optional[str] = None
    position: Optional[dict] = None  # For visualization {"x": 0, "y": 0}
    children: list[str] = Field(default_factory=list)
    parent: Optional[str] = None
    metadata: Optional[dict] = None


class NetworkTopology(BaseModel):
    """
    Complete network topology representation.

    Provides a graph-based view of the network for visualization
    and path calculation.

    Attributes:
        id: Topology identifier
        name: Topology name
        nodes: Node ID to TopologyNode mapping (string keys for LLDP flexibility)
        links: Link ID to NetworkLink mapping
        vlans: Configured VLANs
        last_scan: Last topology scan timestamp
        scan_duration_seconds: Duration of last scan
    """

    id: UUID = Field(default_factory=uuid4)
    name: str = "default"

    nodes: dict[str, TopologyNode] = Field(default_factory=dict)
    links: dict[str, NetworkLink] = Field(default_factory=dict)
    vlans: list[VLAN] = Field(default_factory=list)

    last_scan: Optional[datetime] = None
    scan_duration_seconds: Optional[float] = None

    def get_node_neighbors(self, node_id: str) -> list[str]:
        """Get all nodes directly connected to a node."""
        neighbors = []
        for link in self.links.values():
            if link.source_node_id == node_id:
                if link.target_node_id:
                    neighbors.append(link.target_node_id)
            elif link.target_node_id == node_id:
                if link.source_node_id:
                    neighbors.append(link.source_node_id)
        return neighbors

    def get_device_neighbors(self, device_id: UUID) -> list[UUID]:
        """Get all devices directly connected to a device (legacy UUID support)."""
        neighbors = []
        for link in self.links.values():
            if link.source_device_id == device_id and link.target_device_id:
                neighbors.append(link.target_device_id)
            elif link.target_device_id == device_id and link.source_device_id:
                neighbors.append(link.source_device_id)
        return neighbors

    def get_path(self, source_id: str, target_id: str) -> list[str]:
        """
        Find path between two nodes using BFS.
        Returns list of node IDs representing the path.
        """
        if source_id == target_id:
            return [source_id]

        visited = {source_id}
        queue = [[source_id]]

        while queue:
            path = queue.pop(0)
            current = path[-1]

            for neighbor in self.get_node_neighbors(current):
                if neighbor == target_id:
                    return path + [neighbor]
                if neighbor not in visited:
                    visited.add(neighbor)
                    queue.append(path + [neighbor])

        return []  # No path found

    def get_vlan_by_id(self, vlan_id: int) -> Optional[VLAN]:
        """Get VLAN by its ID."""
        for vlan in self.vlans:
            if vlan.id == vlan_id:
                return vlan
        return None

    def get_vlans_by_purpose(self, purpose: VLANPurpose) -> list[VLAN]:
        """Get all VLANs with a specific purpose."""
        return [v for v in self.vlans if v.purpose == purpose]

    def get_nodes_by_type(self, node_type: str) -> list[TopologyNode]:
        """Get all nodes of a specific type."""
        return [n for n in self.nodes.values() if n.node_type == node_type]

    def get_node_by_mac(self, mac_address: str) -> Optional[TopologyNode]:
        """Find a node by MAC address."""
        mac_lower = mac_address.lower()
        for node in self.nodes.values():
            if node.mac_address and node.mac_address.lower() == mac_lower:
                return node
        return None


class TrafficFlow(BaseModel):
    """
    Represents a traffic flow for analysis and QoS.

    Attributes:
        id: Unique flow identifier
        source_ip: Source IP address
        source_port: Source port number
        destination_ip: Destination IP address
        destination_port: Destination port number
        protocol: Protocol (TCP, UDP, ICMP)
        application: Detected application name
        bytes_total: Total bytes transferred
        packets_total: Total packets transferred
        start_time: Flow start timestamp
        last_seen: Last activity timestamp
        dscp_marking: DSCP QoS marking
        priority: Assigned priority level
    """

    id: UUID = Field(default_factory=uuid4)

    source_ip: str
    source_port: int
    destination_ip: str
    destination_port: int
    protocol: str  # TCP, UDP, ICMP, etc.

    application: Optional[str] = None  # Detected application

    bytes_total: int = 0
    packets_total: int = 0

    start_time: datetime = Field(default_factory=_utc_now)
    last_seen: datetime = Field(default_factory=_utc_now)

    # QoS
    dscp_marking: Optional[int] = None
    priority: Optional[str] = None

    @property
    def duration_seconds(self) -> float:
        """Get flow duration in seconds."""
        return (self.last_seen - self.start_time).total_seconds()

    @property
    def flow_tuple(self) -> tuple:
        """Get the 5-tuple identifying this flow."""
        return (
            self.source_ip,
            self.source_port,
            self.destination_ip,
            self.destination_port,
            self.protocol,
        )


class QoSPolicy(BaseModel):
    """
    Quality of Service policy definition.

    Used by the Optimizer agent to manage traffic prioritization.

    Attributes:
        id: Policy identifier
        name: Policy name
        description: Human-readable description
        match_applications: Applications this policy matches
        match_source_vlans: Source VLANs to match
        match_destination_vlans: Destination VLANs to match
        match_dscp: DSCP values to match
        set_dscp: DSCP value to set on matching traffic
        bandwidth_limit_mbps: Maximum bandwidth
        bandwidth_guarantee_mbps: Minimum guaranteed bandwidth
        priority_queue: Priority queue assignment (0-7)
        enabled: Whether policy is active
    """

    id: UUID = Field(default_factory=uuid4)
    name: str
    description: Optional[str] = None

    # Matching criteria
    match_applications: list[str] = Field(default_factory=list)
    match_source_vlans: list[int] = Field(default_factory=list)
    match_destination_vlans: list[int] = Field(default_factory=list)
    match_dscp: list[int] = Field(default_factory=list)

    # Actions
    set_dscp: Optional[int] = None
    bandwidth_limit_mbps: Optional[int] = None
    bandwidth_guarantee_mbps: Optional[int] = None
    priority_queue: Optional[int] = Field(default=None, ge=0, le=7)

    enabled: bool = True

    def matches_flow(self, flow: TrafficFlow) -> bool:
        """Check if this policy matches a traffic flow."""
        if self.match_applications:
            if flow.application not in self.match_applications:
                return False

        if self.match_dscp:
            if flow.dscp_marking not in self.match_dscp:
                return False

        # Add VLAN matching when flow has VLAN info
        return True


class DNSRecord(BaseModel):
    """DNS record for internal DNS management."""

    id: UUID = Field(default_factory=uuid4)
    name: str  # Hostname
    zone: str  # DNS zone
    record_type: str = "A"  # A, AAAA, CNAME, PTR
    value: str  # IP address or target
    ttl: int = 300
    auto_managed: bool = False
    device_id: Optional[UUID] = None  # Link to device if auto-managed

    @property
    def fqdn(self) -> str:
        """Get fully qualified domain name."""
        return f"{self.name}.{self.zone}"


class DHCPLease(BaseModel):
    """DHCP lease information."""

    id: UUID = Field(default_factory=uuid4)
    mac_address: str
    ip_address: str
    hostname: Optional[str] = None
    vlan_id: Optional[int] = None
    lease_start: datetime = Field(default_factory=_utc_now)
    lease_end: Optional[datetime] = None
    is_static: bool = False
    device_id: Optional[UUID] = None

    @property
    def is_expired(self) -> bool:
        """Check if lease has expired."""
        if self.lease_end is None:
            return False
        return _utc_now() > self.lease_end
