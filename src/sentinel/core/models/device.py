"""
Device models for network asset tracking.

This module defines the core data structures for representing network devices,
their interfaces, fingerprints, and classification within the Sentinel platform.
"""
from datetime import datetime, timezone
from enum import Enum
from typing import Optional
from pydantic import BaseModel, Field
from uuid import UUID, uuid4


def _utc_now() -> datetime:
    """Get current UTC time (timezone-aware)."""
    return datetime.now(timezone.utc)


class DeviceType(str, Enum):
    """Classification of network device types."""
    WORKSTATION = "workstation"
    SERVER = "server"
    NETWORK = "network"
    STORAGE = "storage"
    IOT = "iot"
    MOBILE = "mobile"
    PRINTER = "printer"
    CAMERA = "camera"
    UNKNOWN = "unknown"


class DeviceStatus(str, Enum):
    """Current operational status of a device."""
    ONLINE = "online"
    OFFLINE = "offline"
    QUARANTINED = "quarantined"
    MAINTENANCE = "maintenance"


class TrustLevel(str, Enum):
    """Zero-trust classification for devices."""
    TRUSTED = "trusted"
    VERIFIED = "verified"
    UNKNOWN = "unknown"
    UNTRUSTED = "untrusted"
    QUARANTINED = "quarantined"


class NetworkInterface(BaseModel):
    """
    Represents a network interface on a device.
    
    Attributes:
        mac_address: Hardware MAC address
        ip_addresses: List of assigned IP addresses
        vlan_id: VLAN assignment if known
        speed_mbps: Link speed in Mbps
        is_primary: Whether this is the primary interface
    """
    mac_address: str
    ip_addresses: list[str] = Field(default_factory=list)
    vlan_id: Optional[int] = None
    speed_mbps: Optional[int] = None
    is_primary: bool = False
    
    def __hash__(self):
        return hash(self.mac_address)


class DeviceFingerprint(BaseModel):
    """
    Device identification fingerprint from network analysis.
    
    Attributes:
        vendor: Manufacturer determined from MAC OUI
        model: Specific model if detectable
        os_family: Operating system family (Linux, Windows, etc.)
        os_version: Specific OS version
        services: Detected running services
        open_ports: Open TCP/UDP ports
        confidence: Classification confidence score (0.0-1.0)
    """
    vendor: Optional[str] = None
    model: Optional[str] = None
    os_family: Optional[str] = None
    os_version: Optional[str] = None
    services: list[str] = Field(default_factory=list)
    open_ports: list[int] = Field(default_factory=list)
    confidence: float = Field(ge=0.0, le=1.0, default=0.0)


class Device(BaseModel):
    """
    Core device model representing any network-connected asset.
    
    Uses opaque identifiers to maintain information silo architecture.
    This is the primary entity tracked by the Discovery agent and
    referenced throughout the Sentinel platform.
    
    Attributes:
        id: Unique device identifier (UUID)
        hostname: DNS hostname if known
        display_name: Human-friendly name
        device_type: Classification of device type
        status: Current operational status
        trust_level: Zero-trust classification
        interfaces: Network interfaces on the device
        fingerprint: Device fingerprinting data
        assigned_vlan: VLAN assignment by Planner agent
        assigned_zone: Security zone assignment
        first_seen: First detection timestamp
        last_seen: Most recent detection timestamp
        last_activity: Most recent network activity
        tags: User-defined tags
        custom_attributes: Arbitrary key-value metadata
        managed_by_agent: Whether agents manage this device
        agent_last_action: Last action taken by an agent
    """
    id: UUID = Field(default_factory=uuid4)
    hostname: Optional[str] = None
    display_name: Optional[str] = None
    
    # Classification
    device_type: DeviceType = DeviceType.UNKNOWN
    status: DeviceStatus = DeviceStatus.ONLINE
    trust_level: TrustLevel = TrustLevel.UNKNOWN
    
    # Network
    interfaces: list[NetworkInterface] = Field(default_factory=list)
    fingerprint: DeviceFingerprint = Field(default_factory=DeviceFingerprint)
    
    # Segmentation
    assigned_vlan: Optional[int] = None
    assigned_zone: Optional[str] = None
    
    # Timestamps
    first_seen: datetime = Field(default_factory=_utc_now)
    last_seen: datetime = Field(default_factory=_utc_now)
    last_activity: Optional[datetime] = None
    
    # Metadata
    tags: list[str] = Field(default_factory=list)
    custom_attributes: dict = Field(default_factory=dict)
    
    # Agent tracking
    managed_by_agent: bool = False
    agent_last_action: Optional[str] = None
    
    @property
    def primary_ip(self) -> Optional[str]:
        """Get the primary IP address."""
        for iface in self.interfaces:
            if iface.is_primary and iface.ip_addresses:
                return iface.ip_addresses[0]
        # Fallback to first available
        for iface in self.interfaces:
            if iface.ip_addresses:
                return iface.ip_addresses[0]
        return None
    
    @property
    def primary_mac(self) -> Optional[str]:
        """Get the primary MAC address."""
        for iface in self.interfaces:
            if iface.is_primary:
                return iface.mac_address
        return self.interfaces[0].mac_address if self.interfaces else None
    
    @property
    def all_ips(self) -> list[str]:
        """Get all IP addresses across all interfaces."""
        ips = []
        for iface in self.interfaces:
            ips.extend(iface.ip_addresses)
        return ips
    
    @property
    def all_macs(self) -> list[str]:
        """Get all MAC addresses."""
        return [iface.mac_address for iface in self.interfaces]


class DeviceGroup(BaseModel):
    """
    Logical grouping of devices for policy application.
    
    Attributes:
        id: Unique group identifier
        name: Group name
        description: Human-readable description
        device_ids: List of device UUIDs in this group
        auto_membership_rules: Rules for automatic membership
        policies: Policy IDs applied to this group
    """
    id: UUID = Field(default_factory=uuid4)
    name: str
    description: Optional[str] = None
    device_ids: list[UUID] = Field(default_factory=list)
    auto_membership_rules: dict = Field(default_factory=dict)
    policies: list[str] = Field(default_factory=list)
    
    def add_device(self, device_id: UUID) -> None:
        """Add a device to the group."""
        if device_id not in self.device_ids:
            self.device_ids.append(device_id)
    
    def remove_device(self, device_id: UUID) -> bool:
        """Remove a device from the group. Returns True if removed."""
        if device_id in self.device_ids:
            self.device_ids.remove(device_id)
            return True
        return False


class DeviceInventory(BaseModel):
    """
    Collection of all known devices.
    
    Provides indexed access by various identifiers.
    """
    devices: dict[UUID, Device] = Field(default_factory=dict)
    mac_index: dict[str, UUID] = Field(default_factory=dict)
    ip_index: dict[str, UUID] = Field(default_factory=dict)
    
    def add_device(self, device: Device) -> None:
        """Add or update a device in the inventory."""
        self.devices[device.id] = device
        
        # Update MAC index
        for mac in device.all_macs:
            self.mac_index[mac.lower()] = device.id
        
        # Update IP index
        for ip in device.all_ips:
            self.ip_index[ip] = device.id
    
    def get_by_mac(self, mac: str) -> Optional[Device]:
        """Look up device by MAC address."""
        device_id = self.mac_index.get(mac.lower())
        return self.devices.get(device_id) if device_id else None
    
    def get_by_ip(self, ip: str) -> Optional[Device]:
        """Look up device by IP address."""
        device_id = self.ip_index.get(ip)
        return self.devices.get(device_id) if device_id else None
    
    def get_by_type(self, device_type: DeviceType) -> list[Device]:
        """Get all devices of a specific type."""
        return [d for d in self.devices.values() if d.device_type == device_type]
    
    def get_by_vlan(self, vlan_id: int) -> list[Device]:
        """Get all devices on a specific VLAN."""
        return [d for d in self.devices.values() if d.assigned_vlan == vlan_id]
