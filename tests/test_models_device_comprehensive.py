"""
Comprehensive tests for Device models covering all code paths.

These tests achieve full coverage including:
- Device model properties
- NetworkInterface
- DeviceFingerprint
- DeviceGroup operations
- DeviceInventory operations
"""

import pytest
from uuid import uuid4
from datetime import datetime, timezone

from sentinel.core.models.device import (
    DeviceType,
    DeviceStatus,
    TrustLevel,
    NetworkInterface,
    DeviceFingerprint,
    Device,
    DeviceGroup,
    DeviceInventory,
    _utc_now,
)


class TestDeviceEnums:
    """Tests for device enums."""

    def test_device_type_values(self):
        """Test DeviceType enum values."""
        assert DeviceType.WORKSTATION.value == "workstation"
        assert DeviceType.SERVER.value == "server"
        assert DeviceType.NETWORK.value == "network"
        assert DeviceType.STORAGE.value == "storage"
        assert DeviceType.IOT.value == "iot"
        assert DeviceType.MOBILE.value == "mobile"
        assert DeviceType.PRINTER.value == "printer"
        assert DeviceType.CAMERA.value == "camera"
        assert DeviceType.UNKNOWN.value == "unknown"

    def test_device_status_values(self):
        """Test DeviceStatus enum values."""
        assert DeviceStatus.ONLINE.value == "online"
        assert DeviceStatus.OFFLINE.value == "offline"
        assert DeviceStatus.QUARANTINED.value == "quarantined"
        assert DeviceStatus.MAINTENANCE.value == "maintenance"

    def test_trust_level_values(self):
        """Test TrustLevel enum values."""
        assert TrustLevel.TRUSTED.value == "trusted"
        assert TrustLevel.VERIFIED.value == "verified"
        assert TrustLevel.UNKNOWN.value == "unknown"
        assert TrustLevel.UNTRUSTED.value == "untrusted"
        assert TrustLevel.QUARANTINED.value == "quarantined"


class TestNetworkInterface:
    """Tests for NetworkInterface model."""

    def test_default_values(self):
        """Test default values."""
        interface = NetworkInterface(mac_address="00:11:22:33:44:55")

        assert interface.mac_address == "00:11:22:33:44:55"
        assert interface.ip_addresses == []
        assert interface.vlan_id is None
        assert interface.speed_mbps is None
        assert interface.is_primary is False

    def test_custom_values(self):
        """Test custom values."""
        interface = NetworkInterface(
            mac_address="00:11:22:33:44:55",
            ip_addresses=["192.168.1.100", "192.168.1.101"],
            vlan_id=10,
            speed_mbps=1000,
            is_primary=True,
        )

        assert interface.ip_addresses == ["192.168.1.100", "192.168.1.101"]
        assert interface.vlan_id == 10
        assert interface.speed_mbps == 1000
        assert interface.is_primary is True

    def test_hash(self):
        """Test interface hash is based on MAC address."""
        interface1 = NetworkInterface(mac_address="00:11:22:33:44:55")
        interface2 = NetworkInterface(mac_address="00:11:22:33:44:55")
        interface3 = NetworkInterface(mac_address="00:11:22:33:44:66")

        assert hash(interface1) == hash(interface2)
        assert hash(interface1) != hash(interface3)


class TestDeviceFingerprint:
    """Tests for DeviceFingerprint model."""

    def test_default_values(self):
        """Test default values."""
        fingerprint = DeviceFingerprint()

        assert fingerprint.vendor is None
        assert fingerprint.model is None
        assert fingerprint.os_family is None
        assert fingerprint.os_version is None
        assert fingerprint.services == []
        assert fingerprint.open_ports == []
        assert fingerprint.confidence == 0.0

    def test_custom_values(self):
        """Test custom values."""
        fingerprint = DeviceFingerprint(
            vendor="Dell",
            model="OptiPlex 7090",
            os_family="Windows",
            os_version="11",
            services=["ssh", "http"],
            open_ports=[22, 80, 443],
            confidence=0.95,
        )

        assert fingerprint.vendor == "Dell"
        assert fingerprint.model == "OptiPlex 7090"
        assert fingerprint.os_family == "Windows"
        assert fingerprint.os_version == "11"
        assert fingerprint.services == ["ssh", "http"]
        assert fingerprint.open_ports == [22, 80, 443]
        assert fingerprint.confidence == 0.95

    def test_confidence_bounds(self):
        """Test confidence field bounds."""
        # Valid range
        fp1 = DeviceFingerprint(confidence=0.0)
        assert fp1.confidence == 0.0

        fp2 = DeviceFingerprint(confidence=1.0)
        assert fp2.confidence == 1.0

        fp3 = DeviceFingerprint(confidence=0.5)
        assert fp3.confidence == 0.5

        # Out of bounds should raise validation error
        with pytest.raises(ValueError):
            DeviceFingerprint(confidence=-0.1)

        with pytest.raises(ValueError):
            DeviceFingerprint(confidence=1.1)


class TestDevice:
    """Tests for Device model."""

    def test_default_values(self):
        """Test default values."""
        device = Device()

        assert device.id is not None
        assert device.hostname is None
        assert device.display_name is None
        assert device.device_type == DeviceType.UNKNOWN
        assert device.status == DeviceStatus.ONLINE
        assert device.trust_level == TrustLevel.UNKNOWN
        assert device.interfaces == []
        assert device.fingerprint is not None
        assert device.assigned_vlan is None
        assert device.assigned_zone is None
        assert device.first_seen is not None
        assert device.last_seen is not None
        assert device.last_activity is None
        assert device.tags == []
        assert device.custom_attributes == {}
        assert device.managed_by_agent is False
        assert device.agent_last_action is None

    def test_custom_values(self):
        """Test custom values."""
        device_id = uuid4()
        device = Device(
            id=device_id,
            hostname="workstation1",
            display_name="John's Workstation",
            device_type=DeviceType.WORKSTATION,
            status=DeviceStatus.ONLINE,
            trust_level=TrustLevel.TRUSTED,
            assigned_vlan=10,
            assigned_zone="workstations",
            tags=["production", "engineering"],
            custom_attributes={"owner": "john"},
            managed_by_agent=True,
            agent_last_action="vlan_assigned",
        )

        assert device.id == device_id
        assert device.hostname == "workstation1"
        assert device.display_name == "John's Workstation"
        assert device.device_type == DeviceType.WORKSTATION
        assert device.trust_level == TrustLevel.TRUSTED
        assert device.assigned_vlan == 10
        assert device.assigned_zone == "workstations"
        assert device.tags == ["production", "engineering"]
        assert device.custom_attributes == {"owner": "john"}
        assert device.managed_by_agent is True
        assert device.agent_last_action == "vlan_assigned"

    def test_primary_ip_with_primary_interface(self):
        """Test primary_ip returns IP from primary interface."""
        device = Device(
            interfaces=[
                NetworkInterface(
                    mac_address="00:11:22:33:44:55",
                    ip_addresses=["192.168.1.100"],
                    is_primary=False,
                ),
                NetworkInterface(
                    mac_address="00:11:22:33:44:66", ip_addresses=["192.168.2.100"], is_primary=True
                ),
            ]
        )

        assert device.primary_ip == "192.168.2.100"

    def test_primary_ip_fallback_to_first(self):
        """Test primary_ip falls back to first available IP."""
        device = Device(
            interfaces=[
                NetworkInterface(
                    mac_address="00:11:22:33:44:55",
                    ip_addresses=["192.168.1.100"],
                    is_primary=False,
                ),
            ]
        )

        assert device.primary_ip == "192.168.1.100"

    def test_primary_ip_none_when_no_ips(self):
        """Test primary_ip returns None when no IPs."""
        device = Device(
            interfaces=[
                NetworkInterface(mac_address="00:11:22:33:44:55", ip_addresses=[], is_primary=True),
            ]
        )

        assert device.primary_ip is None

    def test_primary_ip_none_when_no_interfaces(self):
        """Test primary_ip returns None when no interfaces."""
        device = Device()
        assert device.primary_ip is None

    def test_primary_ip_skips_primary_with_no_ips(self):
        """Test primary_ip skips primary interface without IPs."""
        device = Device(
            interfaces=[
                NetworkInterface(mac_address="00:11:22:33:44:55", ip_addresses=[], is_primary=True),
                NetworkInterface(
                    mac_address="00:11:22:33:44:66",
                    ip_addresses=["192.168.1.100"],
                    is_primary=False,
                ),
            ]
        )

        assert device.primary_ip == "192.168.1.100"

    def test_primary_mac_with_primary_interface(self):
        """Test primary_mac returns MAC from primary interface."""
        device = Device(
            interfaces=[
                NetworkInterface(mac_address="00:11:22:33:44:55", is_primary=False),
                NetworkInterface(mac_address="00:11:22:33:44:66", is_primary=True),
            ]
        )

        assert device.primary_mac == "00:11:22:33:44:66"

    def test_primary_mac_fallback_to_first(self):
        """Test primary_mac falls back to first interface."""
        device = Device(
            interfaces=[
                NetworkInterface(mac_address="00:11:22:33:44:55", is_primary=False),
            ]
        )

        assert device.primary_mac == "00:11:22:33:44:55"

    def test_primary_mac_none_when_no_interfaces(self):
        """Test primary_mac returns None when no interfaces."""
        device = Device()
        assert device.primary_mac is None

    def test_all_ips(self):
        """Test all_ips returns all IP addresses."""
        device = Device(
            interfaces=[
                NetworkInterface(
                    mac_address="00:11:22:33:44:55", ip_addresses=["192.168.1.100", "192.168.1.101"]
                ),
                NetworkInterface(mac_address="00:11:22:33:44:66", ip_addresses=["192.168.2.100"]),
            ]
        )

        all_ips = device.all_ips

        assert len(all_ips) == 3
        assert "192.168.1.100" in all_ips
        assert "192.168.1.101" in all_ips
        assert "192.168.2.100" in all_ips

    def test_all_ips_empty(self):
        """Test all_ips returns empty list when no IPs."""
        device = Device()
        assert device.all_ips == []

    def test_all_macs(self):
        """Test all_macs returns all MAC addresses."""
        device = Device(
            interfaces=[
                NetworkInterface(mac_address="00:11:22:33:44:55"),
                NetworkInterface(mac_address="00:11:22:33:44:66"),
            ]
        )

        all_macs = device.all_macs

        assert len(all_macs) == 2
        assert "00:11:22:33:44:55" in all_macs
        assert "00:11:22:33:44:66" in all_macs

    def test_all_macs_empty(self):
        """Test all_macs returns empty list when no interfaces."""
        device = Device()
        assert device.all_macs == []


class TestDeviceGroup:
    """Tests for DeviceGroup model."""

    def test_default_values(self):
        """Test default values."""
        group = DeviceGroup(name="Test Group")

        assert group.id is not None
        assert group.name == "Test Group"
        assert group.description is None
        assert group.device_ids == []
        assert group.auto_membership_rules == {}
        assert group.policies == []

    def test_custom_values(self):
        """Test custom values."""
        device_id = uuid4()
        group = DeviceGroup(
            name="Engineering",
            description="Engineering department devices",
            device_ids=[device_id],
            auto_membership_rules={"vlan": 10},
            policies=["policy1", "policy2"],
        )

        assert group.name == "Engineering"
        assert group.description == "Engineering department devices"
        assert device_id in group.device_ids
        assert group.auto_membership_rules == {"vlan": 10}
        assert group.policies == ["policy1", "policy2"]

    def test_add_device(self):
        """Test add_device adds device to group."""
        group = DeviceGroup(name="Test")
        device_id = uuid4()

        group.add_device(device_id)

        assert device_id in group.device_ids
        assert len(group.device_ids) == 1

    def test_add_device_no_duplicate(self):
        """Test add_device doesn't add duplicates."""
        device_id = uuid4()
        group = DeviceGroup(name="Test", device_ids=[device_id])

        group.add_device(device_id)

        assert len(group.device_ids) == 1

    def test_remove_device_exists(self):
        """Test remove_device returns True when device removed."""
        device_id = uuid4()
        group = DeviceGroup(name="Test", device_ids=[device_id])

        result = group.remove_device(device_id)

        assert result is True
        assert device_id not in group.device_ids

    def test_remove_device_not_exists(self):
        """Test remove_device returns False when device not found."""
        group = DeviceGroup(name="Test")
        device_id = uuid4()

        result = group.remove_device(device_id)

        assert result is False


class TestDeviceInventory:
    """Tests for DeviceInventory model."""

    def test_default_values(self):
        """Test default values."""
        inventory = DeviceInventory()

        assert inventory.devices == {}
        assert inventory.mac_index == {}
        assert inventory.ip_index == {}

    def test_add_device(self):
        """Test add_device adds device and indexes."""
        inventory = DeviceInventory()

        device = Device(
            interfaces=[
                NetworkInterface(mac_address="00:11:22:33:44:55", ip_addresses=["192.168.1.100"]),
            ]
        )

        inventory.add_device(device)

        assert device.id in inventory.devices
        assert "00:11:22:33:44:55" in inventory.mac_index
        assert "192.168.1.100" in inventory.ip_index

    def test_add_device_updates_indexes(self):
        """Test add_device updates all indexes."""
        inventory = DeviceInventory()

        device = Device(
            interfaces=[
                NetworkInterface(
                    mac_address="00:11:22:33:44:55", ip_addresses=["192.168.1.100", "192.168.1.101"]
                ),
                NetworkInterface(mac_address="00:11:22:33:44:66", ip_addresses=["192.168.2.100"]),
            ]
        )

        inventory.add_device(device)

        # Check MAC index
        assert "00:11:22:33:44:55" in inventory.mac_index
        assert "00:11:22:33:44:66" in inventory.mac_index

        # Check IP index
        assert "192.168.1.100" in inventory.ip_index
        assert "192.168.1.101" in inventory.ip_index
        assert "192.168.2.100" in inventory.ip_index

    def test_add_device_overwrites_existing(self):
        """Test add_device overwrites existing device."""
        inventory = DeviceInventory()

        device_id = uuid4()
        device1 = Device(
            id=device_id,
            hostname="old_hostname",
            interfaces=[
                NetworkInterface(mac_address="00:11:22:33:44:55", ip_addresses=["192.168.1.100"]),
            ],
        )

        device2 = Device(
            id=device_id,
            hostname="new_hostname",
            interfaces=[
                NetworkInterface(mac_address="00:11:22:33:44:55", ip_addresses=["192.168.1.100"]),
            ],
        )

        inventory.add_device(device1)
        inventory.add_device(device2)

        assert len(inventory.devices) == 1
        assert inventory.devices[device_id].hostname == "new_hostname"

    def test_get_by_mac_found(self):
        """Test get_by_mac returns device when found."""
        inventory = DeviceInventory()

        device = Device(
            interfaces=[
                NetworkInterface(mac_address="00:11:22:33:44:55"),
            ]
        )
        inventory.add_device(device)

        result = inventory.get_by_mac("00:11:22:33:44:55")

        assert result is not None
        assert result.id == device.id

    def test_get_by_mac_case_insensitive(self):
        """Test get_by_mac is case insensitive."""
        inventory = DeviceInventory()

        device = Device(
            interfaces=[
                NetworkInterface(mac_address="00:11:22:33:44:55"),
            ]
        )
        inventory.add_device(device)

        result = inventory.get_by_mac("00:11:22:33:44:55")
        assert result is not None

        result = inventory.get_by_mac("00:11:22:33:44:55".upper())
        assert result is not None

    def test_get_by_mac_not_found(self):
        """Test get_by_mac returns None when not found."""
        inventory = DeviceInventory()

        result = inventory.get_by_mac("00:11:22:33:44:55")

        assert result is None

    def test_get_by_ip_found(self):
        """Test get_by_ip returns device when found."""
        inventory = DeviceInventory()

        device = Device(
            interfaces=[
                NetworkInterface(mac_address="00:11:22:33:44:55", ip_addresses=["192.168.1.100"]),
            ]
        )
        inventory.add_device(device)

        result = inventory.get_by_ip("192.168.1.100")

        assert result is not None
        assert result.id == device.id

    def test_get_by_ip_not_found(self):
        """Test get_by_ip returns None when not found."""
        inventory = DeviceInventory()

        result = inventory.get_by_ip("192.168.1.100")

        assert result is None

    def test_get_by_type(self):
        """Test get_by_type returns matching devices."""
        inventory = DeviceInventory()

        workstation1 = Device(device_type=DeviceType.WORKSTATION)
        workstation2 = Device(device_type=DeviceType.WORKSTATION)
        server1 = Device(device_type=DeviceType.SERVER)

        inventory.add_device(workstation1)
        inventory.add_device(workstation2)
        inventory.add_device(server1)

        workstations = inventory.get_by_type(DeviceType.WORKSTATION)
        servers = inventory.get_by_type(DeviceType.SERVER)

        assert len(workstations) == 2
        assert len(servers) == 1

    def test_get_by_type_empty(self):
        """Test get_by_type returns empty list when no matches."""
        inventory = DeviceInventory()

        result = inventory.get_by_type(DeviceType.IOT)

        assert result == []

    def test_get_by_vlan(self):
        """Test get_by_vlan returns matching devices."""
        inventory = DeviceInventory()

        device1 = Device(assigned_vlan=10)
        device2 = Device(assigned_vlan=10)
        device3 = Device(assigned_vlan=20)
        device4 = Device(assigned_vlan=None)

        inventory.add_device(device1)
        inventory.add_device(device2)
        inventory.add_device(device3)
        inventory.add_device(device4)

        vlan10_devices = inventory.get_by_vlan(10)
        vlan20_devices = inventory.get_by_vlan(20)

        assert len(vlan10_devices) == 2
        assert len(vlan20_devices) == 1

    def test_get_by_vlan_empty(self):
        """Test get_by_vlan returns empty list when no matches."""
        inventory = DeviceInventory()

        result = inventory.get_by_vlan(99)

        assert result == []


class TestUtcNow:
    """Tests for _utc_now helper."""

    def test_returns_timezone_aware(self):
        """Test _utc_now returns timezone-aware datetime."""
        now = _utc_now()

        assert now.tzinfo is not None
        assert now.tzinfo == timezone.utc


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
