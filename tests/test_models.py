"""
Tests for Sentinel core models.
"""

import pytest
from datetime import datetime
from uuid import uuid4

from sentinel.core.models.device import (
    Device,
    DeviceType,
    DeviceFingerprint,
    NetworkInterface,
    DeviceInventory,
)
from sentinel.core.models.network import VLAN, TrafficFlow, QoSPolicy
from sentinel.core.models.policy import FirewallRule, SegmentationPolicy
from sentinel.core.models.event import Event, EventCategory, EventSeverity


class TestDeviceModels:
    """Tests for device models."""

    def test_device_creation(self):
        """Test basic device creation."""
        from sentinel.core.models.device import TrustLevel, DeviceStatus

        device = Device(id=str(uuid4()), device_type=DeviceType.WORKSTATION, hostname="test-ws-01")

        assert device.hostname == "test-ws-01"
        assert device.device_type == DeviceType.WORKSTATION
        assert device.trust_level == TrustLevel.UNKNOWN  # Default
        assert device.status == DeviceStatus.ONLINE  # Default

    def test_device_with_interface(self):
        """Test device with network interface."""
        interface = NetworkInterface(
            mac_address="00:11:22:33:44:55", ip_addresses=["192.168.1.100"], vlan_id=10
        )

        device = Device(
            id=str(uuid4()),
            device_type=DeviceType.SERVER,
            hostname="test-server",
            interfaces=[interface],
        )

        assert len(device.interfaces) == 1
        assert device.interfaces[0].mac_address == "00:11:22:33:44:55"
        assert device.primary_mac == "00:11:22:33:44:55"

    def test_device_fingerprint(self):
        """Test device fingerprinting."""
        fingerprint = DeviceFingerprint(
            vendor="Dell",
            model="OptiPlex 7090",
            os_family="Windows",
            os_version="11",
            confidence=0.85,
        )

        assert fingerprint.vendor == "Dell"
        assert fingerprint.confidence == 0.85

    def test_device_inventory(self):
        """Test device inventory collection."""
        inventory = DeviceInventory()

        device1 = Device(
            id=str(uuid4()),
            device_type=DeviceType.WORKSTATION,
            hostname="ws-01",
            interfaces=[
                NetworkInterface(mac_address="00:11:22:33:44:55", ip_addresses=["192.168.1.100"])
            ],
        )

        device2 = Device(
            id=str(uuid4()),
            device_type=DeviceType.SERVER,
            hostname="srv-01",
            interfaces=[
                NetworkInterface(mac_address="AA:BB:CC:DD:EE:FF", ip_addresses=["192.168.1.10"])
            ],
        )

        inventory.add_device(device1)
        inventory.add_device(device2)

        assert len(inventory.devices) == 2
        assert inventory.get_by_mac("00:11:22:33:44:55") == device1
        assert inventory.get_by_ip("192.168.1.10") == device2


class TestNetworkModels:
    """Tests for network models."""

    def test_vlan_creation(self):
        """Test VLAN creation."""
        vlan = VLAN(
            id=10,
            name="Workstations",
            purpose="workstations",
            subnet="192.168.10.0/24",
            gateway="192.168.10.1",
            dhcp_enabled=True,
        )

        assert vlan.id == 10
        assert vlan.name == "Workstations"
        assert vlan.dhcp_enabled == True

    def test_traffic_flow(self):
        """Test traffic flow model."""
        flow = TrafficFlow(
            id=str(uuid4()),
            source_ip="192.168.1.100",
            source_port=54321,
            destination_ip="8.8.8.8",
            destination_port=443,
            protocol="tcp",
            bytes_sent=1024,
            bytes_received=2048,
            application="web",
        )

        assert flow.destination_port == 443
        assert flow.application == "web"

    def test_qos_policy(self):
        """Test QoS policy model."""
        policy = QoSPolicy(
            id=str(uuid4()),
            name="voip-priority",
            description="High priority for VoIP",
            priority_queue=1,
            bandwidth_guarantee_mbps=10,
            set_dscp=46,
        )

        assert policy.priority_queue == 1
        assert policy.set_dscp == 46


class TestPolicyModels:
    """Tests for policy models."""

    def test_firewall_rule(self):
        """Test firewall rule creation."""
        from sentinel.core.models.policy import PolicyAction

        rule = FirewallRule(
            id=str(uuid4()),
            name="allow-ssh",
            description="Allow SSH from management",
            action=PolicyAction.ALLOW,
            source_zones=["management"],
            destination_ports=["22"],
            protocols=["tcp"],
        )

        assert rule.action == PolicyAction.ALLOW
        assert "22" in rule.destination_ports

    def test_segmentation_policy(self):
        """Test segmentation policy."""
        policy = SegmentationPolicy(
            id=str(uuid4()),
            name="ws-to-server",
            source_vlan=10,
            destination_vlan=20,
            allowed_services=["http", "https", "ssh"],
            default_action="deny",
        )

        assert policy.source_vlan == 10
        assert "ssh" in policy.allowed_services


class TestEventModels:
    """Tests for event models."""

    def test_event_creation(self):
        """Test event creation."""
        event = Event(
            id=str(uuid4()),
            category=EventCategory.NETWORK,
            event_type="device.discovered",
            severity=EventSeverity.INFO,
            source="discovery",
            title="New device discovered",
            description="Device 00:11:22:33:44:55 found on network",
        )

        assert event.category == EventCategory.NETWORK
        assert event.severity == EventSeverity.INFO
        assert event.acknowledged == False

    def test_event_with_data(self):
        """Test event with additional data."""
        event = Event(
            id=str(uuid4()),
            category=EventCategory.SECURITY,
            event_type="security.alert",
            severity=EventSeverity.WARNING,
            source="guardian",
            title="Suspicious activity detected",
            data={"source_ip": "192.168.1.100", "destination_port": 4444, "connection_count": 50},
        )

        assert event.data["source_ip"] == "192.168.1.100"


@pytest.mark.asyncio
class TestAsyncComponents:
    """Tests for async components."""

    async def test_event_bus(self):
        """Test event bus pub/sub."""
        import asyncio
        from sentinel.core.event_bus import EventBus

        bus = EventBus()
        received_events = []

        async def handler(event):
            received_events.append(event)

        # subscribe is synchronous
        bus.subscribe(handler, event_type="test.event")

        # Start the bus processor
        await bus.start()

        event = Event(
            id=str(uuid4()),
            category=EventCategory.SYSTEM,
            event_type="test.event",
            severity=EventSeverity.INFO,
            source="test",
            title="Test event",
        )

        await bus.publish(event)

        # Give the processor time to handle the event
        await asyncio.sleep(0.1)

        await bus.stop()

        assert len(received_events) == 1
        assert received_events[0].title == "Test event"

    async def test_state_manager_memory(self):
        """Test in-memory state manager."""
        from sentinel.core.state import StateManager

        manager = StateManager({"backend": "memory"})
        await manager.initialize()

        # Test set/get
        await manager.set("test:key", "test-value")
        value = await manager.get("test:key")
        assert value == "test-value"

        # Test delete
        await manager.delete("test:key")
        value = await manager.get("test:key")
        assert value is None

        # Test counter
        await manager.increment("test:counter")
        await manager.increment("test:counter")
        count = await manager.get("test:counter")
        assert count == 2

        await manager.close()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
