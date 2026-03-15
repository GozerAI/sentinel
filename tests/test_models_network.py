"""
Tests for Network models.

Tests cover VLANs, network links, topology, traffic flows, QoS policies,
DNS records, and DHCP leases.
"""
import pytest
from datetime import datetime, timedelta, timezone
from uuid import uuid4

from sentinel.core.models.network import (
    VLANPurpose,
    VLAN,
    LinkType,
    LinkStatus,
    NetworkLink,
    TopologyNode,
    NetworkTopology,
    TrafficFlow,
    QoSPolicy,
    DNSRecord,
    DHCPLease,
    _utc_now,
)


class TestVLANPurpose:
    """Tests for VLANPurpose enum."""

    def test_vlan_purpose_values(self):
        """Test VLANPurpose enum values."""
        assert VLANPurpose.MANAGEMENT.value == "management"
        assert VLANPurpose.WORKSTATIONS.value == "workstations"
        assert VLANPurpose.SERVERS.value == "servers"
        assert VLANPurpose.STORAGE.value == "storage"
        assert VLANPurpose.IOT.value == "iot"
        assert VLANPurpose.GUEST.value == "guest"
        assert VLANPurpose.DMZ.value == "dmz"
        assert VLANPurpose.QUARANTINE.value == "quarantine"
        assert VLANPurpose.AI_COMPUTE.value == "ai_compute"
        assert VLANPurpose.CUSTOM.value == "custom"


class TestVLAN:
    """Tests for VLAN model."""

    def test_required_fields(self):
        """Test required fields."""
        vlan = VLAN(
            id=10,
            name="Management",
            subnet="192.168.10.0/24",
            gateway="192.168.10.1"
        )

        assert vlan.id == 10
        assert vlan.name == "Management"
        assert vlan.subnet == "192.168.10.0/24"
        assert vlan.gateway == "192.168.10.1"

    def test_default_values(self):
        """Test default values."""
        vlan = VLAN(
            id=20,
            name="Servers",
            subnet="192.168.20.0/24",
            gateway="192.168.20.1"
        )

        assert vlan.purpose == VLANPurpose.CUSTOM
        assert vlan.dhcp_enabled is True
        assert vlan.isolated is False
        assert vlan.allowed_destinations == []
        assert vlan.auto_managed is False
        assert vlan.created_at is not None

    def test_custom_values(self):
        """Test custom values."""
        vlan = VLAN(
            id=666,
            name="Quarantine",
            purpose=VLANPurpose.QUARANTINE,
            subnet="192.168.66.0/24",
            gateway="192.168.66.1",
            dhcp_enabled=True,
            dhcp_range_start="192.168.66.100",
            dhcp_range_end="192.168.66.200",
            isolated=True,
            auto_managed=True
        )

        assert vlan.purpose == VLANPurpose.QUARANTINE
        assert vlan.isolated is True
        assert vlan.dhcp_range_start == "192.168.66.100"

    def test_network_address_property(self):
        """Test network_address property."""
        vlan = VLAN(
            id=10,
            name="Test",
            subnet="192.168.10.0/24",
            gateway="192.168.10.1"
        )

        assert vlan.network_address == "192.168.10.0"

    def test_prefix_length_property(self):
        """Test prefix_length property."""
        vlan = VLAN(
            id=10,
            name="Test",
            subnet="192.168.10.0/24",
            gateway="192.168.10.1"
        )

        assert vlan.prefix_length == 24

    def test_vlan_id_validation(self):
        """Test VLAN ID validation (1-4094)."""
        # Valid VLAN IDs
        vlan1 = VLAN(id=1, name="Min", subnet="10.0.0.0/8", gateway="10.0.0.1")
        vlan4094 = VLAN(id=4094, name="Max", subnet="10.0.0.0/8", gateway="10.0.0.1")

        assert vlan1.id == 1
        assert vlan4094.id == 4094


class TestLinkEnums:
    """Tests for link enums."""

    def test_link_type_values(self):
        """Test LinkType enum values."""
        assert LinkType.ETHERNET.value == "ethernet"
        assert LinkType.WIFI.value == "wifi"
        assert LinkType.AGGREGATE.value == "aggregate"
        assert LinkType.VIRTUAL.value == "virtual"
        assert LinkType.VPN.value == "vpn"

    def test_link_status_values(self):
        """Test LinkStatus enum values."""
        assert LinkStatus.UP.value == "up"
        assert LinkStatus.DOWN.value == "down"
        assert LinkStatus.DEGRADED.value == "degraded"


class TestNetworkLink:
    """Tests for NetworkLink model."""

    def test_required_fields(self):
        """Test required fields."""
        link = NetworkLink(
            source_device_id=uuid4(),
            target_device_id=uuid4()
        )

        assert link.source_device_id is not None
        assert link.target_device_id is not None

    def test_default_values(self):
        """Test default values."""
        link = NetworkLink(
            source_device_id=uuid4(),
            target_device_id=uuid4()
        )

        assert link.link_type == LinkType.ETHERNET
        assert link.status == LinkStatus.UP
        assert link.utilization_percent == 0.0
        assert link.bytes_in == 0
        assert link.bytes_out == 0
        assert link.errors_in == 0
        assert link.errors_out == 0

    def test_custom_values(self):
        """Test custom values."""
        link = NetworkLink(
            source_device_id=uuid4(),
            source_port="eth0",
            target_device_id=uuid4(),
            target_port="eth1",
            link_type=LinkType.AGGREGATE,
            speed_mbps=10000,
            duplex="full"
        )

        assert link.source_port == "eth0"
        assert link.target_port == "eth1"
        assert link.link_type == LinkType.AGGREGATE
        assert link.speed_mbps == 10000

    def test_is_healthy_all_good(self):
        """Test is_healthy when everything is good."""
        link = NetworkLink(
            source_device_id=uuid4(),
            target_device_id=uuid4(),
            status=LinkStatus.UP,
            errors_in=0,
            errors_out=0,
            utilization_percent=50.0
        )

        assert link.is_healthy is True

    def test_is_healthy_link_down(self):
        """Test is_healthy when link is down."""
        link = NetworkLink(
            source_device_id=uuid4(),
            target_device_id=uuid4(),
            status=LinkStatus.DOWN
        )

        assert link.is_healthy is False

    def test_is_healthy_has_errors(self):
        """Test is_healthy when link has errors."""
        link = NetworkLink(
            source_device_id=uuid4(),
            target_device_id=uuid4(),
            errors_in=10
        )

        assert link.is_healthy is False

    def test_is_healthy_high_utilization(self):
        """Test is_healthy when utilization is high."""
        link = NetworkLink(
            source_device_id=uuid4(),
            target_device_id=uuid4(),
            utilization_percent=95.0
        )

        assert link.is_healthy is False


class TestTopologyNode:
    """Tests for TopologyNode model."""

    def test_required_fields(self):
        """Test required fields."""
        node = TopologyNode(
            device_id=uuid4(),
            node_type="switch",
            layer=2
        )

        assert node.device_id is not None
        assert node.node_type == "switch"
        assert node.layer == 2

    def test_default_values(self):
        """Test default values."""
        node = TopologyNode(
            device_id=uuid4(),
            node_type="router",
            layer=1
        )

        assert node.position is None
        assert node.children == []
        assert node.parent is None

    def test_with_children(self):
        """Test node with children."""
        child1 = uuid4()
        child2 = uuid4()
        parent = uuid4()

        node = TopologyNode(
            device_id=uuid4(),
            node_type="switch",
            layer=2,
            children=[child1, child2],
            parent=parent
        )

        assert len(node.children) == 2
        assert child1 in node.children
        assert node.parent == parent


class TestNetworkTopology:
    """Tests for NetworkTopology model."""

    def test_default_values(self):
        """Test default values."""
        topology = NetworkTopology()

        assert topology.name == "default"
        assert topology.nodes == {}
        assert topology.links == []
        assert topology.vlans == []
        assert topology.last_scan is None

    def test_get_device_neighbors(self):
        """Test getting device neighbors."""
        device1 = uuid4()
        device2 = uuid4()
        device3 = uuid4()
        device4 = uuid4()

        link1 = NetworkLink(source_device_id=device1, target_device_id=device2)
        link2 = NetworkLink(source_device_id=device1, target_device_id=device3)
        link3 = NetworkLink(source_device_id=device3, target_device_id=device4)

        topology = NetworkTopology(links=[link1, link2, link3])

        neighbors = topology.get_device_neighbors(device1)

        assert len(neighbors) == 2
        assert device2 in neighbors
        assert device3 in neighbors

    def test_get_path_same_device(self):
        """Test getting path to same device."""
        device1 = uuid4()
        topology = NetworkTopology()

        path = topology.get_path(device1, device1)

        assert path == [device1]

    def test_get_path_direct_connection(self):
        """Test getting path for direct connection."""
        device1 = uuid4()
        device2 = uuid4()

        link = NetworkLink(source_device_id=device1, target_device_id=device2)
        topology = NetworkTopology(links=[link])

        path = topology.get_path(device1, device2)

        assert path == [device1, device2]

    def test_get_path_multi_hop(self):
        """Test getting path through multiple hops."""
        device1 = uuid4()
        device2 = uuid4()
        device3 = uuid4()

        link1 = NetworkLink(source_device_id=device1, target_device_id=device2)
        link2 = NetworkLink(source_device_id=device2, target_device_id=device3)
        topology = NetworkTopology(links=[link1, link2])

        path = topology.get_path(device1, device3)

        assert path == [device1, device2, device3]

    def test_get_path_no_path(self):
        """Test getting path when no path exists."""
        device1 = uuid4()
        device2 = uuid4()
        device3 = uuid4()

        link = NetworkLink(source_device_id=device1, target_device_id=device2)
        topology = NetworkTopology(links=[link])

        path = topology.get_path(device1, device3)

        assert path == []

    def test_get_vlan_by_id_found(self):
        """Test getting VLAN by ID when found."""
        vlan1 = VLAN(id=10, name="VLAN10", subnet="10.0.0.0/24", gateway="10.0.0.1")
        vlan2 = VLAN(id=20, name="VLAN20", subnet="20.0.0.0/24", gateway="20.0.0.1")

        topology = NetworkTopology(vlans=[vlan1, vlan2])

        found = topology.get_vlan_by_id(10)

        assert found is not None
        assert found.name == "VLAN10"

    def test_get_vlan_by_id_not_found(self):
        """Test getting VLAN by ID when not found."""
        vlan = VLAN(id=10, name="VLAN10", subnet="10.0.0.0/24", gateway="10.0.0.1")
        topology = NetworkTopology(vlans=[vlan])

        found = topology.get_vlan_by_id(99)

        assert found is None

    def test_get_vlans_by_purpose(self):
        """Test getting VLANs by purpose."""
        vlan1 = VLAN(
            id=10, name="Servers1", subnet="10.0.0.0/24", gateway="10.0.0.1",
            purpose=VLANPurpose.SERVERS
        )
        vlan2 = VLAN(
            id=20, name="Servers2", subnet="20.0.0.0/24", gateway="20.0.0.1",
            purpose=VLANPurpose.SERVERS
        )
        vlan3 = VLAN(
            id=30, name="Guest", subnet="30.0.0.0/24", gateway="30.0.0.1",
            purpose=VLANPurpose.GUEST
        )

        topology = NetworkTopology(vlans=[vlan1, vlan2, vlan3])

        servers = topology.get_vlans_by_purpose(VLANPurpose.SERVERS)

        assert len(servers) == 2
        assert all(v.purpose == VLANPurpose.SERVERS for v in servers)


class TestTrafficFlow:
    """Tests for TrafficFlow model."""

    def test_required_fields(self):
        """Test required fields."""
        flow = TrafficFlow(
            source_ip="192.168.1.100",
            source_port=54321,
            destination_ip="10.0.0.50",
            destination_port=443,
            protocol="TCP"
        )

        assert flow.source_ip == "192.168.1.100"
        assert flow.source_port == 54321
        assert flow.destination_ip == "10.0.0.50"
        assert flow.destination_port == 443
        assert flow.protocol == "TCP"

    def test_default_values(self):
        """Test default values."""
        flow = TrafficFlow(
            source_ip="192.168.1.100",
            source_port=54321,
            destination_ip="10.0.0.50",
            destination_port=443,
            protocol="TCP"
        )

        assert flow.application is None
        assert flow.bytes_total == 0
        assert flow.packets_total == 0
        assert flow.dscp_marking is None
        assert flow.priority is None

    def test_duration_seconds(self):
        """Test duration_seconds property."""
        start = _utc_now()
        end = start + timedelta(minutes=5)

        flow = TrafficFlow(
            source_ip="192.168.1.100",
            source_port=54321,
            destination_ip="10.0.0.50",
            destination_port=443,
            protocol="TCP",
            start_time=start,
            last_seen=end
        )

        assert flow.duration_seconds == 300.0

    def test_flow_tuple(self):
        """Test flow_tuple property."""
        flow = TrafficFlow(
            source_ip="192.168.1.100",
            source_port=54321,
            destination_ip="10.0.0.50",
            destination_port=443,
            protocol="TCP"
        )

        expected = ("192.168.1.100", 54321, "10.0.0.50", 443, "TCP")
        assert flow.flow_tuple == expected


class TestQoSPolicy:
    """Tests for QoSPolicy model."""

    def test_default_values(self):
        """Test default values."""
        policy = QoSPolicy(name="Default QoS")

        assert policy.name == "Default QoS"
        assert policy.match_applications == []
        assert policy.match_source_vlans == []
        assert policy.match_destination_vlans == []
        assert policy.match_dscp == []
        assert policy.set_dscp is None
        assert policy.bandwidth_limit_mbps is None
        assert policy.bandwidth_guarantee_mbps is None
        assert policy.priority_queue is None
        assert policy.enabled is True

    def test_custom_values(self):
        """Test custom values."""
        policy = QoSPolicy(
            name="VoIP Priority",
            match_applications=["sip", "rtp"],
            set_dscp=46,
            bandwidth_guarantee_mbps=10,
            priority_queue=5
        )

        assert policy.match_applications == ["sip", "rtp"]
        assert policy.set_dscp == 46
        assert policy.priority_queue == 5

    def test_matches_flow_no_criteria(self):
        """Test matches_flow with no criteria."""
        policy = QoSPolicy(name="Test")
        flow = TrafficFlow(
            source_ip="192.168.1.100",
            source_port=54321,
            destination_ip="10.0.0.50",
            destination_port=443,
            protocol="TCP"
        )

        assert policy.matches_flow(flow) is True

    def test_matches_flow_application_match(self):
        """Test matches_flow with matching application."""
        policy = QoSPolicy(
            name="Test",
            match_applications=["https"]
        )
        flow = TrafficFlow(
            source_ip="192.168.1.100",
            source_port=54321,
            destination_ip="10.0.0.50",
            destination_port=443,
            protocol="TCP",
            application="https"
        )

        assert policy.matches_flow(flow) is True

    def test_matches_flow_application_no_match(self):
        """Test matches_flow with non-matching application."""
        policy = QoSPolicy(
            name="Test",
            match_applications=["voip"]
        )
        flow = TrafficFlow(
            source_ip="192.168.1.100",
            source_port=54321,
            destination_ip="10.0.0.50",
            destination_port=443,
            protocol="TCP",
            application="https"
        )

        assert policy.matches_flow(flow) is False

    def test_matches_flow_dscp_match(self):
        """Test matches_flow with matching DSCP."""
        policy = QoSPolicy(
            name="Test",
            match_dscp=[46]
        )
        flow = TrafficFlow(
            source_ip="192.168.1.100",
            source_port=54321,
            destination_ip="10.0.0.50",
            destination_port=443,
            protocol="TCP",
            dscp_marking=46
        )

        assert policy.matches_flow(flow) is True


class TestDNSRecord:
    """Tests for DNSRecord model."""

    def test_default_values(self):
        """Test default values."""
        record = DNSRecord(
            name="server1",
            zone="example.com",
            value="192.168.1.10"
        )

        assert record.name == "server1"
        assert record.zone == "example.com"
        assert record.record_type == "A"
        assert record.value == "192.168.1.10"
        assert record.ttl == 300
        assert record.auto_managed is False
        assert record.device_id is None

    def test_fqdn_property(self):
        """Test fqdn property."""
        record = DNSRecord(
            name="server1",
            zone="example.com",
            value="192.168.1.10"
        )

        assert record.fqdn == "server1.example.com"


class TestDHCPLease:
    """Tests for DHCPLease model."""

    def test_default_values(self):
        """Test default values."""
        lease = DHCPLease(
            mac_address="AA:BB:CC:DD:EE:FF",
            ip_address="192.168.1.100"
        )

        assert lease.mac_address == "AA:BB:CC:DD:EE:FF"
        assert lease.ip_address == "192.168.1.100"
        assert lease.hostname is None
        assert lease.vlan_id is None
        assert lease.lease_start is not None
        assert lease.lease_end is None
        assert lease.is_static is False
        assert lease.device_id is None

    def test_is_expired_no_end(self):
        """Test is_expired when no end time set."""
        lease = DHCPLease(
            mac_address="AA:BB:CC:DD:EE:FF",
            ip_address="192.168.1.100"
        )

        assert lease.is_expired is False

    def test_is_expired_future_end(self):
        """Test is_expired with future end time."""
        lease = DHCPLease(
            mac_address="AA:BB:CC:DD:EE:FF",
            ip_address="192.168.1.100",
            lease_end=_utc_now() + timedelta(hours=1)
        )

        assert lease.is_expired is False

    def test_is_expired_past_end(self):
        """Test is_expired with past end time."""
        lease = DHCPLease(
            mac_address="AA:BB:CC:DD:EE:FF",
            ip_address="192.168.1.100",
            lease_end=_utc_now() - timedelta(hours=1)
        )

        assert lease.is_expired is True


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
