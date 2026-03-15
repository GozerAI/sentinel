"""
Tests for the DiscoveryAgent class.

Tests cover device discovery, fingerprinting, classification,
VLAN recommendations, and event handling.
"""
import asyncio
import pytest
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

from sentinel.agents.discovery import (
    DiscoveryAgent,
    VENDOR_MAC_PREFIXES,
    SERVICE_SIGNATURES,
    VLAN_RECOMMENDATIONS
)
from sentinel.core.models.device import (
    Device, DeviceType, DeviceStatus, TrustLevel,
    NetworkInterface, DeviceFingerprint, DeviceInventory
)
from sentinel.core.models.event import Event, EventCategory, EventSeverity
from sentinel.core.utils import utc_now


@pytest.fixture
def mock_engine():
    """Create a mock engine."""
    engine = MagicMock()
    engine.event_bus = MagicMock()
    engine.event_bus.publish = AsyncMock()
    engine.event_bus.subscribe = MagicMock()
    engine.get_integration = MagicMock(return_value=None)
    engine.state = MagicMock()
    engine.state.set = AsyncMock()
    engine.state.get = AsyncMock(return_value=None)
    return engine


@pytest.fixture
def default_config():
    """Default agent configuration."""
    return {
        "scan_interval_seconds": 60,
        "full_scan_interval_seconds": 600,
        "networks": ["192.168.1.0/24"],
        "port_scan_enabled": True,
        "service_detection_enabled": True,
        "auto_execute_threshold": 0.95,
        "confirm_threshold": 0.60
    }


@pytest.fixture
def agent(mock_engine, default_config):
    """Create a discovery agent."""
    return DiscoveryAgent(mock_engine, default_config)


class TestDiscoveryAgentInit:
    """Tests for agent initialization."""

    def test_init_with_defaults(self, mock_engine):
        """Test initialization with minimal config."""
        agent = DiscoveryAgent(mock_engine, {})

        assert agent.agent_name == "discovery"
        assert agent.scan_interval == 300  # Default
        assert agent.full_scan_interval == 3600  # Default
        assert agent.networks_to_scan == ["192.168.1.0/24"]
        assert agent.port_scan_enabled is True
        assert agent.service_detection_enabled is True

    def test_init_with_custom_config(self, mock_engine, default_config):
        """Test initialization with custom config."""
        agent = DiscoveryAgent(mock_engine, default_config)

        assert agent.scan_interval == 60
        assert agent.full_scan_interval == 600
        assert agent.networks_to_scan == ["192.168.1.0/24"]

    def test_init_creates_inventory_and_topology(self, agent):
        """Test that inventory and topology are created."""
        assert agent._inventory is not None
        assert agent._topology is not None
        assert isinstance(agent._inventory, DeviceInventory)


class TestDiscoveryAgentSubscriptions:
    """Tests for event subscriptions."""

    @pytest.mark.asyncio
    async def test_subscribe_events(self, agent, mock_engine):
        """Test event subscriptions."""
        await agent._subscribe_events()

        # Should subscribe to DHCP and ARP events
        assert mock_engine.event_bus.subscribe.call_count == 2


class TestDiscoveryAgentVendorLookup:
    """Tests for vendor lookup."""

    def test_lookup_vendor_known(self, agent):
        """Test vendor lookup for known MAC."""
        vendor = agent._lookup_vendor("00:50:56:AA:BB:CC")
        assert vendor == "VMware"

    def test_lookup_vendor_unknown(self, agent):
        """Test vendor lookup for unknown MAC."""
        vendor = agent._lookup_vendor("FF:FF:FF:AA:BB:CC")
        assert vendor is None

    def test_lookup_vendor_none(self, agent):
        """Test vendor lookup with None."""
        vendor = agent._lookup_vendor(None)
        assert vendor is None

    def test_lookup_vendor_normalizes_format(self, agent):
        """Test vendor lookup normalizes MAC format."""
        # Test with dashes
        vendor = agent._lookup_vendor("00-50-56-AA-BB-CC")
        assert vendor == "VMware"

        # Test lowercase
        vendor = agent._lookup_vendor("00:50:56:aa:bb:cc")
        assert vendor == "VMware"


class TestDiscoveryAgentClassifyDevice:
    """Tests for device classification."""

    def test_classify_printer(self, agent):
        """Test classification of printer."""
        fingerprint = DeviceFingerprint(
            open_ports=[9100, 515],
            services=["jetdirect", "lpd"]
        )
        device_type = agent._classify_device(fingerprint)
        assert device_type == DeviceType.PRINTER

    def test_classify_camera(self, agent):
        """Test classification of camera."""
        fingerprint = DeviceFingerprint(
            open_ports=[554, 80],
            services=["rtsp", "http"]
        )
        device_type = agent._classify_device(fingerprint)
        assert device_type == DeviceType.CAMERA

    def test_classify_server(self, agent):
        """Test classification of server."""
        fingerprint = DeviceFingerprint(
            open_ports=[22, 80, 3306, 5432],  # SSH, HTTP, MySQL, PostgreSQL
            services=["ssh", "http", "mysql", "postgresql"]
        )
        device_type = agent._classify_device(fingerprint)
        assert device_type == DeviceType.SERVER

    def test_classify_storage(self, agent):
        """Test classification of storage device."""
        fingerprint = DeviceFingerprint(
            open_ports=[2049, 111],
            services=["nfs", "rpcbind"]
        )
        device_type = agent._classify_device(fingerprint)
        assert device_type == DeviceType.STORAGE

    def test_classify_iot_by_vendor(self, agent):
        """Test classification of IoT by vendor."""
        fingerprint = DeviceFingerprint(
            vendor="Espressif Systems",
            open_ports=[80]
        )
        device_type = agent._classify_device(fingerprint)
        assert device_type == DeviceType.IOT

    def test_classify_iot_by_ports(self, agent):
        """Test classification of IoT by port pattern."""
        fingerprint = DeviceFingerprint(
            open_ports=[80, 1883]  # HTTP and MQTT only
        )
        device_type = agent._classify_device(fingerprint)
        assert device_type == DeviceType.IOT

    def test_classify_raspberry_pi_server(self, agent):
        """Test classification of Raspberry Pi as server."""
        fingerprint = DeviceFingerprint(
            vendor="Raspberry Pi",
            open_ports=[22, 80]
        )
        device_type = agent._classify_device(fingerprint)
        assert device_type == DeviceType.SERVER

    def test_classify_unknown(self, agent):
        """Test classification falls back to unknown."""
        fingerprint = DeviceFingerprint(
            open_ports=[12345]  # Unusual port
        )
        device_type = agent._classify_device(fingerprint)
        assert device_type == DeviceType.UNKNOWN

    def test_classify_workstation(self, agent):
        """Test classification of workstation."""
        fingerprint = DeviceFingerprint(
            open_ports=[22, 3389, 5900]  # SSH, RDP, VNC
        )
        device_type = agent._classify_device(fingerprint)
        assert device_type == DeviceType.WORKSTATION


class TestDiscoveryAgentCalculateConfidence:
    """Tests for confidence calculation."""

    def test_calculate_confidence_full(self, agent):
        """Test confidence with all data."""
        fingerprint = DeviceFingerprint(
            vendor="Dell",
            os_family="Linux",
            services=["ssh", "http"],
            open_ports=[22, 80]
        )
        confidence = agent._calculate_confidence(fingerprint)
        assert confidence == 1.0  # All components present

    def test_calculate_confidence_partial(self, agent):
        """Test confidence with partial data."""
        fingerprint = DeviceFingerprint(
            vendor="Dell",
            open_ports=[22]
        )
        confidence = agent._calculate_confidence(fingerprint)
        assert confidence == 0.50  # Vendor + ports

    def test_calculate_confidence_minimal(self, agent):
        """Test confidence with minimal data."""
        fingerprint = DeviceFingerprint()
        confidence = agent._calculate_confidence(fingerprint)
        assert confidence == 0.0


class TestDiscoveryAgentDetectServices:
    """Tests for service detection."""

    def test_detect_services_known_ports(self, agent):
        """Test service detection for known ports."""
        services = agent._detect_services([22, 80, 443])
        assert "ssh" in services
        assert "http" in services
        assert "https" in services

    def test_detect_services_unknown_ports(self, agent):
        """Test service detection ignores unknown ports."""
        services = agent._detect_services([12345, 54321])
        assert services == []

    def test_detect_services_database_ports(self, agent):
        """Test service detection for database ports."""
        services = agent._detect_services([3306, 5432, 6379])
        assert "mysql" in services
        assert "postgresql" in services
        assert "redis" in services


class TestDiscoveryAgentARPScan:
    """Tests for ARP scanning."""

    @pytest.mark.asyncio
    async def test_arp_scan_with_router(self, agent, mock_engine):
        """Test ARP scan using router integration."""
        mock_router = MagicMock()
        mock_router.get_arp_table = AsyncMock(return_value=[
            {"mac": "00:50:56:AA:BB:CC", "ip": "192.168.1.10"},
            {"mac": "B8:27:EB:11:22:33", "ip": "192.168.1.20"}
        ])
        mock_engine.get_integration.return_value = mock_router

        devices = await agent._arp_scan("192.168.1.0/24")

        assert len(devices) == 2
        assert devices[0].primary_mac == "00:50:56:AA:BB:CC"
        assert devices[0].fingerprint.vendor == "VMware"

    @pytest.mark.asyncio
    async def test_arp_scan_without_router(self, agent, mock_engine):
        """Test ARP scan without router integration."""
        mock_engine.get_integration.return_value = None

        devices = await agent._arp_scan("192.168.1.0/24")

        assert devices == []

    @pytest.mark.asyncio
    async def test_arp_scan_router_error(self, agent, mock_engine):
        """Test ARP scan handles router errors."""
        mock_router = MagicMock()
        mock_router.get_arp_table = AsyncMock(side_effect=Exception("Router error"))
        mock_engine.get_integration.return_value = mock_router

        devices = await agent._arp_scan("192.168.1.0/24")

        assert devices == []


class TestDiscoveryAgentFingerprintDevice:
    """Tests for device fingerprinting."""

    @pytest.mark.asyncio
    async def test_fingerprint_device_no_ip(self, agent):
        """Test fingerprinting device with no IP."""
        device = Device(interfaces=[])

        await agent._fingerprint_device(device)

        # Should return early without error
        assert device.fingerprint.open_ports == []

    @pytest.mark.asyncio
    async def test_fingerprint_device_port_scan_disabled(self, agent):
        """Test fingerprinting with port scan disabled."""
        agent.port_scan_enabled = False

        device = Device(
            interfaces=[NetworkInterface(
                mac_address="00:11:22:33:44:55",
                ip_addresses=["192.168.1.100"],
                is_primary=True
            )]
        )

        await agent._fingerprint_device(device)

        # Should not have open ports
        assert device.fingerprint.open_ports == []


class TestDiscoveryAgentProcessDiscoveredDevices:
    """Tests for processing discovered devices."""

    @pytest.mark.asyncio
    async def test_process_new_device(self, agent, mock_engine):
        """Test processing a new device."""
        device = Device(
            interfaces=[NetworkInterface(
                mac_address="00:11:22:33:44:55",
                ip_addresses=["192.168.1.100"],
                is_primary=True
            )]
        )
        device.device_type = DeviceType.WORKSTATION
        device.fingerprint.confidence = 0.80

        await agent._process_discovered_devices([device], full_scan=False)

        # Device should be added to inventory
        assert agent._inventory.get_by_mac("00:11:22:33:44:55") is not None

        # Event should be published
        mock_engine.event_bus.publish.assert_called()

    @pytest.mark.asyncio
    async def test_process_existing_device_update(self, agent, mock_engine):
        """Test processing an existing device."""
        # Add device first
        device = Device(
            interfaces=[NetworkInterface(
                mac_address="00:11:22:33:44:55",
                ip_addresses=["192.168.1.100"],
                is_primary=True
            )]
        )
        device.status = DeviceStatus.ONLINE
        agent._inventory.add_device(device)

        # Process same device again
        updated = Device(
            interfaces=[NetworkInterface(
                mac_address="00:11:22:33:44:55",
                ip_addresses=["192.168.1.100"],
                is_primary=True
            )]
        )

        await agent._process_discovered_devices([updated], full_scan=False)

        # Should update last_seen
        existing = agent._inventory.get_by_mac("00:11:22:33:44:55")
        assert existing.last_seen is not None

    @pytest.mark.asyncio
    async def test_process_device_reclassified(self, agent, mock_engine):
        """Test processing when device type changes."""
        # Add device first as unknown
        device = Device(
            interfaces=[NetworkInterface(
                mac_address="00:11:22:33:44:55",
                ip_addresses=["192.168.1.100"],
                is_primary=True
            )]
        )
        device.device_type = DeviceType.UNKNOWN
        agent._inventory.add_device(device)

        # Process with new type on full scan
        updated = Device(
            interfaces=[NetworkInterface(
                mac_address="00:11:22:33:44:55",
                ip_addresses=["192.168.1.100"],
                is_primary=True
            )]
        )
        updated.device_type = DeviceType.SERVER

        await agent._process_discovered_devices([updated], full_scan=True)

        # Should emit reclassified event
        events = [call.args[0] for call in mock_engine.event_bus.publish.call_args_list]
        reclassified_events = [e for e in events if e.event_type == "device.reclassified"]
        assert len(reclassified_events) == 1

    @pytest.mark.asyncio
    async def test_process_device_no_mac(self, agent, mock_engine):
        """Test processing device without MAC address."""
        device = Device(interfaces=[])

        await agent._process_discovered_devices([device], full_scan=False)

        # Should skip device
        assert len(agent._inventory.devices) == 0


class TestDiscoveryAgentProposeSegmentation:
    """Tests for VLAN segmentation proposals."""

    @pytest.mark.asyncio
    async def test_propose_segmentation_high_confidence(self, agent, mock_engine):
        """Test segmentation proposal with high confidence."""
        # Disable IoT segmenter to test legacy path
        agent._iot_segmenter = None
        agent.enable_auto_segmentation = False

        device = Device(
            interfaces=[NetworkInterface(
                mac_address="00:11:22:33:44:55",
                ip_addresses=["192.168.1.100"],
                is_primary=True
            )]
        )
        device.device_type = DeviceType.IOT
        device.fingerprint.confidence = 0.90  # Above confirm_threshold

        await agent._propose_segmentation(device)

        # Should create decision
        assert len(agent._decisions) == 1

        # Should execute action
        assert len(agent._actions) == 1

    @pytest.mark.asyncio
    async def test_propose_segmentation_low_confidence(self, agent, mock_engine):
        """Test segmentation proposal with low confidence."""
        # Disable IoT segmenter to test legacy path
        agent._iot_segmenter = None
        agent.enable_auto_segmentation = False

        device = Device(
            interfaces=[NetworkInterface(
                mac_address="00:11:22:33:44:55",
                ip_addresses=["192.168.1.100"],
                is_primary=True
            )]
        )
        device.device_type = DeviceType.UNKNOWN
        device.fingerprint.confidence = 0.30  # Below confirm_threshold

        await agent._propose_segmentation(device)

        # Should create decision but not execute
        assert len(agent._decisions) == 1

    @pytest.mark.asyncio
    async def test_propose_segmentation_with_iot_segmenter(self, agent, mock_engine):
        """Test segmentation with IoT segmenter enabled."""
        # IoT segmenter should be enabled by default if available
        if agent._iot_segmenter is None:
            pytest.skip("IoT segmenter not available")

        device = Device(
            interfaces=[NetworkInterface(
                mac_address="00:11:22:33:44:55",
                ip_addresses=["192.168.1.100"],
                is_primary=True
            )]
        )
        device.device_type = DeviceType.IOT
        device.fingerprint.confidence = 0.90

        await agent._propose_segmentation(device)

        # With IoT segmenter, device should be segmented
        # Check device was assigned a VLAN
        assert device.assigned_vlan is not None or device.managed_by_agent

    def test_vlan_recommendations_cover_all_types(self):
        """Test that VLAN recommendations exist for all device types."""
        for device_type in DeviceType:
            if device_type != DeviceType.UNKNOWN:
                assert device_type in VLAN_RECOMMENDATIONS or device_type in [
                    DeviceType.CONTAINER, DeviceType.VIRTUAL_MACHINE
                ]


class TestDiscoveryAgentCheckOfflineDevices:
    """Tests for offline device detection."""

    @pytest.mark.asyncio
    async def test_check_offline_device(self, agent, mock_engine):
        """Test detection of offline device."""
        device = Device(
            interfaces=[NetworkInterface(
                mac_address="00:11:22:33:44:55",
                ip_addresses=["192.168.1.100"],
                is_primary=True
            )]
        )
        device.status = DeviceStatus.ONLINE
        device.last_seen = utc_now() - timedelta(minutes=30)  # 30 mins ago
        agent._inventory.add_device(device)

        await agent._check_offline_devices()

        # Device should be marked offline
        assert device.status == DeviceStatus.OFFLINE

        # Event should be published
        mock_engine.event_bus.publish.assert_called()

    @pytest.mark.asyncio
    async def test_check_online_device_stays_online(self, agent, mock_engine):
        """Test that recently seen device stays online."""
        device = Device(
            interfaces=[NetworkInterface(
                mac_address="00:11:22:33:44:55",
                ip_addresses=["192.168.1.100"],
                is_primary=True
            )]
        )
        device.status = DeviceStatus.ONLINE
        device.last_seen = utc_now() - timedelta(minutes=5)  # 5 mins ago
        agent._inventory.add_device(device)

        await agent._check_offline_devices()

        # Device should stay online
        assert device.status == DeviceStatus.ONLINE


class TestDiscoveryAgentUpdateTopology:
    """Tests for topology updates."""

    @pytest.mark.asyncio
    async def test_update_topology_no_switch(self, agent, mock_engine):
        """Test topology update without switch integration."""
        mock_engine.get_integration.return_value = None

        await agent._update_topology()

        # Should still save topology and publish event
        mock_engine.state.set.assert_called()
        mock_engine.event_bus.publish.assert_called()

    @pytest.mark.asyncio
    async def test_update_topology_with_switch_error(self, agent, mock_engine):
        """Test topology update when switch errors."""
        mock_switch = MagicMock()
        mock_switch.get_lldp_neighbors = AsyncMock(side_effect=Exception("Switch error"))
        mock_engine.get_integration.return_value = mock_switch

        # Should not raise
        await agent._update_topology()


class TestDiscoveryAgentEventHandlers:
    """Tests for event handlers."""

    @pytest.mark.asyncio
    async def test_handle_dhcp_event_new_device(self, agent, mock_engine):
        """Test handling DHCP event for new device."""
        event = Event(
            category=EventCategory.NETWORK,
            event_type="network.dhcp.lease",
            severity=EventSeverity.INFO,
            source="router",
            title="DHCP Lease",
            data={
                "mac": "00:11:22:33:44:55",
                "ip": "192.168.1.100",
                "hostname": "test-host"
            }
        )

        # Disable port scanning for faster test
        agent.port_scan_enabled = False

        await agent._handle_dhcp_event(event)

        # Device should be in inventory
        device = agent._inventory.get_by_mac("00:11:22:33:44:55")
        assert device is not None
        assert device.hostname == "test-host"

    @pytest.mark.asyncio
    async def test_handle_dhcp_event_existing_device(self, agent, mock_engine):
        """Test handling DHCP event for existing device."""
        # Add device first
        device = Device(
            interfaces=[NetworkInterface(
                mac_address="00:11:22:33:44:55",
                ip_addresses=["192.168.1.100"],
                is_primary=True
            )]
        )
        agent._inventory.add_device(device)

        event = Event(
            category=EventCategory.NETWORK,
            event_type="network.dhcp.lease",
            severity=EventSeverity.INFO,
            source="router",
            title="DHCP Lease",
            data={
                "mac": "00:11:22:33:44:55",
                "ip": "192.168.1.100"
            }
        )

        await agent._handle_dhcp_event(event)

        # Should not add duplicate
        assert len(agent._inventory.devices) == 1

    @pytest.mark.asyncio
    async def test_handle_dhcp_event_incomplete_data(self, agent, mock_engine):
        """Test handling DHCP event with incomplete data."""
        event = Event(
            category=EventCategory.NETWORK,
            event_type="network.dhcp.lease",
            severity=EventSeverity.INFO,
            source="router",
            title="DHCP Lease",
            data={"mac": None, "ip": None}
        )

        await agent._handle_dhcp_event(event)

        # Should not add anything
        assert len(agent._inventory.devices) == 0

    @pytest.mark.asyncio
    async def test_handle_arp_event_existing_device(self, agent, mock_engine):
        """Test handling ARP event updates last_seen."""
        # Add device first
        device = Device(
            interfaces=[NetworkInterface(
                mac_address="00:11:22:33:44:55",
                ip_addresses=["192.168.1.100"],
                is_primary=True
            )]
        )
        device.status = DeviceStatus.OFFLINE
        device.last_seen = utc_now() - timedelta(hours=1)
        agent._inventory.add_device(device)

        event = Event(
            category=EventCategory.NETWORK,
            event_type="network.arp.new",
            severity=EventSeverity.INFO,
            source="router",
            title="ARP Entry",
            data={
                "mac": "00:11:22:33:44:55",
                "ip": "192.168.1.100"
            }
        )

        await agent._handle_arp_event(event)

        # Should update last_seen and status
        assert device.status == DeviceStatus.ONLINE

    @pytest.mark.asyncio
    async def test_handle_arp_event_unknown_device(self, agent, mock_engine):
        """Test handling ARP event for unknown device."""
        event = Event(
            category=EventCategory.NETWORK,
            event_type="network.arp.new",
            severity=EventSeverity.INFO,
            source="router",
            title="ARP Entry",
            data={
                "mac": "00:11:22:33:44:55",
                "ip": "192.168.1.100"
            }
        )

        await agent._handle_arp_event(event)

        # Should not add device (handled in next scan)
        assert len(agent._inventory.devices) == 0


class TestDiscoveryAgentDoExecute:
    """Tests for action execution."""

    @pytest.mark.asyncio
    async def test_do_execute_assign_vlan(self, agent, mock_engine):
        """Test VLAN assignment execution."""
        # Add device to inventory
        device = Device(
            interfaces=[NetworkInterface(
                mac_address="00:11:22:33:44:55",
                ip_addresses=["192.168.1.100"],
                is_primary=True
            )]
        )
        agent._inventory.add_device(device)

        # Mock switch
        mock_switch = MagicMock()
        mock_switch.set_port_vlan = AsyncMock()
        mock_engine.get_integration.return_value = mock_switch

        from sentinel.core.models.event import AgentAction
        action = AgentAction(
            agent_name="discovery",
            action_type="assign_vlan",
            target_type="device",
            target_id=str(device.id),
            parameters={
                "vlan_id": 100,
                "mac": "00:11:22:33:44:55"
            },
            reasoning="Test",
            confidence=0.95
        )

        result = await agent._do_execute(action)

        assert result["success"] is True
        assert result["assigned_vlan"] == 100
        assert device.assigned_vlan == 100

    @pytest.mark.asyncio
    async def test_do_execute_unknown_action(self, agent, mock_engine):
        """Test execution of unknown action type."""
        from sentinel.core.models.event import AgentAction
        action = AgentAction(
            agent_name="discovery",
            action_type="unknown_action",
            target_type="device",
            target_id="123",
            parameters={},
            reasoning="Test",
            confidence=0.95
        )

        with pytest.raises(ValueError, match="Unknown action type"):
            await agent._do_execute(action)


class TestDiscoveryAgentRollback:
    """Tests for action rollback."""

    @pytest.mark.asyncio
    async def test_capture_rollback_data(self, agent):
        """Test capturing rollback data."""
        # Add device with existing VLAN
        device = Device(
            interfaces=[NetworkInterface(
                mac_address="00:11:22:33:44:55",
                ip_addresses=["192.168.1.100"],
                is_primary=True
            )]
        )
        device.assigned_vlan = 10
        agent._inventory.add_device(device)

        from sentinel.core.models.event import AgentAction
        action = AgentAction(
            agent_name="discovery",
            action_type="assign_vlan",
            target_type="device",
            target_id=str(device.id),
            parameters={"mac": "00:11:22:33:44:55", "vlan_id": 100},
            reasoning="Test",
            confidence=0.95
        )

        rollback_data = await agent._capture_rollback_data(action)

        assert rollback_data["previous_vlan"] == 10
        assert rollback_data["mac"] == "00:11:22:33:44:55"

    @pytest.mark.asyncio
    async def test_do_rollback(self, agent, mock_engine):
        """Test rollback execution."""
        # Add device
        device = Device(
            interfaces=[NetworkInterface(
                mac_address="00:11:22:33:44:55",
                ip_addresses=["192.168.1.100"],
                is_primary=True
            )]
        )
        device.assigned_vlan = 100
        agent._inventory.add_device(device)

        # Mock switch
        mock_switch = MagicMock()
        mock_switch.set_port_vlan = AsyncMock()
        mock_engine.get_integration.return_value = mock_switch

        from sentinel.core.models.event import AgentAction
        action = AgentAction(
            agent_name="discovery",
            action_type="assign_vlan",
            target_type="device",
            target_id=str(device.id),
            parameters={"mac": "00:11:22:33:44:55", "vlan_id": 100},
            reasoning="Test",
            confidence=0.95,
            rollback_data={"previous_vlan": 10, "mac": "00:11:22:33:44:55"}
        )

        await agent._do_rollback(action)

        # Should restore previous VLAN
        assert device.assigned_vlan == 10
        mock_switch.set_port_vlan.assert_called_once()


class TestDiscoveryAgentGetRelevantState:
    """Tests for _get_relevant_state."""

    @pytest.mark.asyncio
    async def test_get_relevant_state(self, agent):
        """Test getting relevant state."""
        # Add some devices
        for i in range(3):
            device = Device(
                interfaces=[NetworkInterface(
                    mac_address=f"00:11:22:33:44:{i:02d}",
                    ip_addresses=[f"192.168.1.{100+i}"],
                    is_primary=True
                )]
            )
            device.device_type = DeviceType.WORKSTATION
            agent._inventory.add_device(device)

        state = await agent._get_relevant_state()

        assert state["device_count"] == 3


class TestDiscoveryAgentProperties:
    """Tests for agent properties."""

    def test_inventory_property(self, agent):
        """Test inventory property."""
        assert agent.inventory is agent._inventory

    def test_topology_property(self, agent):
        """Test topology property."""
        assert agent.topology is agent._topology


class TestDiscoveryAgentAnalyze:
    """Tests for analyze method."""

    @pytest.mark.asyncio
    async def test_analyze_returns_none(self, agent):
        """Test that analyze returns None (handled elsewhere)."""
        event = Event(
            category=EventCategory.DEVICE,
            event_type="device.discovered",
            severity=EventSeverity.INFO,
            source="test",
            title="Test"
        )

        result = await agent.analyze(event)

        assert result is None


class TestDiscoveryAgentQuickScan:
    """Tests for quick scan."""

    @pytest.mark.asyncio
    async def test_perform_quick_scan(self, agent, mock_engine):
        """Test quick scan execution."""
        mock_router = MagicMock()
        mock_router.get_arp_table = AsyncMock(return_value=[
            {"mac": "00:50:56:AA:BB:CC", "ip": "192.168.1.10"}
        ])
        mock_engine.get_integration.return_value = mock_router

        await agent._perform_quick_scan()

        # Should have scanned
        mock_router.get_arp_table.assert_called_once()


class TestDiscoveryAgentFullScan:
    """Tests for full scan."""

    @pytest.mark.asyncio
    async def test_perform_full_scan(self, agent, mock_engine):
        """Test full scan execution."""
        # Disable port scanning for speed
        agent.port_scan_enabled = False

        mock_router = MagicMock()
        mock_router.get_arp_table = AsyncMock(return_value=[
            {"mac": "00:50:56:AA:BB:CC", "ip": "192.168.1.10"}
        ])
        mock_engine.get_integration.return_value = mock_router

        await agent._perform_full_scan()

        # Should have saved state
        mock_engine.state.set.assert_called()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
