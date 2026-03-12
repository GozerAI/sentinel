"""
Integration tests for API with SentinelEngine.

Tests the full API functionality when connected to a real engine instance.
"""

import asyncio
import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

from fastapi.testclient import TestClient

from sentinel.core.engine import SentinelEngine
from sentinel.core.models.device import Device, DeviceType, NetworkInterface, DeviceStatus
from sentinel.core.models.event import Event, EventCategory, EventSeverity
from sentinel.api.app import create_app
import sentinel.api.auth as auth_module


class TestAPIEngineIntegration:
    """Tests for API integration with engine."""

    @pytest.fixture
    def engine_config(self):
        """Configuration for integration test engine."""
        return {
            "agents": {
                "discovery": {"enabled": True, "networks": ["192.168.1.0/24"]},
                "guardian": {"enabled": True, "quarantine_vlan": 666},
                "planner": {"enabled": True},
                "optimizer": {"enabled": True},
                "healer": {"enabled": True},
            },
            "state": {"backend": "memory"},
            "api": {"auth": {"enabled": False}},  # Disable auth for testing
        }

    @pytest.fixture
    async def engine(self, engine_config):
        """Create and start an engine for testing."""
        engine = SentinelEngine(engine_config)
        await engine.start()
        yield engine
        await engine.stop()

    @pytest.fixture
    def client(self, engine):
        """Create test client with real engine."""
        # Disable auth
        original_auth = getattr(auth_module, "_auth_config", None)
        auth_module._auth_config = None

        app = create_app(engine)

        try:
            yield TestClient(app)
        finally:
            auth_module._auth_config = original_auth

    def test_status_reflects_engine_state(self, client, engine):
        """Test that /status endpoint reflects real engine state."""
        response = client.get("/status")

        assert response.status_code == 200
        data = response.json()

        assert data["status"] == "running"
        assert data["uptime_seconds"] >= 0

        # Verify agents are reported
        assert "agents" in data
        assert len(data["agents"]) == 5  # All 5 agents enabled

    def test_devices_endpoint_reflects_inventory(self, client, engine):
        """Test that /devices endpoint shows inventory contents."""
        # Add a device to inventory
        discovery = engine.get_agent("discovery")
        device = Device(
            id=uuid4(),
            device_type=DeviceType.WORKSTATION,
            hostname="integration-test-device",
            interfaces=[
                NetworkInterface(
                    mac_address="AA:BB:CC:DD:EE:FF",
                    ip_addresses=["192.168.1.150"],
                )
            ],
        )
        discovery._inventory.add_device(device)

        # Query devices endpoint
        response = client.get("/devices")

        assert response.status_code == 200
        data = response.json()

        assert data["total"] >= 1
        device_macs = [d["mac"] for d in data["devices"]]
        assert "AA:BB:CC:DD:EE:FF" in device_macs

    def test_get_device_by_mac(self, client, engine):
        """Test retrieving specific device by MAC address."""
        # Add a device
        discovery = engine.get_agent("discovery")
        device = Device(
            id=uuid4(),
            device_type=DeviceType.SERVER,
            hostname="test-server",
            interfaces=[
                NetworkInterface(
                    mac_address="11:22:33:44:55:66",
                    ip_addresses=["192.168.1.10"],
                )
            ],
        )
        discovery._inventory.add_device(device)

        # Query by MAC
        response = client.get("/devices/11:22:33:44:55:66")

        assert response.status_code == 200
        data = response.json()
        assert data["hostname"] == "test-server"
        assert data["device_type"] == "server"

    def test_devices_filter_by_type(self, client, engine):
        """Test filtering devices by type."""
        discovery = engine.get_agent("discovery")

        # Add devices of different types
        workstation = Device(
            device_type=DeviceType.WORKSTATION,
            hostname="ws-01",
            interfaces=[NetworkInterface(mac_address="WS:01:00:00:00:01")],
        )
        server = Device(
            device_type=DeviceType.SERVER,
            hostname="srv-01",
            interfaces=[NetworkInterface(mac_address="SV:01:00:00:00:01")],
        )
        iot = Device(
            device_type=DeviceType.IOT,
            hostname="iot-01",
            interfaces=[NetworkInterface(mac_address="IO:01:00:00:00:01")],
        )

        discovery._inventory.add_device(workstation)
        discovery._inventory.add_device(server)
        discovery._inventory.add_device(iot)

        # Filter by workstation
        response = client.get("/devices?device_type=workstation")
        assert response.status_code == 200
        data = response.json()

        # Only workstations should be returned
        for device in data["devices"]:
            assert device["device_type"] == "workstation"

    def test_vlans_endpoint_reflects_planner(self, client, engine):
        """Test that /vlans endpoint shows planner's VLANs."""
        planner = engine.get_agent("planner")

        # Add VLANs to planner
        planner._vlans[10] = {
            "id": 10,
            "name": "Management",
            "subnet": "192.168.10.0/24",
            "isolated": False,
        }
        planner._vlans[20] = {
            "id": 20,
            "name": "Servers",
            "subnet": "192.168.20.0/24",
            "isolated": False,
        }

        response = client.get("/vlans")

        assert response.status_code == 200
        data = response.json()

        assert len(data) >= 2
        vlan_ids = [v["id"] for v in data]
        assert 10 in vlan_ids
        assert 20 in vlan_ids

    def test_create_vlan_updates_planner(self, client, engine):
        """Test that creating a VLAN updates planner state."""
        response = client.post(
            "/vlans",
            json={
                "id": 100,
                "name": "Test VLAN",
                "subnet": "192.168.100.0/24",
                "purpose": "testing",
                "isolated": True,
            },
        )

        assert response.status_code == 200

        # Verify planner has the VLAN
        planner = engine.get_agent("planner")
        assert 100 in planner._vlans
        assert planner._vlans[100]["name"] == "Test VLAN"
        assert planner._vlans[100]["isolated"] is True

    def test_agents_endpoint_shows_all_agents(self, client, engine):
        """Test that /agents endpoint lists all running agents."""
        response = client.get("/agents")

        assert response.status_code == 200
        data = response.json()

        # Should have all 5 agents
        assert len(data) == 5

        agent_names = [a["name"] for a in data]
        assert "discovery" in agent_names
        assert "guardian" in agent_names
        assert "planner" in agent_names
        assert "optimizer" in agent_names
        assert "healer" in agent_names

        # All should be enabled
        for agent in data:
            assert agent["enabled"] is True

    def test_security_blocked_shows_guardian_state(self, client, engine):
        """Test that security endpoints reflect guardian state."""
        guardian = engine.get_agent("guardian")

        # Block some IPs
        guardian._blocked_ips.add("10.0.0.100")
        guardian._blocked_ips.add("10.0.0.101")

        response = client.get("/security/blocked")

        assert response.status_code == 200
        data = response.json()

        assert data["count"] == 2
        assert "10.0.0.100" in data["blocked_ips"]
        assert "10.0.0.101" in data["blocked_ips"]

    def test_quarantined_shows_guardian_state(self, client, engine):
        """Test quarantined devices endpoint."""
        guardian = engine.get_agent("guardian")

        # Quarantine some devices
        guardian._quarantined_devices.add("device-001")
        guardian._quarantined_devices.add("device-002")

        response = client.get("/security/quarantined")

        assert response.status_code == 200
        data = response.json()

        assert data["count"] == 2
        assert "device-001" in data["quarantined"]

    def test_health_endpoint_always_works(self, client):
        """Test that health endpoint works without engine queries."""
        response = client.get("/health")

        assert response.status_code == 200
        data = response.json()

        assert data["status"] == "healthy"
        assert "timestamp" in data

    def test_metrics_endpoint_returns_prometheus_format(self, client):
        """Test that /metrics returns valid Prometheus format."""
        response = client.get("/metrics")

        assert response.status_code == 200
        assert "text" in response.headers["content-type"]

        content = response.text
        # Should contain sentinel metrics
        assert "sentinel_" in content


class TestAPIScanIntegration:
    """Tests for scan-related API endpoints."""

    @pytest.fixture
    def engine_config(self):
        return {
            "agents": {
                "discovery": {"enabled": True},
            },
            "state": {"backend": "memory"},
        }

    @pytest.fixture
    async def engine(self, engine_config):
        engine = SentinelEngine(engine_config)
        await engine.start()
        yield engine
        await engine.stop()

    @pytest.fixture
    def client(self, engine):
        original_auth = getattr(auth_module, "_auth_config", None)
        auth_module._auth_config = None
        app = create_app(engine)
        try:
            yield TestClient(app)
        finally:
            auth_module._auth_config = original_auth

    def test_quick_scan_triggers_discovery(self, client, engine):
        """Test that quick scan endpoint triggers discovery."""
        response = client.post("/scan/quick")

        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "scan_initiated"
        assert data["type"] == "quick"

    def test_full_scan_triggers_discovery(self, client, engine):
        """Test that full scan endpoint triggers discovery."""
        response = client.post("/scan/full")

        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "scan_initiated"
        assert data["type"] == "full"

    def test_device_scan_triggers_fingerprinting(self, client, engine):
        """Test that device scan triggers fingerprinting."""
        # Add a device first
        discovery = engine.get_agent("discovery")
        device = Device(
            device_type=DeviceType.WORKSTATION,
            hostname="scan-test",
            interfaces=[
                NetworkInterface(
                    mac_address="SC:AN:00:00:00:01",
                    ip_addresses=["192.168.1.200"],
                )
            ],
        )
        discovery._inventory.add_device(device)

        response = client.post("/devices/SC:AN:00:00:00:01/scan")

        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "scan_initiated"


class TestAPIEventIntegration:
    """Tests for event-related API endpoints."""

    @pytest.fixture
    def engine_config(self):
        return {
            "agents": {
                "discovery": {"enabled": True},
            },
            "state": {"backend": "memory"},
        }

    @pytest.fixture
    async def engine(self, engine_config):
        engine = SentinelEngine(engine_config)
        await engine.start()
        yield engine
        await engine.stop()

    @pytest.fixture
    def client(self, engine):
        original_auth = getattr(auth_module, "_auth_config", None)
        auth_module._auth_config = None
        app = create_app(engine)
        try:
            yield TestClient(app)
        finally:
            auth_module._auth_config = original_auth

    def test_events_list_shows_bus_history(self, client, engine):
        """Test that events endpoint shows event bus history."""

        # Publish some events to the bus
        async def publish_events():
            for i in range(3):
                event = Event(
                    category=EventCategory.SYSTEM,
                    event_type=f"test.event.{i}",
                    severity=EventSeverity.INFO,
                    source="test",
                    title=f"Test event {i}",
                )
                await engine.event_bus.publish(event)

        asyncio.get_event_loop().run_until_complete(publish_events())

        response = client.get("/events")
        assert response.status_code == 200

    def test_events_filter_by_category(self, client, engine):
        """Test filtering events by category."""

        # Publish events of different categories
        async def publish_events():
            await engine.event_bus.publish(
                Event(
                    category=EventCategory.SECURITY,
                    event_type="security.alert",
                    severity=EventSeverity.WARNING,
                    source="test",
                    title="Security event",
                )
            )
            await engine.event_bus.publish(
                Event(
                    category=EventCategory.NETWORK,
                    event_type="network.change",
                    severity=EventSeverity.INFO,
                    source="test",
                    title="Network event",
                )
            )

        asyncio.get_event_loop().run_until_complete(publish_events())

        response = client.get("/events?category=security")
        assert response.status_code == 200


class TestAPIPolicyIntegration:
    """Tests for policy-related API endpoints."""

    @pytest.fixture
    def engine_config(self):
        return {
            "agents": {
                "planner": {"enabled": True},
            },
            "state": {"backend": "memory"},
        }

    @pytest.fixture
    async def engine(self, engine_config):
        engine = SentinelEngine(engine_config)
        await engine.start()
        yield engine
        await engine.stop()

    @pytest.fixture
    def client(self, engine):
        original_auth = getattr(auth_module, "_auth_config", None)
        auth_module._auth_config = None
        app = create_app(engine)
        try:
            yield TestClient(app)
        finally:
            auth_module._auth_config = original_auth

    def test_policies_shows_planner_policies(self, client, engine):
        """Test that policies endpoint shows planner's policies."""
        planner = engine.get_agent("planner")

        # Add a segmentation policy
        planner._segmentation_policies["ws-to-srv"] = {
            "id": "ws-to-srv",
            "name": "Workstations to Servers",
            "source_vlan": 10,
            "destination_vlan": 20,
            "allowed_services": ["http", "https", "ssh"],
            "denied_services": [],
            "default_action": "deny",
        }

        response = client.get("/policies")

        assert response.status_code == 200
        data = response.json()

        assert len(data) >= 1
        policy_names = [p["name"] for p in data]
        assert "Workstations to Servers" in policy_names

    def test_firewall_rules_shows_planner_rules(self, client, engine):
        """Test that firewall rules endpoint shows planner's rules."""
        planner = engine.get_agent("planner")

        # Add a firewall rule
        planner._firewall_rules["allow-ssh"] = {
            "id": "allow-ssh",
            "name": "Allow SSH",
            "description": "Allow SSH from management",
            "action": "allow",
            "source_zone": "management",
            "destination_port": 22,
            "protocol": "tcp",
            "auto_generated": True,
        }

        response = client.get("/firewall-rules")

        assert response.status_code == 200
        data = response.json()

        assert len(data) >= 1
        rule_names = [r["name"] for r in data]
        assert "Allow SSH" in rule_names


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
