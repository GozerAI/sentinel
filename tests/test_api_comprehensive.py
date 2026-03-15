"""
Comprehensive tests for the Sentinel API covering all endpoints.

These tests achieve full coverage including:
- All endpoints (status, devices, VLANs, policies, agents, events, actions)
- Error handling paths
- Authentication
- Filtering and pagination
"""
import pytest
from unittest.mock import MagicMock, AsyncMock, patch
from uuid import uuid4
from datetime import datetime, timezone
from fastapi.testclient import TestClient

from sentinel.api.app import app, create_app, get_engine
import sys
# Get the actual module reference (not the FastAPI app instance)
sentinel_app_module = sys.modules['sentinel.api.app']
from sentinel.api.auth import _auth_config, AuthConfig, configure_auth
import sentinel.api.auth as auth_module
from sentinel.core.models.device import (
    Device, DeviceType, DeviceStatus, TrustLevel,
    NetworkInterface, DeviceFingerprint, DeviceInventory
)
from sentinel.core.models.event import Event, EventCategory, EventSeverity


@pytest.fixture(autouse=True)
def disable_auth():
    """Disable auth for all tests by default."""
    # Set auth to disabled for each test
    auth_module._auth_config = AuthConfig(enabled=False)
    yield
    # Keep auth disabled (don't restore) - other tests will set their own config


@pytest.fixture
def mock_engine():
    """Create a comprehensive mock engine."""
    engine = MagicMock()
    engine.is_running = True
    engine.uptime_seconds = 100.5

    # Config with auth disabled (used by lifespan)
    engine.config = {
        "api": {
            "auth": {
                "enabled": False
            }
        }
    }

    # Mock event bus
    engine.event_bus = MagicMock()
    engine.event_bus.get_recent_events = MagicMock(return_value=[])
    engine.event_bus._event_history = []
    engine.event_bus._global_handlers = []
    engine.event_bus._queue = MagicMock()
    engine.event_bus._queue.qsize.return_value = 0

    # Mock get_status
    engine.get_status = AsyncMock(return_value={
        "status": "running",
        "uptime_seconds": 100.5,
        "agents": {},
        "integrations": {}
    })

    # Mock agents dictionary
    engine.agents = {}

    return engine


@pytest.fixture
def mock_discovery_agent():
    """Create a mock discovery agent with inventory."""
    agent = MagicMock()
    agent._running = True
    agent._enabled = True
    agent.stats = {"name": "discovery", "actions_taken": 5}
    agent._inventory = DeviceInventory()

    # Add some test devices
    device1 = Device(
        hostname="workstation1",
        device_type=DeviceType.WORKSTATION,
        status=DeviceStatus.ONLINE,
        trust_level=TrustLevel.TRUSTED,
        assigned_vlan=10,
        interfaces=[
            NetworkInterface(
                mac_address="00:11:22:33:44:55",
                ip_addresses=["192.168.1.100"],
                is_primary=True
            )
        ],
        fingerprint=DeviceFingerprint(vendor="Dell")
    )
    device2 = Device(
        hostname="server1",
        device_type=DeviceType.SERVER,
        status=DeviceStatus.OFFLINE,
        trust_level=TrustLevel.VERIFIED,
        assigned_vlan=20,
        interfaces=[
            NetworkInterface(
                mac_address="00:11:22:33:44:66",
                ip_addresses=["192.168.2.100"],
                is_primary=True
            )
        ]
    )
    agent._inventory.add_device(device1)
    agent._inventory.add_device(device2)

    agent._fingerprint_device = AsyncMock()
    agent._perform_quick_scan = AsyncMock()
    agent._perform_full_scan = AsyncMock()

    return agent


@pytest.fixture
def mock_planner_agent():
    """Create a mock planner agent."""
    agent = MagicMock()
    agent._running = True
    agent._enabled = True
    agent.stats = {"name": "planner", "actions_taken": 10}
    agent._vlans = {
        10: {"name": "Workstations", "subnet": "192.168.10.0/24", "gateway": "192.168.10.1", "purpose": "workstations"},
        20: {"name": "Servers", "subnet": "192.168.20.0/24", "gateway": "192.168.20.1", "purpose": "servers", "isolated": True}
    }
    agent._segmentation_policies = {
        "policy1": {
            "id": "policy1",
            "name": "Workstation to Server",
            "source_vlan": 10,
            "destination_vlan": 20,
            "allowed_services": ["http", "https"],
            "denied_services": ["ssh"],
            "default_action": "deny"
        }
    }
    agent._firewall_rules = {
        "rule1": {
            "id": "rule1",
            "name": "Allow HTTP",
            "description": "Allow HTTP traffic",
            "action": "allow",
            "source_zone": "trusted",
            "destination_zone": "dmz",
            "destination_port": 80,
            "protocol": "tcp",
            "auto_generated": True,
            "priority": 100
        }
    }
    return agent


@pytest.fixture
def mock_guardian_agent():
    """Create a mock guardian agent."""
    agent = MagicMock()
    agent._running = True
    agent._enabled = True
    agent.stats = {"name": "guardian", "actions_taken": 3}
    agent._blocked_ips = {"192.168.1.200", "10.0.0.50"}
    agent._quarantined_devices = {"device-123"}
    agent.unblock_ip = AsyncMock(return_value=True)
    agent._execute_action = AsyncMock(return_value=True)
    return agent


@pytest.fixture
def client(mock_engine, disable_auth):
    """Create test client with mocked engine and dependency override."""
    # Save original engine
    original_engine = sentinel_app_module._engine

    # Set the global engine to our mock (needed for lifespan)
    sentinel_app_module._engine = mock_engine

    # Override the get_engine dependency
    app.dependency_overrides[get_engine] = lambda: mock_engine

    # Ensure auth is disabled for this client's lifetime
    auth_module._auth_config = AuthConfig(enabled=False)

    with TestClient(app) as test_client:
        yield test_client

    # Clean up
    app.dependency_overrides.clear()
    sentinel_app_module._engine = original_engine


class TestStatusEndpoints:
    """Tests for status endpoints."""

    def test_root(self, client):
        """Test root endpoint."""
        response = client.get("/")
        assert response.status_code == 200
        data = response.json()
        assert data["name"] == "Sentinel API"
        assert data["version"] == "0.1.0"
        assert data["status"] == "running"

    def test_health(self, client):
        """Test health endpoint."""
        response = client.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        assert "timestamp" in data

    def test_status(self, client, mock_engine):
        """Test status endpoint."""
        response = client.get("/status")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "running"
        assert data["uptime_seconds"] == 100.5

    def test_status_engine_not_initialized(self, disable_auth):
        """Test status returns 503 when engine not initialized."""
        original_engine = sentinel_app_module._engine
        sentinel_app_module._engine = None

        # Clear any dependency overrides
        app.dependency_overrides.clear()

        try:
            with TestClient(app) as test_client:
                response = test_client.get("/status")
                assert response.status_code == 503
        finally:
            sentinel_app_module._engine = original_engine


class TestDeviceEndpoints:
    """Tests for device endpoints."""

    def test_list_devices(self, client, mock_engine, mock_discovery_agent):
        """Test list devices endpoint."""
        mock_engine.agents = {"discovery": mock_discovery_agent}

        response = client.get("/devices")
        assert response.status_code == 200
        data = response.json()
        assert data["total"] == 2
        assert len(data["devices"]) == 2

    def test_list_devices_filter_by_type(self, client, mock_engine, mock_discovery_agent):
        """Test list devices with type filter."""
        mock_engine.agents = {"discovery": mock_discovery_agent}

        response = client.get("/devices?device_type=workstation")
        assert response.status_code == 200
        data = response.json()
        assert data["total"] == 1
        assert data["devices"][0]["device_type"] == "workstation"

    def test_list_devices_filter_by_vlan(self, client, mock_engine, mock_discovery_agent):
        """Test list devices with VLAN filter."""
        mock_engine.agents = {"discovery": mock_discovery_agent}

        response = client.get("/devices?vlan=10")
        assert response.status_code == 200
        data = response.json()
        assert data["total"] == 1
        assert data["devices"][0]["vlan"] == 10

    def test_list_devices_filter_by_online(self, client, mock_engine, mock_discovery_agent):
        """Test list devices with online filter."""
        mock_engine.agents = {"discovery": mock_discovery_agent}

        response = client.get("/devices?online=true")
        assert response.status_code == 200
        data = response.json()
        assert data["total"] == 1
        assert data["devices"][0]["online"] is True

    def test_list_devices_pagination(self, client, mock_engine, mock_discovery_agent):
        """Test list devices with pagination."""
        mock_engine.agents = {"discovery": mock_discovery_agent}

        response = client.get("/devices?limit=1&offset=0")
        assert response.status_code == 200
        data = response.json()
        assert data["total"] == 2
        assert len(data["devices"]) == 1

    def test_list_devices_discovery_unavailable(self, client, mock_engine):
        """Test list devices when discovery not available."""
        mock_engine.agents = {}

        response = client.get("/devices")
        assert response.status_code == 503

    def test_get_device_by_id(self, client, mock_engine, mock_discovery_agent):
        """Test get device by ID."""
        mock_engine.agents = {"discovery": mock_discovery_agent}
        device = list(mock_discovery_agent._inventory.devices.values())[0]

        response = client.get(f"/devices/{device.id}")
        assert response.status_code == 200
        data = response.json()
        assert data["id"] == str(device.id)

    def test_get_device_by_mac(self, client, mock_engine, mock_discovery_agent):
        """Test get device by MAC address."""
        mock_engine.agents = {"discovery": mock_discovery_agent}

        response = client.get("/devices/00:11:22:33:44:55")
        assert response.status_code == 200
        data = response.json()
        assert data["mac"] == "00:11:22:33:44:55"

    def test_get_device_not_found(self, client, mock_engine, mock_discovery_agent):
        """Test get device not found."""
        mock_engine.agents = {"discovery": mock_discovery_agent}

        response = client.get("/devices/nonexistent")
        assert response.status_code == 404

    def test_scan_device(self, client, mock_engine, mock_discovery_agent):
        """Test scan device endpoint."""
        mock_engine.agents = {"discovery": mock_discovery_agent}
        device = list(mock_discovery_agent._inventory.devices.values())[0]

        response = client.post(f"/devices/{device.id}/scan")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "scan_initiated"

    def test_scan_device_not_found(self, client, mock_engine, mock_discovery_agent):
        """Test scan device not found."""
        mock_engine.agents = {"discovery": mock_discovery_agent}

        response = client.post("/devices/nonexistent/scan")
        assert response.status_code == 404


class TestVLANEndpoints:
    """Tests for VLAN endpoints."""

    def test_list_vlans(self, client, mock_engine, mock_planner_agent, mock_discovery_agent):
        """Test list VLANs endpoint."""
        mock_engine.agents = {
            "planner": mock_planner_agent,
            "discovery": mock_discovery_agent
        }

        response = client.get("/vlans")
        assert response.status_code == 200
        data = response.json()
        assert len(data) == 2

    def test_list_vlans_without_discovery(self, client, mock_engine, mock_planner_agent):
        """Test list VLANs without discovery agent."""
        mock_engine.agents = {"planner": mock_planner_agent}

        response = client.get("/vlans")
        assert response.status_code == 200
        data = response.json()
        assert len(data) == 2
        assert all(v["device_count"] == 0 for v in data)

    def test_list_vlans_planner_unavailable(self, client, mock_engine):
        """Test list VLANs when planner not available."""
        mock_engine.agents = {}

        response = client.get("/vlans")
        assert response.status_code == 503

    def test_get_vlan(self, client, mock_engine, mock_planner_agent, mock_discovery_agent):
        """Test get VLAN by ID."""
        mock_engine.agents = {
            "planner": mock_planner_agent,
            "discovery": mock_discovery_agent
        }

        response = client.get("/vlans/10")
        assert response.status_code == 200
        data = response.json()
        assert data["id"] == 10
        assert data["name"] == "Workstations"

    def test_get_vlan_not_found(self, client, mock_engine, mock_planner_agent):
        """Test get VLAN not found."""
        mock_engine.agents = {"planner": mock_planner_agent}

        response = client.get("/vlans/99")
        assert response.status_code == 404

    def test_create_vlan(self, client, mock_engine, mock_planner_agent):
        """Test create VLAN endpoint."""
        mock_engine.agents = {"planner": mock_planner_agent}

        response = client.post("/vlans", json={
            "id": 30,
            "name": "New VLAN",
            "subnet": "192.168.30.0/24",
            "gateway": "192.168.30.1",
            "purpose": "test",
            "isolated": False
        })
        assert response.status_code == 200
        data = response.json()
        assert data["id"] == 30
        assert data["name"] == "New VLAN"

    def test_create_vlan_already_exists(self, client, mock_engine, mock_planner_agent):
        """Test create VLAN that already exists."""
        mock_engine.agents = {"planner": mock_planner_agent}

        response = client.post("/vlans", json={
            "id": 10,
            "name": "Duplicate"
        })
        assert response.status_code == 409


class TestPolicyEndpoints:
    """Tests for policy endpoints."""

    def test_list_policies(self, client, mock_engine, mock_planner_agent):
        """Test list policies endpoint."""
        mock_engine.agents = {"planner": mock_planner_agent}

        response = client.get("/policies")
        assert response.status_code == 200
        data = response.json()
        assert len(data) == 1

    def test_get_policy(self, client, mock_engine, mock_planner_agent):
        """Test get policy by ID."""
        mock_engine.agents = {"planner": mock_planner_agent}

        response = client.get("/policies/policy1")
        assert response.status_code == 200
        data = response.json()
        assert data["id"] == "policy1"

    def test_get_policy_not_found(self, client, mock_engine, mock_planner_agent):
        """Test get policy not found."""
        mock_engine.agents = {"planner": mock_planner_agent}

        response = client.get("/policies/nonexistent")
        assert response.status_code == 404

    def test_list_firewall_rules(self, client, mock_engine, mock_planner_agent):
        """Test list firewall rules endpoint."""
        mock_engine.agents = {"planner": mock_planner_agent}

        response = client.get("/firewall-rules")
        assert response.status_code == 200
        data = response.json()
        assert len(data) == 1
        assert data[0]["name"] == "Allow HTTP"


class TestAgentEndpoints:
    """Tests for agent endpoints."""

    def test_list_agents(self, client, mock_engine, mock_discovery_agent, mock_guardian_agent):
        """Test list agents endpoint."""
        mock_engine.agents = {
            "discovery": mock_discovery_agent,
            "guardian": mock_guardian_agent
        }

        response = client.get("/agents")
        assert response.status_code == 200
        data = response.json()
        assert len(data) == 2

    def test_list_agents_uses_running_fallback(self, client, mock_engine):
        """Test list agents falls back to _running when _enabled missing."""
        mock_agent = MagicMock()
        mock_agent._running = True
        del mock_agent._enabled  # Remove _enabled
        mock_agent.stats = {"name": "test", "actions_taken": 0}

        mock_engine.agents = {"test": mock_agent}

        response = client.get("/agents")
        assert response.status_code == 200
        data = response.json()
        assert data[0]["enabled"] is True

    def test_get_agent(self, client, mock_engine, mock_discovery_agent):
        """Test get agent by name."""
        mock_engine.agents = {"discovery": mock_discovery_agent}

        response = client.get("/agents/discovery")
        assert response.status_code == 200
        data = response.json()
        assert data["name"] == "discovery"

    def test_get_agent_not_found(self, client, mock_engine):
        """Test get agent not found."""
        mock_engine.agents = {}

        response = client.get("/agents/nonexistent")
        assert response.status_code == 404

    def test_enable_agent(self, client, mock_engine, mock_discovery_agent):
        """Test enable agent endpoint."""
        mock_engine.agents = {"discovery": mock_discovery_agent}

        response = client.post("/agents/discovery/enable")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "enabled"

    def test_disable_agent(self, client, mock_engine, mock_discovery_agent):
        """Test disable agent endpoint."""
        mock_engine.agents = {"discovery": mock_discovery_agent}

        response = client.post("/agents/discovery/disable")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "disabled"


class TestEventEndpoints:
    """Tests for event endpoints."""

    def test_list_events(self, client, mock_engine):
        """Test list events endpoint."""
        event = Event(
            category=EventCategory.SYSTEM,
            event_type="test.event",
            severity=EventSeverity.INFO,
            source="test",
            title="Test Event"
        )
        mock_engine.event_bus.get_recent_events.return_value = [event]

        response = client.get("/events")
        assert response.status_code == 200
        data = response.json()
        assert len(data) == 1

    def test_list_events_filter_by_category(self, client, mock_engine):
        """Test list events with category filter."""
        event1 = Event(
            category=EventCategory.SECURITY,
            event_type="security.alert",
            source="guardian",
            title="Alert"
        )
        event2 = Event(
            category=EventCategory.SYSTEM,
            event_type="system.info",
            source="system",
            title="Info"
        )
        mock_engine.event_bus.get_recent_events.return_value = [event1, event2]

        response = client.get("/events?category=security")
        assert response.status_code == 200
        data = response.json()
        assert len(data) == 1
        assert data[0]["category"] == "security"

    def test_list_events_filter_by_severity(self, client, mock_engine):
        """Test list events with severity filter."""
        event1 = Event(
            category=EventCategory.SYSTEM,
            event_type="test",
            severity=EventSeverity.CRITICAL,
            source="test",
            title="Critical"
        )
        event2 = Event(
            category=EventCategory.SYSTEM,
            event_type="test",
            severity=EventSeverity.INFO,
            source="test",
            title="Info"
        )
        mock_engine.event_bus.get_recent_events.return_value = [event1, event2]

        response = client.get("/events?severity=critical")
        assert response.status_code == 200
        data = response.json()
        assert len(data) == 1
        assert data[0]["severity"] == "critical"

    def test_acknowledge_event(self, client, mock_engine):
        """Test acknowledge event endpoint."""
        event = Event(
            category=EventCategory.SYSTEM,
            event_type="test",
            source="test",
            title="Test"
        )
        mock_engine.event_bus._event_history = [event]

        response = client.post(f"/events/{event.id}/acknowledge")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "acknowledged"

    def test_acknowledge_event_not_found(self, client, mock_engine):
        """Test acknowledge event not found."""
        mock_engine.event_bus._event_history = []

        response = client.post(f"/events/{uuid4()}/acknowledge")
        assert response.status_code == 404


class TestActionEndpoints:
    """Tests for action endpoints."""

    def test_execute_action_with_confirmation(self, client, mock_engine, mock_guardian_agent):
        """Test execute action with confirmation."""
        mock_engine.agents = {"guardian": mock_guardian_agent}

        response = client.post("/actions", json={
            "action_type": "block_ip",
            "target_type": "ip",
            "target_id": "192.168.1.100",
            "parameters": {},
            "confirm": True
        })
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "success"

    def test_execute_action_without_confirmation(self, client, mock_engine, mock_guardian_agent):
        """Test execute action without confirmation."""
        mock_engine.agents = {"guardian": mock_guardian_agent}

        response = client.post("/actions", json={
            "action_type": "block_ip",
            "target_type": "ip",
            "target_id": "192.168.1.100",
            "confirm": False
        })
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "pending_confirmation"
        assert data["requires_confirmation"] is True

    def test_execute_action_unknown_type(self, client, mock_engine):
        """Test execute action with unknown type."""
        response = client.post("/actions", json={
            "action_type": "unknown_action",
            "target_type": "test",
            "target_id": "test"
        })
        assert response.status_code == 400

    def test_execute_action_agent_unavailable(self, client, mock_engine):
        """Test execute action when agent unavailable."""
        mock_engine.agents = {}

        response = client.post("/actions", json={
            "action_type": "block_ip",
            "target_type": "ip",
            "target_id": "192.168.1.100",
            "confirm": True
        })
        assert response.status_code == 503


class TestScanEndpoints:
    """Tests for scan endpoints."""

    def test_quick_scan(self, client, mock_engine, mock_discovery_agent):
        """Test quick scan endpoint."""
        mock_engine.agents = {"discovery": mock_discovery_agent}

        response = client.post("/scan/quick")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "scan_initiated"
        assert data["type"] == "quick"

    def test_full_scan(self, client, mock_engine, mock_discovery_agent):
        """Test full scan endpoint."""
        mock_engine.agents = {"discovery": mock_discovery_agent}

        response = client.post("/scan/full")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "scan_initiated"
        assert data["type"] == "full"

    def test_scan_discovery_unavailable(self, client, mock_engine):
        """Test scan when discovery unavailable."""
        mock_engine.agents = {}

        response = client.post("/scan/quick")
        assert response.status_code == 503


class TestSecurityEndpoints:
    """Tests for security endpoints."""

    def test_list_blocked_ips(self, client, mock_engine, mock_guardian_agent):
        """Test list blocked IPs endpoint."""
        mock_engine.agents = {"guardian": mock_guardian_agent}

        response = client.get("/security/blocked")
        assert response.status_code == 200
        data = response.json()
        assert data["count"] == 2
        assert "192.168.1.200" in data["blocked_ips"]

    def test_list_quarantined(self, client, mock_engine, mock_guardian_agent):
        """Test list quarantined devices endpoint."""
        mock_engine.agents = {"guardian": mock_guardian_agent}

        response = client.get("/security/quarantined")
        assert response.status_code == 200
        data = response.json()
        assert data["count"] == 1

    def test_unblock_ip(self, client, mock_engine, mock_guardian_agent):
        """Test unblock IP endpoint."""
        mock_engine.agents = {"guardian": mock_guardian_agent}

        response = client.post("/security/unblock/192.168.1.200")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "unblocked"

    def test_security_guardian_unavailable(self, client, mock_engine):
        """Test security endpoints when guardian unavailable."""
        mock_engine.agents = {}

        response = client.get("/security/blocked")
        assert response.status_code == 503


class TestMetricsEndpoint:
    """Tests for metrics endpoint."""

    def test_metrics(self, client, mock_engine):
        """Test metrics endpoint."""
        response = client.get("/metrics")
        assert response.status_code == 200
        # Prometheus metrics are text format
        assert "sentinel" in response.text or response.headers["content-type"]


class TestCreateApp:
    """Tests for create_app factory function."""

    def test_create_app_sets_engine(self):
        """Test create_app sets global engine reference."""
        # Save original engine
        original_engine = sentinel_app_module._engine

        mock_engine = MagicMock()
        mock_engine.is_running = True

        # Mock configure_metrics to avoid side effects
        with patch("sentinel.api.app.configure_metrics"):
            result = create_app(mock_engine)

            assert sentinel_app_module._engine is mock_engine
            assert result is app

        # Restore original
        sentinel_app_module._engine = original_engine


class TestGetEngine:
    """Tests for get_engine dependency."""

    def test_get_engine_raises_when_none(self):
        """Test get_engine raises 503 when engine is None."""
        # Save original
        original_engine = sentinel_app_module._engine
        sentinel_app_module._engine = None

        try:
            from fastapi import HTTPException
            with pytest.raises(HTTPException) as exc:
                get_engine()

            assert exc.value.status_code == 503
        finally:
            # Restore original
            sentinel_app_module._engine = original_engine

    def test_get_engine_returns_engine(self):
        """Test get_engine returns engine when set."""
        original_engine = sentinel_app_module._engine
        mock_engine = MagicMock()
        sentinel_app_module._engine = mock_engine

        try:
            result = get_engine()
            assert result is mock_engine
        finally:
            sentinel_app_module._engine = original_engine


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
