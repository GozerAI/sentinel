"""
Tests for Sentinel API endpoints.
"""
import sys
import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from fastapi.testclient import TestClient
from uuid import uuid4


class MockDevice:
    """Mock device for testing."""

    def __init__(self, device_id=None, mac="00:11:22:33:44:55"):
        from sentinel.core.models.device import DeviceType, DeviceStatus, DeviceFingerprint, TrustLevel

        self.id = device_id or uuid4()
        self.hostname = "test-device"
        self.device_type = DeviceType.WORKSTATION
        self.status = DeviceStatus.ONLINE
        self.assigned_vlan = 10
        self.trust_level = TrustLevel.UNKNOWN
        self.last_seen = None
        self.interfaces = [MockInterface(mac)]
        self.fingerprint = DeviceFingerprint(vendor="Test Vendor")

    @property
    def primary_mac(self):
        return self.interfaces[0].mac_address if self.interfaces else None

    @property
    def primary_ip(self):
        return "192.168.1.100"


class MockInterface:
    """Mock network interface."""

    def __init__(self, mac):
        self.mac_address = mac
        self.ip_addresses = ["192.168.1.100"]


class MockInventory:
    """Mock device inventory."""

    def __init__(self):
        self.devices = {}

    def add_device(self, device):
        self.devices[device.id] = device

    def get_by_mac(self, mac):
        for d in self.devices.values():
            if d.primary_mac == mac:
                return d
        return None


class MockDiscoveryAgent:
    """Mock discovery agent for testing."""

    def __init__(self):
        self._inventory = MockInventory()
        self._enabled = True

    async def _perform_quick_scan(self):
        pass

    async def _perform_full_scan(self):
        pass

    async def _fingerprint_device(self, device):
        pass

    @property
    def stats(self):
        return {"events_processed": 0, "decisions_made": 0}


class MockPlannerAgent:
    """Mock planner agent for testing."""

    def __init__(self):
        self._vlans = {
            10: {"id": 10, "name": "Workstations", "subnet": "192.168.10.0/24", "isolated": False},
            20: {"id": 20, "name": "Servers", "subnet": "192.168.20.0/24", "isolated": False},
        }
        self._segmentation_policies = {}
        self._firewall_rules = {}
        self._enabled = True

    @property
    def stats(self):
        return {"vlans": len(self._vlans), "policies": 0}


class MockGuardianAgent:
    """Mock guardian agent for testing."""

    def __init__(self):
        self._blocked_ips = set()
        self._quarantined_devices = set()
        self._enabled = True

    async def unblock_ip(self, ip):
        if ip in self._blocked_ips:
            self._blocked_ips.remove(ip)
            return True
        return False

    @property
    def stats(self):
        return {"blocked": len(self._blocked_ips)}


class MockEngine:
    """Mock engine for API testing."""

    def __init__(self):
        self.agents = {
            "discovery": MockDiscoveryAgent(),
            "planner": MockPlannerAgent(),
            "guardian": MockGuardianAgent(),
        }
        self._running = True
        self._start_time = None
        self.config = {}

    async def get_status(self):
        return {
            "status": "running",
            "uptime_seconds": 100.0,
            "agents": {
                name: {"enabled": agent._enabled}
                for name, agent in self.agents.items()
            },
            "integrations": {}
        }


@pytest.fixture
def mock_engine():
    """Create mock engine with test data."""
    engine = MockEngine()

    # Add some test devices
    device1 = MockDevice(mac="00:11:22:33:44:55")
    device2 = MockDevice(mac="AA:BB:CC:DD:EE:FF")
    engine.agents["discovery"]._inventory.add_device(device1)
    engine.agents["discovery"]._inventory.add_device(device2)

    return engine


@pytest.fixture
def client(mock_engine):
    """Create test client with mock engine."""
    from sentinel.api.app import create_app
    import sentinel.api.auth as auth_module
    import sentinel.api.app as app_module

    # Save original state
    original_auth = getattr(auth_module, '_auth_config', None)
    original_engine = getattr(app_module, '_engine', None)

    # Disable auth for testing
    auth_module._auth_config = None

    # Create app with mock engine
    fastapi_app = create_app(mock_engine)

    try:
        yield TestClient(fastapi_app)
    finally:
        # Restore original state
        auth_module._auth_config = original_auth
        app_module._engine = original_engine


class TestStatusEndpoints:
    """Tests for status endpoints."""

    def test_root(self, client):
        """Test root endpoint."""
        response = client.get("/")
        assert response.status_code == 200
        data = response.json()
        assert data["name"] == "Sentinel API"

    def test_health(self, client):
        """Test health check endpoint."""
        response = client.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        assert "timestamp" in data

    def test_status(self, client):
        """Test status endpoint."""
        response = client.get("/status")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "running"
        assert "uptime_seconds" in data
        assert "agents" in data


class TestDeviceEndpoints:
    """Tests for device endpoints."""

    def test_list_devices(self, client):
        """Test listing devices."""
        response = client.get("/devices")
        assert response.status_code == 200
        data = response.json()
        assert "devices" in data
        assert "total" in data
        assert data["total"] == 2

    def test_list_devices_with_filter(self, client):
        """Test listing devices with type filter."""
        response = client.get("/devices", params={"device_type": "workstation"})
        assert response.status_code == 200
        data = response.json()
        assert data["total"] >= 0

    def test_get_device_by_mac(self, client):
        """Test getting device by MAC address."""
        response = client.get("/devices/00:11:22:33:44:55")
        assert response.status_code == 200
        data = response.json()
        assert data["mac"] == "00:11:22:33:44:55"

    def test_get_device_not_found(self, client):
        """Test getting nonexistent device."""
        response = client.get("/devices/FF:FF:FF:FF:FF:FF")
        assert response.status_code == 404

    def test_scan_device(self, client):
        """Test triggering device scan."""
        response = client.post("/devices/00:11:22:33:44:55/scan")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "scan_initiated"


class TestVLANEndpoints:
    """Tests for VLAN endpoints."""

    def test_list_vlans(self, client):
        """Test listing VLANs."""
        response = client.get("/vlans")
        assert response.status_code == 200
        data = response.json()
        assert len(data) == 2

    def test_get_vlan(self, client):
        """Test getting specific VLAN."""
        response = client.get("/vlans/10")
        assert response.status_code == 200
        data = response.json()
        assert data["id"] == 10
        assert data["name"] == "Workstations"

    def test_get_vlan_not_found(self, client):
        """Test getting nonexistent VLAN."""
        response = client.get("/vlans/999")
        assert response.status_code == 404

    def test_create_vlan(self, client):
        """Test creating a VLAN."""
        response = client.post("/vlans", json={
            "id": 30,
            "name": "IoT",
            "subnet": "192.168.30.0/24",
            "purpose": "iot",
            "isolated": True
        })
        assert response.status_code == 200
        data = response.json()
        assert data["id"] == 30
        assert data["name"] == "IoT"
        assert data["isolated"] is True

    def test_create_duplicate_vlan(self, client):
        """Test creating duplicate VLAN fails."""
        response = client.post("/vlans", json={
            "id": 10,
            "name": "Duplicate"
        })
        assert response.status_code == 409


class TestAgentEndpoints:
    """Tests for agent endpoints."""

    def test_list_agents(self, client):
        """Test listing agents."""
        response = client.get("/agents")
        assert response.status_code == 200
        data = response.json()
        assert len(data) == 3
        names = [a["name"] for a in data]
        assert "discovery" in names
        assert "planner" in names
        assert "guardian" in names

    def test_get_agent(self, client):
        """Test getting specific agent."""
        response = client.get("/agents/discovery")
        assert response.status_code == 200
        data = response.json()
        assert data["name"] == "discovery"
        assert data["enabled"] is True

    def test_get_agent_not_found(self, client):
        """Test getting nonexistent agent."""
        response = client.get("/agents/nonexistent")
        assert response.status_code == 404


class TestScanEndpoints:
    """Tests for scan endpoints."""

    def test_quick_scan(self, client):
        """Test quick scan endpoint."""
        response = client.post("/scan/quick")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "scan_initiated"
        assert data["type"] == "quick"

    def test_full_scan(self, client):
        """Test full scan endpoint."""
        response = client.post("/scan/full")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "scan_initiated"
        assert data["type"] == "full"


class TestSecurityEndpoints:
    """Tests for security endpoints."""

    def test_list_blocked_ips(self, client):
        """Test listing blocked IPs."""
        response = client.get("/security/blocked")
        assert response.status_code == 200
        data = response.json()
        assert "blocked_ips" in data
        assert "count" in data

    def test_list_quarantined(self, client):
        """Test listing quarantined devices."""
        response = client.get("/security/quarantined")
        assert response.status_code == 200
        data = response.json()
        assert "quarantined" in data
        assert "count" in data


class TestPolicyEndpoints:
    """Tests for policy endpoints."""

    def test_list_policies(self, client):
        """Test listing policies."""
        response = client.get("/policies")
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)

    def test_list_firewall_rules(self, client):
        """Test listing firewall rules."""
        response = client.get("/firewall-rules")
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
