"""
Tests for Sentinel AI Agents.
"""

import asyncio
import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

from sentinel.core.models.event import Event, EventCategory, EventSeverity
from sentinel.core.models.device import Device, DeviceType, NetworkInterface, DeviceFingerprint


class MockEngine:
    """Mock engine for testing agents."""

    def __init__(self):
        from sentinel.core.event_bus import EventBus
        from sentinel.core.state import StateManager

        self.event_bus = EventBus()
        self.state = MagicMock()
        self.state.get = AsyncMock(return_value=None)
        self.state.set = AsyncMock()
        self.config = {
            "vlans": [
                {"id": 10, "name": "Workstations"},
                {"id": 20, "name": "Servers"},
            ]
        }
        self.agents = {}
        self._integrations = {}

    def get_integration(self, name):
        return self._integrations.get(name)


@pytest.fixture
async def mock_engine():
    """Create mock engine."""
    engine = MockEngine()
    await engine.event_bus.start()
    yield engine
    await engine.event_bus.stop()


class TestBaseAgent:
    """Tests for BaseAgent functionality."""

    @pytest.mark.asyncio
    async def test_agent_start_stop(self, mock_engine):
        """Test agent can start and stop."""
        from sentinel.agents.base import BaseAgent

        class TestAgent(BaseAgent):
            agent_name = "test"
            agent_description = "Test agent"

            async def _subscribe_events(self):
                pass

            async def _main_loop(self):
                while self._running:
                    await asyncio.sleep(0.1)

            async def analyze(self, event):
                return None

            async def _do_execute(self, action):
                return {"success": True}

            async def _do_rollback(self, action):
                pass

        agent = TestAgent(mock_engine, {})
        await agent.start()

        assert agent._running is True

        await agent.stop()

        assert agent._running is False

    @pytest.mark.asyncio
    async def test_agent_stats(self, mock_engine):
        """Test agent stats are tracked."""
        from sentinel.agents.base import BaseAgent

        class StatsTestAgent(BaseAgent):
            agent_name = "stats_test"
            agent_description = "Stats test agent"

            async def _subscribe_events(self):
                pass

            async def _main_loop(self):
                pass

            async def analyze(self, event):
                return None

            async def _do_execute(self, action):
                return {"success": True}

            async def _do_rollback(self, action):
                pass

        agent = StatsTestAgent(mock_engine, {})

        stats = agent.stats
        assert "name" in stats
        assert "running" in stats
        assert "total_actions" in stats
        assert "total_decisions" in stats


class TestDiscoveryAgent:
    """Tests for Discovery Agent."""

    @pytest.fixture
    def discovery_config(self):
        return {
            "scan_interval_seconds": 60,
            "full_scan_interval_seconds": 3600,
            "networks": ["192.168.1.0/24"],
            "port_scan_enabled": True,
        }

    @pytest.mark.asyncio
    async def test_discovery_agent_creation(self, mock_engine, discovery_config):
        """Test discovery agent can be created."""
        from sentinel.agents.discovery import DiscoveryAgent

        agent = DiscoveryAgent(mock_engine, discovery_config)

        assert agent.agent_name == "discovery"
        assert agent.scan_interval == 60
        assert "192.168.1.0/24" in agent.networks_to_scan

    @pytest.mark.asyncio
    async def test_vendor_lookup(self, mock_engine, discovery_config):
        """Test MAC vendor lookup."""
        from sentinel.agents.discovery import DiscoveryAgent

        agent = DiscoveryAgent(mock_engine, discovery_config)

        # Known vendor
        vendor = agent._lookup_vendor("B8:27:EB:00:00:00")
        assert vendor == "Raspberry Pi"

        # Unknown vendor
        vendor = agent._lookup_vendor("XX:XX:XX:00:00:00")
        assert vendor is None

    @pytest.mark.asyncio
    async def test_device_classification(self, mock_engine, discovery_config):
        """Test device classification based on fingerprint."""
        from sentinel.agents.discovery import DiscoveryAgent

        agent = DiscoveryAgent(mock_engine, discovery_config)

        # Server-like fingerprint (using server-specific ports)
        fp = DeviceFingerprint(
            vendor="Dell",
            open_ports=[22, 80, 3306, 5432],  # SSH, HTTP, MySQL, PostgreSQL
            services=["ssh", "http", "mysql", "postgresql"],
        )
        device_type = agent._classify_device(fp)
        assert device_type == DeviceType.SERVER

        # Printer-like fingerprint
        fp = DeviceFingerprint(vendor="HP", open_ports=[9100, 631], services=["jetdirect", "ipp"])
        device_type = agent._classify_device(fp)
        assert device_type == DeviceType.PRINTER

    @pytest.mark.asyncio
    async def test_confidence_calculation(self, mock_engine, discovery_config):
        """Test confidence score calculation."""
        from sentinel.agents.discovery import DiscoveryAgent

        agent = DiscoveryAgent(mock_engine, discovery_config)

        # Full fingerprint
        fp = DeviceFingerprint(
            vendor="Dell", os_family="Linux", open_ports=[22, 80], services=["ssh", "http"]
        )
        confidence = agent._calculate_confidence(fp)
        assert confidence >= 0.75

        # Minimal fingerprint
        fp = DeviceFingerprint()
        confidence = agent._calculate_confidence(fp)
        assert confidence == 0.0


class TestGuardianAgent:
    """Tests for Guardian Agent."""

    @pytest.fixture
    def guardian_config(self):
        return {
            "threat_thresholds": {
                "port_scan": 50,
                "failed_auth": 5,
            },
            "quarantine_vlan": 666,
        }

    @pytest.mark.asyncio
    async def test_guardian_agent_creation(self, mock_engine, guardian_config):
        """Test guardian agent can be created."""
        from sentinel.agents.guardian import GuardianAgent

        agent = GuardianAgent(mock_engine, guardian_config)

        assert agent.agent_name == "guardian"
        assert agent.port_scan_threshold == 50
        assert agent.failed_auth_threshold == 5


class TestPlannerAgent:
    """Tests for Planner Agent."""

    @pytest.fixture
    def planner_config(self):
        return {"require_confirmation_for": ["create_vlan", "delete_vlan"]}

    @pytest.mark.asyncio
    async def test_planner_agent_creation(self, mock_engine, planner_config):
        """Test planner agent can be created."""
        from sentinel.agents.planner import PlannerAgent

        agent = PlannerAgent(mock_engine, planner_config)

        assert agent.agent_name == "planner"
        assert "create_vlan" in agent.require_confirmation

    @pytest.mark.asyncio
    async def test_segmentation_check(self, mock_engine, planner_config):
        """Test segmentation policy checking."""
        from sentinel.agents.planner import PlannerAgent

        agent = PlannerAgent(mock_engine, planner_config)

        # Add a test policy
        agent._segmentation_policies["test_policy"] = {
            "source_vlan": 10,
            "destination_vlan": 20,
            "allowed_services": ["ssh", "http"],
            "denied_services": [],
            "default_action": "deny",
        }

        # Allowed service
        allowed = agent._check_segmentation(10, 20, "ssh")
        assert allowed is True

        # Denied by default
        allowed = agent._check_segmentation(10, 20, "ftp")
        assert allowed is False


class TestHealerAgent:
    """Tests for Healer Agent."""

    @pytest.fixture
    def healer_config(self):
        return {
            "health_check_interval_seconds": 60,
            "max_restart_attempts": 3,
        }

    @pytest.mark.asyncio
    async def test_healer_agent_creation(self, mock_engine, healer_config):
        """Test healer agent can be created."""
        from sentinel.agents.healer import HealerAgent

        agent = HealerAgent(mock_engine, healer_config)

        assert agent.agent_name == "healer"
        assert agent.health_check_interval == 60
        assert agent.max_restart_attempts == 3


class TestOptimizerAgent:
    """Tests for Optimizer Agent."""

    @pytest.fixture
    def optimizer_config(self):
        return {
            "flow_analysis_interval_seconds": 300,
            "bandwidth_threshold_mbps": 100,
        }

    @pytest.mark.asyncio
    async def test_optimizer_agent_creation(self, mock_engine, optimizer_config):
        """Test optimizer agent can be created."""
        from sentinel.agents.optimizer import OptimizerAgent

        agent = OptimizerAgent(mock_engine, optimizer_config)

        assert agent.agent_name == "optimizer"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
