"""
Tests for orchestration bridges.

Tests cover the integration bridges that coordinate between
Discovery, Compute Cluster, and other Sentinel components.
"""

import asyncio
import pytest
from datetime import datetime
from unittest.mock import MagicMock, AsyncMock, patch
from uuid import uuid4

from sentinel.orchestration.bridges import (
    BridgeAction,
    IntegrationBridge,
    DiscoveryComputeBridge,
    InfrastructureIntegrationBridge,
)
from sentinel.core.models.event import Event, EventCategory, EventSeverity


# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def mock_engine():
    """Create a mock Sentinel engine."""
    engine = MagicMock()
    engine.event_bus = MagicMock()
    engine.event_bus.subscribe = MagicMock()
    engine.event_bus.publish = AsyncMock()
    engine.get_agent = MagicMock(return_value=None)
    engine.get_integration = MagicMock(return_value=None)
    engine.register_integration = MagicMock()
    return engine


@pytest.fixture
def mock_discovery_agent():
    """Create a mock discovery agent."""
    agent = MagicMock()
    agent.discovered_infrastructure = {
        "192.168.1.100": {
            "type": "raspberry_pi",
            "integration_type": "compute_node",
            "ip": "192.168.1.100",
            "mac": "DC:A6:32:11:22:33",
            "hostname": "rpi-node1",
            "confidence": 0.85,
        },
        "192.168.1.1": {
            "type": "mikrotik",
            "integration_type": "mikrotik",
            "ip": "192.168.1.1",
            "mac": "64:D1:54:11:22:33",
            "hostname": "mikrotik-router",
            "confidence": 0.95,
        },
    }
    return agent


@pytest.fixture
def mock_cluster_manager():
    """Create a mock compute cluster manager."""
    manager = MagicMock()
    manager._probe_node = AsyncMock(return_value=None)
    manager.register_node = AsyncMock()
    manager.k3s_server_url = None
    manager.provision_k3s_server = AsyncMock(return_value=True)
    manager.provision_k3s_agent = AsyncMock(return_value=True)
    return manager


@pytest.fixture
def discovery_compute_bridge(mock_engine):
    """Create a discovery-compute bridge."""
    return DiscoveryComputeBridge(mock_engine)


@pytest.fixture
def infra_integration_bridge(mock_engine):
    """Create an infrastructure integration bridge."""
    return InfrastructureIntegrationBridge(mock_engine)


# =============================================================================
# Tests - BridgeAction
# =============================================================================


class TestBridgeAction:
    """Tests for BridgeAction dataclass."""

    def test_action_creation(self):
        """Test creating a bridge action."""
        action = BridgeAction(
            bridge_name="test_bridge",
            action_type="test_action",
            source_event="test.event",
            target_component="test_component",
        )
        assert action.bridge_name == "test_bridge"
        assert action.action_type == "test_action"
        assert action.success is True

    def test_action_defaults(self):
        """Test default values."""
        action = BridgeAction(
            bridge_name="test",
            action_type="test",
        )
        assert action.source_event is None
        assert action.target_component == ""
        assert action.details == {}
        assert action.success is True
        assert action.error == ""
        assert action.timestamp is not None

    def test_action_to_dict(self):
        """Test action serialization."""
        action = BridgeAction(
            bridge_name="test_bridge",
            action_type="register_node",
            details={"ip": "192.168.1.100"},
        )
        data = action.to_dict()

        assert data["bridge_name"] == "test_bridge"
        assert data["action_type"] == "register_node"
        assert data["details"]["ip"] == "192.168.1.100"
        assert "timestamp" in data

    def test_action_with_error(self):
        """Test action with failure."""
        action = BridgeAction(
            bridge_name="test",
            action_type="test",
            success=False,
            error="Connection refused",
        )
        assert action.success is False
        assert action.error == "Connection refused"


# =============================================================================
# Tests - DiscoveryComputeBridge
# =============================================================================


class TestDiscoveryComputeBridge:
    """Tests for DiscoveryComputeBridge."""

    def test_bridge_creation(self, discovery_compute_bridge):
        """Test bridge creation with defaults."""
        assert discovery_compute_bridge.bridge_name == "discovery_compute"
        assert discovery_compute_bridge.auto_register is True
        assert discovery_compute_bridge.auto_provision_k3s is False
        assert "raspberry_pi" in discovery_compute_bridge.allowed_types

    def test_bridge_custom_config(self, mock_engine):
        """Test bridge with custom configuration."""
        config = {
            "auto_register": False,
            "auto_provision_k3s": True,
            "allowed_types": ["raspberry_pi"],
        }
        bridge = DiscoveryComputeBridge(mock_engine, config)

        assert bridge.auto_register is False
        assert bridge.auto_provision_k3s is True
        assert bridge.allowed_types == ["raspberry_pi"]

    @pytest.mark.asyncio
    async def test_bridge_start(self, discovery_compute_bridge):
        """Test bridge start subscribes to events."""
        await discovery_compute_bridge.start()

        discovery_compute_bridge.engine.event_bus.subscribe.assert_called_once()
        call_args = discovery_compute_bridge.engine.event_bus.subscribe.call_args
        assert call_args[1]["event_type"] == "infrastructure.discovered"

    @pytest.mark.asyncio
    async def test_bridge_stop(self, discovery_compute_bridge):
        """Test bridge stop."""
        await discovery_compute_bridge.stop()
        # Should complete without error

    @pytest.mark.asyncio
    async def test_handle_infrastructure_discovered_disabled(self, discovery_compute_bridge):
        """Test that disabled bridge ignores events."""
        discovery_compute_bridge.disable()

        event = Event(
            category=EventCategory.NETWORK,
            event_type="infrastructure.discovered",
            severity=EventSeverity.INFO,
            source="discovery",
            title="Test",
            data={"type": "raspberry_pi", "ip": "192.168.1.100"},
        )

        await discovery_compute_bridge._handle_infrastructure_discovered(event)
        assert len(discovery_compute_bridge._registered_ips) == 0

    @pytest.mark.asyncio
    async def test_handle_infrastructure_discovered_wrong_type(self, discovery_compute_bridge):
        """Test that bridge ignores non-allowed types."""
        event = Event(
            category=EventCategory.NETWORK,
            event_type="infrastructure.discovered",
            severity=EventSeverity.INFO,
            source="discovery",
            title="Test",
            data={"type": "mikrotik", "ip": "192.168.1.1"},
        )

        await discovery_compute_bridge._handle_infrastructure_discovered(event)
        assert len(discovery_compute_bridge._registered_ips) == 0

    @pytest.mark.asyncio
    async def test_handle_infrastructure_discovered_no_cluster_manager(
        self, discovery_compute_bridge
    ):
        """Test handling when cluster manager not available."""
        await discovery_compute_bridge.start()

        event = Event(
            category=EventCategory.NETWORK,
            event_type="infrastructure.discovered",
            severity=EventSeverity.INFO,
            source="discovery",
            title="Test",
            data={"type": "raspberry_pi", "ip": "192.168.1.100"},
        )

        await discovery_compute_bridge._handle_infrastructure_discovered(event)
        assert len(discovery_compute_bridge._registered_ips) == 0

    @pytest.mark.asyncio
    async def test_register_compute_node_success(
        self, discovery_compute_bridge, mock_cluster_manager
    ):
        """Test successful node registration."""
        # Create a mock node without importing the actual class
        mock_node = MagicMock()
        mock_node.id = uuid4()
        mock_node.hostname = "rpi-node1"
        mock_node.roles = set()
        mock_node.labels = {}
        mock_node.add_role = MagicMock()

        mock_cluster_manager._probe_node = AsyncMock(return_value=mock_node)
        discovery_compute_bridge._cluster_manager = mock_cluster_manager

        infra_data = {
            "type": "raspberry_pi",
            "ip": "192.168.1.100",
            "mac": "DC:A6:32:11:22:33",
            "hostname": "rpi-node1",
        }

        # Mock the import in the bridge method
        with patch.dict("sys.modules", {"sentinel.integrations.compute.node": MagicMock()}):
            await discovery_compute_bridge._register_compute_node(infra_data)

        assert "192.168.1.100" in discovery_compute_bridge._registered_ips
        mock_cluster_manager.register_node.assert_called_once_with(mock_node)

    @pytest.mark.asyncio
    async def test_register_compute_node_probe_failed(
        self, discovery_compute_bridge, mock_cluster_manager
    ):
        """Test handling probe failure."""
        mock_cluster_manager._probe_node = AsyncMock(return_value=None)
        discovery_compute_bridge._cluster_manager = mock_cluster_manager

        infra_data = {
            "type": "raspberry_pi",
            "ip": "192.168.1.100",
        }

        await discovery_compute_bridge._register_compute_node(infra_data)

        assert "192.168.1.100" not in discovery_compute_bridge._registered_ips
        assert len(discovery_compute_bridge._actions) == 1
        assert discovery_compute_bridge._actions[0].success is False

    def test_get_registered_nodes(self, discovery_compute_bridge):
        """Test getting registered nodes."""
        discovery_compute_bridge._registered_ips.add("192.168.1.100")
        discovery_compute_bridge._registered_ips.add("192.168.1.101")

        nodes = discovery_compute_bridge.get_registered_nodes()
        assert len(nodes) == 2
        assert "192.168.1.100" in nodes

    @pytest.mark.asyncio
    async def test_manual_register_no_discovery_agent(self, discovery_compute_bridge):
        """Test manual register without discovery agent."""
        result = await discovery_compute_bridge.manual_register("192.168.1.100")
        assert result is False

    @pytest.mark.asyncio
    async def test_manual_register_no_infra_data(
        self, discovery_compute_bridge, mock_discovery_agent
    ):
        """Test manual register with unknown IP."""
        discovery_compute_bridge._discovery_agent = mock_discovery_agent

        result = await discovery_compute_bridge.manual_register("192.168.1.200")
        assert result is False

    def test_enable_disable(self, discovery_compute_bridge):
        """Test enable/disable functionality."""
        assert discovery_compute_bridge.enabled is True

        discovery_compute_bridge.disable()
        assert discovery_compute_bridge.enabled is False

        discovery_compute_bridge.enable()
        assert discovery_compute_bridge.enabled is True


# =============================================================================
# Tests - InfrastructureIntegrationBridge
# =============================================================================


class TestInfrastructureIntegrationBridge:
    """Tests for InfrastructureIntegrationBridge."""

    def test_bridge_creation(self, infra_integration_bridge):
        """Test bridge creation with defaults."""
        assert infra_integration_bridge.bridge_name == "infrastructure_integration"
        assert infra_integration_bridge.auto_configure is False
        assert infra_integration_bridge.require_credentials is True

    def test_bridge_custom_config(self, mock_engine):
        """Test bridge with custom configuration."""
        config = {
            "auto_configure": True,
            "require_credentials": False,
            "credentials": {"192.168.1.1": {"username": "admin", "password": "secret"}},
        }
        bridge = InfrastructureIntegrationBridge(mock_engine, config)

        assert bridge.auto_configure is True
        assert bridge.require_credentials is False
        assert "192.168.1.1" in bridge._credentials

    @pytest.mark.asyncio
    async def test_bridge_start(self, infra_integration_bridge):
        """Test bridge start subscribes to events."""
        await infra_integration_bridge.start()

        infra_integration_bridge.engine.event_bus.subscribe.assert_called_once()

    @pytest.mark.asyncio
    async def test_handle_discovery_disabled(self, infra_integration_bridge):
        """Test disabled bridge ignores events."""
        infra_integration_bridge.disable()

        event = Event(
            category=EventCategory.NETWORK,
            event_type="infrastructure.discovered",
            severity=EventSeverity.INFO,
            source="discovery",
            title="Test",
            data={"type": "mikrotik", "ip": "192.168.1.1"},
        )

        await infra_integration_bridge._handle_infrastructure_discovered(event)
        assert len(infra_integration_bridge._configured) == 0

    @pytest.mark.asyncio
    async def test_handle_discovery_no_credentials(self, infra_integration_bridge):
        """Test that bridge requires credentials by default."""
        infra_integration_bridge.auto_configure = True

        event = Event(
            category=EventCategory.NETWORK,
            event_type="infrastructure.discovered",
            severity=EventSeverity.INFO,
            source="discovery",
            title="Test",
            data={
                "type": "mikrotik",
                "integration_type": "mikrotik",
                "ip": "192.168.1.1",
            },
        )

        await infra_integration_bridge._handle_infrastructure_discovered(event)
        assert len(infra_integration_bridge._configured) == 0

    @pytest.mark.asyncio
    async def test_handle_discovery_with_credentials(self, mock_engine):
        """Test auto-configuration with credentials."""
        config = {
            "auto_configure": True,
            "credentials": {
                "mikrotik": {"username": "admin", "password": "secret"},
            },
        }
        bridge = InfrastructureIntegrationBridge(mock_engine, config)

        # Mock the MikroTik integration module
        mock_mikrotik_module = MagicMock()
        mock_integration = MagicMock()
        mock_integration.connect = AsyncMock()
        mock_mikrotik_module.MikroTikIntegration.return_value = mock_integration

        with patch.dict(
            "sys.modules", {"sentinel.integrations.routers.mikrotik": mock_mikrotik_module}
        ):
            event = Event(
                category=EventCategory.NETWORK,
                event_type="infrastructure.discovered",
                severity=EventSeverity.INFO,
                source="discovery",
                title="Test",
                data={
                    "type": "mikrotik",
                    "integration_type": "mikrotik",
                    "ip": "192.168.1.1",
                },
            )

            await bridge._handle_infrastructure_discovered(event)

            mock_mikrotik_module.MikroTikIntegration.assert_called_once()
            mock_integration.connect.assert_called_once()
            mock_engine.register_integration.assert_called_once()
            assert "192.168.1.1" in bridge._configured

    @pytest.mark.asyncio
    async def test_configure_unknown_integration(self, infra_integration_bridge):
        """Test handling unknown integration type."""
        infra_data = {
            "type": "unknown_device",
            "integration_type": "unknown",
            "ip": "192.168.1.99",
        }

        await infra_integration_bridge._configure_integration(infra_data, {})

        assert len(infra_integration_bridge._actions) == 1
        assert infra_integration_bridge._actions[0].success is False
        assert "Unknown integration type" in infra_integration_bridge._actions[0].error

    def test_add_credentials(self, infra_integration_bridge):
        """Test adding credentials."""
        infra_integration_bridge.add_credentials(
            "192.168.1.1", {"username": "admin", "password": "secret"}
        )

        assert "192.168.1.1" in infra_integration_bridge._credentials
        assert infra_integration_bridge._credentials["192.168.1.1"]["username"] == "admin"

    def test_get_configured_integrations(self, infra_integration_bridge):
        """Test getting configured integrations."""
        infra_integration_bridge._configured["192.168.1.1"] = "mikrotik"
        infra_integration_bridge._configured["192.168.1.2"] = "unifi"

        configured = infra_integration_bridge.get_configured_integrations()
        assert len(configured) == 2
        assert configured["192.168.1.1"] == "mikrotik"


# =============================================================================
# Tests - Action History
# =============================================================================


class TestActionHistory:
    """Tests for bridge action history."""

    def test_record_action(self, discovery_compute_bridge):
        """Test recording actions."""
        action = BridgeAction(
            bridge_name="test",
            action_type="test_action",
        )

        discovery_compute_bridge.record_action(action)
        assert len(discovery_compute_bridge._actions) == 1

    def test_action_history_limit(self, discovery_compute_bridge):
        """Test action history is limited."""
        discovery_compute_bridge._max_action_history = 5

        for i in range(10):
            action = BridgeAction(
                bridge_name="test",
                action_type=f"action_{i}",
            )
            discovery_compute_bridge.record_action(action)

        assert len(discovery_compute_bridge._actions) == 5
        # Should keep most recent
        assert discovery_compute_bridge._actions[-1].action_type == "action_9"

    def test_get_action_history(self, discovery_compute_bridge):
        """Test getting action history with limit."""
        for i in range(5):
            action = BridgeAction(
                bridge_name="test",
                action_type=f"action_{i}",
            )
            discovery_compute_bridge.record_action(action)

        history = discovery_compute_bridge.get_action_history(limit=3)
        assert len(history) == 3
        assert history[-1].action_type == "action_4"
