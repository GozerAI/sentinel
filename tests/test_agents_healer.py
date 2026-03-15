"""
Comprehensive tests for HealerAgent.

Tests cover:
- Initialization with various configurations
- Event subscriptions
- Health check functionality
- Service restart logic
- VM migration proposals
- Predictive analysis
- Action execution
- Rollback functionality
"""
import asyncio
import pytest
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, AsyncMock, patch

from sentinel.agents.healer import HealerAgent
from sentinel.core.models.event import (
    Event, EventCategory, EventSeverity,
    AgentAction
)


@pytest.fixture
def mock_engine():
    """Create a mock engine."""
    engine = MagicMock()
    engine.event_bus = MagicMock()
    engine.event_bus.subscribe = MagicMock()
    engine.event_bus.publish = AsyncMock()
    engine.state = MagicMock()
    engine.state.set = AsyncMock()
    engine.get_integration = MagicMock(return_value=None)
    return engine


@pytest.fixture
def default_config():
    """Default healer configuration."""
    return {
        "health_check_interval_seconds": 30,
        "auto_restart_services": True,
        "max_restart_attempts": 3,
        "auto_failover": True,
        "auto_execute_threshold": 0.95,
        "log_execute_threshold": 0.80,
        "confirm_threshold": 0.60,
    }


@pytest.fixture
def agent(mock_engine, default_config):
    """Create a healer agent for testing."""
    return HealerAgent(mock_engine, default_config)


class TestHealerAgentInit:
    """Tests for healer agent initialization."""

    def test_init_with_defaults(self, mock_engine, default_config):
        """Test initialization with default config."""
        agent = HealerAgent(mock_engine, default_config)

        assert agent.agent_name == "healer"
        assert agent.agent_description == "Self-healing and automated recovery"
        assert agent.health_check_interval == 30
        assert agent.auto_restart is True
        assert agent.max_restart_attempts == 3
        assert agent.auto_failover is True

    def test_init_with_custom_config(self, mock_engine):
        """Test initialization with custom config."""
        config = {
            "health_check_interval_seconds": 60,
            "auto_restart_services": False,
            "max_restart_attempts": 5,
            "auto_failover": False,
        }
        agent = HealerAgent(mock_engine, config)

        assert agent.health_check_interval == 60
        assert agent.auto_restart is False
        assert agent.max_restart_attempts == 5
        assert agent.auto_failover is False

    def test_init_creates_tracking_structures(self, mock_engine, default_config):
        """Test that initialization creates empty tracking structures."""
        agent = HealerAgent(mock_engine, default_config)

        assert agent._health_status == {}
        assert agent._restart_counts == {}
        assert agent._last_restart == {}
        assert agent._failure_predictions == []
        assert agent._last_health_check is None


class TestHealerAgentSubscriptions:
    """Tests for event subscriptions."""

    @pytest.mark.asyncio
    async def test_subscribe_events(self, agent, mock_engine):
        """Test event subscriptions are set up correctly."""
        await agent._subscribe_events()

        # Should subscribe to health.alert, service.down, resource.critical
        assert mock_engine.event_bus.subscribe.call_count == 3

        call_args = [call[1] for call in mock_engine.event_bus.subscribe.call_args_list]
        event_types = [args.get("event_type") for args in call_args]

        assert "health.alert" in event_types
        assert "service.down" in event_types
        assert "resource.critical" in event_types


class TestHealerAgentHealthChecks:
    """Tests for health check functionality."""

    @pytest.mark.asyncio
    async def test_check_router_health_no_integration(self, agent, mock_engine):
        """Test router health check when no integration configured."""
        mock_engine.get_integration.return_value = None

        result = await agent._check_router_health()

        assert result["healthy"] is True
        assert "No router integration" in result["message"]

    @pytest.mark.asyncio
    async def test_check_router_health_success(self, agent, mock_engine):
        """Test router health check success."""
        mock_router = MagicMock()
        mock_router.health_check = AsyncMock(return_value=True)
        mock_router.connected = True
        mock_engine.get_integration.return_value = mock_router

        result = await agent._check_router_health()

        assert result["healthy"] is True
        assert result["connected"] is True
        assert result["message"] == "OK"

    @pytest.mark.asyncio
    async def test_check_router_health_failure(self, agent, mock_engine):
        """Test router health check failure."""
        mock_router = MagicMock()
        mock_router.health_check = AsyncMock(return_value=False)
        mock_router.connected = False
        mock_engine.get_integration.return_value = mock_router

        result = await agent._check_router_health()

        assert result["healthy"] is False
        assert result["connected"] is False

    @pytest.mark.asyncio
    async def test_check_router_health_exception(self, agent, mock_engine):
        """Test router health check with exception."""
        mock_router = MagicMock()
        mock_router.health_check = AsyncMock(side_effect=Exception("Connection error"))
        mock_engine.get_integration.return_value = mock_router

        result = await agent._check_router_health()

        assert result["healthy"] is False
        assert "Connection error" in result["error"]

    @pytest.mark.asyncio
    async def test_check_switch_health_no_integration(self, agent, mock_engine):
        """Test switch health check when no integration."""
        mock_engine.get_integration.return_value = None

        result = await agent._check_switch_health()

        assert result["healthy"] is True
        assert "No switch integration" in result["message"]

    @pytest.mark.asyncio
    async def test_check_switch_health_success(self, agent, mock_engine):
        """Test switch health check success."""
        mock_switch = MagicMock()
        mock_switch.health_check = AsyncMock(return_value=True)
        mock_switch.connected = True
        mock_engine.get_integration.return_value = mock_switch

        result = await agent._check_switch_health()

        assert result["healthy"] is True

    @pytest.mark.asyncio
    async def test_check_switch_health_exception(self, agent, mock_engine):
        """Test switch health check with exception."""
        mock_switch = MagicMock()
        mock_switch.health_check = AsyncMock(side_effect=Exception("Switch error"))
        mock_engine.get_integration.return_value = mock_switch

        result = await agent._check_switch_health()

        assert result["healthy"] is False
        assert "Switch error" in result["error"]

    @pytest.mark.asyncio
    async def test_check_hypervisor_health_no_integration(self, agent, mock_engine):
        """Test hypervisor health check when no integration."""
        mock_engine.get_integration.return_value = None

        result = await agent._check_hypervisor_health()

        assert result["healthy"] is True
        assert "No hypervisor integration" in result["message"]

    @pytest.mark.asyncio
    async def test_check_hypervisor_health_success(self, agent, mock_engine):
        """Test hypervisor health check success."""
        mock_hypervisor = MagicMock()
        mock_hypervisor.health_check = AsyncMock(return_value=True)
        mock_hypervisor.connected = True
        mock_hypervisor.get_host_resources = AsyncMock(return_value={
            "cpu_percent": 50,
            "memory_percent": 60
        })
        mock_engine.get_integration.return_value = mock_hypervisor

        result = await agent._check_hypervisor_health()

        assert result["healthy"] is True
        assert result["cpu_percent"] == 50
        assert result["memory_percent"] == 60
        assert result["warnings"] == []

    @pytest.mark.asyncio
    async def test_check_hypervisor_health_high_cpu(self, agent, mock_engine):
        """Test hypervisor health check with high CPU."""
        mock_hypervisor = MagicMock()
        mock_hypervisor.health_check = AsyncMock(return_value=True)
        mock_hypervisor.connected = True
        mock_hypervisor.get_host_resources = AsyncMock(return_value={
            "cpu_percent": 95,
            "memory_percent": 60
        })
        mock_engine.get_integration.return_value = mock_hypervisor

        result = await agent._check_hypervisor_health()

        assert result["healthy"] is False  # Has warnings
        assert "High CPU: 95%" in result["warnings"]

    @pytest.mark.asyncio
    async def test_check_hypervisor_health_high_memory(self, agent, mock_engine):
        """Test hypervisor health check with high memory."""
        mock_hypervisor = MagicMock()
        mock_hypervisor.health_check = AsyncMock(return_value=True)
        mock_hypervisor.connected = True
        mock_hypervisor.get_host_resources = AsyncMock(return_value={
            "cpu_percent": 50,
            "memory_percent": 95
        })
        mock_engine.get_integration.return_value = mock_hypervisor

        result = await agent._check_hypervisor_health()

        assert result["healthy"] is False
        assert "High memory: 95%" in result["warnings"]

    @pytest.mark.asyncio
    async def test_check_hypervisor_health_exception(self, agent, mock_engine):
        """Test hypervisor health check with exception."""
        mock_hypervisor = MagicMock()
        mock_hypervisor.health_check = AsyncMock(side_effect=Exception("Hypervisor error"))
        mock_engine.get_integration.return_value = mock_hypervisor

        result = await agent._check_hypervisor_health()

        assert result["healthy"] is False
        assert "Hypervisor error" in result["error"]

    @pytest.mark.asyncio
    async def test_check_storage_health_no_integration(self, agent, mock_engine):
        """Test storage health check when no integration."""
        mock_engine.get_integration.return_value = None

        result = await agent._check_storage_health()

        assert result["healthy"] is True
        assert "No storage integration" in result["message"]

    @pytest.mark.asyncio
    async def test_check_storage_health_success(self, agent, mock_engine):
        """Test storage health check success."""
        mock_storage = MagicMock()
        mock_storage.get_health = AsyncMock(return_value={"healthy": True, "status": "OK"})
        mock_storage.get_pools = AsyncMock(return_value=[
            {"name": "pool1", "status": "ONLINE"},
            {"name": "pool2", "status": "ONLINE"}
        ])
        mock_engine.get_integration.return_value = mock_storage

        result = await agent._check_storage_health()

        assert result["healthy"] is True
        assert result["pool_count"] == 2
        assert result["unhealthy_pools"] == []

    @pytest.mark.asyncio
    async def test_check_storage_health_degraded_pool(self, agent, mock_engine):
        """Test storage health check with degraded pool."""
        mock_storage = MagicMock()
        mock_storage.get_health = AsyncMock(return_value={"healthy": True, "status": "OK"})
        mock_storage.get_pools = AsyncMock(return_value=[
            {"name": "pool1", "status": "ONLINE"},
            {"name": "pool2", "status": "DEGRADED"}
        ])
        mock_engine.get_integration.return_value = mock_storage

        result = await agent._check_storage_health()

        assert result["healthy"] is False
        assert "pool2" in result["unhealthy_pools"]

    @pytest.mark.asyncio
    async def test_check_storage_health_exception(self, agent, mock_engine):
        """Test storage health check with exception."""
        mock_storage = MagicMock()
        mock_storage.get_health = AsyncMock(side_effect=Exception("Storage error"))
        mock_engine.get_integration.return_value = mock_storage

        result = await agent._check_storage_health()

        assert result["healthy"] is False
        assert "Storage error" in result["error"]


class TestHealerAgentRunHealthChecks:
    """Tests for the run_health_checks method."""

    @pytest.mark.asyncio
    async def test_run_health_checks_all_healthy(self, agent, mock_engine):
        """Test running health checks when all healthy."""
        # Mock all health check methods
        agent._check_router_health = AsyncMock(return_value={"healthy": True})
        agent._check_switch_health = AsyncMock(return_value={"healthy": True})
        agent._check_hypervisor_health = AsyncMock(return_value={"healthy": True})
        agent._check_storage_health = AsyncMock(return_value={"healthy": True})

        await agent._run_health_checks()

        # Should store health status
        assert "router" in agent._health_status
        assert "switch" in agent._health_status
        assert "hypervisor" in agent._health_status
        assert "storage" in agent._health_status

        # Should persist to state
        mock_engine.state.set.assert_called_once()

        # Should publish event
        mock_engine.event_bus.publish.assert_called_once()

    @pytest.mark.asyncio
    async def test_run_health_checks_unhealthy_triggers_recovery(self, agent, mock_engine):
        """Test that unhealthy check triggers recovery evaluation."""
        agent._check_router_health = AsyncMock(return_value={"healthy": False, "error": "Connection lost"})
        agent._check_switch_health = AsyncMock(return_value={"healthy": True})
        agent._check_hypervisor_health = AsyncMock(return_value={"healthy": True})
        agent._check_storage_health = AsyncMock(return_value={"healthy": True})
        agent._evaluate_recovery = AsyncMock()

        await agent._run_health_checks()

        # Should call evaluate_recovery for router
        agent._evaluate_recovery.assert_called_once()
        call_args = agent._evaluate_recovery.call_args
        assert call_args[0][0] == "router"

    @pytest.mark.asyncio
    async def test_run_health_checks_exception_handling(self, agent, mock_engine):
        """Test health check handles exceptions gracefully."""
        agent._check_router_health = AsyncMock(side_effect=Exception("Check failed"))
        agent._check_switch_health = AsyncMock(return_value={"healthy": True})
        agent._check_hypervisor_health = AsyncMock(return_value={"healthy": True})
        agent._check_storage_health = AsyncMock(return_value={"healthy": True})

        await agent._run_health_checks()

        # Router should be marked as unhealthy
        assert agent._health_status["router"]["healthy"] is False
        assert "Check failed" in agent._health_status["router"]["status"]["error"]


class TestHealerAgentEventHandlers:
    """Tests for event handlers."""

    @pytest.mark.asyncio
    async def test_handle_health_alert_unhealthy(self, agent, mock_engine):
        """Test handling unhealthy health alert."""
        agent._evaluate_recovery = AsyncMock()

        event = Event(
            category=EventCategory.SYSTEM,
            event_type="health.alert",
            severity=EventSeverity.WARNING,
            source="test",
            title="Health Alert",
            description="Component unhealthy",
            data={"component": "router", "status": "unhealthy"}
        )

        await agent._handle_health_alert(event)

        agent._evaluate_recovery.assert_called_once_with("router", {"component": "router", "status": "unhealthy"})

    @pytest.mark.asyncio
    async def test_handle_health_alert_healthy(self, agent, mock_engine):
        """Test handling healthy health alert (no action)."""
        agent._evaluate_recovery = AsyncMock()

        event = Event(
            category=EventCategory.SYSTEM,
            event_type="health.alert",
            severity=EventSeverity.INFO,
            source="test",
            title="Health Alert",
            description="Component healthy",
            data={"component": "router", "status": "healthy"}
        )

        await agent._handle_health_alert(event)

        agent._evaluate_recovery.assert_not_called()

    @pytest.mark.asyncio
    async def test_handle_service_down(self, agent, mock_engine):
        """Test handling service down event."""
        agent._attempt_service_restart = AsyncMock()

        event = Event(
            category=EventCategory.SYSTEM,
            event_type="service.down",
            severity=EventSeverity.ERROR,
            source="test",
            title="Service Down",
            description="Service failed",
            data={"service": "nginx", "host": "server1"}
        )

        await agent._handle_service_down(event)

        agent._attempt_service_restart.assert_called_once_with("nginx", "server1")

    @pytest.mark.asyncio
    async def test_handle_service_down_auto_restart_disabled(self, mock_engine):
        """Test service down handler when auto restart is disabled."""
        config = {"auto_restart_services": False}
        agent = HealerAgent(mock_engine, config)
        agent._attempt_service_restart = AsyncMock()

        event = Event(
            category=EventCategory.SYSTEM,
            event_type="service.down",
            severity=EventSeverity.ERROR,
            source="test",
            title="Service Down",
            description="Service failed",
            data={"service": "nginx", "host": "server1"}
        )

        await agent._handle_service_down(event)

        agent._attempt_service_restart.assert_not_called()

    @pytest.mark.asyncio
    async def test_handle_resource_critical(self, agent, mock_engine):
        """Test handling resource critical event."""
        agent._evaluate_resource_action = AsyncMock()

        event = Event(
            category=EventCategory.SYSTEM,
            event_type="resource.critical",
            severity=EventSeverity.WARNING,
            source="test",
            title="Resource Critical",
            description="High CPU",
            data={"resource_type": "cpu", "host": "server1", "utilization": 98}
        )

        await agent._handle_resource_critical(event)

        agent._evaluate_resource_action.assert_called_once()


class TestHealerAgentServiceRestart:
    """Tests for service restart functionality."""

    @pytest.mark.asyncio
    async def test_attempt_service_restart_first_attempt(self, agent, mock_engine):
        """Test first restart attempt."""
        await agent._attempt_service_restart("nginx", "server1")

        # Should execute action
        mock_engine.event_bus.publish.assert_called()

        # Check the action was created
        action_event = mock_engine.event_bus.publish.call_args[0][0]
        assert "service_restart" in action_event.event_type or "agent.action" in action_event.event_type

    @pytest.mark.asyncio
    async def test_attempt_service_restart_max_attempts_exceeded(self, agent, mock_engine):
        """Test restart when max attempts exceeded."""
        service_key = "server1:nginx"
        agent._restart_counts[service_key] = 3  # Max is 3

        await agent._attempt_service_restart("nginx", "server1")

        # Should publish escalation event, not restart
        mock_engine.event_bus.publish.assert_called()
        event = mock_engine.event_bus.publish.call_args[0][0]
        assert event.event_type == "service.restart.failed"
        assert event.severity == EventSeverity.CRITICAL

    @pytest.mark.asyncio
    async def test_attempt_service_restart_reset_counter(self, agent, mock_engine):
        """Test restart counter resets after an hour."""
        service_key = "server1:nginx"
        agent._restart_counts[service_key] = 2
        agent._last_restart[service_key] = datetime.now(timezone.utc) - timedelta(hours=2)

        await agent._attempt_service_restart("nginx", "server1")

        # Counter should be reset, action should execute
        mock_engine.event_bus.publish.assert_called()


class TestHealerAgentRecovery:
    """Tests for recovery evaluation."""

    @pytest.mark.asyncio
    async def test_evaluate_recovery_with_error(self, agent, mock_engine):
        """Test recovery evaluation when component has error."""
        await agent._evaluate_recovery("router", {"error": "Connection refused"})

        # Should create decision and execute reconnect action
        assert len(agent._decisions) > 0
        mock_engine.event_bus.publish.assert_called()

    @pytest.mark.asyncio
    async def test_evaluate_recovery_with_warnings(self, agent, mock_engine):
        """Test recovery evaluation with warnings."""
        agent._evaluate_resource_action = AsyncMock()

        await agent._evaluate_recovery("hypervisor", {
            "healthy": False,
            "warnings": ["High CPU: 95%"]
        })

        # Should evaluate resource action
        agent._evaluate_resource_action.assert_called_once()

    @pytest.mark.asyncio
    async def test_evaluate_resource_action_high_cpu(self, agent, mock_engine):
        """Test resource action for high CPU."""
        agent._propose_vm_migration = AsyncMock()

        await agent._evaluate_resource_action({
            "resource_type": "cpu",
            "host": "server1",
            "utilization": 98
        })

        agent._propose_vm_migration.assert_called_once_with("server1", "cpu")

    @pytest.mark.asyncio
    async def test_evaluate_resource_action_high_memory(self, agent, mock_engine):
        """Test resource action for high memory."""
        agent._propose_vm_migration = AsyncMock()

        await agent._evaluate_resource_action({
            "resource_type": "memory",
            "host": "server1",
            "utilization": 98
        })

        agent._propose_vm_migration.assert_called_once_with("server1", "memory")

    @pytest.mark.asyncio
    async def test_evaluate_resource_action_disk_warning(self, agent, mock_engine):
        """Test resource action for disk space."""
        await agent._evaluate_resource_action({
            "resource_type": "disk",
            "host": "server1",
            "utilization": 92
        })

        # Should publish warning event
        mock_engine.event_bus.publish.assert_called()
        event = mock_engine.event_bus.publish.call_args[0][0]
        assert event.event_type == "resource.disk.warning"

    @pytest.mark.asyncio
    async def test_evaluate_resource_action_normal_levels(self, agent, mock_engine):
        """Test no action for normal resource levels."""
        agent._propose_vm_migration = AsyncMock()

        await agent._evaluate_resource_action({
            "resource_type": "cpu",
            "host": "server1",
            "utilization": 50
        })

        agent._propose_vm_migration.assert_not_called()


class TestHealerAgentVMMigration:
    """Tests for VM migration functionality."""

    @pytest.mark.asyncio
    async def test_propose_vm_migration_auto_failover_disabled(self, mock_engine):
        """Test VM migration not proposed when auto failover disabled."""
        config = {"auto_failover": False}
        agent = HealerAgent(mock_engine, config)

        await agent._propose_vm_migration("server1", "cpu")

        # Should not call hypervisor
        mock_engine.get_integration.assert_not_called()

    @pytest.mark.asyncio
    async def test_propose_vm_migration_no_hypervisor(self, agent, mock_engine):
        """Test VM migration when no hypervisor available."""
        mock_engine.get_integration.return_value = None

        await agent._propose_vm_migration("server1", "cpu")

        # No action should be taken
        mock_engine.event_bus.publish.assert_not_called()

    @pytest.mark.asyncio
    async def test_propose_vm_migration_success(self, agent, mock_engine):
        """Test successful VM migration proposal."""
        mock_hypervisor = MagicMock()
        mock_hypervisor.get_vms = AsyncMock(return_value=[
            {"id": "vm1", "name": "web-server", "host": "server1", "cpu_usage": 30},
            {"id": "vm2", "name": "db-server", "host": "server1", "cpu_usage": 60},
        ])
        mock_engine.get_integration.return_value = mock_hypervisor

        await agent._propose_vm_migration("server1", "cpu")

        # Should create decision and action
        assert len(agent._decisions) > 0
        mock_engine.event_bus.publish.assert_called()

    @pytest.mark.asyncio
    async def test_propose_vm_migration_no_vms_on_host(self, agent, mock_engine):
        """Test VM migration when no VMs on host."""
        mock_hypervisor = MagicMock()
        mock_hypervisor.get_vms = AsyncMock(return_value=[
            {"id": "vm1", "name": "web-server", "host": "server2", "cpu_usage": 30},
        ])
        mock_engine.get_integration.return_value = mock_hypervisor

        await agent._propose_vm_migration("server1", "cpu")

        # No action for empty host
        mock_engine.event_bus.publish.assert_not_called()

    @pytest.mark.asyncio
    async def test_propose_vm_migration_exception(self, agent, mock_engine):
        """Test VM migration handles exceptions."""
        mock_hypervisor = MagicMock()
        mock_hypervisor.get_vms = AsyncMock(side_effect=Exception("API error"))
        mock_engine.get_integration.return_value = mock_hypervisor

        # Should not raise
        await agent._propose_vm_migration("server1", "cpu")


class TestHealerAgentPredictiveAnalysis:
    """Tests for predictive analysis."""

    @pytest.mark.asyncio
    async def test_predictive_analysis_with_warnings(self, agent, mock_engine):
        """Test predictive analysis detects warnings."""
        agent._health_status = {
            "hypervisor": {
                "healthy": True,
                "status": {"warnings": ["High CPU: 85%"]}
            }
        }

        await agent._predictive_analysis()

        # Should add prediction
        assert len(agent._failure_predictions) == 1
        assert agent._failure_predictions[0]["component"] == "hypervisor"

    @pytest.mark.asyncio
    async def test_predictive_analysis_cleans_old(self, agent, mock_engine):
        """Test predictive analysis cleans old predictions."""
        old_time = (datetime.now(timezone.utc) - timedelta(hours=2)).isoformat()
        agent._failure_predictions = [
            {"component": "old", "timestamp": old_time}
        ]
        agent._health_status = {}

        await agent._predictive_analysis()

        # Old prediction should be cleaned
        assert len(agent._failure_predictions) == 0


class TestHealerAgentDoExecute:
    """Tests for action execution."""

    @pytest.mark.asyncio
    async def test_do_execute_reconnect_success(self, agent, mock_engine):
        """Test reconnect action execution."""
        mock_integration = MagicMock()
        mock_integration.reconnect = AsyncMock()
        mock_engine.get_integration.return_value = mock_integration

        action = AgentAction(
            agent_name="healer",
            action_type="reconnect",
            target_type="integration",
            target_id="router",
            parameters={},
            reasoning="Test reconnect",
            confidence=0.85
        )

        result = await agent._do_execute(action)

        assert result["reconnected"] is True
        mock_integration.reconnect.assert_called_once()

    @pytest.mark.asyncio
    async def test_do_execute_reconnect_no_integration(self, agent, mock_engine):
        """Test reconnect when integration not found."""
        mock_engine.get_integration.return_value = None

        action = AgentAction(
            agent_name="healer",
            action_type="reconnect",
            target_type="integration",
            target_id="router",
            parameters={},
            reasoning="Test reconnect",
            confidence=0.85
        )

        result = await agent._do_execute(action)

        assert result["reconnected"] is False
        assert "not found" in result["error"]

    @pytest.mark.asyncio
    async def test_do_execute_service_restart_via_vm(self, agent, mock_engine):
        """Test service restart action via VM restart."""
        # Mock hypervisor with a matching VM
        mock_hypervisor = MagicMock()
        mock_hypervisor.get_vms = AsyncMock(return_value=[
            {"id": "vm-nginx-1", "name": "nginx-server", "host": "server1"}
        ])
        mock_hypervisor.stop_vm = AsyncMock()
        mock_hypervisor.start_vm = AsyncMock()
        mock_engine.get_integration.return_value = mock_hypervisor

        action = AgentAction(
            agent_name="healer",
            action_type="service_restart",
            target_type="service",
            target_id="server1:nginx",
            parameters={"service": "nginx", "host": "server1", "attempt": 1},
            reasoning="Test restart",
            confidence=0.90
        )

        # Patch sleep to speed up test
        with patch("asyncio.sleep", new_callable=AsyncMock):
            result = await agent._do_execute(action)

        assert result["restarted"] is True
        assert result["method"] == "vm_restart"
        assert agent._restart_counts["server1:nginx"] == 1
        mock_hypervisor.stop_vm.assert_called_once_with("vm-nginx-1")
        mock_hypervisor.start_vm.assert_called_once_with("vm-nginx-1")

    @pytest.mark.asyncio
    async def test_do_execute_service_restart_manual_fallback(self, agent, mock_engine):
        """Test service restart falls back to manual when no integration available."""
        # Mock engine to return None for all integrations
        mock_engine.get_integration.return_value = None

        action = AgentAction(
            agent_name="healer",
            action_type="service_restart",
            target_type="service",
            target_id="server1:nginx",
            parameters={"service": "nginx", "host": "server1", "attempt": 1},
            reasoning="Test restart",
            confidence=0.90
        )

        result = await agent._do_execute(action)

        assert result["restarted"] is False
        assert result["method"] == "manual_required"
        # Still tracks the attempt
        assert agent._restart_counts["server1:nginx"] == 1

    @pytest.mark.asyncio
    async def test_do_execute_vm_migration_success(self, agent, mock_engine):
        """Test VM migration action."""
        mock_hypervisor = MagicMock()
        mock_hypervisor.migrate_vm = AsyncMock(return_value=True)
        mock_engine.get_integration.return_value = mock_hypervisor

        action = AgentAction(
            agent_name="healer",
            action_type="vm_migration",
            target_type="vm",
            target_id="vm1",
            parameters={"target_host": "server2"},
            reasoning="Test migration",
            confidence=0.75
        )

        result = await agent._do_execute(action)

        assert result["migrated"] is True
        mock_hypervisor.migrate_vm.assert_called_once_with("vm1", "server2")

    @pytest.mark.asyncio
    async def test_do_execute_vm_migration_no_hypervisor(self, agent, mock_engine):
        """Test VM migration without hypervisor."""
        mock_engine.get_integration.return_value = None

        action = AgentAction(
            agent_name="healer",
            action_type="vm_migration",
            target_type="vm",
            target_id="vm1",
            parameters={"target_host": "server2"},
            reasoning="Test migration",
            confidence=0.75
        )

        result = await agent._do_execute(action)

        assert result["migrated"] is False

    @pytest.mark.asyncio
    async def test_do_execute_vm_restart(self, agent, mock_engine):
        """Test VM restart action."""
        mock_hypervisor = MagicMock()
        mock_hypervisor.stop_vm = AsyncMock()
        mock_hypervisor.start_vm = AsyncMock()
        mock_engine.get_integration.return_value = mock_hypervisor

        action = AgentAction(
            agent_name="healer",
            action_type="vm_restart",
            target_type="vm",
            target_id="vm1",
            parameters={},
            reasoning="Test restart",
            confidence=0.85
        )

        with patch("asyncio.sleep", new_callable=AsyncMock):
            result = await agent._do_execute(action)

        assert result["restarted"] is True
        mock_hypervisor.stop_vm.assert_called_once_with("vm1")
        mock_hypervisor.start_vm.assert_called_once_with("vm1")

    @pytest.mark.asyncio
    async def test_do_execute_vm_restart_no_hypervisor(self, agent, mock_engine):
        """Test VM restart without hypervisor."""
        mock_engine.get_integration.return_value = None

        action = AgentAction(
            agent_name="healer",
            action_type="vm_restart",
            target_type="vm",
            target_id="vm1",
            parameters={},
            reasoning="Test restart",
            confidence=0.85
        )

        result = await agent._do_execute(action)

        assert result["restarted"] is False

    @pytest.mark.asyncio
    async def test_do_execute_unknown_action(self, agent, mock_engine):
        """Test unknown action type raises error."""
        action = AgentAction(
            agent_name="healer",
            action_type="unknown_action",
            target_type="test",
            target_id="test",
            parameters={},
            reasoning="Test",
            confidence=0.5
        )

        with pytest.raises(ValueError, match="Unknown action type"):
            await agent._do_execute(action)


class TestHealerAgentRollback:
    """Tests for rollback functionality."""

    @pytest.mark.asyncio
    async def test_capture_rollback_data_vm_migration(self, agent, mock_engine):
        """Test rollback data capture for VM migration."""
        action = AgentAction(
            agent_name="healer",
            action_type="vm_migration",
            target_type="vm",
            target_id="vm1",
            parameters={"source_host": "server1"},
            reasoning="Test",
            confidence=0.75
        )

        rollback_data = await agent._capture_rollback_data(action)

        assert rollback_data["action"] == "vm_migration"
        assert rollback_data["vm_id"] == "vm1"
        assert rollback_data["original_host"] == "server1"

    @pytest.mark.asyncio
    async def test_capture_rollback_data_other_action(self, agent, mock_engine):
        """Test rollback data capture for non-VM actions."""
        action = AgentAction(
            agent_name="healer",
            action_type="service_restart",
            target_type="service",
            target_id="service1",
            parameters={},
            reasoning="Test",
            confidence=0.85
        )

        rollback_data = await agent._capture_rollback_data(action)

        assert rollback_data is None

    @pytest.mark.asyncio
    async def test_do_rollback_vm_migration(self, agent, mock_engine):
        """Test rollback for VM migration."""
        mock_hypervisor = MagicMock()
        mock_hypervisor.migrate_vm = AsyncMock()
        mock_engine.get_integration.return_value = mock_hypervisor

        action = AgentAction(
            agent_name="healer",
            action_type="vm_migration",
            target_type="vm",
            target_id="vm1",
            parameters={},
            reasoning="Test",
            confidence=0.75,
            rollback_data={
                "action": "vm_migration",
                "vm_id": "vm1",
                "original_host": "server1"
            }
        )

        await agent._do_rollback(action)

        mock_hypervisor.migrate_vm.assert_called_once_with("vm1", "server1")

    @pytest.mark.asyncio
    async def test_do_rollback_no_rollback_data(self, agent, mock_engine):
        """Test rollback with no rollback data."""
        action = AgentAction(
            agent_name="healer",
            action_type="service_restart",
            target_type="service",
            target_id="service1",
            parameters={},
            reasoning="Test",
            confidence=0.85
        )

        # Should not raise
        await agent._do_rollback(action)


class TestHealerAgentProperties:
    """Tests for agent properties."""

    @pytest.mark.asyncio
    async def test_get_relevant_state(self, agent, mock_engine):
        """Test getting relevant state."""
        agent._health_status = {"router": {"healthy": True}}
        agent._restart_counts = {"service1": 2}
        agent._failure_predictions = [{"component": "test"}]

        state = await agent._get_relevant_state()

        assert state["health_status"] == {"router": {"healthy": True}}
        assert state["restart_counts"] == {"service1": 2}
        assert state["failure_predictions"] == 1

    def test_stats_property(self, agent, mock_engine):
        """Test stats property."""
        agent._health_status = {
            "router": {"healthy": True},
            "switch": {"healthy": False}
        }
        agent._restart_counts = {"service1": 2, "service2": 1}
        agent._failure_predictions = [{"test": 1}]

        stats = agent.stats

        assert stats["name"] == "healer"
        assert stats["components_monitored"] == 2
        assert stats["healthy_components"] == 1
        assert stats["restart_attempts"] == 3
        assert stats["failure_predictions"] == 1


class TestHealerAgentAnalyze:
    """Tests for analyze method."""

    @pytest.mark.asyncio
    async def test_analyze_returns_none(self, agent, mock_engine):
        """Test analyze returns None (handlers do the work)."""
        event = Event(
            category=EventCategory.SYSTEM,
            event_type="test",
            severity=EventSeverity.INFO,
            source="test",
            title="Test",
            description="Test event",
            data={}
        )

        result = await agent.analyze(event)

        assert result is None


class TestHealerAgentMainLoop:
    """Tests for main loop functionality."""

    @pytest.mark.asyncio
    async def test_main_loop_runs_health_checks(self, agent, mock_engine):
        """Test main loop runs health checks periodically."""
        health_check_called = []

        async def mock_health_check():
            health_check_called.append(True)

        agent._run_health_checks = mock_health_check
        agent._predictive_analysis = AsyncMock()
        agent._running = True

        # Create a sleep mock that stops the loop after first iteration
        call_count = 0

        async def mock_sleep(duration):
            nonlocal call_count
            call_count += 1
            if call_count >= 1:
                agent._running = False

        with patch("sentinel.agents.healer.asyncio.sleep", mock_sleep):
            await agent._main_loop()

        # Should have run health checks
        assert len(health_check_called) >= 1

    @pytest.mark.asyncio
    async def test_main_loop_handles_exception(self, agent, mock_engine):
        """Test main loop continues after exception."""
        call_count = 0

        async def failing_health_check():
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                raise Exception("Test error")

        agent._run_health_checks = failing_health_check
        agent._running = True

        sleep_count = 0

        async def mock_sleep(duration):
            nonlocal sleep_count
            sleep_count += 1
            if sleep_count >= 2:
                agent._running = False

        with patch("sentinel.agents.healer.asyncio.sleep", mock_sleep):
            await agent._main_loop()

        # Should have attempted health check despite error
        assert call_count >= 1
