"""
Comprehensive tests for TestingAgent.

Tests cover:
- Initialization with various configurations
- Event subscriptions
- Integration health checking
- Agent monitoring
- Event performance tracking
- Resource monitoring
- Issue detection and resolution
- Action execution
"""
import asyncio
import pytest
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, AsyncMock, patch, PropertyMock

from sentinel.agents.testing import TestingAgent
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
    engine.state.get = AsyncMock(return_value=None)
    engine.state.set = AsyncMock()
    engine.get_integration = MagicMock(return_value=None)
    engine._agents = {}
    engine.metrics = None
    return engine


@pytest.fixture
def default_config():
    """Default testing agent configuration."""
    return {
        "health_check_interval_seconds": 60,
        "max_event_processing_delay_ms": 500,
        "auto_restart_failed_agents": False,
        "alert_on_integration_failure": True,
        "auto_execute_threshold": 0.95,
        "log_execute_threshold": 0.80,
        "confirm_threshold": 0.60,
    }


@pytest.fixture
def agent(mock_engine, default_config):
    """Create a testing agent for testing."""
    return TestingAgent(mock_engine, default_config)


class TestTestingAgentInit:
    """Tests for testing agent initialization."""

    def test_init_with_defaults(self, mock_engine, default_config):
        """Test initialization with default config."""
        agent = TestingAgent(mock_engine, default_config)

        assert agent.agent_name == "testing"
        assert agent.agent_description == "Automated system health and issue detection"
        assert agent.health_check_interval == 60
        assert agent.max_event_delay_ms == 500
        assert agent.auto_restart_agents is False
        assert agent.alert_on_integration_failure is True

    def test_init_with_custom_config(self, mock_engine):
        """Test initialization with custom config."""
        config = {
            "health_check_interval_seconds": 120,
            "max_event_processing_delay_ms": 1000,
            "auto_restart_failed_agents": True,
            "alert_on_integration_failure": False,
        }
        agent = TestingAgent(mock_engine, config)

        assert agent.health_check_interval == 120
        assert agent.max_event_delay_ms == 1000
        assert agent.auto_restart_agents is True
        assert agent.alert_on_integration_failure is False

    def test_init_creates_tracking_structures(self, mock_engine, default_config):
        """Test that initialization creates empty tracking structures."""
        agent = TestingAgent(mock_engine, default_config)

        assert agent._detected_issues == {}
        assert agent._resolved_issues == []
        assert agent._health_history == []
        assert agent._agent_metrics == {}
        assert agent._last_health_check is None
        assert agent._event_processing_times == []
        assert agent._integration_status == {}


class TestTestingAgentSubscriptions:
    """Tests for event subscriptions."""

    @pytest.mark.asyncio
    async def test_subscribe_events(self, agent, mock_engine):
        """Test event subscriptions are set up correctly."""
        await agent._subscribe_events()

        assert mock_engine.event_bus.subscribe.call_count == 3

        call_args = [call[1] for call in mock_engine.event_bus.subscribe.call_args_list]
        event_types = [args.get("event_type") for args in call_args]

        assert "agent.action.*" in event_types
        assert "system.error" in event_types
        assert "integration.status.*" in event_types


class TestTestingAgentIntegrationChecks:
    """Tests for integration health checking."""

    @pytest.mark.asyncio
    async def test_check_integrations_no_integrations(self, agent, mock_engine):
        """Test integration check when no integrations configured."""
        mock_engine.get_integration.return_value = None

        issues = await agent._check_integrations()

        assert issues == []

    @pytest.mark.asyncio
    async def test_check_integrations_disconnected(self, agent, mock_engine):
        """Test detection of disconnected integration."""
        mock_router = MagicMock()
        mock_router.connected = False
        mock_engine.get_integration.return_value = mock_router

        issues = await agent._check_integrations()

        assert len(issues) > 0
        assert any(i["type"] == "integration_disconnected" for i in issues)

    @pytest.mark.asyncio
    async def test_check_integrations_unhealthy(self, agent, mock_engine):
        """Test detection of unhealthy integration."""
        mock_router = MagicMock()
        mock_router.connected = True
        mock_router.health_check = AsyncMock(return_value=False)
        mock_engine.get_integration.return_value = mock_router

        issues = await agent._check_integrations()

        assert len(issues) > 0
        assert any(i["type"] == "integration_unhealthy" for i in issues)

    @pytest.mark.asyncio
    async def test_check_integrations_healthy(self, agent, mock_engine):
        """Test healthy integration check."""
        mock_router = MagicMock()
        mock_router.connected = True
        mock_router.health_check = AsyncMock(return_value=True)
        mock_engine.get_integration.return_value = mock_router

        issues = await agent._check_integrations()

        # No issues for healthy integration
        assert not any(i.get("component") == "router" for i in issues)

    @pytest.mark.asyncio
    async def test_check_integrations_exception(self, agent, mock_engine):
        """Test integration check handles exception."""
        mock_router = MagicMock()
        mock_router.connected = True
        mock_router.health_check = AsyncMock(side_effect=Exception("Connection error"))
        mock_engine.get_integration.return_value = mock_router

        issues = await agent._check_integrations()

        assert len(issues) > 0
        assert any(i["type"] == "integration_error" for i in issues)


class TestTestingAgentAgentChecks:
    """Tests for agent monitoring."""

    @pytest.mark.asyncio
    async def test_check_agents_no_agents(self, agent, mock_engine):
        """Test agent check with no agents."""
        mock_engine._agents = {}

        issues = await agent._check_agents()

        assert issues == []

    @pytest.mark.asyncio
    async def test_check_agents_running(self, agent, mock_engine):
        """Test check for running agent."""
        mock_agent = MagicMock()
        mock_agent._running = True
        mock_agent.stats = {"actions_this_minute": 5}
        mock_engine._agents = {"other_agent": mock_agent}

        issues = await agent._check_agents()

        assert not any(i.get("component") == "other_agent" and i["type"] == "agent_stopped" for i in issues)

    @pytest.mark.asyncio
    async def test_check_agents_stopped(self, agent, mock_engine):
        """Test detection of stopped agent."""
        mock_agent = MagicMock()
        mock_agent._running = False
        mock_engine._agents = {"stopped_agent": mock_agent}

        issues = await agent._check_agents()

        assert len(issues) > 0
        assert any(i["type"] == "agent_stopped" for i in issues)

    @pytest.mark.asyncio
    async def test_check_agents_high_activity(self, agent, mock_engine):
        """Test detection of high agent activity."""
        mock_agent = MagicMock()
        mock_agent._running = True
        mock_agent.stats = {"actions_this_minute": 100}  # High activity
        mock_engine._agents = {"busy_agent": mock_agent}

        issues = await agent._check_agents()

        assert len(issues) > 0
        assert any(i["type"] == "agent_high_activity" for i in issues)

    @pytest.mark.asyncio
    async def test_check_agents_skips_self(self, agent, mock_engine):
        """Test that agent skips checking itself."""
        mock_engine._agents = {"testing": agent}  # Self

        issues = await agent._check_agents()

        # Should not report issues about itself
        assert not any(i.get("component") == "testing" for i in issues)


class TestTestingAgentEventPerformance:
    """Tests for event performance checking."""

    @pytest.mark.asyncio
    async def test_check_event_performance_no_event_bus(self, agent, mock_engine):
        """Test event performance check without event bus."""
        mock_engine.event_bus = None

        issues = await agent._check_event_performance()

        assert issues == []

    @pytest.mark.asyncio
    async def test_check_event_performance_queue_backlog(self, agent, mock_engine):
        """Test detection of event queue backlog."""
        mock_engine.event_bus._queue_depth = 200  # High backlog

        issues = await agent._check_event_performance()

        assert len(issues) > 0
        assert any(i["type"] == "event_queue_backlog" for i in issues)

    @pytest.mark.asyncio
    async def test_check_event_performance_slow_processing(self, agent, mock_engine):
        """Test detection of slow event processing."""
        mock_engine.event_bus._queue_depth = 10  # Low queue to avoid backlog issue
        agent._event_processing_times = [600, 700, 800]  # All above 500ms threshold

        issues = await agent._check_event_performance()

        assert len(issues) > 0
        assert any(i["type"] == "slow_event_processing" for i in issues)

    @pytest.mark.asyncio
    async def test_check_event_performance_normal(self, agent, mock_engine):
        """Test normal event performance."""
        mock_engine.event_bus._queue_depth = 10
        agent._event_processing_times = [100, 150, 200]  # All below threshold

        issues = await agent._check_event_performance()

        # No issues for normal performance
        assert not any(i["type"] in ("event_queue_backlog", "slow_event_processing") for i in issues)


class TestTestingAgentResourceChecks:
    """Tests for resource monitoring."""

    @pytest.mark.asyncio
    async def test_check_resources_no_metrics(self, agent, mock_engine):
        """Test resource check without metrics."""
        mock_engine.metrics = None

        issues = await agent._check_resources()

        assert issues == []

    @pytest.mark.asyncio
    async def test_check_resources_high_memory(self, agent, mock_engine):
        """Test detection of high memory usage."""
        mock_metrics = MagicMock()
        mock_metrics.get_value = AsyncMock(return_value=95)  # 95% memory
        mock_engine.metrics = mock_metrics

        issues = await agent._check_resources()

        assert len(issues) > 0
        assert any(i["type"] == "high_memory" for i in issues)

    @pytest.mark.asyncio
    async def test_check_resources_normal_memory(self, agent, mock_engine):
        """Test normal memory usage."""
        mock_metrics = MagicMock()
        mock_metrics.get_value = AsyncMock(return_value=50)  # 50% memory
        mock_engine.metrics = mock_metrics

        issues = await agent._check_resources()

        assert not any(i["type"] == "high_memory" for i in issues)


class TestTestingAgentIssueTracking:
    """Tests for issue detection and tracking."""

    @pytest.mark.asyncio
    async def test_record_issue_new(self, agent, mock_engine):
        """Test recording a new issue."""
        issue = {
            "type": "test_issue",
            "severity": "medium",
            "component": "test",
            "message": "Test issue"
        }

        await agent._record_issue("test_1", issue)

        assert "test_1" in agent._detected_issues
        assert agent._detected_issues["test_1"]["occurrence_count"] == 1
        mock_engine.event_bus.publish.assert_called()

    @pytest.mark.asyncio
    async def test_record_issue_existing(self, agent, mock_engine):
        """Test recording existing issue increments count."""
        agent._detected_issues = {
            "test_1": {
                "type": "test_issue",
                "occurrence_count": 1,
                "first_detected": datetime.now(timezone.utc).isoformat()
            }
        }

        issue = {"type": "test_issue", "severity": "medium", "component": "test", "message": "Test"}
        await agent._record_issue("test_1", issue)

        assert agent._detected_issues["test_1"]["occurrence_count"] == 2

    @pytest.mark.asyncio
    async def test_clear_issue(self, agent, mock_engine):
        """Test clearing a resolved issue."""
        agent._detected_issues = {
            "test_1": {
                "type": "test_issue",
                "occurrence_count": 3,
                "first_detected": datetime.now(timezone.utc).isoformat()
            }
        }

        await agent._clear_issue("test_1")

        assert "test_1" not in agent._detected_issues
        assert len(agent._resolved_issues) == 1
        mock_engine.event_bus.publish.assert_called()

    @pytest.mark.asyncio
    async def test_clear_issue_not_found(self, agent, mock_engine):
        """Test clearing non-existent issue."""
        await agent._clear_issue("nonexistent")

        # Should not raise or add to resolved
        assert len(agent._resolved_issues) == 0


class TestTestingAgentHealthCheck:
    """Tests for system health check."""

    @pytest.mark.asyncio
    async def test_run_system_health_check(self, agent, mock_engine):
        """Test running full system health check."""
        agent._check_integrations = AsyncMock(return_value=[])
        agent._check_agents = AsyncMock(return_value=[])
        agent._check_event_performance = AsyncMock(return_value=[])
        agent._check_resources = AsyncMock(return_value=[])

        await agent._run_system_health_check()

        agent._check_integrations.assert_called_once()
        agent._check_agents.assert_called_once()
        agent._check_event_performance.assert_called_once()
        agent._check_resources.assert_called_once()

        # Should record health check
        assert len(agent._health_history) == 1

        # Should publish health check event
        mock_engine.event_bus.publish.assert_called()

    @pytest.mark.asyncio
    async def test_run_system_health_check_with_issues(self, agent, mock_engine):
        """Test health check with issues found."""
        agent._check_integrations = AsyncMock(return_value=[
            {"type": "integration_error", "severity": "high", "component": "router", "message": "Error"}
        ])
        agent._check_agents = AsyncMock(return_value=[])
        agent._check_event_performance = AsyncMock(return_value=[])
        agent._check_resources = AsyncMock(return_value=[])

        await agent._run_system_health_check()

        # Health check should reflect issues
        assert agent._health_history[-1]["issues_found"] == 1

    @pytest.mark.asyncio
    async def test_health_history_limited(self, agent, mock_engine):
        """Test health history is limited to 100 entries."""
        agent._health_history = [{"test": i} for i in range(150)]
        agent._check_integrations = AsyncMock(return_value=[])
        agent._check_agents = AsyncMock(return_value=[])
        agent._check_event_performance = AsyncMock(return_value=[])
        agent._check_resources = AsyncMock(return_value=[])

        await agent._run_system_health_check()

        assert len(agent._health_history) == 100


class TestTestingAgentEventHandlers:
    """Tests for event handlers."""

    @pytest.mark.asyncio
    async def test_handle_agent_action(self, agent, mock_engine):
        """Test handling agent action event."""
        event = Event(
            category=EventCategory.AGENT,
            event_type="agent.action.executed",
            severity=EventSeverity.INFO,
            source="test",
            title="Action",
            description="Test action",
            data={"agent_name": "healer"}
        )

        await agent._handle_agent_action(event)

        assert "healer" in agent._agent_metrics
        assert agent._agent_metrics["healer"]["actions"] >= 1

    @pytest.mark.asyncio
    async def test_handle_system_error(self, agent, mock_engine):
        """Test handling system error event."""
        event = Event(
            category=EventCategory.SYSTEM,
            event_type="system.error",
            severity=EventSeverity.ERROR,
            source="test",
            title="Error",
            description="System error",
            data={
                "component": "database",
                "error_type": "connection",
                "message": "Connection lost"
            }
        )

        await agent._handle_system_error(event)

        # Should record issue
        assert len(agent._detected_issues) > 0

    @pytest.mark.asyncio
    async def test_handle_integration_status_disconnected(self, agent, mock_engine):
        """Test handling integration disconnected status."""
        event = Event(
            category=EventCategory.SYSTEM,
            event_type="integration.status.changed",
            severity=EventSeverity.WARNING,
            source="test",
            title="Integration Status",
            description="Status changed",
            data={"integration": "router", "status": "disconnected"}
        )

        await agent._handle_integration_status(event)

        assert "router" in agent._integration_status
        assert len(agent._detected_issues) > 0

    @pytest.mark.asyncio
    async def test_handle_integration_status_connected(self, agent, mock_engine):
        """Test handling integration connected status clears issue."""
        # First record a disconnected issue
        agent._detected_issues["int_router_status_disconnected"] = {
            "type": "integration_disconnected",
            "component": "router"
        }

        event = Event(
            category=EventCategory.SYSTEM,
            event_type="integration.status.changed",
            severity=EventSeverity.INFO,
            source="test",
            title="Integration Status",
            description="Status changed",
            data={"integration": "router", "status": "connected"}
        )

        await agent._handle_integration_status(event)

        # Issue should be cleared
        assert "int_router_status_disconnected" not in agent._detected_issues


class TestTestingAgentDoExecute:
    """Tests for action execution."""

    @pytest.mark.asyncio
    async def test_do_execute_restart_agent_success(self, agent, mock_engine):
        """Test restarting agent successfully."""
        mock_stopped_agent = MagicMock()
        mock_stopped_agent.start = AsyncMock()
        mock_engine._agents = {"stopped_agent": mock_stopped_agent}

        action = AgentAction(
            agent_name="testing",
            action_type="restart_agent",
            target_type="agent",
            target_id="stopped_agent",
            parameters={"agent_name": "stopped_agent"},
            reasoning="Agent stopped",
            confidence=0.85
        )

        result = await agent._do_execute(action)

        assert result["restarted"] is True
        mock_stopped_agent.start.assert_called_once()

    @pytest.mark.asyncio
    async def test_do_execute_restart_agent_not_found(self, agent, mock_engine):
        """Test restarting non-existent agent."""
        mock_engine._agents = {}

        action = AgentAction(
            agent_name="testing",
            action_type="restart_agent",
            target_type="agent",
            target_id="nonexistent",
            parameters={"agent_name": "nonexistent"},
            reasoning="Agent stopped",
            confidence=0.85
        )

        result = await agent._do_execute(action)

        assert result["restarted"] is False
        assert "not found" in result["error"]

    @pytest.mark.asyncio
    async def test_do_execute_restart_agent_error(self, agent, mock_engine):
        """Test restarting agent with error."""
        mock_agent = MagicMock()
        mock_agent.start = AsyncMock(side_effect=Exception("Start failed"))
        mock_engine._agents = {"failing_agent": mock_agent}

        action = AgentAction(
            agent_name="testing",
            action_type="restart_agent",
            target_type="agent",
            target_id="failing_agent",
            parameters={"agent_name": "failing_agent"},
            reasoning="Agent stopped",
            confidence=0.85
        )

        result = await agent._do_execute(action)

        assert result["restarted"] is False
        assert "Start failed" in result["error"]

    @pytest.mark.asyncio
    async def test_do_execute_clear_issue(self, agent, mock_engine):
        """Test clearing issue action."""
        agent._detected_issues = {
            "test_issue": {"type": "test", "occurrence_count": 1}
        }

        action = AgentAction(
            agent_name="testing",
            action_type="clear_issue",
            target_type="issue",
            target_id="test_issue",
            parameters={"issue_id": "test_issue"},
            reasoning="Clear resolved issue",
            confidence=0.95
        )

        result = await agent._do_execute(action)

        assert result["cleared"] is True
        assert "test_issue" not in agent._detected_issues

    @pytest.mark.asyncio
    async def test_do_execute_clear_issue_not_found(self, agent, mock_engine):
        """Test clearing non-existent issue."""
        action = AgentAction(
            agent_name="testing",
            action_type="clear_issue",
            target_type="issue",
            target_id="nonexistent",
            parameters={"issue_id": "nonexistent"},
            reasoning="Clear issue",
            confidence=0.95
        )

        result = await agent._do_execute(action)

        assert result["cleared"] is False

    @pytest.mark.asyncio
    async def test_do_execute_unknown_action(self, agent, mock_engine):
        """Test unknown action type raises error."""
        action = AgentAction(
            agent_name="testing",
            action_type="unknown_action",
            target_type="test",
            target_id="test",
            parameters={},
            reasoning="Test",
            confidence=0.5
        )

        with pytest.raises(ValueError, match="Unknown action type"):
            await agent._do_execute(action)


class TestTestingAgentCleanup:
    """Tests for data cleanup."""

    @pytest.mark.asyncio
    async def test_cleanup_old_resolved_issues(self, agent, mock_engine):
        """Test cleanup removes old resolved issues."""
        old_time = (datetime.now(timezone.utc) - timedelta(hours=48)).isoformat()
        recent_time = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()

        agent._resolved_issues = [
            {"type": "old", "resolved_at": old_time},
            {"type": "recent", "resolved_at": recent_time}
        ]

        await agent._cleanup_old_data()

        assert len(agent._resolved_issues) == 1
        assert agent._resolved_issues[0]["type"] == "recent"

    @pytest.mark.asyncio
    async def test_cleanup_old_processing_times(self, agent, mock_engine):
        """Test cleanup limits processing times."""
        agent._event_processing_times = list(range(2000))

        await agent._cleanup_old_data()

        assert len(agent._event_processing_times) == 1000


class TestTestingAgentProperties:
    """Tests for agent properties."""

    def test_detected_issues_property(self, agent):
        """Test detected issues property returns copy."""
        agent._detected_issues = {"test": {"type": "test"}}

        issues = agent.detected_issues

        assert issues == {"test": {"type": "test"}}
        assert issues is not agent._detected_issues

    def test_resolved_issues_property(self, agent):
        """Test resolved issues property returns copy."""
        agent._resolved_issues = [{"type": "resolved"}]

        issues = agent.resolved_issues

        assert issues == [{"type": "resolved"}]
        assert issues is not agent._resolved_issues

    def test_integration_status_property(self, agent):
        """Test integration status property returns copy."""
        agent._integration_status = {"router": {"connected": True}}

        status = agent.integration_status

        assert status == {"router": {"connected": True}}
        assert status is not agent._integration_status

    @pytest.mark.asyncio
    async def test_get_relevant_state(self, agent, mock_engine):
        """Test getting relevant state."""
        agent._detected_issues = {"issue1": {}, "issue2": {}}
        agent._resolved_issues = [{"resolved": True}]
        agent._integration_status = {"router": {"connected": True}}
        agent._agent_metrics = {"healer": {}, "guardian": {}}

        state = await agent._get_relevant_state()

        assert state["detected_issues"] == 2
        assert state["resolved_issues"] == 1
        assert "router" in state["integration_status"]
        assert len(state["agent_metrics"]) == 2

    def test_stats_property(self, agent, mock_engine):
        """Test stats property."""
        agent._detected_issues = {"issue1": {}}
        agent._resolved_issues = [{"r": 1}, {"r": 2}]
        agent._health_history = [{"h": 1}, {"h": 2}, {"h": 3}]
        agent._integration_status = {"router": {}}
        agent._agent_metrics = {"healer": {}, "guardian": {}}

        stats = agent.stats

        assert stats["name"] == "testing"
        assert stats["detected_issues"] == 1
        assert stats["resolved_issues_24h"] == 2
        assert stats["health_checks"] == 3
        assert stats["integrations_monitored"] == 1
        assert stats["agents_monitored"] == 2


class TestTestingAgentMainLoop:
    """Tests for main loop functionality."""

    @pytest.mark.asyncio
    async def test_main_loop_runs_health_checks(self, agent, mock_engine):
        """Test main loop runs health checks."""
        health_check_called = []

        async def mock_health_check():
            health_check_called.append(True)

        agent._run_system_health_check = mock_health_check
        agent._check_resolved_issues = AsyncMock()
        agent._cleanup_old_data = AsyncMock()
        agent._running = True

        call_count = 0

        async def mock_sleep(duration):
            nonlocal call_count
            call_count += 1
            if call_count >= 1:
                agent._running = False

        with patch("sentinel.agents.testing.asyncio.sleep", mock_sleep):
            await agent._main_loop()

        assert len(health_check_called) >= 1

    @pytest.mark.asyncio
    async def test_main_loop_handles_exception(self, agent, mock_engine):
        """Test main loop handles exceptions."""
        call_count = 0

        async def failing_check():
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                raise Exception("Check failed")

        agent._run_system_health_check = failing_check
        agent._check_resolved_issues = AsyncMock()
        agent._cleanup_old_data = AsyncMock()
        agent._running = True

        sleep_count = 0

        async def mock_sleep(duration):
            nonlocal sleep_count
            sleep_count += 1
            if sleep_count >= 2:
                agent._running = False

        with patch("sentinel.agents.testing.asyncio.sleep", mock_sleep):
            await agent._main_loop()

        assert call_count >= 1


class TestTestingAgentAgentRestart:
    """Tests for agent restart functionality."""

    @pytest.mark.asyncio
    async def test_propose_agent_restart(self, agent, mock_engine):
        """Test proposing agent restart."""
        await agent._propose_agent_restart("stopped_agent")

        assert len(agent._decisions) > 0
        mock_engine.event_bus.publish.assert_called()


class TestTestingAgentAnalyze:
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
