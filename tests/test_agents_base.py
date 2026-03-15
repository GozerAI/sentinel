"""
Tests for the BaseAgent class.

Tests cover agent lifecycle, action execution, confidence thresholds,
rate limiting, and rollback functionality.
"""
import asyncio
import pytest
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

from sentinel.agents.base import BaseAgent
from sentinel.core.models.event import (
    Event, EventCategory, EventSeverity, AgentAction, AgentDecision
)
from sentinel.core.utils import utc_now


class ConcreteAgent(BaseAgent):
    """Concrete implementation for testing."""
    agent_name = "test_agent"
    agent_description = "Test agent for unit tests"

    def __init__(self, engine, config):
        super().__init__(engine, config)
        self._subscribed = False
        self._executed_actions = []
        self._rollback_data_captured = []

    async def _subscribe_events(self):
        self._subscribed = True

    async def analyze(self, event):
        return AgentDecision(
            agent_name=self.agent_name,
            decision_type="test_decision",
            analysis="Test analysis",
            confidence=0.85,
        )

    async def _do_execute(self, action):
        self._executed_actions.append(action)
        return {"result": "success"}

    async def _capture_rollback_data(self, action):
        self._rollback_data_captured.append(action)
        return {"original_state": "captured"}

    async def _do_rollback(self, action):
        pass


@pytest.fixture
def mock_engine():
    """Create a mock engine."""
    engine = MagicMock()
    engine.event_bus = MagicMock()
    engine.event_bus.publish = AsyncMock()
    engine.event_bus.subscribe = MagicMock()
    engine.get_integration = MagicMock(return_value=None)
    return engine


@pytest.fixture
def default_config():
    """Default agent configuration (autonomous mode)."""
    return {
        "auto_execute_threshold": 0.95,
        "log_execute_threshold": 0.80,
        "confirm_threshold": 0.60,
        "max_actions_per_minute": 10,
        "llm_enabled": True,
        "llm_model": "llama3.1:8b",
        "fully_autonomous": True,
        "confirmation_timeout_seconds": 0.1,  # Very short for fast tests
    }


@pytest.fixture
def non_autonomous_config():
    """Non-autonomous agent configuration (waits for human confirmation)."""
    return {
        "auto_execute_threshold": 0.95,
        "log_execute_threshold": 0.80,
        "confirm_threshold": 0.60,
        "max_actions_per_minute": 10,
        "llm_enabled": True,
        "llm_model": "llama3.1:8b",
        "fully_autonomous": False,
    }


@pytest.fixture
def non_autonomous_agent(mock_engine, non_autonomous_config):
    """Create a test agent in non-autonomous mode."""
    return ConcreteAgent(mock_engine, non_autonomous_config)


@pytest.fixture
def agent(mock_engine, default_config):
    """Create a test agent."""
    return ConcreteAgent(mock_engine, default_config)


class TestBaseAgentInit:
    """Tests for agent initialization."""

    def test_init_with_defaults(self, mock_engine):
        """Test initialization with default config."""
        agent = ConcreteAgent(mock_engine, {})

        assert agent.agent_name == "test_agent"
        assert agent.engine is mock_engine
        assert agent._running is False
        assert agent.auto_execute_threshold == 0.95
        assert agent.log_execute_threshold == 0.80
        assert agent.confirm_threshold == 0.60
        assert agent.max_actions_per_minute == 10

    def test_init_with_custom_config(self, mock_engine):
        """Test initialization with custom config."""
        config = {
            "auto_execute_threshold": 0.99,
            "log_execute_threshold": 0.90,
            "confirm_threshold": 0.70,
            "max_actions_per_minute": 5
        }
        agent = ConcreteAgent(mock_engine, config)

        assert agent.auto_execute_threshold == 0.99
        assert agent.log_execute_threshold == 0.90
        assert agent.confirm_threshold == 0.70
        assert agent.max_actions_per_minute == 5

    def test_init_creates_empty_histories(self, agent):
        """Test that histories are initialized empty."""
        assert agent._actions == []
        assert agent._decisions == []
        assert agent._action_timestamps == []


class TestBaseAgentLifecycle:
    """Tests for agent start/stop lifecycle."""

    @pytest.mark.asyncio
    async def test_start_agent(self, agent):
        """Test starting the agent."""
        await agent.start()

        assert agent._running is True
        assert agent._subscribed is True

    @pytest.mark.asyncio
    async def test_stop_agent(self, agent):
        """Test stopping the agent."""
        await agent.start()
        await agent.stop()

        assert agent._running is False

    @pytest.mark.asyncio
    async def test_stop_without_start(self, agent):
        """Test stopping agent that wasn't started."""
        await agent.stop()

        assert agent._running is False

    @pytest.mark.asyncio
    async def test_start_calls_subscribe_events(self, agent):
        """Test that start calls _subscribe_events."""
        await agent.start()

        assert agent._subscribed is True


class TestBaseAgentAnalyze:
    """Tests for agent analysis."""

    @pytest.mark.asyncio
    async def test_analyze_returns_decision(self, agent):
        """Test that analyze returns an AgentDecision."""
        event = Event(
            category=EventCategory.DEVICE,
            event_type="device.discovered",
            severity=EventSeverity.INFO,
            source="test",
            title="Test event"
        )

        decision = await agent.analyze(event)

        assert decision is not None
        assert isinstance(decision, AgentDecision)
        assert decision.agent_name == "test_agent"
        assert decision.confidence == 0.85


class TestBaseAgentExecuteAction:
    """Tests for action execution."""

    @pytest.mark.asyncio
    async def test_execute_action_auto_execute(self, agent):
        """Test action execution with high confidence (auto-execute)."""
        action = await agent.execute_action(
            action_type="test_action",
            target_type="device",
            target_id="device-123",
            parameters={"param": "value"},
            reasoning="Test reasoning",
            confidence=0.98  # Above auto_execute_threshold
        )

        assert action.status == "executed"
        assert len(agent._executed_actions) == 1

    @pytest.mark.asyncio
    async def test_execute_action_log_execute(self, agent):
        """Test action execution with medium confidence (log-execute)."""
        action = await agent.execute_action(
            action_type="test_action",
            target_type="device",
            target_id="device-123",
            parameters={},
            reasoning="Test reasoning",
            confidence=0.85  # Between log_execute and auto_execute
        )

        assert action.status == "executed"
        assert len(agent._executed_actions) == 1

    @pytest.mark.asyncio
    async def test_execute_action_pending_confirmation_non_autonomous(
        self, non_autonomous_agent
    ):
        """Test non-autonomous action with low confidence requests confirmation."""
        action = await non_autonomous_agent.execute_action(
            action_type="test_action",
            target_type="device",
            target_id="device-123",
            parameters={},
            reasoning="Test reasoning",
            confidence=0.65  # Between confirm and log_execute
        )

        assert action.status == "pending_confirmation"
        assert len(non_autonomous_agent._executed_actions) == 0

    @pytest.mark.asyncio
    async def test_execute_action_escalated_non_autonomous(self, non_autonomous_agent):
        """Test non-autonomous action with very low confidence is escalated."""
        action = await non_autonomous_agent.execute_action(
            action_type="test_action",
            target_type="device",
            target_id="device-123",
            parameters={},
            reasoning="Test reasoning",
            confidence=0.40  # Below confirm_threshold
        )

        assert action.status == "escalated"
        assert len(non_autonomous_agent._executed_actions) == 0

    @pytest.mark.asyncio
    async def test_execute_action_autonomous_timeout(self, agent):
        """Test autonomous mode auto-approves after timeout."""
        action = await agent.execute_action(
            action_type="test_action",
            target_type="device",
            target_id="device-123",
            parameters={},
            reasoning="Test reasoning",
            confidence=0.65  # Between confirm and log_execute
        )

        # In autonomous mode, action should be executed after timeout
        assert action.status == "executed"
        assert action.confirmed_by == "autonomous_timeout"
        assert len(agent._executed_actions) == 1

    @pytest.mark.asyncio
    async def test_execute_action_autonomous_fallback(self, agent):
        """Test autonomous mode uses fallback for very low confidence."""
        action = await agent.execute_action(
            action_type="test_action",
            target_type="device",
            target_id="device-123",
            parameters={},
            reasoning="Test reasoning",
            confidence=0.40,  # Below confirm_threshold
            reversible=True
        )

        # In autonomous mode with reversible action, should execute via fallback
        assert action.status == "executed"
        assert action.confirmed_by == "autonomous_fallback"
        assert len(agent._executed_actions) == 1

    @pytest.mark.asyncio
    async def test_execute_action_stores_action(self, agent):
        """Test that executed action is stored."""
        await agent.execute_action(
            action_type="test_action",
            target_type="device",
            target_id="device-123",
            parameters={},
            reasoning="Test",
            confidence=0.98
        )

        assert len(agent._actions) == 1
        assert agent._actions[0].action_type == "test_action"

    @pytest.mark.asyncio
    async def test_execute_action_publishes_event(self, agent, mock_engine):
        """Test that action execution publishes event."""
        await agent.execute_action(
            action_type="test_action",
            target_type="device",
            target_id="device-123",
            parameters={},
            reasoning="Test",
            confidence=0.98
        )

        mock_engine.event_bus.publish.assert_called()

    @pytest.mark.asyncio
    async def test_execute_action_captures_rollback_data(self, agent):
        """Test that rollback data is captured for reversible actions."""
        await agent.execute_action(
            action_type="test_action",
            target_type="device",
            target_id="device-123",
            parameters={},
            reasoning="Test",
            confidence=0.98,
            reversible=True
        )

        assert len(agent._rollback_data_captured) == 1


class TestBaseAgentRateLimiting:
    """Tests for rate limiting."""

    def test_check_rate_limit_under_limit(self, agent):
        """Test rate limit check when under limit."""
        assert agent._check_rate_limit() is True

    def test_check_rate_limit_at_limit(self, agent):
        """Test rate limit check when at limit."""
        # Fill up action timestamps
        now = utc_now()
        agent._action_timestamps = [now] * 10

        assert agent._check_rate_limit() is False

    def test_check_rate_limit_old_timestamps_removed(self, agent):
        """Test that old timestamps are removed."""
        old_time = utc_now() - timedelta(seconds=120)  # 2 minutes ago
        agent._action_timestamps = [old_time] * 10

        # Should be true because old timestamps are cleaned up
        assert agent._check_rate_limit() is True
        assert len(agent._action_timestamps) == 0

    @pytest.mark.asyncio
    async def test_execute_action_rate_limited(self, agent):
        """Test action execution when rate limited."""
        # Fill up rate limit
        now = utc_now()
        agent._action_timestamps = [now] * 10

        with pytest.raises(RuntimeError, match="rate limit"):
            await agent.execute_action(
                action_type="test_action",
                target_type="device",
                target_id="device-123",
                parameters={},
                reasoning="Test",
                confidence=0.98
            )


class TestBaseAgentRollback:
    """Tests for action rollback."""

    @pytest.mark.asyncio
    async def test_rollback_action_success(self, agent, mock_engine):
        """Test successful action rollback."""
        # First execute an action
        action = await agent.execute_action(
            action_type="test_action",
            target_type="device",
            target_id="device-123",
            parameters={},
            reasoning="Test",
            confidence=0.98,
            reversible=True
        )

        # Now rollback
        result = await agent.rollback_action(action)

        assert result is True
        assert action.status == "rolled_back"

    @pytest.mark.asyncio
    async def test_rollback_action_not_reversible(self, agent):
        """Test rollback of non-reversible action."""
        action = AgentAction(
            agent_name="test_agent",
            action_type="test_action",
            target_type="device",
            target_id="device-123",
            parameters={},
            reasoning="Test",
            confidence=0.98,
            reversible=False
        )
        action.mark_executed({"result": "success"})

        result = await agent.rollback_action(action)

        assert result is False


class TestBaseAgentConfirmation:
    """Tests for action confirmation."""

    @pytest.mark.asyncio
    async def test_confirm_action_success(self, non_autonomous_agent):
        """Test confirming a pending action (non-autonomous mode)."""
        # Create a pending action
        action = await non_autonomous_agent.execute_action(
            action_type="test_action",
            target_type="device",
            target_id="device-123",
            parameters={},
            reasoning="Test",
            confidence=0.65  # Will be pending in non-autonomous mode
        )

        # Confirm it
        result = await non_autonomous_agent.confirm_action(action.id, "test_user")

        assert result is True
        assert action.status == "executed"
        assert action.confirmed_by == "test_user"

    @pytest.mark.asyncio
    async def test_confirm_action_not_found(self, agent):
        """Test confirming non-existent action."""
        result = await agent.confirm_action(uuid4(), "test_user")

        assert result is False

    @pytest.mark.asyncio
    async def test_confirm_action_not_pending(self, agent):
        """Test confirming action that's not pending."""
        # Create and execute an action
        action = await agent.execute_action(
            action_type="test_action",
            target_type="device",
            target_id="device-123",
            parameters={},
            reasoning="Test",
            confidence=0.98  # Will auto-execute
        )

        # Try to confirm it
        result = await agent.confirm_action(action.id, "test_user")

        assert result is False


class TestBaseAgentStats:
    """Tests for agent statistics."""

    def test_stats_initial(self, agent):
        """Test initial stats."""
        stats = agent.stats

        assert stats["name"] == "test_agent"
        assert stats["running"] is False
        assert stats["total_actions"] == 0
        assert stats["total_decisions"] == 0
        assert stats["actions_this_minute"] == 0
        assert "thresholds" in stats

    @pytest.mark.asyncio
    async def test_stats_after_actions(self, agent):
        """Test stats after executing actions."""
        await agent.start()

        await agent.execute_action(
            action_type="test1",
            target_type="device",
            target_id="d1",
            parameters={},
            reasoning="Test",
            confidence=0.98
        )
        await agent.execute_action(
            action_type="test2",
            target_type="device",
            target_id="d2",
            parameters={},
            reasoning="Test",
            confidence=0.98
        )

        stats = agent.stats

        assert stats["running"] is True
        assert stats["total_actions"] == 2
        assert stats["actions_this_minute"] == 2


class TestBaseAgentRecentHistory:
    """Tests for recent action/decision retrieval."""

    @pytest.mark.asyncio
    async def test_get_recent_actions(self, agent):
        """Test getting recent actions."""
        # Increase rate limit for this test
        agent.max_actions_per_minute = 20

        for i in range(15):
            await agent.execute_action(
                action_type=f"action_{i}",
                target_type="device",
                target_id=f"d{i}",
                parameters={},
                reasoning="Test",
                confidence=0.98
            )

        recent = agent.get_recent_actions(5)

        assert len(recent) == 5
        assert recent[-1].action_type == "action_14"

    def test_get_recent_actions_empty(self, agent):
        """Test getting recent actions when empty."""
        recent = agent.get_recent_actions(10)
        assert recent == []

    def test_get_recent_decisions_empty(self, agent):
        """Test getting recent decisions when empty."""
        recent = agent.get_recent_decisions(10)
        assert recent == []


class TestBaseAgentLLM:
    """Tests for LLM integration."""

    @pytest.mark.asyncio
    async def test_query_llm_no_integration(self, agent):
        """Test query_llm when no LLM integration."""
        with pytest.raises(RuntimeError, match="No LLM integration"):
            await agent.query_llm("Test prompt")

    @pytest.mark.asyncio
    async def test_query_llm_with_integration(self, agent, mock_engine):
        """Test query_llm with LLM integration."""
        mock_llm = MagicMock()
        mock_llm.complete = AsyncMock(return_value="LLM response")
        mock_engine.get_integration = MagicMock(return_value=mock_llm)

        result = await agent.query_llm("Test prompt")

        assert result == "LLM response"
        mock_llm.complete.assert_called_once()


class TestBaseAgentExecuteActionInternal:
    """Tests for internal action execution."""

    @pytest.mark.asyncio
    async def test_execute_action_internal_success(self, agent):
        """Test successful internal execution."""
        action = AgentAction(
            agent_name="test_agent",
            action_type="test",
            target_type="device",
            target_id="d1",
            parameters={},
            reasoning="Test",
            confidence=0.98
        )

        result = await agent._execute_action_internal(action)

        assert result.status == "executed"

    @pytest.mark.asyncio
    async def test_execute_action_internal_failure(self, agent):
        """Test internal execution with failure."""
        # Make _do_execute raise an exception
        async def failing_execute(action):
            raise ValueError("Execution failed!")

        agent._do_execute = failing_execute

        action = AgentAction(
            agent_name="test_agent",
            action_type="test",
            target_type="device",
            target_id="d1",
            parameters={},
            reasoning="Test",
            confidence=0.98
        )

        result = await agent._execute_action_internal(action)

        assert result.status == "failed"


class TestBaseAgentRollbackFailure:
    """Tests for rollback failure handling."""

    @pytest.mark.asyncio
    async def test_rollback_action_exception(self, agent, mock_engine):
        """Test rollback when _do_rollback raises exception."""
        # Execute an action first
        action = await agent.execute_action(
            action_type="test_action",
            target_type="device",
            target_id="device-123",
            parameters={},
            reasoning="Test",
            confidence=0.98,
            reversible=True
        )

        # Make _do_rollback raise an exception
        async def failing_rollback(action):
            raise RuntimeError("Rollback failed!")

        agent._do_rollback = failing_rollback

        # Rollback should return False
        result = await agent.rollback_action(action)

        assert result is False


class TestBaseAgentEscalateToLLM:
    """Tests for LLM escalation."""

    @pytest.mark.asyncio
    async def test_escalate_to_llm_no_llm_integration(self, agent, mock_engine):
        """Test escalation when no LLM integration."""
        mock_engine.get_integration.return_value = None

        action = AgentAction(
            agent_name="test_agent",
            action_type="test",
            target_type="device",
            target_id="d1",
            parameters={},
            reasoning="Test",
            confidence=0.30
        )

        # Should not raise, just log warning
        await agent._escalate_to_llm(action, None)

    @pytest.mark.asyncio
    async def test_escalate_to_llm_disabled(self, agent, mock_engine):
        """Test escalation when LLM disabled."""
        agent.llm_enabled = False
        mock_llm = MagicMock()
        mock_engine.get_integration.return_value = mock_llm

        action = AgentAction(
            agent_name="test_agent",
            action_type="test",
            target_type="device",
            target_id="d1",
            parameters={},
            reasoning="Test",
            confidence=0.30
        )

        await agent._escalate_to_llm(action, None)

        # LLM should not be called
        mock_llm.analyze_decision.assert_not_called()

    @pytest.mark.asyncio
    async def test_escalate_to_llm_success(self, agent, mock_engine):
        """Test successful LLM escalation."""
        mock_llm = MagicMock()
        mock_llm.analyze_decision = AsyncMock(return_value={"recommendation": "proceed"})
        mock_engine.get_integration.return_value = mock_llm

        action = AgentAction(
            agent_name="test_agent",
            action_type="test",
            target_type="device",
            target_id="d1",
            parameters={},
            reasoning="Test",
            confidence=0.30
        )

        trigger_event = Event(
            category=EventCategory.DEVICE,
            event_type="device.discovered",
            severity=EventSeverity.INFO,
            source="test",
            title="Test event"
        )

        await agent._escalate_to_llm(action, trigger_event)

        mock_llm.analyze_decision.assert_called_once()

    @pytest.mark.asyncio
    async def test_escalate_to_llm_exception(self, agent, mock_engine):
        """Test LLM escalation when LLM call fails."""
        mock_llm = MagicMock()
        mock_llm.analyze_decision = AsyncMock(side_effect=Exception("LLM error"))
        mock_engine.get_integration.return_value = mock_llm

        action = AgentAction(
            agent_name="test_agent",
            action_type="test",
            target_type="device",
            target_id="d1",
            parameters={},
            reasoning="Test",
            confidence=0.30
        )

        # Should not raise
        await agent._escalate_to_llm(action, None)


class TestBaseAgentGetRelevantState:
    """Tests for _get_relevant_state method."""

    @pytest.mark.asyncio
    async def test_get_relevant_state_default(self, agent):
        """Test default _get_relevant_state returns empty dict."""
        state = await agent._get_relevant_state()

        assert state == {}


class TestBaseAgentMainLoop:
    """Tests for main loop handling."""

    @pytest.mark.asyncio
    async def test_start_with_main_loop(self, mock_engine, default_config):
        """Test start with _main_loop method."""
        loop_started = []

        class AgentWithLoop(ConcreteAgent):
            async def _main_loop(self):
                loop_started.append(True)
                while self._running:
                    await asyncio.sleep(0.1)

        agent = AgentWithLoop(mock_engine, default_config)
        await agent.start()

        # Give the loop a moment to start
        await asyncio.sleep(0.2)

        assert agent._task is not None
        assert len(loop_started) == 1

        await agent.stop()

    @pytest.mark.asyncio
    async def test_stop_cancels_task(self, mock_engine, default_config):
        """Test stop cancels running task."""
        class AgentWithLoop(ConcreteAgent):
            async def _main_loop(self):
                while self._running:
                    await asyncio.sleep(0.1)

        agent = AgentWithLoop(mock_engine, default_config)
        await agent.start()

        await asyncio.sleep(0.1)
        assert agent._task is not None

        await agent.stop()

        assert agent._running is False


class TestBaseAgentExecuteActionWithTriggerEvent:
    """Tests for execute_action with trigger_event."""

    @pytest.mark.asyncio
    async def test_execute_action_with_trigger_event(self, agent):
        """Test action execution with trigger event."""
        trigger = Event(
            category=EventCategory.DEVICE,
            event_type="device.discovered",
            severity=EventSeverity.INFO,
            source="test",
            title="Test event"
        )

        action = await agent.execute_action(
            action_type="test_action",
            target_type="device",
            target_id="device-123",
            parameters={},
            reasoning="Test",
            confidence=0.98,
            trigger_event=trigger
        )

        assert action.trigger_event_id == trigger.id


class TestBaseAgentQueryLLMOptions:
    """Tests for query_llm options."""

    @pytest.mark.asyncio
    async def test_query_llm_prefer_fallback(self, agent, mock_engine):
        """Test query_llm with prefer_local=False."""
        mock_llm = MagicMock()
        mock_llm.complete = AsyncMock(return_value="LLM response")
        mock_engine.get_integration.return_value = mock_llm

        await agent.query_llm("Test prompt", prefer_local=False)

        # Should use fallback model
        mock_llm.complete.assert_called_once()
        call_kwargs = mock_llm.complete.call_args[1]
        assert call_kwargs["model"] == agent.llm_fallback

    @pytest.mark.asyncio
    async def test_query_llm_with_system_prompt(self, agent, mock_engine):
        """Test query_llm with system prompt."""
        mock_llm = MagicMock()
        mock_llm.complete = AsyncMock(return_value="LLM response")
        mock_engine.get_integration.return_value = mock_llm

        await agent.query_llm("Test prompt", system_prompt="Be helpful")

        mock_llm.complete.assert_called_once()
        call_kwargs = mock_llm.complete.call_args[1]
        assert call_kwargs["system_prompt"] == "Be helpful"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
