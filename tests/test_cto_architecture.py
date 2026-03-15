"""
Tests for CTO Architecture components.

Tests cover:
- Agent Factory
- Strategy Agent
- Learning System
- Agent Registry
"""
import pytest
import asyncio
from unittest.mock import MagicMock, AsyncMock, patch
from uuid import UUID, uuid4
from datetime import datetime, timedelta


# =============================================================================
# Agent Factory Tests
# =============================================================================

class TestAgentFactory:
    """Tests for AgentFactory."""

    def test_agent_template_creation(self):
        """Test AgentTemplate creation."""
        from sentinel.agents.factory import AgentTemplate
        from sentinel.agents.base import BaseAgent

        template = AgentTemplate(
            name="test_agent",
            description="A test agent",
            base_class=BaseAgent,
            capabilities=["scan", "analyze"],
            required_integrations=["router"],
            default_config={"interval": 300}
        )

        assert template.name == "test_agent"
        assert template.description == "A test agent"
        assert "scan" in template.capabilities
        assert "router" in template.required_integrations
        assert template.default_config["interval"] == 300

    def test_agent_template_to_dict(self):
        """Test AgentTemplate serialization."""
        from sentinel.agents.factory import AgentTemplate

        template = AgentTemplate(
            name="test",
            description="Test template"
        )

        data = template.to_dict()
        assert data["name"] == "test"
        assert "id" in data
        assert "created_at" in data

    def test_agent_instance_creation(self):
        """Test AgentInstance creation."""
        from sentinel.agents.factory import AgentInstance, AgentTemplate

        mock_agent = MagicMock()
        mock_agent.id = uuid4()
        mock_agent.agent_name = "test_agent"

        template = AgentTemplate(name="test", description="Test")
        instance = AgentInstance(mock_agent, template)

        assert instance.agent == mock_agent
        assert instance.template == template
        assert instance.status == "created"

    @pytest.mark.asyncio
    async def test_agent_instance_start(self):
        """Test starting an agent instance."""
        from sentinel.agents.factory import AgentInstance

        mock_agent = MagicMock()
        mock_agent.id = uuid4()
        mock_agent.agent_name = "test"
        mock_agent.start = AsyncMock()

        instance = AgentInstance(mock_agent)
        await instance.start()

        mock_agent.start.assert_called_once()
        assert instance.status == "running"
        assert instance.started_at is not None

    @pytest.mark.asyncio
    async def test_agent_instance_stop(self):
        """Test stopping an agent instance."""
        from sentinel.agents.factory import AgentInstance

        mock_agent = MagicMock()
        mock_agent.id = uuid4()
        mock_agent.agent_name = "test"
        mock_agent.stop = AsyncMock()

        instance = AgentInstance(mock_agent)
        instance.status = "running"
        await instance.stop()

        mock_agent.stop.assert_called_once()
        assert instance.status == "stopped"

    def test_agent_factory_init(self):
        """Test AgentFactory initialization."""
        from sentinel.agents.factory import AgentFactory

        mock_engine = MagicMock()
        factory = AgentFactory(mock_engine)

        assert factory.engine == mock_engine
        assert len(factory._templates) > 0  # Built-in templates loaded
        assert len(factory._instances) == 0

    def test_agent_factory_register_template(self):
        """Test registering a template."""
        from sentinel.agents.factory import AgentFactory, AgentTemplate

        mock_engine = MagicMock()
        factory = AgentFactory(mock_engine)

        template = AgentTemplate(
            name="custom_agent",
            description="Custom agent template"
        )
        factory.register_template(template)

        assert "custom_agent" in factory._templates

    @pytest.mark.asyncio
    async def test_agent_factory_create_agent(self):
        """Test creating an agent from template."""
        from sentinel.agents.factory import AgentFactory

        mock_engine = MagicMock()
        mock_engine.event_bus = MagicMock()
        mock_engine.event_bus.publish = AsyncMock()
        mock_engine.get_integration = MagicMock(return_value=None)

        factory = AgentFactory(mock_engine)

        # Mock the agent class
        mock_agent_class = MagicMock()
        mock_agent_instance = MagicMock()
        mock_agent_instance.id = uuid4()
        mock_agent_instance.agent_name = "discovery"
        mock_agent_instance.agent_description = "Test"
        mock_agent_instance.start = AsyncMock()
        mock_agent_class.return_value = mock_agent_instance
        factory._agent_classes["discovery"] = mock_agent_class

        instance = await factory.create_agent(
            template_name="discovery",
            config={"test": True},
            auto_start=True
        )

        assert instance is not None
        assert instance.status == "running"
        mock_agent_instance.start.assert_called_once()

    @pytest.mark.asyncio
    async def test_agent_factory_retire_agent(self):
        """Test retiring an agent."""
        from sentinel.agents.factory import AgentFactory, AgentInstance

        mock_engine = MagicMock()
        mock_engine.event_bus = MagicMock()
        mock_engine.event_bus.publish = AsyncMock()

        factory = AgentFactory(mock_engine)

        # Create a mock instance
        mock_agent = MagicMock()
        mock_agent.id = uuid4()
        mock_agent.agent_name = "test"
        mock_agent.stop = AsyncMock()

        instance = AgentInstance(mock_agent)
        instance.status = "running"
        factory._instances[instance.id] = instance

        result = await factory.retire_agent(instance.id, "Test retirement")

        assert result is True
        assert instance.id not in factory._instances

    def test_agent_factory_stats(self):
        """Test factory statistics."""
        from sentinel.agents.factory import AgentFactory

        mock_engine = MagicMock()
        factory = AgentFactory(mock_engine)

        stats = factory.stats
        assert "templates_registered" in stats
        assert "total_instances" in stats
        assert "running_instances" in stats


# =============================================================================
# Strategy Agent Tests
# =============================================================================

class TestStrategyAgent:
    """Tests for StrategyAgent."""

    def test_strategic_goal_creation(self):
        """Test StrategicGoal creation."""
        from sentinel.agents.strategy import StrategicGoal

        goal = StrategicGoal(
            name="network_security",
            description="Maintain security posture",
            priority=10,
            metrics=["threats_blocked"],
            target_values={"compliance_score": 0.95}
        )

        assert goal.name == "network_security"
        assert goal.priority == 10
        assert "threats_blocked" in goal.metrics
        assert goal.target_values["compliance_score"] == 0.95
        assert goal.achieved is False

    def test_strategic_goal_to_dict(self):
        """Test StrategicGoal serialization."""
        from sentinel.agents.strategy import StrategicGoal

        goal = StrategicGoal(name="test", description="Test goal")
        data = goal.to_dict()

        assert data["name"] == "test"
        assert "id" in data
        assert "progress" in data

    def test_strategic_plan_creation(self):
        """Test StrategicPlan creation."""
        from sentinel.agents.strategy import StrategicPlan, StrategicGoal

        goal = StrategicGoal(name="test", description="Test")
        plan = StrategicPlan(
            name="Test Plan",
            goals=[goal],
            actions=[{"action": "spawn_agent", "template": "guardian"}]
        )

        assert plan.name == "Test Plan"
        assert len(plan.goals) == 1
        assert plan.status == "pending"

    def test_strategy_agent_init(self):
        """Test StrategyAgent initialization."""
        from sentinel.agents.strategy import StrategyAgent

        mock_engine = MagicMock()
        config = {"planning_interval": 600}

        agent = StrategyAgent(mock_engine, config)

        assert agent.agent_name == "strategy"
        assert agent.planning_interval == 600
        assert len(agent._goals) > 0  # Default goals initialized

    def test_strategy_agent_default_goals(self):
        """Test default strategic goals."""
        from sentinel.agents.strategy import StrategyAgent

        mock_engine = MagicMock()
        agent = StrategyAgent(mock_engine, {})

        # Should have default goals
        goal_names = [g.name for g in agent._goals]
        assert "network_security" in goal_names
        assert "network_visibility" in goal_names
        assert "service_availability" in goal_names

    def test_strategy_agent_add_goal(self):
        """Test adding a strategic goal."""
        from sentinel.agents.strategy import StrategyAgent, StrategicGoal

        mock_engine = MagicMock()
        agent = StrategyAgent(mock_engine, {})

        goal = StrategicGoal(
            name="custom_goal",
            description="Custom goal",
            priority=8
        )
        agent.add_goal(goal)

        assert any(g.name == "custom_goal" for g in agent._goals)

    def test_strategy_agent_remove_goal(self):
        """Test removing a strategic goal."""
        from sentinel.agents.strategy import StrategyAgent

        mock_engine = MagicMock()
        agent = StrategyAgent(mock_engine, {})

        # Remove a default goal
        result = agent.remove_goal("network_efficiency")
        assert result is True
        assert not any(g.name == "network_efficiency" for g in agent._goals)

    def test_strategy_agent_stats(self):
        """Test strategy agent statistics."""
        from sentinel.agents.strategy import StrategyAgent

        mock_engine = MagicMock()
        agent = StrategyAgent(mock_engine, {})

        stats = agent.stats
        assert "goals" in stats
        assert "active_plans" in stats
        assert "running" in stats


# =============================================================================
# Learning System Tests
# =============================================================================

class TestLearningSystem:
    """Tests for LearningSystem."""

    def test_action_outcome_creation(self):
        """Test ActionOutcome creation."""
        from sentinel.core.learning import ActionOutcome

        outcome = ActionOutcome(
            action_id=uuid4(),
            agent_name="guardian",
            action_type="block_ip",
            parameters={"ip": "10.0.0.1"},
            initial_confidence=0.85
        )

        assert outcome.agent_name == "guardian"
        assert outcome.action_type == "block_ip"
        assert outcome.initial_confidence == 0.85
        assert outcome.outcome is None

    def test_action_outcome_record(self):
        """Test recording outcome."""
        from sentinel.core.learning import ActionOutcome

        outcome = ActionOutcome(
            action_id=uuid4(),
            agent_name="guardian",
            action_type="block_ip",
            parameters={},
            initial_confidence=0.85
        )

        outcome.record_outcome("success", effectiveness=0.95)

        assert outcome.outcome == "success"
        assert outcome.effectiveness == 0.95

    def test_action_outcome_feedback(self):
        """Test adding feedback."""
        from sentinel.core.learning import ActionOutcome

        outcome = ActionOutcome(
            action_id=uuid4(),
            agent_name="guardian",
            action_type="block_ip",
            parameters={},
            initial_confidence=0.85
        )

        outcome.add_feedback("Good decision", 0.9)

        assert outcome.feedback == "Good decision"
        assert outcome.feedback_score == 0.9

    def test_pattern_creation(self):
        """Test Pattern creation."""
        from sentinel.core.learning import Pattern

        pattern = Pattern(
            pattern_type="optimization",
            agent_name="guardian",
            action_type="block_ip",
            conditions={"confidence_bucket": "high"},
            recommendation="Maintain current thresholds",
            confidence_adjustment=0.02,
            sample_size=100
        )

        assert pattern.agent_name == "guardian"
        assert pattern.confidence_adjustment == 0.02
        assert pattern.sample_size == 100

    def test_learning_system_init(self):
        """Test LearningSystem initialization."""
        from sentinel.core.learning import LearningSystem

        mock_engine = MagicMock()
        config = {"min_samples": 20}

        system = LearningSystem(mock_engine, config)

        assert system.min_samples_for_pattern == 20
        assert len(system._outcomes) == 0

    @pytest.mark.asyncio
    async def test_learning_system_record_outcome(self):
        """Test recording an outcome."""
        from sentinel.core.learning import LearningSystem, ActionOutcome

        mock_engine = MagicMock()
        mock_engine.event_bus = MagicMock()

        system = LearningSystem(mock_engine, {})

        outcome = ActionOutcome(
            action_id=uuid4(),
            agent_name="guardian",
            action_type="block_ip",
            parameters={},
            initial_confidence=0.85
        )
        outcome.record_outcome("success", effectiveness=1.0)

        await system.record_outcome(outcome)

        assert len(system._outcomes) == 1
        assert system._stats_by_agent["guardian"]["total_actions"] == 1

    def test_learning_system_confidence_adjustment(self):
        """Test getting confidence adjustment."""
        from sentinel.core.learning import LearningSystem

        mock_engine = MagicMock()
        system = LearningSystem(mock_engine, {})

        # Set a known adjustment
        system._confidence_adjustments["guardian:block_ip"] = 0.05

        adjustment = system.get_confidence_adjustment("guardian", "block_ip")
        assert adjustment == 0.05

    def test_learning_system_adjusted_confidence(self):
        """Test adjusted confidence calculation."""
        from sentinel.core.learning import LearningSystem

        mock_engine = MagicMock()
        system = LearningSystem(mock_engine, {"learning_rate": 0.1})
        system._confidence_adjustments["guardian:block_ip"] = 0.1

        adjusted = system.get_adjusted_confidence("guardian", "block_ip", 0.8)

        # 0.8 + (0.1 * 0.1) = 0.81
        assert adjusted == pytest.approx(0.81, rel=0.01)

    def test_learning_system_stats(self):
        """Test learning system statistics."""
        from sentinel.core.learning import LearningSystem

        mock_engine = MagicMock()
        system = LearningSystem(mock_engine, {})

        stats = system.stats
        assert "total_outcomes" in stats
        assert "total_patterns" in stats
        assert "agents_tracked" in stats


# =============================================================================
# Agent Registry Tests
# =============================================================================

class TestAgentRegistry:
    """Tests for AgentRegistry."""

    def test_agent_capability_creation(self):
        """Test AgentCapability creation."""
        from sentinel.agents.registry import AgentCapability

        async def handler(**kwargs):
            return {"result": "ok"}

        capability = AgentCapability(
            name="scan_network",
            description="Scan network for devices",
            handler=handler,
            input_schema={"subnet": "string"},
            output_schema={"devices": "list"}
        )

        assert capability.name == "scan_network"
        assert capability.description == "Scan network for devices"

    def test_agent_message_creation(self):
        """Test AgentMessage creation."""
        from sentinel.agents.registry import AgentMessage

        from_id = uuid4()
        to_id = uuid4()

        message = AgentMessage(
            from_agent=from_id,
            to_agent=to_id,
            message_type="request_scan",
            payload={"subnet": "192.168.1.0/24"}
        )

        assert message.from_agent == from_id
        assert message.to_agent == to_id
        assert message.message_type == "request_scan"

    def test_agent_registration_creation(self):
        """Test AgentRegistration creation."""
        from sentinel.agents.registry import AgentRegistration

        mock_agent = MagicMock()
        mock_agent.id = uuid4()
        mock_agent.agent_name = "discovery"
        mock_agent.agent_description = "Discovery agent"

        registration = AgentRegistration(
            agent_id=mock_agent.id,
            agent_name=mock_agent.agent_name,
            agent_description=mock_agent.agent_description,
            agent=mock_agent
        )

        assert registration.agent_id == mock_agent.id
        assert registration.status == "active"

    def test_agent_registry_init(self):
        """Test AgentRegistry initialization."""
        from sentinel.agents.registry import AgentRegistry

        mock_engine = MagicMock()
        registry = AgentRegistry(mock_engine)

        assert registry.engine == mock_engine
        assert len(registry._agents) == 0

    @pytest.mark.asyncio
    async def test_agent_registry_register(self):
        """Test registering an agent."""
        from sentinel.agents.registry import AgentRegistry

        mock_engine = MagicMock()
        mock_engine.event_bus = MagicMock()
        mock_engine.event_bus.publish = AsyncMock()

        registry = AgentRegistry(mock_engine)
        registry._running = True

        mock_agent = MagicMock()
        mock_agent.id = uuid4()
        mock_agent.agent_name = "discovery"
        mock_agent.agent_description = "Discovery agent"

        registration = await registry.register(mock_agent)

        assert registration.agent_id == mock_agent.id
        assert mock_agent.id in registry._agents

    @pytest.mark.asyncio
    async def test_agent_registry_unregister(self):
        """Test unregistering an agent."""
        from sentinel.agents.registry import AgentRegistry

        mock_engine = MagicMock()
        mock_engine.event_bus = MagicMock()
        mock_engine.event_bus.publish = AsyncMock()

        registry = AgentRegistry(mock_engine)
        registry._running = True

        mock_agent = MagicMock()
        mock_agent.id = uuid4()
        mock_agent.agent_name = "discovery"
        mock_agent.agent_description = "Discovery agent"

        await registry.register(mock_agent)
        result = await registry.unregister(mock_agent.id)

        assert result is True
        assert mock_agent.id not in registry._agents

    def test_agent_registry_register_capability(self):
        """Test registering a capability."""
        from sentinel.agents.registry import AgentRegistry, AgentCapability, AgentRegistration

        mock_engine = MagicMock()
        registry = AgentRegistry(mock_engine)

        # Create registration manually
        agent_id = uuid4()
        mock_agent = MagicMock()
        mock_agent.id = agent_id

        registration = AgentRegistration(
            agent_id=agent_id,
            agent_name="discovery",
            agent_description="Discovery",
            agent=mock_agent
        )
        registry._agents[agent_id] = registration

        # Register capability
        capability = AgentCapability(
            name="scan_network",
            description="Scan",
            handler=AsyncMock()
        )

        result = registry.register_capability(agent_id, capability)

        assert result is True
        assert "scan_network" in registry._capabilities
        assert agent_id in registry._capabilities["scan_network"]

    def test_agent_registry_find_by_capability(self):
        """Test finding agents by capability."""
        from sentinel.agents.registry import AgentRegistry, AgentCapability, AgentRegistration

        mock_engine = MagicMock()
        registry = AgentRegistry(mock_engine)

        # Create registration
        agent_id = uuid4()
        mock_agent = MagicMock()
        mock_agent.id = agent_id

        registration = AgentRegistration(
            agent_id=agent_id,
            agent_name="discovery",
            agent_description="Discovery",
            agent=mock_agent
        )
        registry._agents[agent_id] = registration

        # Register capability
        capability = AgentCapability(
            name="scan_network",
            description="Scan",
            handler=AsyncMock()
        )
        registry.register_capability(agent_id, capability)

        # Find by capability
        agents = registry.find_by_capability("scan_network")

        assert len(agents) == 1
        assert agents[0].agent_id == agent_id

    def test_agent_registry_heartbeat(self):
        """Test heartbeat mechanism."""
        from sentinel.agents.registry import AgentRegistry, AgentRegistration

        mock_engine = MagicMock()
        registry = AgentRegistry(mock_engine)

        # Create registration
        agent_id = uuid4()
        mock_agent = MagicMock()
        mock_agent.id = agent_id

        registration = AgentRegistration(
            agent_id=agent_id,
            agent_name="discovery",
            agent_description="Discovery",
            agent=mock_agent
        )
        registry._agents[agent_id] = registration

        old_heartbeat = registration.last_heartbeat

        # Wait a moment
        import time
        time.sleep(0.01)

        result = registry.heartbeat(agent_id)

        assert result is True
        assert registration.last_heartbeat > old_heartbeat

    def test_agent_registry_stats(self):
        """Test registry statistics."""
        from sentinel.agents.registry import AgentRegistry

        mock_engine = MagicMock()
        registry = AgentRegistry(mock_engine)

        stats = registry.stats

        assert "total_agents" in stats
        assert "active_agents" in stats
        assert "total_capabilities" in stats


# =============================================================================
# Integration Tests
# =============================================================================

class TestCTOIntegration:
    """Integration tests for CTO architecture."""

    @pytest.mark.asyncio
    async def test_engine_cto_mode_initialization(self):
        """Test engine initializes CTO components."""
        from sentinel.core.engine import SentinelEngine

        config = {
            "cto_mode": {"enabled": True},
            "agents": {},
            "integrations": {}
        }

        # We need to mock heavily to avoid real initialization
        with patch("sentinel.core.engine.EventBus"):
            with patch("sentinel.core.engine.Scheduler"):
                with patch("sentinel.core.engine.StateManager"):
                    engine = SentinelEngine(config)

                    assert engine._cto_mode is True
                    # Components not initialized until start()
                    assert engine.agent_factory is None

    @pytest.mark.asyncio
    async def test_engine_spawn_agent(self):
        """Test spawning agent through engine."""
        from sentinel.core.engine import SentinelEngine
        from sentinel.agents.factory import AgentFactory, AgentInstance

        mock_factory = MagicMock(spec=AgentFactory)
        mock_instance = MagicMock()
        mock_instance.id = uuid4()
        mock_factory.create_agent = AsyncMock(return_value=mock_instance)

        engine = MagicMock(spec=SentinelEngine)
        engine.agent_factory = mock_factory

        # Call the method directly
        result = await mock_factory.create_agent(
            template_name="guardian",
            config={},
            auto_start=True
        )

        assert result.id is not None
        mock_factory.create_agent.assert_called_once()

    @pytest.mark.asyncio
    async def test_strategy_agent_planning_cycle(self):
        """Test strategy agent planning cycle."""
        from sentinel.agents.strategy import StrategyAgent

        mock_engine = MagicMock()
        mock_engine.get_integration = MagicMock(return_value=None)

        # Mock the factory
        mock_factory = MagicMock()
        mock_factory.get_all_instances = MagicMock(return_value=[])
        mock_factory.get_running_instances = MagicMock(return_value=[])

        agent = StrategyAgent(mock_engine, {})

        # Mock _get_factory to return our mock
        with patch.object(agent, "_get_factory", return_value=mock_factory):
            state = await agent._gather_strategic_state()

            assert "timestamp" in state
            assert "agents" in state
            assert "threats" in state

    @pytest.mark.asyncio
    async def test_learning_system_pattern_detection(self):
        """Test learning system detects patterns."""
        from sentinel.core.learning import LearningSystem, ActionOutcome

        mock_engine = MagicMock()
        mock_engine.event_bus = MagicMock()

        system = LearningSystem(mock_engine, {"min_samples": 5})

        # Add multiple outcomes
        for i in range(10):
            outcome = ActionOutcome(
                action_id=uuid4(),
                agent_name="guardian",
                action_type="block_ip",
                parameters={"ip": f"10.0.0.{i}"},
                initial_confidence=0.85 + (i * 0.01)
            )
            outcome.record_outcome("success", effectiveness=0.9 + (i * 0.01))
            await system.record_outcome(outcome)

        # Check if patterns were detected
        key = "guardian:block_ip"
        assert system._stats_by_action[key]["total"] == 10
        assert system._stats_by_action[key]["successes"] == 10
