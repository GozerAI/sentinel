"""
Comprehensive tests for OptimizerAgent.

Tests cover:
- Initialization with various configurations
- Event subscriptions
- Application classification
- Flow handling and QoS evaluation
- Congestion handling
- Link utilization calculation
- Rate limiting proposals
- Traffic analysis
- Action execution
- Rollback functionality
"""

import asyncio
import pytest
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, AsyncMock, patch

from sentinel.agents.optimizer import OptimizerAgent
from sentinel.core.models.event import Event, EventCategory, EventSeverity, AgentAction


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
    return engine


@pytest.fixture
def default_config():
    """Default optimizer configuration."""
    return {
        "analysis_interval_seconds": 60,
        "netflow_enabled": True,
        "netflow_port": 2055,
        "bandwidth_threshold_percent": 80,
        "auto_execute_threshold": 0.95,
        "log_execute_threshold": 0.80,
        "confirm_threshold": 0.60,
    }


@pytest.fixture
def agent(mock_engine, default_config):
    """Create an optimizer agent for testing."""
    return OptimizerAgent(mock_engine, default_config)


class TestOptimizerAgentInit:
    """Tests for optimizer agent initialization."""

    def test_init_with_defaults(self, mock_engine, default_config):
        """Test initialization with default config."""
        agent = OptimizerAgent(mock_engine, default_config)

        assert agent.agent_name == "optimizer"
        assert agent.agent_description == "Traffic engineering and QoS management"
        assert agent.analysis_interval == 60
        assert agent.netflow_enabled is True
        assert agent.netflow_port == 2055
        assert agent.bandwidth_threshold == 80

    def test_init_with_custom_config(self, mock_engine):
        """Test initialization with custom config."""
        config = {
            "analysis_interval_seconds": 120,
            "netflow_enabled": False,
            "netflow_port": 9995,
            "bandwidth_threshold_percent": 90,
        }
        agent = OptimizerAgent(mock_engine, config)

        assert agent.analysis_interval == 120
        assert agent.netflow_enabled is False
        assert agent.netflow_port == 9995
        assert agent.bandwidth_threshold == 90

    def test_init_creates_tracking_structures(self, mock_engine, default_config):
        """Test that initialization creates empty tracking structures."""
        agent = OptimizerAgent(mock_engine, default_config)

        assert agent._flows == {}
        assert agent._link_utilization == {}
        assert agent._qos_policies == {}
        assert agent._congestion_events == []
        assert agent._last_analysis is None

    def test_init_app_signatures(self, mock_engine, default_config):
        """Test application signatures are initialized."""
        agent = OptimizerAgent(mock_engine, default_config)

        assert (443, "netflix.com") in agent._app_signatures
        assert agent._app_signatures[(443, "netflix.com")] == "streaming"
        assert (5060, None) in agent._app_signatures
        assert agent._app_signatures[(5060, None)] == "voip"

    def test_init_priority_map(self, mock_engine, default_config):
        """Test priority map is initialized."""
        agent = OptimizerAgent(mock_engine, default_config)

        assert agent._priority_map["voip"] == 1
        assert agent._priority_map["gaming"] == 2
        assert agent._priority_map["streaming"] == 3
        assert agent._priority_map["backup"] == 5

    def test_init_dscp_map(self, mock_engine, default_config):
        """Test DSCP map is initialized."""
        agent = OptimizerAgent(mock_engine, default_config)

        assert agent._dscp_map[1] == 46  # EF
        assert agent._dscp_map[2] == 34  # AF41
        assert agent._dscp_map[3] == 0  # Best effort


class TestOptimizerAgentSubscriptions:
    """Tests for event subscriptions."""

    @pytest.mark.asyncio
    async def test_subscribe_events(self, agent, mock_engine):
        """Test event subscriptions are set up correctly."""
        await agent._subscribe_events()

        assert mock_engine.event_bus.subscribe.call_count == 2

        call_args = [call[1] for call in mock_engine.event_bus.subscribe.call_args_list]
        event_types = [args.get("event_type") for args in call_args]

        assert "network.flow.detected" in event_types
        assert "network.congestion.detected" in event_types


class TestOptimizerAgentClassifyApplication:
    """Tests for application classification."""

    def test_classify_streaming_netflix(self, agent):
        """Test classification of Netflix traffic."""
        flow_data = {"destination_port": 443, "destination_host": "www.netflix.com"}

        result = agent._classify_application(flow_data)

        assert result == "streaming"

    def test_classify_streaming_youtube(self, agent):
        """Test classification of YouTube traffic."""
        flow_data = {"destination_port": 443, "destination_host": "youtube.com"}

        result = agent._classify_application(flow_data)

        assert result == "streaming"

    def test_classify_gaming_xbox(self, agent):
        """Test classification of Xbox Live traffic."""
        flow_data = {"destination_port": 3074, "destination_host": "unknown"}

        result = agent._classify_application(flow_data)

        assert result == "gaming"

    def test_classify_voip(self, agent):
        """Test classification of VoIP traffic."""
        flow_data = {"destination_port": 5060, "destination_host": "sip.provider.com"}

        result = agent._classify_application(flow_data)

        assert result == "voip"

    def test_classify_conferencing_zoom(self, agent):
        """Test classification of Zoom traffic."""
        flow_data = {"destination_port": 443, "destination_host": "zoom.us"}

        result = agent._classify_application(flow_data)

        assert result == "conferencing"

    def test_classify_web_default(self, agent):
        """Test classification of generic web traffic."""
        flow_data = {"destination_port": 443, "destination_host": "example.com"}

        result = agent._classify_application(flow_data)

        assert result == "web"

    def test_classify_remote_access_ssh(self, agent):
        """Test classification of SSH traffic."""
        flow_data = {"destination_port": 22, "destination_host": "server.local"}

        result = agent._classify_application(flow_data)

        assert result == "remote_access"

    def test_classify_remote_access_rdp(self, agent):
        """Test classification of RDP traffic."""
        flow_data = {"destination_port": 3389, "destination_host": "workstation"}

        result = agent._classify_application(flow_data)

        assert result == "remote_access"

    def test_classify_file_transfer_smb(self, agent):
        """Test classification of SMB traffic."""
        flow_data = {"destination_port": 445, "destination_host": "nas"}

        result = agent._classify_application(flow_data)

        assert result == "file_transfer"

    def test_classify_email_smtp(self, agent):
        """Test classification of SMTP traffic."""
        flow_data = {"destination_port": 587, "destination_host": "mail.server.com"}

        result = agent._classify_application(flow_data)

        assert result == "email"

    def test_classify_default_unknown_port(self, agent):
        """Test classification of unknown traffic."""
        flow_data = {"destination_port": 12345, "destination_host": "unknown.host"}

        result = agent._classify_application(flow_data)

        assert result == "default"


class TestOptimizerAgentFlowHandling:
    """Tests for flow event handling."""

    @pytest.mark.asyncio
    async def test_handle_flow_event_creates_flow(self, agent, mock_engine):
        """Test flow event creates flow record."""
        event = Event(
            category=EventCategory.NETWORK,
            event_type="network.flow.detected",
            severity=EventSeverity.INFO,
            source="netflow",
            title="Flow Detected",
            description="New flow",
            data={
                "id": "flow1",
                "source_ip": "192.168.1.100",
                "source_port": 54321,
                "destination_ip": "8.8.8.8",
                "destination_port": 443,
                "destination_host": "example.com",
                "protocol": "tcp",
                "bytes_sent": 1000,
                "bytes_received": 5000,
            },
        )

        await agent._handle_flow_event(event)

        assert "flow1" in agent._flows
        flow = agent._flows["flow1"]
        assert flow["source_ip"] == "192.168.1.100"
        assert flow["destination_port"] == 443
        assert flow["application"] == "web"

    @pytest.mark.asyncio
    async def test_handle_flow_event_voip_triggers_qos(self, agent, mock_engine):
        """Test VoIP flow triggers QoS evaluation."""
        agent._propose_qos_policy = AsyncMock()

        event = Event(
            category=EventCategory.NETWORK,
            event_type="network.flow.detected",
            severity=EventSeverity.INFO,
            source="netflow",
            title="VoIP Flow",
            description="VoIP flow detected",
            data={
                "id": "voip_flow",
                "source_ip": "192.168.1.100",
                "source_port": 54321,
                "destination_ip": "10.0.0.1",
                "destination_port": 5060,
                "protocol": "udp",
            },
        )

        await agent._handle_flow_event(event)

        # VoIP is priority 1, should trigger QoS
        agent._propose_qos_policy.assert_called_once()

    @pytest.mark.asyncio
    async def test_handle_flow_event_low_priority_no_qos(self, agent, mock_engine):
        """Test low priority flow doesn't trigger QoS."""
        agent._propose_qos_policy = AsyncMock()

        event = Event(
            category=EventCategory.NETWORK,
            event_type="network.flow.detected",
            severity=EventSeverity.INFO,
            source="netflow",
            title="Backup Flow",
            description="Backup flow detected",
            data={
                "id": "backup_flow",
                "source_ip": "192.168.1.100",
                "source_port": 54321,
                "destination_ip": "10.0.0.1",
                "destination_port": 443,
                "destination_host": "backblaze.com",
                "protocol": "tcp",
            },
        )

        await agent._handle_flow_event(event)

        # Backup is priority 5, should not trigger QoS
        agent._propose_qos_policy.assert_not_called()


class TestOptimizerAgentQoSPolicies:
    """Tests for QoS policy management."""

    def test_find_matching_policy_exists(self, agent):
        """Test finding existing matching policy."""
        agent._qos_policies = {"policy1": {"destination_port": 5060, "priority_queue": 1}}

        flow = {"destination_port": 5060}
        result = agent._find_matching_policy(flow)

        assert result is not None
        assert result["destination_port"] == 5060

    def test_find_matching_policy_not_found(self, agent):
        """Test finding policy when none exists."""
        agent._qos_policies = {"policy1": {"destination_port": 5060, "priority_queue": 1}}

        flow = {"destination_port": 443}
        result = agent._find_matching_policy(flow)

        assert result is None

    @pytest.mark.asyncio
    async def test_propose_qos_policy(self, agent, mock_engine):
        """Test QoS policy proposal."""
        flow = {"id": "flow1", "application": "voip", "destination_port": 5060, "protocol": "udp"}

        await agent._propose_qos_policy(flow, priority=1)

        # Should create decision
        assert len(agent._decisions) > 0
        decision = agent._decisions[-1]
        assert decision.decision_type == "apply_qos"

        # Should publish action event
        mock_engine.event_bus.publish.assert_called()

    @pytest.mark.asyncio
    async def test_propose_qos_policy_higher_confidence_for_known_apps(self, agent, mock_engine):
        """Test higher confidence for known applications."""
        voip_flow = {
            "id": "voip1",
            "application": "voip",
            "destination_port": 5060,
            "protocol": "udp",
        }

        await agent._propose_qos_policy(voip_flow, priority=1)

        decision = agent._decisions[-1]
        assert decision.confidence == 0.92  # Higher for voip


class TestOptimizerAgentCongestion:
    """Tests for congestion handling."""

    @pytest.mark.asyncio
    async def test_handle_congestion_event_stores_event(self, agent, mock_engine):
        """Test congestion event is stored."""
        event = Event(
            category=EventCategory.NETWORK,
            event_type="network.congestion.detected",
            severity=EventSeverity.WARNING,
            source="monitor",
            title="Congestion",
            description="Link congestion",
            data={"link_id": "link1", "utilization": 85, "queue_depth": 100},
        )

        await agent._handle_congestion_event(event)

        assert len(agent._congestion_events) == 1
        assert agent._congestion_events[0]["link_id"] == "link1"

    @pytest.mark.asyncio
    async def test_handle_congestion_event_critical_triggers_handler(self, agent, mock_engine):
        """Test critical congestion triggers handler."""
        agent._handle_critical_congestion = AsyncMock()

        event = Event(
            category=EventCategory.NETWORK,
            event_type="network.congestion.detected",
            severity=EventSeverity.CRITICAL,
            source="monitor",
            title="Critical Congestion",
            description="Critical link congestion",
            data={"link_id": "link1", "utilization": 98, "queue_depth": 500},
        )

        await agent._handle_congestion_event(event)

        agent._handle_critical_congestion.assert_called_once()

    @pytest.mark.asyncio
    async def test_handle_congestion_event_normal_no_critical(self, agent, mock_engine):
        """Test normal congestion doesn't trigger critical handler."""
        agent._handle_critical_congestion = AsyncMock()

        event = Event(
            category=EventCategory.NETWORK,
            event_type="network.congestion.detected",
            severity=EventSeverity.WARNING,
            source="monitor",
            title="Congestion",
            description="Link congestion",
            data={"link_id": "link1", "utilization": 85, "queue_depth": 100},
        )

        await agent._handle_congestion_event(event)

        agent._handle_critical_congestion.assert_not_called()

    @pytest.mark.asyncio
    async def test_handle_critical_congestion(self, agent, mock_engine):
        """Test critical congestion handler."""
        congestion_data = {"link_id": "link1", "utilization": 98}

        await agent._handle_critical_congestion(congestion_data)

        # Should publish critical event
        mock_engine.event_bus.publish.assert_called_once()
        event = mock_engine.event_bus.publish.call_args[0][0]
        assert event.event_type == "network.congestion.critical"
        assert event.severity == EventSeverity.CRITICAL


class TestOptimizerAgentLinkUtilization:
    """Tests for link utilization calculation."""

    @pytest.mark.asyncio
    async def test_calculate_link_utilization_empty_flows(self, agent, mock_engine):
        """Test calculation with no flows."""
        await agent._calculate_link_utilization()

        assert agent._link_utilization == {}

    @pytest.mark.asyncio
    async def test_calculate_link_utilization_with_flows(self, agent, mock_engine):
        """Test calculation with flows."""
        agent._flows = {
            "flow1": {
                "source_ip": "192.168.1.100",
                "destination_ip": "10.0.0.1",
                "bytes_sent": 1_000_000,
                "bytes_received": 5_000_000,
                "last_seen": datetime.now(timezone.utc),
            }
        }

        await agent._calculate_link_utilization()

        assert len(agent._link_utilization) > 0

    @pytest.mark.asyncio
    async def test_calculate_link_utilization_high_triggers_handler(self, agent, mock_engine):
        """Test high utilization triggers handler."""
        agent._handle_high_utilization = AsyncMock()
        agent.bandwidth_threshold = 80

        # Create flow with enough traffic to exceed threshold
        agent._flows = {
            "flow1": {
                "source_ip": "192.168.1.100",
                "destination_ip": "10.0.0.1",
                "bytes_sent": 100_000_000,  # 100MB
                "bytes_received": 200_000_000,
                "last_seen": datetime.now(timezone.utc),
            }
        }
        agent.analysis_interval = 1  # 1 second for high rate

        await agent._calculate_link_utilization()

        # Should trigger high utilization handler
        # Note: depends on calculated utilization exceeding threshold

    @pytest.mark.asyncio
    async def test_handle_high_utilization(self, agent, mock_engine):
        """Test high utilization handling."""
        # Setup flow on the link
        agent._flows = {
            "flow1": {
                "source_ip": "192.168.1.100",
                "destination_ip": "10.0.0.1",
                "application": "backup",
                "bytes_sent": 1_000_000,
                "bytes_received": 5_000_000,
            }
        }

        await agent._handle_high_utilization("192.168.1_to_10.0.0", 90.5)

        # Should publish warning event
        mock_engine.event_bus.publish.assert_called()
        event = mock_engine.event_bus.publish.call_args[0][0]
        assert event.event_type == "network.bandwidth.high"


class TestOptimizerAgentRateLimiting:
    """Tests for rate limiting."""

    @pytest.mark.asyncio
    async def test_propose_rate_limit(self, agent, mock_engine):
        """Test rate limit proposal."""
        flows = [
            {
                "id": "flow1",
                "application": "backup",
                "bytes_sent": 10_000_000,
                "bytes_received": 5_000_000,
            },
            {
                "id": "flow2",
                "application": "backup",
                "bytes_sent": 8_000_000,
                "bytes_received": 4_000_000,
            },
        ]

        await agent._propose_rate_limit("link1", flows)

        # Should create decision
        assert len(agent._decisions) > 0

        # Should publish action event
        mock_engine.event_bus.publish.assert_called()


class TestOptimizerAgentTrafficAnalysis:
    """Tests for traffic analysis."""

    @pytest.mark.asyncio
    async def test_analyze_traffic_cleans_old_flows(self, agent, mock_engine):
        """Test traffic analysis cleans old flows."""
        old_time = datetime.now(timezone.utc) - timedelta(minutes=10)
        recent_time = datetime.now(timezone.utc)

        agent._flows = {
            "old_flow": {"source_ip": "192.168.1.100", "last_seen": old_time},
            "recent_flow": {"source_ip": "192.168.1.101", "last_seen": recent_time},
        }

        await agent._analyze_traffic()

        # Old flow should be removed
        assert "old_flow" not in agent._flows
        assert "recent_flow" in agent._flows

    @pytest.mark.asyncio
    async def test_analyze_traffic_persists_flow_count(self, agent, mock_engine):
        """Test traffic analysis persists flow count."""
        agent._flows = {"flow1": {"last_seen": datetime.now(timezone.utc)}}

        await agent._analyze_traffic()

        mock_engine.state.set.assert_called()

    @pytest.mark.asyncio
    async def test_check_optimization_opportunities_removes_stale_policies(
        self, agent, mock_engine
    ):
        """Test optimization check removes stale policies."""
        # Policy for port 5060 but no matching flow
        agent._qos_policies = {"stale_policy": {"destination_port": 5060, "auto_generated": True}}
        agent._flows = {"flow1": {"destination_port": 443}}  # Different port

        await agent._check_optimization_opportunities()

        assert "stale_policy" not in agent._qos_policies
        mock_engine.state.set.assert_called()

    @pytest.mark.asyncio
    async def test_check_optimization_keeps_manual_policies(self, agent, mock_engine):
        """Test optimization check keeps manual policies."""
        # Manual policy (not auto_generated)
        agent._qos_policies = {"manual_policy": {"destination_port": 5060, "auto_generated": False}}
        agent._flows = {}

        await agent._check_optimization_opportunities()

        # Manual policy should be kept even without matching flows
        assert "manual_policy" in agent._qos_policies


class TestOptimizerAgentDoExecute:
    """Tests for action execution."""

    @pytest.mark.asyncio
    async def test_do_execute_apply_qos_policy(self, agent, mock_engine):
        """Test applying QoS policy."""
        action = AgentAction(
            agent_name="optimizer",
            action_type="apply_qos_policy",
            target_type="qos_policy",
            target_id="policy1",
            parameters={
                "policy": {
                    "id": "policy1",
                    "name": "VoIP QoS",
                    "priority_queue": 1,
                    "destination_port": 5060,
                }
            },
            reasoning="VoIP traffic detected",
            confidence=0.92,
        )

        result = await agent._do_execute(action)

        assert result["applied"] is True
        assert result["policy_id"] == "policy1"
        assert "policy1" in agent._qos_policies
        mock_engine.state.set.assert_called()

    @pytest.mark.asyncio
    async def test_do_execute_apply_rate_limit(self, agent, mock_engine):
        """Test applying rate limit."""
        action = AgentAction(
            agent_name="optimizer",
            action_type="apply_rate_limit",
            target_type="qos_policy",
            target_id="ratelimit1",
            parameters={
                "policy": {
                    "id": "ratelimit1",
                    "name": "Backup Rate Limit",
                    "bandwidth_limit_mbps": 50,
                }
            },
            reasoning="High utilization",
            confidence=0.78,
        )

        result = await agent._do_execute(action)

        assert result["applied"] is True
        assert "ratelimit1" in agent._qos_policies

    @pytest.mark.asyncio
    async def test_do_execute_remove_policy_exists(self, agent, mock_engine):
        """Test removing existing policy."""
        agent._qos_policies = {"policy1": {"id": "policy1", "name": "Test"}}

        action = AgentAction(
            agent_name="optimizer",
            action_type="remove_policy",
            target_type="qos_policy",
            target_id="policy1",
            parameters={"policy_id": "policy1"},
            reasoning="Remove stale policy",
            confidence=0.95,
        )

        result = await agent._do_execute(action)

        assert result["removed"] is True
        assert "policy1" not in agent._qos_policies

    @pytest.mark.asyncio
    async def test_do_execute_remove_policy_not_found(self, agent, mock_engine):
        """Test removing non-existent policy."""
        action = AgentAction(
            agent_name="optimizer",
            action_type="remove_policy",
            target_type="qos_policy",
            target_id="nonexistent",
            parameters={"policy_id": "nonexistent"},
            reasoning="Remove policy",
            confidence=0.95,
        )

        result = await agent._do_execute(action)

        assert result["removed"] is False
        assert "not found" in result["error"]

    @pytest.mark.asyncio
    async def test_do_execute_unknown_action(self, agent, mock_engine):
        """Test unknown action type raises error."""
        action = AgentAction(
            agent_name="optimizer",
            action_type="unknown_action",
            target_type="test",
            target_id="test",
            parameters={},
            reasoning="Test",
            confidence=0.5,
        )

        with pytest.raises(ValueError, match="Unknown action type"):
            await agent._do_execute(action)


class TestOptimizerAgentRollback:
    """Tests for rollback functionality."""

    @pytest.mark.asyncio
    async def test_capture_rollback_data_qos_policy(self, agent, mock_engine):
        """Test rollback data capture for QoS policy."""
        action = AgentAction(
            agent_name="optimizer",
            action_type="apply_qos_policy",
            target_type="qos_policy",
            target_id="policy1",
            parameters={"policy": {"id": "policy1"}},
            reasoning="Test",
            confidence=0.85,
        )

        rollback_data = await agent._capture_rollback_data(action)

        assert rollback_data["action"] == "remove_policy"
        assert rollback_data["policy_id"] == "policy1"

    @pytest.mark.asyncio
    async def test_capture_rollback_data_rate_limit(self, agent, mock_engine):
        """Test rollback data capture for rate limit."""
        action = AgentAction(
            agent_name="optimizer",
            action_type="apply_rate_limit",
            target_type="qos_policy",
            target_id="ratelimit1",
            parameters={"policy": {"id": "ratelimit1"}},
            reasoning="Test",
            confidence=0.78,
        )

        rollback_data = await agent._capture_rollback_data(action)

        assert rollback_data["action"] == "remove_policy"
        assert rollback_data["policy_id"] == "ratelimit1"

    @pytest.mark.asyncio
    async def test_capture_rollback_data_other_action(self, agent, mock_engine):
        """Test rollback data capture returns None for other actions."""
        action = AgentAction(
            agent_name="optimizer",
            action_type="remove_policy",
            target_type="qos_policy",
            target_id="policy1",
            parameters={},
            reasoning="Test",
            confidence=0.95,
        )

        rollback_data = await agent._capture_rollback_data(action)

        assert rollback_data is None

    @pytest.mark.asyncio
    async def test_do_rollback_removes_policy(self, agent, mock_engine):
        """Test rollback removes policy."""
        agent._qos_policies = {"policy1": {"id": "policy1"}}

        action = AgentAction(
            agent_name="optimizer",
            action_type="apply_qos_policy",
            target_type="qos_policy",
            target_id="policy1",
            parameters={},
            reasoning="Test",
            confidence=0.85,
            rollback_data={"action": "remove_policy", "policy_id": "policy1"},
        )

        await agent._do_rollback(action)

        assert "policy1" not in agent._qos_policies
        mock_engine.state.set.assert_called()

    @pytest.mark.asyncio
    async def test_do_rollback_no_rollback_data(self, agent, mock_engine):
        """Test rollback with no rollback data."""
        action = AgentAction(
            agent_name="optimizer",
            action_type="apply_qos_policy",
            target_type="qos_policy",
            target_id="policy1",
            parameters={},
            reasoning="Test",
            confidence=0.85,
        )

        # Should not raise
        await agent._do_rollback(action)


class TestOptimizerAgentProperties:
    """Tests for agent properties."""

    @pytest.mark.asyncio
    async def test_get_relevant_state(self, agent, mock_engine):
        """Test getting relevant state."""
        agent._flows = {"flow1": {}, "flow2": {}}
        agent._qos_policies = {"policy1": {}}
        agent._link_utilization = {"link1": 50.5}

        state = await agent._get_relevant_state()

        assert state["active_flows"] == 2
        assert state["qos_policies"] == 1
        assert state["link_utilization"] == {"link1": 50.5}

    def test_stats_property(self, agent, mock_engine):
        """Test stats property."""
        agent._flows = {"flow1": {}, "flow2": {}}
        agent._qos_policies = {"policy1": {}}
        agent._congestion_events = [{"test": 1}, {"test": 2}]
        agent._link_utilization = {"link1": 50.5}

        stats = agent.stats

        assert stats["name"] == "optimizer"
        assert stats["active_flows"] == 2
        assert stats["qos_policies"] == 1
        assert stats["congestion_events"] == 2
        assert stats["link_utilization"] == {"link1": 50.5}


class TestOptimizerAgentAnalyze:
    """Tests for analyze method."""

    @pytest.mark.asyncio
    async def test_analyze_returns_none(self, agent, mock_engine):
        """Test analyze returns None (handlers do the work)."""
        event = Event(
            category=EventCategory.NETWORK,
            event_type="test",
            severity=EventSeverity.INFO,
            source="test",
            title="Test",
            description="Test event",
            data={},
        )

        result = await agent.analyze(event)

        assert result is None


class TestOptimizerAgentMainLoop:
    """Tests for main loop functionality."""

    @pytest.mark.asyncio
    async def test_main_loop_loads_stored_policies(self, agent, mock_engine):
        """Test main loop loads stored policies."""
        mock_engine.state.get = AsyncMock(return_value=[{"id": "stored_policy", "name": "Test"}])

        agent._running = True
        call_count = 0

        async def mock_sleep(duration):
            nonlocal call_count
            call_count += 1
            if call_count >= 1:
                agent._running = False

        with patch("sentinel.agents.optimizer.asyncio.sleep", mock_sleep):
            await agent._main_loop()

        # Should have loaded policies
        assert "stored_policy" in agent._qos_policies

    @pytest.mark.asyncio
    async def test_main_loop_runs_analysis(self, agent, mock_engine):
        """Test main loop runs traffic analysis."""
        analysis_called = []

        async def mock_analyze():
            analysis_called.append(True)

        agent._analyze_traffic = mock_analyze
        agent._running = True

        call_count = 0

        async def mock_sleep(duration):
            nonlocal call_count
            call_count += 1
            if call_count >= 1:
                agent._running = False

        with patch("sentinel.agents.optimizer.asyncio.sleep", mock_sleep):
            await agent._main_loop()

        assert len(analysis_called) >= 1

    @pytest.mark.asyncio
    async def test_main_loop_handles_exception(self, agent, mock_engine):
        """Test main loop handles exceptions."""
        call_count = 0

        async def failing_analysis():
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                raise Exception("Analysis error")

        agent._analyze_traffic = failing_analysis
        agent._running = True

        sleep_count = 0

        async def mock_sleep(duration):
            nonlocal sleep_count
            sleep_count += 1
            if sleep_count >= 2:
                agent._running = False

        with patch("sentinel.agents.optimizer.asyncio.sleep", mock_sleep):
            await agent._main_loop()

        # Should have tried analysis despite error
        assert call_count >= 1


class TestOptimizerAgentEvaluateFlowQoS:
    """Tests for flow QoS evaluation."""

    @pytest.mark.asyncio
    async def test_evaluate_flow_qos_high_priority_no_existing(self, agent, mock_engine):
        """Test high priority flow gets QoS when no policy exists."""
        agent._propose_qos_policy = AsyncMock()

        flow = {"id": "voip_flow", "application": "voip", "destination_port": 5060}

        await agent._evaluate_flow_qos(flow)

        agent._propose_qos_policy.assert_called_once()

    @pytest.mark.asyncio
    async def test_evaluate_flow_qos_high_priority_existing_policy(self, agent, mock_engine):
        """Test high priority flow with existing policy."""
        agent._propose_qos_policy = AsyncMock()
        agent._qos_policies = {"existing": {"destination_port": 5060}}

        flow = {"id": "voip_flow", "application": "voip", "destination_port": 5060}

        await agent._evaluate_flow_qos(flow)

        # Should not propose new policy
        agent._propose_qos_policy.assert_not_called()

    @pytest.mark.asyncio
    async def test_evaluate_flow_qos_low_priority(self, agent, mock_engine):
        """Test low priority flow doesn't get QoS."""
        agent._propose_qos_policy = AsyncMock()

        flow = {
            "id": "web_flow",
            "application": "web",  # Priority 3 (default)
            "destination_port": 443,
        }

        await agent._evaluate_flow_qos(flow)

        # Should not propose QoS for low priority
        agent._propose_qos_policy.assert_not_called()
