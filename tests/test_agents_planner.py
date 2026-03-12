"""
Comprehensive tests for PlannerAgent.

Tests cover:
- Initialization with various configurations
- Event subscriptions
- Device classification handling
- VLAN management
- Segmentation policies
- Firewall rule generation
- Policy violations and responses
- Action execution
- Rollback functionality
"""

import asyncio
import pytest
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, AsyncMock, patch

from sentinel.agents.planner import PlannerAgent
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
    engine.config = {}
    engine.get_integration = MagicMock(return_value=None)
    return engine


@pytest.fixture
def default_config():
    """Default planner configuration."""
    return {
        "require_confirmation_for": ["create_vlan", "delete_vlan", "modify_firewall"],
        "auto_execute_threshold": 0.95,
        "log_execute_threshold": 0.80,
        "confirm_threshold": 0.60,
    }


@pytest.fixture
def agent(mock_engine, default_config):
    """Create a planner agent for testing."""
    return PlannerAgent(mock_engine, default_config)


class TestPlannerAgentInit:
    """Tests for planner agent initialization."""

    def test_init_with_defaults(self, mock_engine, default_config):
        """Test initialization with default config."""
        agent = PlannerAgent(mock_engine, default_config)

        assert agent.agent_name == "planner"
        assert agent.agent_description == "Network segmentation and VLAN automation"
        assert "create_vlan" in agent.require_confirmation
        assert "delete_vlan" in agent.require_confirmation

    def test_init_with_custom_confirmation(self, mock_engine):
        """Test initialization with custom confirmation list."""
        config = {"require_confirmation_for": ["only_one_action"]}
        agent = PlannerAgent(mock_engine, config)

        assert agent.require_confirmation == ["only_one_action"]

    def test_init_creates_tracking_structures(self, mock_engine, default_config):
        """Test that initialization creates empty tracking structures."""
        agent = PlannerAgent(mock_engine, default_config)

        assert agent._vlans == {}
        assert agent._segmentation_policies == {}
        assert agent._firewall_rules == {}
        assert agent._security_zones == {}

    def test_init_service_ports(self, mock_engine, default_config):
        """Test service ports are initialized."""
        agent = PlannerAgent(mock_engine, default_config)

        assert agent._service_ports["http"] == (80, "tcp")
        assert agent._service_ports["https"] == (443, "tcp")
        assert agent._service_ports["ssh"] == (22, "tcp")
        assert agent._service_ports["dns"] == (53, "udp")

    def test_init_default_zones(self, mock_engine, default_config):
        """Test default security zones are initialized."""
        agent = PlannerAgent(mock_engine, default_config)

        assert "trusted" in agent._default_zones
        assert "restricted" in agent._default_zones
        assert "untrusted" in agent._default_zones
        assert agent._default_zones["trusted"]["trust_level"] == 0.9
        assert 666 in agent._default_zones["untrusted"]["vlans"]


class TestPlannerAgentSubscriptions:
    """Tests for event subscriptions."""

    @pytest.mark.asyncio
    async def test_subscribe_events(self, agent, mock_engine):
        """Test event subscriptions are set up correctly."""
        await agent._subscribe_events()

        assert mock_engine.event_bus.subscribe.call_count == 3

        call_args = [call[1] for call in mock_engine.event_bus.subscribe.call_args_list]
        event_types = [args.get("event_type") for args in call_args]

        assert "device.classified" in event_types
        assert "network.segmentation.request" in event_types
        assert "security.policy.violation" in event_types


class TestPlannerAgentDeviceClassification:
    """Tests for device classification handling."""

    @pytest.mark.asyncio
    async def test_handle_device_classified_vlan_change_needed(self, agent, mock_engine):
        """Test handling device classification that needs VLAN change."""
        agent._evaluate_vlan_change = AsyncMock()

        event = Event(
            category=EventCategory.NETWORK,
            event_type="device.classified",
            severity=EventSeverity.INFO,
            source="discovery",
            title="Device Classified",
            description="Device classified",
            data={
                "device_id": "device1",
                "mac": "00:11:22:33:44:55",
                "current_vlan": 1,
                "recommended_vlan": 10,
                "device_type": "workstation",
            },
        )

        await agent._handle_device_classified(event)

        agent._evaluate_vlan_change.assert_called_once()

    @pytest.mark.asyncio
    async def test_handle_device_classified_no_change_needed(self, agent, mock_engine):
        """Test handling device already in correct VLAN."""
        agent._evaluate_vlan_change = AsyncMock()

        event = Event(
            category=EventCategory.NETWORK,
            event_type="device.classified",
            severity=EventSeverity.INFO,
            source="discovery",
            title="Device Classified",
            description="Device classified",
            data={
                "device_id": "device1",
                "mac": "00:11:22:33:44:55",
                "current_vlan": 10,
                "recommended_vlan": 10,
                "device_type": "workstation",
            },
        )

        await agent._handle_device_classified(event)

        agent._evaluate_vlan_change.assert_not_called()

    @pytest.mark.asyncio
    async def test_handle_device_classified_no_recommended(self, agent, mock_engine):
        """Test handling device with no recommended VLAN."""
        agent._evaluate_vlan_change = AsyncMock()

        event = Event(
            category=EventCategory.NETWORK,
            event_type="device.classified",
            severity=EventSeverity.INFO,
            source="discovery",
            title="Device Classified",
            description="Device classified",
            data={
                "device_id": "device1",
                "mac": "00:11:22:33:44:55",
                "current_vlan": 1,
                "recommended_vlan": None,
            },
        )

        await agent._handle_device_classified(event)

        agent._evaluate_vlan_change.assert_not_called()


class TestPlannerAgentVLANChange:
    """Tests for VLAN change evaluation."""

    @pytest.mark.asyncio
    async def test_evaluate_vlan_change_unknown_vlan(self, agent, mock_engine):
        """Test VLAN change with unknown target VLAN."""
        device_data = {
            "device_id": "device1",
            "mac": "00:11:22:33:44:55",
            "current_vlan": 1,
            "device_type": "workstation",
            "confidence": 0.8,
        }

        # No VLAN 999 defined
        await agent._evaluate_vlan_change(device_data, 999)

        # Should not create decision or execute action
        assert len(agent._decisions) == 0

    @pytest.mark.asyncio
    async def test_evaluate_vlan_change_success(self, agent, mock_engine):
        """Test successful VLAN change evaluation."""
        agent._vlans = {10: {"id": 10, "name": "Workstations", "purpose": "User workstations"}}

        device_data = {
            "device_id": "device1",
            "mac": "00:11:22:33:44:55",
            "current_vlan": 1,
            "device_type": "workstation",
            "confidence": 0.85,
        }

        await agent._evaluate_vlan_change(device_data, 10)

        assert len(agent._decisions) > 0
        decision = agent._decisions[-1]
        assert decision.decision_type == "vlan_change"
        mock_engine.event_bus.publish.assert_called()


class TestPlannerAgentSegmentation:
    """Tests for segmentation policy handling."""

    @pytest.mark.asyncio
    async def test_handle_segmentation_request_allowed(self, agent, mock_engine):
        """Test segmentation request that's allowed."""
        agent._segmentation_policies = {
            "policy1": {
                "source_vlan": 10,
                "destination_vlan": 20,
                "allowed_services": ["http", "https"],
                "default_action": "deny",
            }
        }
        agent._evaluate_segmentation_exception = AsyncMock()

        event = Event(
            category=EventCategory.NETWORK,
            event_type="network.segmentation.request",
            severity=EventSeverity.INFO,
            source="firewall",
            title="Segmentation Request",
            description="Request",
            data={"source_vlan": 10, "destination_vlan": 20, "service": "https"},
        )

        await agent._handle_segmentation_request(event)

        # Should not need exception
        agent._evaluate_segmentation_exception.assert_not_called()

    @pytest.mark.asyncio
    async def test_handle_segmentation_request_denied(self, agent, mock_engine):
        """Test segmentation request that's denied."""
        agent._segmentation_policies = {
            "policy1": {
                "source_vlan": 10,
                "destination_vlan": 20,
                "allowed_services": ["http"],
                "denied_services": ["ssh"],
                "default_action": "deny",
            }
        }
        agent._evaluate_segmentation_exception = AsyncMock()

        event = Event(
            category=EventCategory.NETWORK,
            event_type="network.segmentation.request",
            severity=EventSeverity.INFO,
            source="firewall",
            title="Segmentation Request",
            description="Request",
            data={"source_vlan": 10, "destination_vlan": 20, "service": "ssh"},
        )

        await agent._handle_segmentation_request(event)

        agent._evaluate_segmentation_exception.assert_called_once()

    def test_check_segmentation_allowed_service(self, agent):
        """Test segmentation check for allowed service."""
        agent._segmentation_policies = {
            "policy1": {
                "source_vlan": 10,
                "destination_vlan": 20,
                "allowed_services": ["http", "https"],
                "default_action": "deny",
            }
        }

        result = agent._check_segmentation(10, 20, "https")

        assert result is True

    def test_check_segmentation_denied_service(self, agent):
        """Test segmentation check for denied service."""
        agent._segmentation_policies = {
            "policy1": {
                "source_vlan": 10,
                "destination_vlan": 20,
                "denied_services": ["ssh"],
                "default_action": "allow",
            }
        }

        result = agent._check_segmentation(10, 20, "ssh")

        assert result is False

    def test_check_segmentation_default_deny(self, agent):
        """Test segmentation with default deny."""
        agent._segmentation_policies = {
            "policy1": {
                "source_vlan": 10,
                "destination_vlan": 20,
                "allowed_services": ["http"],
                "default_action": "deny",
            }
        }

        result = agent._check_segmentation(10, 20, "ftp")

        assert result is False

    def test_check_segmentation_default_allow(self, agent):
        """Test segmentation with default allow."""
        agent._segmentation_policies = {
            "policy1": {
                "source_vlan": 10,
                "destination_vlan": 20,
                "allowed_services": [],
                "default_action": "allow",
            }
        }

        result = agent._check_segmentation(10, 20, "ftp")

        assert result is True

    def test_check_segmentation_isolated_vlan(self, agent):
        """Test segmentation check for isolated VLAN."""
        agent._vlans = {50: {"id": 50, "isolated": True, "allowed_destinations": []}}

        result = agent._check_segmentation(50, 20, "http")

        assert result is False

    def test_check_segmentation_no_policy_fallback(self, agent):
        """Test segmentation check with no policy falls back to VLAN rules."""
        agent._vlans = {10: {"id": 10, "isolated": False, "allowed_destinations": [20, 30]}}

        # Allowed destination
        result1 = agent._check_segmentation(10, 20, "http")
        assert result1 is True

        # Not allowed destination
        result2 = agent._check_segmentation(10, 40, "http")
        assert result2 is False

    @pytest.mark.asyncio
    async def test_evaluate_segmentation_exception(self, agent, mock_engine):
        """Test segmentation exception evaluation."""
        request = {
            "source_vlan": 10,
            "destination_vlan": 30,
            "service": "mysql",
            "reason": "Database access needed",
        }

        await agent._evaluate_segmentation_exception(request)

        assert len(agent._decisions) > 0
        mock_engine.event_bus.publish.assert_called()


class TestPlannerAgentPolicyViolation:
    """Tests for policy violation handling."""

    @pytest.mark.asyncio
    async def test_handle_policy_violation_critical(self, agent, mock_engine):
        """Test handling critical policy violation."""
        agent._propose_quarantine = AsyncMock()
        agent._propose_access_restriction = AsyncMock()

        event = Event(
            category=EventCategory.SECURITY,
            event_type="security.policy.violation",
            severity=EventSeverity.CRITICAL,
            source="ids",
            title="Policy Violation",
            description="Critical violation",
            data={"mac": "00:11:22:33:44:55", "vlan": 10, "severity": "critical"},
        )

        await agent._handle_policy_violation(event)

        agent._propose_quarantine.assert_called_once()
        agent._propose_access_restriction.assert_not_called()

    @pytest.mark.asyncio
    async def test_handle_policy_violation_high(self, agent, mock_engine):
        """Test handling high severity policy violation."""
        agent._propose_quarantine = AsyncMock()
        agent._propose_access_restriction = AsyncMock()

        event = Event(
            category=EventCategory.SECURITY,
            event_type="security.policy.violation",
            severity=EventSeverity.ERROR,
            source="ids",
            title="Policy Violation",
            description="High severity violation",
            data={"mac": "00:11:22:33:44:55", "vlan": 10, "severity": "high"},
        )

        await agent._handle_policy_violation(event)

        agent._propose_quarantine.assert_not_called()
        agent._propose_access_restriction.assert_called_once()

    @pytest.mark.asyncio
    async def test_handle_policy_violation_low(self, agent, mock_engine):
        """Test handling low severity policy violation."""
        agent._propose_quarantine = AsyncMock()
        agent._propose_access_restriction = AsyncMock()

        event = Event(
            category=EventCategory.SECURITY,
            event_type="security.policy.violation",
            severity=EventSeverity.WARNING,
            source="ids",
            title="Policy Violation",
            description="Low severity violation",
            data={"mac": "00:11:22:33:44:55", "vlan": 10, "severity": "low"},
        )

        await agent._handle_policy_violation(event)

        agent._propose_quarantine.assert_not_called()
        agent._propose_access_restriction.assert_not_called()

    @pytest.mark.asyncio
    async def test_propose_quarantine(self, agent, mock_engine):
        """Test quarantine proposal."""
        violation = {"mac": "00:11:22:33:44:55", "vlan": 10, "severity": "critical"}

        await agent._propose_quarantine(violation)

        mock_engine.event_bus.publish.assert_called()

    @pytest.mark.asyncio
    async def test_propose_access_restriction(self, agent, mock_engine):
        """Test access restriction proposal."""
        violation = {"mac": "00:11:22:33:44:55", "vlan": 10, "severity": "high"}

        await agent._propose_access_restriction(violation)

        mock_engine.event_bus.publish.assert_called()


class TestPlannerAgentFirewallRules:
    """Tests for firewall rule generation."""

    @pytest.mark.asyncio
    async def test_generate_firewall_rules_empty(self, agent, mock_engine):
        """Test firewall rule generation with no policies."""
        await agent._generate_firewall_rules()

        assert agent._firewall_rules == {}

    @pytest.mark.asyncio
    async def test_generate_firewall_rules_with_policy(self, agent, mock_engine):
        """Test firewall rule generation with policies."""
        agent._vlans = {10: {"id": 10, "name": "Workstations"}, 20: {"id": 20, "name": "Servers"}}
        agent._segmentation_policies = {
            "policy1": {
                "name": "WorkToServer",
                "source_vlan": 10,
                "destination_vlan": 20,
                "allowed_services": ["http", "https"],
                "default_action": "deny",
            }
        }

        await agent._generate_firewall_rules()

        # Should create rules for http, https, and default deny
        assert len(agent._firewall_rules) == 3
        assert "seg_WorkToServer_http" in agent._firewall_rules
        assert "seg_WorkToServer_https" in agent._firewall_rules
        assert "seg_WorkToServer_default_deny" in agent._firewall_rules

    @pytest.mark.asyncio
    async def test_generate_firewall_rules_missing_vlan(self, agent, mock_engine):
        """Test firewall rule generation with missing VLAN."""
        agent._vlans = {
            10: {"id": 10, "name": "Workstations"}
            # Missing VLAN 20
        }
        agent._segmentation_policies = {
            "policy1": {
                "name": "WorkToServer",
                "source_vlan": 10,
                "destination_vlan": 20,
                "allowed_services": ["http"],
                "default_action": "deny",
            }
        }

        await agent._generate_firewall_rules()

        # Should skip due to missing VLAN
        assert len(agent._firewall_rules) == 0


class TestPlannerAgentValidatePolicies:
    """Tests for policy validation."""

    @pytest.mark.asyncio
    async def test_validate_policies_removes_expired(self, agent, mock_engine):
        """Test policy validation removes expired rules."""
        expired_time = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
        future_time = (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()

        agent._firewall_rules = {
            "expired_rule": {"id": "expired_rule", "expires_at": expired_time},
            "valid_rule": {"id": "valid_rule", "expires_at": future_time},
            "permanent_rule": {
                "id": "permanent_rule"
                # No expires_at
            },
        }

        await agent._validate_policies()

        assert "expired_rule" not in agent._firewall_rules
        assert "valid_rule" in agent._firewall_rules
        assert "permanent_rule" in agent._firewall_rules


class TestPlannerAgentDoExecute:
    """Tests for action execution."""

    @pytest.mark.asyncio
    async def test_do_execute_vlan_change_with_switch(self, agent, mock_engine):
        """Test VLAN change with switch integration."""
        mock_switch = MagicMock()
        mock_switch.set_port_vlan = AsyncMock(return_value=True)
        mock_engine.get_integration.return_value = mock_switch

        action = AgentAction(
            agent_name="planner",
            action_type="vlan_change",
            target_type="device",
            target_id="00:11:22:33:44:55",
            parameters={"mac": "00:11:22:33:44:55", "current_vlan": 1, "target_vlan": 10},
            reasoning="Device classified",
            confidence=0.85,
        )

        result = await agent._do_execute(action)

        assert result["changed"] is True
        mock_switch.set_port_vlan.assert_called_once()

    @pytest.mark.asyncio
    async def test_do_execute_vlan_change_no_switch(self, agent, mock_engine):
        """Test VLAN change without switch integration returns failure."""
        mock_engine.get_integration.return_value = None

        action = AgentAction(
            agent_name="planner",
            action_type="vlan_change",
            target_type="device",
            target_id="00:11:22:33:44:55",
            parameters={"mac": "00:11:22:33:44:55", "target_vlan": 10},
            reasoning="Device classified",
            confidence=0.85,
        )

        result = await agent._do_execute(action)

        # Without an integration, change should fail
        assert result["changed"] is False
        assert "error" in result

    @pytest.mark.asyncio
    async def test_do_execute_create_vlan(self, agent, mock_engine):
        """Test VLAN creation."""
        action = AgentAction(
            agent_name="planner",
            action_type="create_vlan",
            target_type="vlan",
            target_id="100",
            parameters={"vlan": {"id": 100, "name": "NewVLAN", "purpose": "Testing"}},
            reasoning="Create new VLAN",
            confidence=0.95,
        )

        result = await agent._do_execute(action)

        assert result["created"] is True
        assert 100 in agent._vlans

    @pytest.mark.asyncio
    async def test_do_execute_delete_vlan_exists(self, agent, mock_engine):
        """Test deleting existing VLAN."""
        agent._vlans = {100: {"id": 100, "name": "ToDelete"}}

        action = AgentAction(
            agent_name="planner",
            action_type="delete_vlan",
            target_type="vlan",
            target_id="100",
            parameters={"vlan_id": 100},
            reasoning="Delete VLAN",
            confidence=0.95,
        )

        result = await agent._do_execute(action)

        assert result["deleted"] is True
        assert 100 not in agent._vlans

    @pytest.mark.asyncio
    async def test_do_execute_delete_vlan_not_found(self, agent, mock_engine):
        """Test deleting non-existent VLAN."""
        action = AgentAction(
            agent_name="planner",
            action_type="delete_vlan",
            target_type="vlan",
            target_id="999",
            parameters={"vlan_id": 999},
            reasoning="Delete VLAN",
            confidence=0.95,
        )

        result = await agent._do_execute(action)

        assert result["deleted"] is False

    @pytest.mark.asyncio
    async def test_do_execute_add_firewall_rule_with_router(self, agent, mock_engine):
        """Test adding firewall rule with router."""
        mock_router = MagicMock()
        mock_router.add_firewall_rule = AsyncMock()
        mock_engine.get_integration.return_value = mock_router

        action = AgentAction(
            agent_name="planner",
            action_type="add_firewall_rule",
            target_type="firewall_rule",
            target_id="rule1",
            parameters={"rule": {"id": "rule1", "name": "Test Rule", "action": "allow"}},
            reasoning="Add firewall rule",
            confidence=0.85,
        )

        result = await agent._do_execute(action)

        assert result["added"] is True
        assert "rule1" in agent._firewall_rules
        mock_router.add_firewall_rule.assert_called_once()

    @pytest.mark.asyncio
    async def test_do_execute_remove_firewall_rule_exists(self, agent, mock_engine):
        """Test removing existing firewall rule."""
        agent._firewall_rules = {"rule1": {"id": "rule1"}}

        action = AgentAction(
            agent_name="planner",
            action_type="remove_firewall_rule",
            target_type="firewall_rule",
            target_id="rule1",
            parameters={"rule_id": "rule1"},
            reasoning="Remove rule",
            confidence=0.95,
        )

        result = await agent._do_execute(action)

        assert result["removed"] is True
        assert "rule1" not in agent._firewall_rules

    @pytest.mark.asyncio
    async def test_do_execute_remove_firewall_rule_not_found(self, agent, mock_engine):
        """Test removing non-existent firewall rule."""
        action = AgentAction(
            agent_name="planner",
            action_type="remove_firewall_rule",
            target_type="firewall_rule",
            target_id="nonexistent",
            parameters={"rule_id": "nonexistent"},
            reasoning="Remove rule",
            confidence=0.95,
        )

        result = await agent._do_execute(action)

        assert result["removed"] is False

    @pytest.mark.asyncio
    async def test_do_execute_quarantine_device(self, agent, mock_engine):
        """Test quarantining device."""
        mock_switch = MagicMock()
        mock_switch.set_port_vlan = AsyncMock()
        mock_engine.get_integration.return_value = mock_switch

        action = AgentAction(
            agent_name="planner",
            action_type="quarantine_device",
            target_type="device",
            target_id="00:11:22:33:44:55",
            parameters={"mac": "00:11:22:33:44:55", "current_vlan": 10},
            reasoning="Quarantine for violation",
            confidence=0.95,
        )

        result = await agent._do_execute(action)

        assert result["quarantined"] is True
        mock_switch.set_port_vlan.assert_called_once_with(mac="00:11:22:33:44:55", vlan_id=666)

    @pytest.mark.asyncio
    async def test_do_execute_segmentation_exception_new_policy(self, agent, mock_engine):
        """Test creating segmentation exception with new policy."""
        agent._generate_firewall_rules = AsyncMock()

        action = AgentAction(
            agent_name="planner",
            action_type="create_segmentation_exception",
            target_type="segmentation_policy",
            target_id="10_to_30",
            parameters={
                "source_vlan": 10,
                "destination_vlan": 30,
                "service": "mysql",
                "reason": "Database access",
            },
            reasoning="Exception request",
            confidence=0.5,
        )

        result = await agent._do_execute(action)

        assert result["created"] is True
        assert "exception_10_to_30" in agent._segmentation_policies
        agent._generate_firewall_rules.assert_called()

    @pytest.mark.asyncio
    async def test_do_execute_segmentation_exception_existing_policy(self, agent, mock_engine):
        """Test creating segmentation exception with existing policy."""
        agent._segmentation_policies = {
            "policy1": {
                "id": "policy1",
                "source_vlan": 10,
                "destination_vlan": 30,
                "allowed_services": ["http"],
                "default_action": "deny",
            }
        }
        agent._generate_firewall_rules = AsyncMock()

        action = AgentAction(
            agent_name="planner",
            action_type="create_segmentation_exception",
            target_type="segmentation_policy",
            target_id="10_to_30",
            parameters={
                "source_vlan": 10,
                "destination_vlan": 30,
                "service": "mysql",
                "reason": "Database access",
            },
            reasoning="Exception request",
            confidence=0.5,
        )

        result = await agent._do_execute(action)

        assert result["created"] is True
        assert result["existing_policy"] is True
        assert "mysql" in agent._segmentation_policies["policy1"]["allowed_services"]

    @pytest.mark.asyncio
    async def test_do_execute_unknown_action(self, agent, mock_engine):
        """Test unknown action type raises error."""
        action = AgentAction(
            agent_name="planner",
            action_type="unknown_action",
            target_type="test",
            target_id="test",
            parameters={},
            reasoning="Test",
            confidence=0.5,
        )

        with pytest.raises(ValueError, match="Unknown action type"):
            await agent._do_execute(action)


class TestPlannerAgentRollback:
    """Tests for rollback functionality."""

    @pytest.mark.asyncio
    async def test_capture_rollback_data_vlan_change(self, agent, mock_engine):
        """Test rollback data capture for VLAN change."""
        action = AgentAction(
            agent_name="planner",
            action_type="vlan_change",
            target_type="device",
            target_id="00:11:22:33:44:55",
            parameters={"mac": "00:11:22:33:44:55", "current_vlan": 1, "target_vlan": 10},
            reasoning="Test",
            confidence=0.85,
        )

        rollback_data = await agent._capture_rollback_data(action)

        assert rollback_data["action"] == "vlan_change"
        assert rollback_data["mac"] == "00:11:22:33:44:55"
        assert rollback_data["target_vlan"] == 1  # Original VLAN

    @pytest.mark.asyncio
    async def test_capture_rollback_data_firewall_rule(self, agent, mock_engine):
        """Test rollback data capture for firewall rule."""
        action = AgentAction(
            agent_name="planner",
            action_type="add_firewall_rule",
            target_type="firewall_rule",
            target_id="rule1",
            parameters={"rule": {"id": "rule1"}},
            reasoning="Test",
            confidence=0.85,
        )

        rollback_data = await agent._capture_rollback_data(action)

        assert rollback_data["action"] == "remove_firewall_rule"
        assert rollback_data["rule_id"] == "rule1"

    @pytest.mark.asyncio
    async def test_capture_rollback_data_quarantine(self, agent, mock_engine):
        """Test rollback data capture for quarantine."""
        action = AgentAction(
            agent_name="planner",
            action_type="quarantine_device",
            target_type="device",
            target_id="00:11:22:33:44:55",
            parameters={"mac": "00:11:22:33:44:55", "current_vlan": 10},
            reasoning="Test",
            confidence=0.95,
        )

        rollback_data = await agent._capture_rollback_data(action)

        assert rollback_data["action"] == "vlan_change"
        assert rollback_data["target_vlan"] == 10

    @pytest.mark.asyncio
    async def test_do_rollback_vlan_change(self, agent, mock_engine):
        """Test rollback for VLAN change."""
        mock_switch = MagicMock()
        mock_switch.set_port_vlan = AsyncMock()
        mock_engine.get_integration.return_value = mock_switch

        action = AgentAction(
            agent_name="planner",
            action_type="vlan_change",
            target_type="device",
            target_id="00:11:22:33:44:55",
            parameters={},
            reasoning="Test",
            confidence=0.85,
            rollback_data={"action": "vlan_change", "mac": "00:11:22:33:44:55", "target_vlan": 1},
        )

        await agent._do_rollback(action)

        mock_switch.set_port_vlan.assert_called_once()

    @pytest.mark.asyncio
    async def test_do_rollback_firewall_rule(self, agent, mock_engine):
        """Test rollback for firewall rule."""
        agent._firewall_rules = {"rule1": {"id": "rule1"}}

        action = AgentAction(
            agent_name="planner",
            action_type="add_firewall_rule",
            target_type="firewall_rule",
            target_id="rule1",
            parameters={},
            reasoning="Test",
            confidence=0.85,
            rollback_data={"action": "remove_firewall_rule", "rule_id": "rule1"},
        )

        await agent._do_rollback(action)

        assert "rule1" not in agent._firewall_rules


class TestPlannerAgentProperties:
    """Tests for agent properties."""

    @pytest.mark.asyncio
    async def test_get_relevant_state(self, agent, mock_engine):
        """Test getting relevant state."""
        agent._vlans = {1: {}, 10: {}}
        agent._segmentation_policies = {"p1": {}}
        agent._firewall_rules = {"r1": {}, "r2": {}, "r3": {}}

        state = await agent._get_relevant_state()

        assert state["vlans"] == 2
        assert state["segmentation_policies"] == 1
        assert state["firewall_rules"] == 3

    def test_stats_property(self, agent, mock_engine):
        """Test stats property."""
        agent._vlans = {1: {}, 10: {}}
        agent._segmentation_policies = {"p1": {}}
        agent._firewall_rules = {"r1": {}, "r2": {}}
        agent._security_zones = {"z1": {}, "z2": {}, "z3": {}}

        stats = agent.stats

        assert stats["name"] == "planner"
        assert stats["vlans"] == 2
        assert stats["segmentation_policies"] == 1
        assert stats["firewall_rules"] == 2
        assert stats["security_zones"] == 3


class TestPlannerAgentAnalyze:
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


class TestPlannerAgentMainLoop:
    """Tests for main loop functionality."""

    @pytest.mark.asyncio
    async def test_main_loop_loads_config(self, agent, mock_engine):
        """Test main loop loads VLANs from config."""
        mock_engine.config = {
            "vlans": [
                {"id": 10, "name": "Workstations", "purpose": "User devices"},
                {"id": 20, "name": "Servers", "subnet": "10.0.20.0/24"},
            ],
            "segmentation_policies": [
                {
                    "name": "WorkToServer",
                    "source_vlan": 10,
                    "destination_vlan": 20,
                    "allowed_services": ["http"],
                }
            ],
        }
        agent._generate_firewall_rules = AsyncMock()
        agent._validate_policies = AsyncMock()
        agent._running = True

        call_count = 0

        async def mock_sleep(duration):
            nonlocal call_count
            call_count += 1
            if call_count >= 1:
                agent._running = False

        with patch("sentinel.agents.planner.asyncio.sleep", mock_sleep):
            await agent._main_loop()

        assert 10 in agent._vlans
        assert 20 in agent._vlans
        assert len(agent._segmentation_policies) > 0

    @pytest.mark.asyncio
    async def test_main_loop_handles_exception(self, agent, mock_engine):
        """Test main loop handles exceptions."""
        call_count = 0

        async def failing_validate():
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                raise Exception("Validation error")

        agent._validate_policies = failing_validate
        agent._generate_firewall_rules = AsyncMock()
        agent._running = True

        sleep_count = 0

        async def mock_sleep(duration):
            nonlocal sleep_count
            sleep_count += 1
            if sleep_count >= 2:
                agent._running = False

        with patch("sentinel.agents.planner.asyncio.sleep", mock_sleep):
            await agent._main_loop()

        assert call_count >= 1
