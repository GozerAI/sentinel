"""
Tests for the PolicyEnforcerAgent.

Tests cover policy loading, violation detection, remediation,
and compliance reporting.
"""
import pytest
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

from sentinel.agents.policy import PolicyEnforcerAgent
from sentinel.core.models.event import Event, EventCategory, EventSeverity, AgentAction
from sentinel.core.models.policy import (
    PolicySet, DevicePolicy, FirewallRule, PolicyAction
)
from sentinel.core.utils import utc_now


@pytest.fixture
def mock_engine():
    """Create a mock engine."""
    engine = MagicMock()
    engine.event_bus = MagicMock()
    engine.event_bus.publish = AsyncMock()
    engine.event_bus.subscribe = MagicMock()
    engine.state = MagicMock()
    engine.state.get = AsyncMock(return_value={})
    engine.state.set = AsyncMock()
    engine.get_integration = MagicMock(return_value=None)
    return engine


@pytest.fixture
def default_config():
    """Default agent configuration."""
    return {
        "enforcement_interval_seconds": 60,
        "violation_threshold": 3,
        "auto_remediate": True,
        "audit_mode": False,
        "fully_autonomous": False,  # Disable auto-approve for tests
    }


@pytest.fixture
def agent(mock_engine, default_config):
    """Create a test agent."""
    return PolicyEnforcerAgent(mock_engine, default_config)


class TestPolicyEnforcerAgentInit:
    """Tests for agent initialization."""

    def test_init_with_defaults(self, mock_engine):
        """Test initialization with default config."""
        agent = PolicyEnforcerAgent(mock_engine, {})

        assert agent.enforcement_interval == 60
        assert agent.violation_threshold == 3
        assert agent.auto_remediate is True
        assert agent.audit_mode is False

    def test_init_with_custom_config(self, mock_engine):
        """Test initialization with custom config."""
        config = {
            "enforcement_interval_seconds": 120,
            "violation_threshold": 5,
            "auto_remediate": False,
            "audit_mode": True
        }
        agent = PolicyEnforcerAgent(mock_engine, config)

        assert agent.enforcement_interval == 120
        assert agent.violation_threshold == 5
        assert agent.auto_remediate is False
        assert agent.audit_mode is True


class TestPolicyEnforcerAgentSubscriptions:
    """Tests for event subscriptions."""

    @pytest.mark.asyncio
    async def test_subscribe_events(self, agent, mock_engine):
        """Test event subscription."""
        await agent._subscribe_events()

        # Should subscribe to device and traffic events
        assert mock_engine.event_bus.subscribe.call_count >= 3


class TestPolicyEnforcerAgentLoadPolicies:
    """Tests for policy loading."""

    @pytest.mark.asyncio
    async def test_load_policies_from_state(self, agent, mock_engine):
        """Test loading policies from state."""
        policy_data = {
            "name": "test_policy_set",
            "firewall_rules": [],
            "device_policies": [],
            "automation_rules": []
        }
        mock_engine.state.get = AsyncMock(return_value=policy_data)

        await agent._load_policies()

        assert agent._policy_set is not None
        assert agent._policy_set.name == "test_policy_set"

    @pytest.mark.asyncio
    async def test_load_policies_creates_default(self, agent, mock_engine):
        """Test creating default policy set when none exists."""
        mock_engine.state.get = AsyncMock(return_value=None)

        await agent._load_policies()

        assert agent._policy_set is not None
        assert agent._policy_set.name == "default"


class TestPolicyEnforcerAgentViolationDetection:
    """Tests for violation detection."""

    @pytest.mark.asyncio
    async def test_detect_vlan_violation(self, agent, mock_engine):
        """Test detecting VLAN policy violation."""
        # Set up a device in wrong VLAN
        inventory = {
            "device-1": {
                "id": "device-1",
                "device_type": "iot",
                "vendor": "Ring",
                "vlan": 100,  # Wrong VLAN
                "name": "Ring Doorbell"
            }
        }
        mock_engine.state.get = AsyncMock(side_effect=lambda key, default=None: {
            "device_inventory": inventory,
            "policy_set": None
        }.get(key, default))

        # Set up policy requiring IoT on VLAN 50
        agent._policy_set = PolicySet(
            name="test",
            device_policies=[
                DevicePolicy(
                    name="iot_policy",
                    match_device_types=["iot"],
                    assign_vlan=50
                )
            ]
        )

        await agent._verify_device_compliance()

        # Should track violation
        assert "device-1" in agent._violation_counts
        assert agent._violation_counts["device-1"] == 1

    @pytest.mark.asyncio
    async def test_remediate_after_threshold(self, agent, mock_engine):
        """Test remediation triggers after threshold violations."""
        agent.violation_threshold = 2
        agent._violation_counts["device-1"] = 2  # Already at threshold

        # Set up mock switch
        mock_switch = MagicMock()
        mock_switch.set_mac_vlan = AsyncMock(return_value=True)
        mock_engine.get_integration.return_value = mock_switch

        device = {
            "id": "device-1",
            "vlan": 100,
            "mac_address": "aa:bb:cc:dd:ee:ff",
            "name": "Test Device"
        }
        policy = DevicePolicy(
            name="test_policy",
            match_device_types=["iot"],
            assign_vlan=50
        )

        # This should trigger remediation
        await agent._handle_vlan_violation("device-1", device, policy, 100)

        # Should have executed action (now remediation action appended)
        assert len(agent._actions) == 1
        # Violation count reset after remediation
        assert agent._violation_counts.get("device-1", 0) == 0


class TestPolicyEnforcerAgentFirewallExpiration:
    """Tests for firewall rule expiration."""

    @pytest.mark.asyncio
    async def test_detect_expired_rule(self, agent, mock_engine):
        """Test detecting expired firewall rule."""
        past = utc_now() - timedelta(hours=1)
        agent._policy_set = PolicySet(
            name="test",
            firewall_rules=[
                FirewallRule(
                    name="expired_rule",
                    action=PolicyAction.DENY,
                    enabled=True,
                    expires_at=past
                )
            ]
        )

        await agent._check_firewall_expirations()

        # Should have created action to disable
        assert len(agent._actions) == 1
        assert agent._actions[0].action_type == "disable_firewall_rule"


class TestPolicyEnforcerAgentDoExecute:
    """Tests for action execution."""

    @pytest.mark.asyncio
    async def test_execute_vlan_assignment(self, agent, mock_engine):
        """Test VLAN assignment execution."""
        mock_switch = MagicMock()
        mock_switch.set_mac_vlan = AsyncMock(return_value=True)
        mock_engine.get_integration.return_value = mock_switch

        action = AgentAction(
            agent_name="policy_enforcer",
            action_type="assign_vlan",
            target_type="device",
            target_id="device-1",
            parameters={"mac_address": "aa:bb:cc:dd:ee:ff", "vlan_id": 50},
            reasoning="Test",
            confidence=0.90
        )

        result = await agent._do_execute(action)

        assert result["success"] is True
        mock_switch.set_mac_vlan.assert_called_once_with("aa:bb:cc:dd:ee:ff", 50)

    @pytest.mark.asyncio
    async def test_execute_vlan_assignment_no_switch(self, agent, mock_engine):
        """Test VLAN assignment without switch integration."""
        mock_engine.get_integration.return_value = None

        action = AgentAction(
            agent_name="policy_enforcer",
            action_type="assign_vlan",
            target_type="device",
            target_id="device-1",
            parameters={"mac_address": "aa:bb:cc:dd:ee:ff", "vlan_id": 50},
            reasoning="Test",
            confidence=0.90
        )

        result = await agent._do_execute(action)

        assert result["success"] is False
        assert "No switch integration" in result["error"]

    @pytest.mark.asyncio
    async def test_execute_disable_firewall_rule(self, agent, mock_engine):
        """Test disabling firewall rule."""
        rule = FirewallRule(name="test_rule", action=PolicyAction.DENY, enabled=True)
        agent._policy_set = PolicySet(name="test", firewall_rules=[rule])

        action = AgentAction(
            agent_name="policy_enforcer",
            action_type="disable_firewall_rule",
            target_type="firewall_rule",
            target_id=str(rule.id),
            parameters={},
            reasoning="Test",
            confidence=0.90
        )

        result = await agent._do_execute(action)

        assert result["success"] is True
        assert rule.enabled is False


class TestPolicyEnforcerAgentComplianceReporting:
    """Tests for compliance reporting."""

    @pytest.mark.asyncio
    async def test_publish_compliance_report(self, agent, mock_engine):
        """Test compliance report publishing."""
        agent._policy_set = PolicySet(name="test")
        agent._violation_counts = {"device-1": 1, "device-2": 0}

        inventory = {"device-1": {}, "device-2": {}, "device-3": {}}
        mock_engine.state.get = AsyncMock(return_value=inventory)

        await agent._publish_compliance_report()

        # Should have compliance stats
        assert "compliance_rate" in agent._compliance_stats
        # 2 out of 3 devices compliant = 66.67%
        assert agent._compliance_stats["devices_in_violation"] == 1


class TestPolicyEnforcerAgentStats:
    """Tests for agent statistics."""

    def test_stats_initial(self, agent):
        """Test initial stats."""
        stats = agent.stats

        assert stats["name"] == "policy_enforcer"
        assert stats["audit_mode"] is False
        assert stats["auto_remediate"] is True


class TestPolicyEnforcerAgentRollback:
    """Tests for rollback functionality."""

    @pytest.mark.asyncio
    async def test_capture_rollback_data_vlan(self, agent, mock_engine):
        """Test capturing rollback data for VLAN assignment."""
        inventory = {"device-1": {"vlan": 100}}
        mock_engine.state.get = AsyncMock(return_value=inventory)

        action = AgentAction(
            agent_name="policy_enforcer",
            action_type="assign_vlan",
            target_type="device",
            target_id="device-1",
            parameters={"vlan_id": 50},
            reasoning="Test",
            confidence=0.90
        )

        rollback_data = await agent._capture_rollback_data(action)

        assert rollback_data["original_vlan"] == 100

    @pytest.mark.asyncio
    async def test_rollback_vlan_assignment(self, agent, mock_engine):
        """Test rolling back VLAN assignment."""
        mock_switch = MagicMock()
        mock_switch.set_mac_vlan = AsyncMock(return_value=True)
        mock_engine.get_integration.return_value = mock_switch

        action = AgentAction(
            agent_name="policy_enforcer",
            action_type="assign_vlan",
            target_type="device",
            target_id="device-1",
            parameters={"mac_address": "aa:bb:cc:dd:ee:ff", "vlan_id": 50},
            reasoning="Test",
            confidence=0.90,
            rollback_data={"action": "assign_vlan", "original_vlan": 100}
        )

        await agent._do_rollback(action)

        mock_switch.set_mac_vlan.assert_called_once_with("aa:bb:cc:dd:ee:ff", 100)
