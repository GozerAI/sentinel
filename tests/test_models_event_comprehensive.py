"""
Comprehensive tests for Event models covering all code paths.

These tests achieve full coverage including:
- Event model methods
- SecurityAlert model
- AgentAction model
- AgentDecision model
- MetricEvent model
- AuditLogEntry model
"""

import pytest
from uuid import uuid4
from datetime import datetime, timezone

from sentinel.core.models.event import (
    EventSeverity,
    EventCategory,
    Event,
    SecurityAlert,
    AgentAction,
    AgentDecision,
    MetricEvent,
    AuditLogEntry,
    _utc_now,
)


class TestEventEnums:
    """Tests for event enums."""

    def test_event_severity_values(self):
        """Test EventSeverity enum values."""
        assert EventSeverity.DEBUG.value == "debug"
        assert EventSeverity.INFO.value == "info"
        assert EventSeverity.WARNING.value == "warning"
        assert EventSeverity.ERROR.value == "error"
        assert EventSeverity.CRITICAL.value == "critical"

    def test_event_category_values(self):
        """Test EventCategory enum values."""
        assert EventCategory.NETWORK.value == "network"
        assert EventCategory.SECURITY.value == "security"
        assert EventCategory.DEVICE.value == "device"
        assert EventCategory.AGENT.value == "agent"
        assert EventCategory.SYSTEM.value == "system"
        assert EventCategory.COMPLIANCE.value == "compliance"


class TestEvent:
    """Tests for Event model."""

    def test_default_values(self):
        """Test default values."""
        event = Event(
            category=EventCategory.SYSTEM,
            event_type="test.event",
            source="test",
            title="Test Event",
        )

        assert event.id is not None
        assert event.timestamp is not None
        assert event.severity == EventSeverity.INFO
        assert event.source_device_id is None
        assert event.description is None
        assert event.data == {}
        assert event.correlation_id is None
        assert event.parent_event_id is None
        assert event.acknowledged is False
        assert event.acknowledged_by is None
        assert event.acknowledged_at is None

    def test_custom_values(self):
        """Test custom values."""
        event_id = uuid4()
        device_id = uuid4()
        correlation_id = uuid4()
        parent_id = uuid4()

        event = Event(
            id=event_id,
            category=EventCategory.SECURITY,
            event_type="security.alert",
            severity=EventSeverity.CRITICAL,
            source="guardian",
            source_device_id=device_id,
            title="Security Alert",
            description="Suspicious activity detected",
            data={"ip": "192.168.1.100"},
            correlation_id=correlation_id,
            parent_event_id=parent_id,
        )

        assert event.id == event_id
        assert event.category == EventCategory.SECURITY
        assert event.severity == EventSeverity.CRITICAL
        assert event.source_device_id == device_id
        assert event.description == "Suspicious activity detected"
        assert event.data["ip"] == "192.168.1.100"
        assert event.correlation_id == correlation_id
        assert event.parent_event_id == parent_id

    def test_acknowledge(self):
        """Test acknowledge method."""
        event = Event(category=EventCategory.SYSTEM, event_type="test", source="test", title="Test")

        assert event.acknowledged is False
        assert event.acknowledged_by is None
        assert event.acknowledged_at is None

        event.acknowledge("admin")

        assert event.acknowledged is True
        assert event.acknowledged_by == "admin"
        assert event.acknowledged_at is not None

    def test_create_child(self):
        """Test create_child creates correlated child event."""
        parent = Event(
            category=EventCategory.NETWORK,
            event_type="network.connection",
            severity=EventSeverity.INFO,
            source="network_monitor",
            source_device_id=uuid4(),
            title="Connection Established",
        )

        child = parent.create_child(
            event_type="network.data_transfer", title="Data Transfer Started"
        )

        # Child inherits from parent
        assert child.category == EventCategory.NETWORK
        assert child.severity == EventSeverity.INFO
        assert child.source == "network_monitor"
        assert child.source_device_id == parent.source_device_id

        # Child has correlation
        assert child.parent_event_id == parent.id
        assert child.correlation_id == parent.id

        # Child specific values
        assert child.event_type == "network.data_transfer"
        assert child.title == "Data Transfer Started"

    def test_create_child_with_overrides(self):
        """Test create_child with keyword overrides."""
        parent = Event(
            category=EventCategory.NETWORK,
            event_type="network.connection",
            severity=EventSeverity.INFO,
            source="network_monitor",
            title="Connection",
        )

        child = parent.create_child(
            event_type="network.error",
            title="Connection Error",
            category=EventCategory.SECURITY,
            severity=EventSeverity.ERROR,
            source="guardian",
            description="Connection failed",
            data={"error": "timeout"},
        )

        # Overridden values
        assert child.category == EventCategory.SECURITY
        assert child.severity == EventSeverity.ERROR
        assert child.source == "guardian"
        assert child.description == "Connection failed"
        assert child.data["error"] == "timeout"

    def test_create_child_uses_parent_correlation_id(self):
        """Test create_child uses parent's correlation_id if set."""
        correlation = uuid4()
        parent = Event(
            category=EventCategory.NETWORK,
            event_type="test",
            source="test",
            title="Test",
            correlation_id=correlation,
        )

        child = parent.create_child(event_type="child", title="Child")

        assert child.correlation_id == correlation


class TestSecurityAlert:
    """Tests for SecurityAlert model."""

    def test_default_values(self):
        """Test default values."""
        alert = SecurityAlert(
            event_type="threat.detected", source="guardian", title="Threat Detected"
        )

        assert alert.category == EventCategory.SECURITY
        assert alert.threat_type is None
        assert alert.mitre_tactic is None
        assert alert.mitre_technique is None
        assert alert.risk_score == 5.0
        assert alert.confidence == 0.5
        assert alert.affected_device_ids == []
        assert alert.affected_user_ids == []
        assert alert.auto_response_taken is False
        assert alert.auto_response_action is None
        assert alert.requires_investigation is True

    def test_custom_values(self):
        """Test custom values."""
        device_id = uuid4()
        alert = SecurityAlert(
            event_type="threat.detected",
            source="guardian",
            title="Malware Detected",
            threat_type="malware",
            mitre_tactic="execution",
            mitre_technique="T1059",
            risk_score=8.5,
            confidence=0.95,
            affected_device_ids=[device_id],
            affected_user_ids=["user1"],
            auto_response_taken=True,
            auto_response_action="Device quarantined",
            requires_investigation=False,
        )

        assert alert.threat_type == "malware"
        assert alert.mitre_tactic == "execution"
        assert alert.mitre_technique == "T1059"
        assert alert.risk_score == 8.5
        assert alert.confidence == 0.95
        assert device_id in alert.affected_device_ids
        assert "user1" in alert.affected_user_ids
        assert alert.auto_response_taken is True
        assert alert.auto_response_action == "Device quarantined"
        assert alert.requires_investigation is False

    def test_is_high_risk_true(self):
        """Test is_high_risk returns True for high risk scores."""
        alert = SecurityAlert(event_type="threat", source="test", title="Test", risk_score=7.0)
        assert alert.is_high_risk is True

        alert2 = SecurityAlert(event_type="threat", source="test", title="Test", risk_score=9.5)
        assert alert2.is_high_risk is True

    def test_is_high_risk_false(self):
        """Test is_high_risk returns False for low risk scores."""
        alert = SecurityAlert(event_type="threat", source="test", title="Test", risk_score=6.9)
        assert alert.is_high_risk is False

    def test_is_actionable_true(self):
        """Test is_actionable when requires investigation and not acknowledged."""
        alert = SecurityAlert(
            event_type="threat", source="test", title="Test", requires_investigation=True
        )
        assert alert.is_actionable is True

    def test_is_actionable_false_acknowledged(self):
        """Test is_actionable False when acknowledged."""
        alert = SecurityAlert(
            event_type="threat", source="test", title="Test", requires_investigation=True
        )
        alert.acknowledge("admin")

        assert alert.is_actionable is False

    def test_is_actionable_false_no_investigation(self):
        """Test is_actionable False when no investigation required."""
        alert = SecurityAlert(
            event_type="threat", source="test", title="Test", requires_investigation=False
        )
        assert alert.is_actionable is False


class TestAgentAction:
    """Tests for AgentAction model."""

    def test_default_values(self):
        """Test default values."""
        action = AgentAction(
            agent_name="guardian",
            action_type="block_ip",
            reasoning="Suspicious activity",
            confidence=0.9,
            target_type="ip",
            target_id="192.168.1.100",
        )

        assert action.id is not None
        assert action.timestamp is not None
        assert action.trigger_event_id is None
        assert action.parameters == {}
        assert action.status == "pending"
        assert action.result is None
        assert action.error_message is None
        assert action.reversible is True
        assert action.rollback_data is None
        assert action.rolled_back_at is None
        assert action.required_confirmation is False
        assert action.confirmed_by is None
        assert action.confirmed_at is None

    def test_is_complete_pending(self):
        """Test is_complete returns False for pending."""
        action = AgentAction(
            agent_name="test",
            action_type="test",
            reasoning="test",
            confidence=0.9,
            target_type="test",
            target_id="test",
        )
        assert action.is_complete is False

    def test_is_complete_executed(self):
        """Test is_complete returns True for executed."""
        action = AgentAction(
            agent_name="test",
            action_type="test",
            reasoning="test",
            confidence=0.9,
            target_type="test",
            target_id="test",
            status="executed",
        )
        assert action.is_complete is True

    def test_is_complete_failed(self):
        """Test is_complete returns True for failed."""
        action = AgentAction(
            agent_name="test",
            action_type="test",
            reasoning="test",
            confidence=0.9,
            target_type="test",
            target_id="test",
            status="failed",
        )
        assert action.is_complete is True

    def test_is_complete_rolled_back(self):
        """Test is_complete returns True for rolled_back."""
        action = AgentAction(
            agent_name="test",
            action_type="test",
            reasoning="test",
            confidence=0.9,
            target_type="test",
            target_id="test",
            status="rolled_back",
        )
        assert action.is_complete is True

    def test_can_rollback_true(self):
        """Test can_rollback returns True when conditions met."""
        action = AgentAction(
            agent_name="test",
            action_type="test",
            reasoning="test",
            confidence=0.9,
            target_type="test",
            target_id="test",
            reversible=True,
            rollback_data={"previous": "state"},
            status="executed",
        )
        assert action.can_rollback is True

    def test_can_rollback_false_not_reversible(self):
        """Test can_rollback False when not reversible."""
        action = AgentAction(
            agent_name="test",
            action_type="test",
            reasoning="test",
            confidence=0.9,
            target_type="test",
            target_id="test",
            reversible=False,
            rollback_data={"previous": "state"},
            status="executed",
        )
        assert action.can_rollback is False

    def test_can_rollback_false_no_rollback_data(self):
        """Test can_rollback False when no rollback data."""
        action = AgentAction(
            agent_name="test",
            action_type="test",
            reasoning="test",
            confidence=0.9,
            target_type="test",
            target_id="test",
            reversible=True,
            rollback_data=None,
            status="executed",
        )
        assert action.can_rollback is False

    def test_can_rollback_false_wrong_status(self):
        """Test can_rollback False when status not executed."""
        action = AgentAction(
            agent_name="test",
            action_type="test",
            reasoning="test",
            confidence=0.9,
            target_type="test",
            target_id="test",
            reversible=True,
            rollback_data={"previous": "state"},
            status="pending",
        )
        assert action.can_rollback is False

    def test_can_rollback_false_already_rolled_back(self):
        """Test can_rollback False when already rolled back."""
        action = AgentAction(
            agent_name="test",
            action_type="test",
            reasoning="test",
            confidence=0.9,
            target_type="test",
            target_id="test",
            reversible=True,
            rollback_data={"previous": "state"},
            status="executed",
            rolled_back_at=_utc_now(),
        )
        assert action.can_rollback is False

    def test_mark_executed(self):
        """Test mark_executed updates status and result."""
        action = AgentAction(
            agent_name="test",
            action_type="test",
            reasoning="test",
            confidence=0.9,
            target_type="test",
            target_id="test",
        )

        action.mark_executed({"success": True, "details": "Done"})

        assert action.status == "executed"
        assert action.result == {"success": True, "details": "Done"}

    def test_mark_failed(self):
        """Test mark_failed updates status and error_message."""
        action = AgentAction(
            agent_name="test",
            action_type="test",
            reasoning="test",
            confidence=0.9,
            target_type="test",
            target_id="test",
        )

        action.mark_failed("Connection timeout")

        assert action.status == "failed"
        assert action.error_message == "Connection timeout"

    def test_mark_rolled_back(self):
        """Test mark_rolled_back updates status and timestamp."""
        action = AgentAction(
            agent_name="test",
            action_type="test",
            reasoning="test",
            confidence=0.9,
            target_type="test",
            target_id="test",
            status="executed",
        )

        action.mark_rolled_back()

        assert action.status == "rolled_back"
        assert action.rolled_back_at is not None


class TestAgentDecision:
    """Tests for AgentDecision model."""

    def test_default_values(self):
        """Test default values."""
        decision = AgentDecision(
            agent_name="planner",
            decision_type="vlan_assignment",
            analysis="Device analysis complete",
            confidence=0.9,
        )

        assert decision.id is not None
        assert decision.timestamp is not None
        assert decision.input_events == []
        assert decision.input_state == {}
        assert decision.options_considered == []
        assert decision.selected_option is None
        assert decision.rejection_reasons == {}
        assert decision.action_ids == []
        assert decision.llm_model is None
        assert decision.llm_prompt_tokens is None
        assert decision.llm_completion_tokens is None

    def test_used_llm_true(self):
        """Test used_llm returns True when LLM model set."""
        decision = AgentDecision(
            agent_name="test",
            decision_type="test",
            analysis="test",
            confidence=0.9,
            llm_model="llama3.1:8b",
        )
        assert decision.used_llm is True

    def test_used_llm_false(self):
        """Test used_llm returns False when no LLM model."""
        decision = AgentDecision(
            agent_name="test", decision_type="test", analysis="test", confidence=0.9
        )
        assert decision.used_llm is False

    def test_total_tokens_both(self):
        """Test total_tokens sums both token counts."""
        decision = AgentDecision(
            agent_name="test",
            decision_type="test",
            analysis="test",
            confidence=0.9,
            llm_prompt_tokens=100,
            llm_completion_tokens=50,
        )
        assert decision.total_tokens == 150

    def test_total_tokens_only_prompt(self):
        """Test total_tokens with only prompt tokens."""
        decision = AgentDecision(
            agent_name="test",
            decision_type="test",
            analysis="test",
            confidence=0.9,
            llm_prompt_tokens=100,
        )
        assert decision.total_tokens == 100

    def test_total_tokens_only_completion(self):
        """Test total_tokens with only completion tokens."""
        decision = AgentDecision(
            agent_name="test",
            decision_type="test",
            analysis="test",
            confidence=0.9,
            llm_completion_tokens=50,
        )
        assert decision.total_tokens == 50

    def test_total_tokens_none(self):
        """Test total_tokens returns 0 when no tokens."""
        decision = AgentDecision(
            agent_name="test", decision_type="test", analysis="test", confidence=0.9
        )
        assert decision.total_tokens == 0


class TestMetricEvent:
    """Tests for MetricEvent model."""

    def test_default_values(self):
        """Test default values."""
        event = MetricEvent(event_type="metric", source="metrics", title="CPU Usage")

        assert event.category == EventCategory.SYSTEM
        assert event.metric_name == ""
        assert event.metric_value == 0.0
        assert event.metric_unit == ""
        assert event.tags == {}

    def test_custom_values(self):
        """Test custom values."""
        event = MetricEvent(
            event_type="metric.cpu",
            source="host_monitor",
            title="CPU Usage",
            metric_name="cpu_usage_percent",
            metric_value=75.5,
            metric_unit="%",
            tags={"host": "server1", "core": "all"},
        )

        assert event.metric_name == "cpu_usage_percent"
        assert event.metric_value == 75.5
        assert event.metric_unit == "%"
        assert event.tags["host"] == "server1"


class TestAuditLogEntry:
    """Tests for AuditLogEntry model."""

    def test_default_values(self):
        """Test default values."""
        entry = AuditLogEntry(
            actor_type="user",
            actor_id="user1",
            actor_name="John Doe",
            action="create",
            resource_type="device",
            resource_id="device-123",
        )

        assert entry.id is not None
        assert entry.timestamp is not None
        assert entry.changes == {}
        assert entry.context == {}
        assert entry.success is True
        assert entry.error_message is None
        assert entry.source_ip is None
        assert entry.user_agent is None

    def test_custom_values(self):
        """Test custom values."""
        entry = AuditLogEntry(
            actor_type="agent",
            actor_id="guardian",
            actor_name="Guardian Agent",
            action="block_ip",
            resource_type="firewall_rule",
            resource_id="rule-456",
            changes={"before": None, "after": {"ip": "192.168.1.100", "action": "block"}},
            context={"trigger_event": "suspicious_traffic"},
            success=True,
            source_ip="127.0.0.1",
            user_agent="Sentinel/1.0",
        )

        assert entry.actor_type == "agent"
        assert entry.actor_id == "guardian"
        assert entry.action == "block_ip"
        assert entry.changes["after"]["ip"] == "192.168.1.100"
        assert entry.context["trigger_event"] == "suspicious_traffic"
        assert entry.source_ip == "127.0.0.1"

    def test_failed_entry(self):
        """Test failed audit log entry."""
        entry = AuditLogEntry(
            actor_type="user",
            actor_id="user1",
            actor_name="John",
            action="delete",
            resource_type="device",
            resource_id="device-123",
            success=False,
            error_message="Permission denied",
        )

        assert entry.success is False
        assert entry.error_message == "Permission denied"


class TestUtcNow:
    """Tests for _utc_now helper."""

    def test_returns_timezone_aware(self):
        """Test _utc_now returns timezone-aware datetime."""
        now = _utc_now()

        assert now.tzinfo is not None
        assert now.tzinfo == timezone.utc


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
