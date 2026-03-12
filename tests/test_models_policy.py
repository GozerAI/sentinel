"""
Tests for Policy models.

Tests cover firewall rules, segmentation policies, device policies,
automation rules, and security zones.
"""

import pytest
from datetime import datetime, timedelta, timezone
from uuid import uuid4

from sentinel.core.models.policy import (
    PolicyAction,
    PolicyScope,
    PolicyPriority,
    FirewallRule,
    SegmentationPolicy,
    DevicePolicy,
    AutomationRule,
    SecurityZone,
    PolicySet,
    _utc_now,
)


class TestPolicyEnums:
    """Tests for policy enums."""

    def test_policy_action_values(self):
        """Test PolicyAction enum values."""
        assert PolicyAction.ALLOW.value == "allow"
        assert PolicyAction.DENY.value == "deny"
        assert PolicyAction.LOG.value == "log"
        assert PolicyAction.ALERT.value == "alert"
        assert PolicyAction.QUARANTINE.value == "quarantine"
        assert PolicyAction.RATE_LIMIT.value == "rate_limit"

    def test_policy_scope_values(self):
        """Test PolicyScope enum values."""
        assert PolicyScope.GLOBAL.value == "global"
        assert PolicyScope.VLAN.value == "vlan"
        assert PolicyScope.DEVICE_GROUP.value == "device_group"
        assert PolicyScope.DEVICE.value == "device"

    def test_policy_priority_values(self):
        """Test PolicyPriority enum values."""
        assert PolicyPriority.CRITICAL == 10
        assert PolicyPriority.HIGH == 25
        assert PolicyPriority.NORMAL == 50
        assert PolicyPriority.LOW == 75
        assert PolicyPriority.DEFAULT == 100


class TestFirewallRule:
    """Tests for FirewallRule model."""

    def test_default_values(self):
        """Test default values."""
        rule = FirewallRule(name="Test Rule")

        assert rule.id is not None
        assert rule.name == "Test Rule"
        assert rule.description is None
        assert rule.source_zones == []
        assert rule.source_addresses == []
        assert rule.destination_zones == []
        assert rule.protocols == ["any"]
        assert rule.action == PolicyAction.DENY
        assert rule.log_enabled is False
        assert rule.priority == 100
        assert rule.enabled is True
        assert rule.auto_generated is False
        assert rule.created_at is not None

    def test_custom_values(self):
        """Test custom values."""
        rule = FirewallRule(
            name="Allow HTTP",
            description="Allow HTTP traffic",
            source_zones=["trusted"],
            destination_zones=["dmz"],
            destination_ports=["80", "443"],
            protocols=["tcp"],
            action=PolicyAction.ALLOW,
            log_enabled=True,
            priority=50,
            auto_generated=True,
            generated_by_agent="guardian",
        )

        assert rule.source_zones == ["trusted"]
        assert rule.destination_zones == ["dmz"]
        assert rule.destination_ports == ["80", "443"]
        assert rule.protocols == ["tcp"]
        assert rule.action == PolicyAction.ALLOW
        assert rule.log_enabled is True
        assert rule.priority == 50
        assert rule.generated_by_agent == "guardian"

    def test_is_expired_no_expiration(self):
        """Test is_expired when no expiration set."""
        rule = FirewallRule(name="Test")
        assert rule.is_expired is False

    def test_is_expired_future_expiration(self):
        """Test is_expired with future expiration."""
        rule = FirewallRule(name="Test", expires_at=_utc_now() + timedelta(hours=1))
        assert rule.is_expired is False

    def test_is_expired_past_expiration(self):
        """Test is_expired with past expiration."""
        rule = FirewallRule(name="Test", expires_at=_utc_now() - timedelta(hours=1))
        assert rule.is_expired is True

    def test_matches_any_protocol(self):
        """Test matching with any protocol."""
        rule = FirewallRule(name="Test", protocols=["any"])
        assert rule.matches("192.168.1.1", 12345, "10.0.0.1", 80, "tcp") is True
        assert rule.matches("192.168.1.1", 12345, "10.0.0.1", 53, "udp") is True

    def test_matches_specific_protocol(self):
        """Test matching specific protocol."""
        rule = FirewallRule(name="Test", protocols=["tcp"])
        assert rule.matches("192.168.1.1", 12345, "10.0.0.1", 80, "tcp") is True
        assert rule.matches("192.168.1.1", 12345, "10.0.0.1", 53, "udp") is False

    def test_matches_destination_port(self):
        """Test matching destination port."""
        rule = FirewallRule(name="Test", destination_ports=["80", "443"])
        assert rule.matches("192.168.1.1", 12345, "10.0.0.1", 80, "tcp") is True
        assert rule.matches("192.168.1.1", 12345, "10.0.0.1", 22, "tcp") is False


class TestSegmentationPolicy:
    """Tests for SegmentationPolicy model."""

    def test_default_values(self):
        """Test default values."""
        policy = SegmentationPolicy(name="Test Policy", source_vlan=10, destination_vlan=20)

        assert policy.id is not None
        assert policy.name == "Test Policy"
        assert policy.source_vlan == 10
        assert policy.destination_vlan == 20
        assert policy.allowed_services == []
        assert policy.denied_services == []
        assert policy.default_action == PolicyAction.DENY
        assert policy.enabled is True

    def test_is_service_allowed_explicit_allow(self):
        """Test service is allowed when explicitly listed."""
        policy = SegmentationPolicy(
            name="Test", source_vlan=10, destination_vlan=20, allowed_services=["http", "https"]
        )

        assert policy.is_service_allowed("http") is True
        assert policy.is_service_allowed("https") is True

    def test_is_service_allowed_explicit_deny(self):
        """Test service is denied when explicitly listed."""
        policy = SegmentationPolicy(
            name="Test",
            source_vlan=10,
            destination_vlan=20,
            allowed_services=["http"],
            denied_services=["ssh"],
        )

        assert policy.is_service_allowed("ssh") is False

    def test_is_service_allowed_default_deny(self):
        """Test service uses default deny."""
        policy = SegmentationPolicy(
            name="Test",
            source_vlan=10,
            destination_vlan=20,
            allowed_services=["http"],
            default_action=PolicyAction.DENY,
        )

        assert policy.is_service_allowed("ftp") is False

    def test_is_service_allowed_default_allow(self):
        """Test service uses default allow."""
        policy = SegmentationPolicy(
            name="Test",
            source_vlan=10,
            destination_vlan=20,
            denied_services=["ssh"],
            default_action=PolicyAction.ALLOW,
        )

        assert policy.is_service_allowed("ftp") is True


class TestDevicePolicy:
    """Tests for DevicePolicy model."""

    def test_default_values(self):
        """Test default values."""
        policy = DevicePolicy(name="Test Policy")

        assert policy.name == "Test Policy"
        assert policy.match_device_types == []
        assert policy.match_vendors == []
        assert policy.match_tags == []
        assert policy.assign_vlan is None
        assert policy.internet_access is True
        assert policy.lan_access is True
        assert policy.priority == 100
        assert policy.enabled is True

    def test_matches_device_by_type(self):
        """Test matching device by type."""
        policy = DevicePolicy(name="Test", match_device_types=["workstation", "laptop"])

        assert policy.matches_device("workstation") is True
        assert policy.matches_device("laptop") is True
        assert policy.matches_device("server") is False

    def test_matches_device_by_vendor(self):
        """Test matching device by vendor."""
        policy = DevicePolicy(name="Test", match_vendors=["Apple", "Dell"])

        assert policy.matches_device("workstation", vendor="Apple Inc.") is True
        assert policy.matches_device("workstation", vendor="Dell Technologies") is True
        assert policy.matches_device("workstation", vendor="HP") is False

    def test_matches_device_by_tags(self):
        """Test matching device by tags."""
        policy = DevicePolicy(name="Test", match_tags=["production", "critical"])

        assert policy.matches_device("workstation", tags=["production"]) is True
        assert policy.matches_device("workstation", tags=["critical"]) is True
        assert policy.matches_device("workstation", tags=["development"]) is False

    def test_matches_device_no_criteria(self):
        """Test matching device with no criteria matches all."""
        policy = DevicePolicy(name="Test")

        assert policy.matches_device("workstation") is True
        assert policy.matches_device("server") is True

    def test_matches_device_combined_criteria(self):
        """Test matching device with combined criteria."""
        policy = DevicePolicy(
            name="Test", match_device_types=["workstation"], match_vendors=["Dell"]
        )

        assert policy.matches_device("workstation", vendor="Dell Inc.") is True
        assert policy.matches_device("server", vendor="Dell Inc.") is False
        assert policy.matches_device("workstation", vendor="HP") is False


class TestAutomationRule:
    """Tests for AutomationRule model."""

    def test_default_values(self):
        """Test default values."""
        rule = AutomationRule(
            name="Test Rule", trigger_event="device.discovered", action_type="assign_vlan"
        )

        assert rule.name == "Test Rule"
        assert rule.trigger_event == "device.discovered"
        assert rule.action_type == "assign_vlan"
        assert rule.trigger_conditions == {}
        assert rule.action_params == {}
        assert rule.requires_confirmation is False
        assert rule.confidence_threshold == 0.8
        assert rule.max_executions_per_hour is None
        assert rule.rollback_enabled is True
        assert rule.rollback_timeout_seconds == 3600
        assert rule.enabled is True
        assert rule.execution_count == 0
        assert rule.last_executed is None
        assert rule.last_result is None

    def test_can_execute_enabled(self):
        """Test can_execute when enabled."""
        rule = AutomationRule(name="Test", trigger_event="test", action_type="test")

        assert rule.can_execute(0) is True

    def test_can_execute_disabled(self):
        """Test can_execute when disabled."""
        rule = AutomationRule(name="Test", trigger_event="test", action_type="test", enabled=False)

        assert rule.can_execute(0) is False

    def test_can_execute_rate_limited(self):
        """Test can_execute with rate limiting."""
        rule = AutomationRule(
            name="Test", trigger_event="test", action_type="test", max_executions_per_hour=5
        )

        assert rule.can_execute(4) is True
        assert rule.can_execute(5) is False
        assert rule.can_execute(10) is False

    def test_record_execution(self):
        """Test recording execution."""
        rule = AutomationRule(name="Test", trigger_event="test", action_type="test")

        assert rule.execution_count == 0
        assert rule.last_executed is None

        rule.record_execution("success")

        assert rule.execution_count == 1
        assert rule.last_executed is not None
        assert rule.last_result == "success"

        rule.record_execution("failure")

        assert rule.execution_count == 2
        assert rule.last_result == "failure"


class TestSecurityZone:
    """Tests for SecurityZone model."""

    def test_default_values(self):
        """Test default values."""
        zone = SecurityZone(name="Trusted")

        assert zone.id is not None
        assert zone.name == "Trusted"
        assert zone.description is None
        assert zone.trust_level == "unknown"
        assert zone.vlans == []
        assert zone.default_ingress_policy == PolicyAction.DENY
        assert zone.default_egress_policy == PolicyAction.ALLOW

    def test_custom_values(self):
        """Test custom values."""
        zone = SecurityZone(
            name="DMZ",
            description="Demilitarized zone",
            trust_level="untrusted",
            vlans=[10, 20, 30],
            default_ingress_policy=PolicyAction.DENY,
            default_egress_policy=PolicyAction.DENY,
        )

        assert zone.name == "DMZ"
        assert zone.trust_level == "untrusted"
        assert zone.vlans == [10, 20, 30]
        assert zone.default_egress_policy == PolicyAction.DENY


class TestPolicySet:
    """Tests for PolicySet model."""

    def test_default_values(self):
        """Test default values."""
        policy_set = PolicySet(name="Default Policies")

        assert policy_set.name == "Default Policies"
        assert policy_set.firewall_rules == []
        assert policy_set.segmentation_policies == []
        assert policy_set.device_policies == []
        assert policy_set.automation_rules == []
        assert policy_set.zones == []
        assert policy_set.enabled is True
        assert policy_set.version == 1

    def test_with_policies(self):
        """Test PolicySet with policies."""
        rule1 = FirewallRule(name="Rule 1", priority=50)
        rule2 = FirewallRule(name="Rule 2", priority=10)
        seg_policy = SegmentationPolicy(name="Seg Policy", source_vlan=10, destination_vlan=20)

        policy_set = PolicySet(
            name="Test Set", firewall_rules=[rule1, rule2], segmentation_policies=[seg_policy]
        )

        assert len(policy_set.firewall_rules) == 2
        assert len(policy_set.segmentation_policies) == 1

    def test_get_firewall_rules_sorted(self):
        """Test getting sorted firewall rules."""
        rule1 = FirewallRule(name="Rule 1", priority=100)
        rule2 = FirewallRule(name="Rule 2", priority=10)
        rule3 = FirewallRule(name="Rule 3", priority=50, enabled=False)
        rule4 = FirewallRule(name="Rule 4", priority=25)

        policy_set = PolicySet(name="Test Set", firewall_rules=[rule1, rule2, rule3, rule4])

        sorted_rules = policy_set.get_firewall_rules_sorted()

        # Should exclude disabled and sort by priority
        assert len(sorted_rules) == 3
        assert sorted_rules[0].name == "Rule 2"  # Priority 10
        assert sorted_rules[1].name == "Rule 4"  # Priority 25
        assert sorted_rules[2].name == "Rule 1"  # Priority 100


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
