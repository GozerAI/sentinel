"""
Tests for the GuardianAgent class.

Tests cover threat detection, anomaly detection, IP blocking,
device quarantine, and security alert generation.
"""

import asyncio
import pytest
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4
from collections import defaultdict

from sentinel.agents.guardian import GuardianAgent
from sentinel.core.models.event import (
    Event,
    EventCategory,
    EventSeverity,
    AgentAction,
    SecurityAlert,
)
from sentinel.core.utils import utc_now


@pytest.fixture
def mock_engine():
    """Create a mock engine."""
    engine = MagicMock()
    engine.event_bus = MagicMock()
    engine.event_bus.publish = AsyncMock()
    engine.event_bus.subscribe = MagicMock()
    engine.get_integration = MagicMock(return_value=None)
    engine.get_agent = MagicMock(return_value=None)
    engine.state = MagicMock()
    engine.state.set = AsyncMock()
    engine.state.get = AsyncMock(return_value=None)
    return engine


@pytest.fixture
def default_config():
    """Default agent configuration."""
    return {
        "auto_quarantine": True,
        "quarantine_vlan": 666,
        "threat_thresholds": {"port_scan": 100, "failed_auth": 10, "bandwidth_spike": 500},
        "auto_execute_threshold": 0.95,
        "confirm_threshold": 0.60,
    }


@pytest.fixture
def agent(mock_engine, default_config):
    """Create a guardian agent."""
    return GuardianAgent(mock_engine, default_config)


class TestGuardianAgentInit:
    """Tests for agent initialization."""

    def test_init_with_defaults(self, mock_engine):
        """Test initialization with minimal config."""
        agent = GuardianAgent(mock_engine, {})

        assert agent.agent_name == "guardian"
        assert agent.auto_quarantine is True
        assert agent.quarantine_vlan == 666
        assert agent.port_scan_threshold == 100
        assert agent.failed_auth_threshold == 10
        assert agent.bandwidth_spike_threshold == 500

    def test_init_with_custom_config(self, mock_engine, default_config):
        """Test initialization with custom config."""
        config = {
            "auto_quarantine": False,
            "quarantine_vlan": 999,
            "threat_thresholds": {"port_scan": 50, "failed_auth": 5, "bandwidth_spike": 200},
        }
        agent = GuardianAgent(mock_engine, config)

        assert agent.auto_quarantine is False
        assert agent.quarantine_vlan == 999
        assert agent.port_scan_threshold == 50
        assert agent.failed_auth_threshold == 5
        assert agent.bandwidth_spike_threshold == 200

    def test_init_creates_tracking_structures(self, agent):
        """Test that tracking structures are initialized."""
        assert agent._connection_counts is not None
        assert agent._port_access is not None
        assert agent._failed_auths is not None
        assert agent._blocked_ips == set()
        assert agent._quarantined_devices == set()
        assert agent._alerts == []


class TestGuardianAgentSubscriptions:
    """Tests for event subscriptions."""

    @pytest.mark.asyncio
    async def test_subscribe_events(self, agent, mock_engine):
        """Test event subscriptions."""
        await agent._subscribe_events()

        # Should subscribe to connection, auth, traffic, and IDS events
        assert mock_engine.event_bus.subscribe.call_count == 4


class TestGuardianAgentConnectionEvents:
    """Tests for connection event handling."""

    @pytest.mark.asyncio
    async def test_handle_connection_event_tracks_connection(self, agent):
        """Test that connection events are tracked."""
        event = Event(
            category=EventCategory.NETWORK,
            event_type="network.connection",
            severity=EventSeverity.INFO,
            source="router",
            title="Connection",
            data={
                "source_ip": "192.168.1.100",
                "destination_ip": "8.8.8.8",
                "destination_port": 443,
            },
        )

        await agent._handle_connection_event(event)

        # Should track connection
        assert len(agent._connection_counts["192.168.1.100"]) == 1
        assert 443 in agent._port_access["192.168.1.100"]

    @pytest.mark.asyncio
    async def test_handle_connection_event_no_source_ip(self, agent):
        """Test handling connection event without source IP."""
        event = Event(
            category=EventCategory.NETWORK,
            event_type="network.connection",
            severity=EventSeverity.INFO,
            source="router",
            title="Connection",
            data={"destination_ip": "8.8.8.8"},
        )

        await agent._handle_connection_event(event)

        # Should not track
        assert len(agent._connection_counts) == 0


class TestGuardianAgentPortScanDetection:
    """Tests for port scan detection."""

    @pytest.mark.asyncio
    async def test_check_port_scan_under_threshold(self, agent, mock_engine):
        """Test no alert when under threshold."""
        agent._connection_counts["192.168.1.100"] = [utc_now()] * 50
        agent._port_access["192.168.1.100"] = set(range(20))

        await agent._check_port_scan("192.168.1.100")

        # Should not create alert
        mock_engine.event_bus.publish.assert_not_called()

    @pytest.mark.asyncio
    async def test_check_port_scan_over_threshold(self, agent, mock_engine):
        """Test alert when over threshold."""
        now = utc_now()
        agent._connection_counts["192.168.1.100"] = [now] * 150
        agent._port_access["192.168.1.100"] = set(range(60))

        await agent._check_port_scan("192.168.1.100")

        # Should create alert
        assert mock_engine.event_bus.publish.called

    @pytest.mark.asyncio
    async def test_check_port_scan_already_blocked(self, agent, mock_engine):
        """Test no additional alert for already blocked IP."""
        agent._blocked_ips.add("192.168.1.100")
        now = utc_now()
        agent._connection_counts["192.168.1.100"] = [now] * 150

        await agent._check_port_scan("192.168.1.100")

        # Should not create new alert
        mock_engine.event_bus.publish.assert_not_called()


class TestGuardianAgentSuspiciousPortDetection:
    """Tests for suspicious port detection."""

    @pytest.mark.asyncio
    async def test_check_c2_port(self, agent, mock_engine):
        """Test detection of C2 port."""
        await agent._check_suspicious_port(
            "192.168.1.100",
            31337,  # Known C2 port (only in C2 list, not crypto mining)
            {"protocol": "tcp"},
        )

        # Should create alert
        mock_engine.event_bus.publish.assert_called()
        alert = mock_engine.event_bus.publish.call_args[0][0]
        assert "C2" in alert.title

    @pytest.mark.asyncio
    async def test_check_crypto_mining_port(self, agent, mock_engine):
        """Test detection of crypto mining port."""
        await agent._check_suspicious_port(
            "192.168.1.100", 3333, {"protocol": "tcp"}  # Known mining port
        )

        # Should create alert
        mock_engine.event_bus.publish.assert_called()
        alert = mock_engine.event_bus.publish.call_args[0][0]
        assert "crypto" in alert.title.lower() or "mining" in alert.title.lower()

    @pytest.mark.asyncio
    async def test_check_normal_port(self, agent, mock_engine):
        """Test no alert for normal port."""
        await agent._check_suspicious_port(
            "192.168.1.100", 443, {"protocol": "tcp"}  # Normal HTTPS
        )

        # Should not create alert
        mock_engine.event_bus.publish.assert_not_called()

    @pytest.mark.asyncio
    async def test_check_suspicious_port_none(self, agent, mock_engine):
        """Test handling None port."""
        await agent._check_suspicious_port("192.168.1.100", None, {})

        # Should not create alert
        mock_engine.event_bus.publish.assert_not_called()


class TestGuardianAgentAuthEvents:
    """Tests for authentication event handling."""

    @pytest.mark.asyncio
    async def test_handle_auth_event_success(self, agent):
        """Test handling successful auth (no tracking)."""
        event = Event(
            category=EventCategory.SECURITY,
            event_type="auth.attempt",
            severity=EventSeverity.INFO,
            source="sshd",
            title="Auth",
            data={"source_ip": "192.168.1.100", "success": True, "service": "ssh"},
        )

        await agent._handle_auth_event(event)

        # Should not track successful auth
        assert len(agent._failed_auths["192.168.1.100"]) == 0

    @pytest.mark.asyncio
    async def test_handle_auth_event_failure(self, agent):
        """Test handling failed auth."""
        event = Event(
            category=EventCategory.SECURITY,
            event_type="auth.attempt",
            severity=EventSeverity.WARNING,
            source="sshd",
            title="Auth",
            data={
                "source_ip": "192.168.1.100",
                "success": False,
                "service": "ssh",
                "username": "root",
            },
        )

        await agent._handle_auth_event(event)

        # Should track failed auth
        assert len(agent._failed_auths["192.168.1.100"]) == 1


class TestGuardianAgentBruteForceDetection:
    """Tests for brute force detection."""

    @pytest.mark.asyncio
    async def test_check_brute_force_under_threshold(self, agent, mock_engine):
        """Test no alert under threshold."""
        now = utc_now()
        agent._failed_auths["192.168.1.100"] = [now] * 5

        await agent._check_brute_force("192.168.1.100", "ssh", "root")

        # Should not create alert
        mock_engine.event_bus.publish.assert_not_called()

    @pytest.mark.asyncio
    async def test_check_brute_force_over_threshold(self, agent, mock_engine):
        """Test alert over threshold."""
        now = utc_now()
        agent._failed_auths["192.168.1.100"] = [now] * 15

        await agent._check_brute_force("192.168.1.100", "ssh", "root")

        # Should create alert
        assert mock_engine.event_bus.publish.called


class TestGuardianAgentTrafficEvents:
    """Tests for traffic event handling."""

    @pytest.mark.asyncio
    async def test_handle_traffic_event_baseline(self, agent):
        """Test traffic event establishes baseline."""
        event = Event(
            category=EventCategory.NETWORK,
            event_type="network.traffic",
            severity=EventSeverity.INFO,
            source="router",
            title="Traffic",
            data={"source_ip": "192.168.1.100", "bytes": 1000},
        )

        await agent._handle_traffic_event(event)

        # Should establish baseline
        assert "192.168.1.100" in agent._bandwidth_baseline

    @pytest.mark.asyncio
    async def test_handle_traffic_event_spike(self, agent, mock_engine):
        """Test traffic spike detection."""
        # Establish low baseline
        agent._bandwidth_baseline["192.168.1.100"] = 100

        event = Event(
            category=EventCategory.NETWORK,
            event_type="network.traffic",
            severity=EventSeverity.INFO,
            source="router",
            title="Traffic",
            data={"source_ip": "192.168.1.100", "bytes": 100000},  # 1000x baseline
        )

        await agent._handle_traffic_event(event)

        # Should create alert
        assert mock_engine.event_bus.publish.called

    @pytest.mark.asyncio
    async def test_handle_traffic_event_no_source_ip(self, agent):
        """Test handling traffic event without source IP."""
        event = Event(
            category=EventCategory.NETWORK,
            event_type="network.traffic",
            severity=EventSeverity.INFO,
            source="router",
            title="Traffic",
            data={"bytes": 1000},
        )

        await agent._handle_traffic_event(event)

        # Should not track
        assert len(agent._bandwidth_baseline) == 0


class TestGuardianAgentIDSAlerts:
    """Tests for IDS alert handling."""

    @pytest.mark.asyncio
    async def test_handle_ids_alert(self, agent, mock_engine):
        """Test handling IDS alert."""
        event = Event(
            category=EventCategory.SECURITY,
            event_type="ids.alert",
            severity=EventSeverity.WARNING,
            source="snort",
            title="IDS Alert",
            data={
                "source_ip": "192.168.1.100",
                "signature": "ET MALWARE Win32/Agent.VBS",
                "severity": "high",
                "description": "Malware detected",
            },
        )

        await agent._handle_ids_alert(event)

        # Should create alert
        mock_engine.event_bus.publish.assert_called()

    @pytest.mark.asyncio
    async def test_handle_ids_alert_critical(self, agent, mock_engine):
        """Test handling critical IDS alert triggers quarantine."""
        event = Event(
            category=EventCategory.SECURITY,
            event_type="ids.alert",
            severity=EventSeverity.CRITICAL,
            source="snort",
            title="IDS Alert",
            data={
                "source_ip": "192.168.1.100",
                "signature": "ET EXPLOIT CVE-2024-1234",
                "severity": "critical",
            },
        )

        await agent._handle_ids_alert(event)

        # Should trigger quarantine
        assert "192.168.1.100" in agent._quarantined_devices or len(agent._actions) > 0


class TestGuardianAgentBlockIP:
    """Tests for IP blocking."""

    @pytest.mark.asyncio
    async def test_block_ip(self, agent, mock_engine):
        """Test blocking an IP."""
        await agent._block_ip("192.168.1.100", "Test block")

        # Should create action and track IP
        assert len(agent._actions) > 0
        assert len(agent._decisions) == 1

    @pytest.mark.asyncio
    async def test_block_ip_already_blocked(self, agent, mock_engine):
        """Test blocking already blocked IP."""
        agent._blocked_ips.add("192.168.1.100")

        await agent._block_ip("192.168.1.100", "Test block")

        # Should not create action
        assert len(agent._actions) == 0


class TestGuardianAgentQuarantineDevice:
    """Tests for device quarantine."""

    @pytest.mark.asyncio
    async def test_quarantine_device(self, agent, mock_engine):
        """Test quarantining a device."""
        await agent._quarantine_device("00:11:22:33:44:55", "Test quarantine")

        # Should create action and track device
        assert len(agent._actions) > 0
        assert len(agent._decisions) == 1

    @pytest.mark.asyncio
    async def test_quarantine_device_already_quarantined(self, agent, mock_engine):
        """Test quarantining already quarantined device."""
        agent._quarantined_devices.add("00:11:22:33:44:55")

        await agent._quarantine_device("00:11:22:33:44:55", "Test quarantine")

        # Should not create action
        assert len(agent._actions) == 0


class TestGuardianAgentCreateAlert:
    """Tests for alert creation."""

    @pytest.mark.asyncio
    async def test_create_alert(self, agent, mock_engine):
        """Test creating a security alert."""
        alert = await agent._create_alert(
            title="Test Alert",
            description="Test description",
            severity=EventSeverity.WARNING,
            threat_type="port_scan",
            source_ip="192.168.1.100",
            confidence=0.8,
        )

        assert alert is not None
        assert alert.title == "Test Alert"
        assert len(agent._alerts) == 1
        mock_engine.event_bus.publish.assert_called()

    @pytest.mark.asyncio
    async def test_create_alert_with_mitre(self, agent, mock_engine):
        """Test alert includes MITRE mapping."""
        alert = await agent._create_alert(
            title="Brute Force",
            description="Test",
            severity=EventSeverity.ERROR,
            threat_type="brute_force",
            confidence=0.9,
        )

        assert alert.mitre_technique == "T1110"

    @pytest.mark.asyncio
    async def test_create_alert_limits_storage(self, agent, mock_engine):
        """Test that alerts are limited."""
        for i in range(1100):
            await agent._create_alert(
                title=f"Alert {i}",
                description="Test",
                severity=EventSeverity.INFO,
                threat_type="test",
                confidence=0.5,
            )

        # Should limit to 500 after cleanup
        assert len(agent._alerts) <= 1000


class TestGuardianAgentRiskScore:
    """Tests for risk score calculation."""

    def test_calculate_risk_score_critical(self, agent):
        """Test risk score for critical severity."""
        score = agent._calculate_risk_score(EventSeverity.CRITICAL, 1.0)
        assert score == 10.0

    def test_calculate_risk_score_warning(self, agent):
        """Test risk score for warning severity."""
        score = agent._calculate_risk_score(EventSeverity.WARNING, 1.0)
        assert score == 5.0

    def test_calculate_risk_score_with_confidence(self, agent):
        """Test risk score adjusted by confidence."""
        score = agent._calculate_risk_score(EventSeverity.ERROR, 0.5)
        assert score == 4.0  # 8.0 * 0.5


class TestGuardianAgentUnblock:
    """Tests for unblocking IPs."""

    @pytest.mark.asyncio
    async def test_unblock_ip(self, agent, mock_engine):
        """Test unblocking an IP."""
        agent._blocked_ips.add("192.168.1.100")

        result = await agent.unblock_ip("192.168.1.100")

        # Should create action
        assert len(agent._actions) > 0

    @pytest.mark.asyncio
    async def test_unblock_ip_not_blocked(self, agent, mock_engine):
        """Test unblocking IP that wasn't blocked."""
        result = await agent.unblock_ip("192.168.1.100")

        assert result is False


class TestGuardianAgentUnquarantine:
    """Tests for unquarantining devices."""

    @pytest.mark.asyncio
    async def test_unquarantine_device(self, agent, mock_engine):
        """Test unquarantining a device."""
        agent._quarantined_devices.add("00:11:22:33:44:55")

        result = await agent.unquarantine_device("00:11:22:33:44:55", 10)

        # Should create action
        assert len(agent._actions) > 0

    @pytest.mark.asyncio
    async def test_unquarantine_device_not_quarantined(self, agent, mock_engine):
        """Test unquarantining device that wasn't quarantined."""
        result = await agent.unquarantine_device("00:11:22:33:44:55", 10)

        assert result is False


class TestGuardianAgentDoExecute:
    """Tests for action execution."""

    @pytest.mark.asyncio
    async def test_do_execute_block_ip_no_router(self, agent, mock_engine):
        """Test block IP without router integration."""
        action = AgentAction(
            agent_name="guardian",
            action_type="block_ip",
            target_type="ip_address",
            target_id="192.168.1.100",
            parameters={"ip": "192.168.1.100", "reason": "Test", "duration_hours": 24},
            reasoning="Test",
            confidence=0.95,
        )

        result = await agent._do_execute(action)

        assert result["blocked"] is True
        assert "192.168.1.100" in agent._blocked_ips

    @pytest.mark.asyncio
    async def test_do_execute_block_ip_with_router(self, agent, mock_engine):
        """Test block IP with router integration."""
        mock_router = MagicMock()
        mock_router.add_firewall_rule = AsyncMock(return_value="rule-123")
        mock_engine.get_integration.return_value = mock_router

        action = AgentAction(
            agent_name="guardian",
            action_type="block_ip",
            target_type="ip_address",
            target_id="192.168.1.100",
            parameters={"ip": "192.168.1.100", "reason": "Test"},
            reasoning="Test",
            confidence=0.95,
        )

        result = await agent._do_execute(action)

        assert result["blocked"] is True
        assert result["rule_id"] == "rule-123"

    @pytest.mark.asyncio
    async def test_do_execute_unblock_ip(self, agent, mock_engine):
        """Test unblock IP."""
        agent._blocked_ips.add("192.168.1.100")

        action = AgentAction(
            agent_name="guardian",
            action_type="unblock_ip",
            target_type="ip_address",
            target_id="192.168.1.100",
            parameters={"ip": "192.168.1.100"},
            reasoning="Test",
            confidence=1.0,
        )

        result = await agent._do_execute(action)

        assert result["unblocked"] is True
        assert "192.168.1.100" not in agent._blocked_ips

    @pytest.mark.asyncio
    async def test_do_execute_quarantine_device_mac(self, agent, mock_engine):
        """Test quarantine device by MAC."""
        mock_switch = MagicMock()
        mock_switch.set_port_vlan = AsyncMock()
        mock_engine.get_integration.return_value = mock_switch

        action = AgentAction(
            agent_name="guardian",
            action_type="quarantine_device",
            target_type="device",
            target_id="00:11:22:33:44:55",
            parameters={"identifier": "00:11:22:33:44:55", "quarantine_vlan": 666},
            reasoning="Test",
            confidence=0.95,
        )

        result = await agent._do_execute(action)

        assert result["quarantined"] is True

    @pytest.mark.asyncio
    async def test_do_execute_unquarantine_device(self, agent, mock_engine):
        """Test unquarantine device."""
        agent._quarantined_devices.add("00:11:22:33:44:55")

        action = AgentAction(
            agent_name="guardian",
            action_type="unquarantine_device",
            target_type="device",
            target_id="00:11:22:33:44:55",
            parameters={"identifier": "00:11:22:33:44:55", "restore_vlan": 10},
            reasoning="Test",
            confidence=1.0,
        )

        result = await agent._do_execute(action)

        assert result["unquarantined"] is True
        assert "00:11:22:33:44:55" not in agent._quarantined_devices

    @pytest.mark.asyncio
    async def test_do_execute_unknown_action(self, agent, mock_engine):
        """Test execution of unknown action type."""
        action = AgentAction(
            agent_name="guardian",
            action_type="unknown_action",
            target_type="device",
            target_id="123",
            parameters={},
            reasoning="Test",
            confidence=0.95,
        )

        with pytest.raises(ValueError, match="Unknown action type"):
            await agent._do_execute(action)


class TestGuardianAgentRollback:
    """Tests for action rollback."""

    @pytest.mark.asyncio
    async def test_capture_rollback_data_block_ip(self, agent):
        """Test capturing rollback data for block IP."""
        action = AgentAction(
            agent_name="guardian",
            action_type="block_ip",
            target_type="ip_address",
            target_id="192.168.1.100",
            parameters={"ip": "192.168.1.100"},
            reasoning="Test",
            confidence=0.95,
        )

        rollback_data = await agent._capture_rollback_data(action)

        assert rollback_data["action"] == "unblock_ip"
        assert rollback_data["ip"] == "192.168.1.100"

    @pytest.mark.asyncio
    async def test_do_rollback_unblock(self, agent, mock_engine):
        """Test rollback unblocks IP."""
        agent._blocked_ips.add("192.168.1.100")

        action = AgentAction(
            agent_name="guardian",
            action_type="block_ip",
            target_type="ip_address",
            target_id="192.168.1.100",
            parameters={"ip": "192.168.1.100"},
            reasoning="Test",
            confidence=0.95,
            rollback_data={"action": "unblock_ip", "ip": "192.168.1.100"},
        )

        await agent._do_rollback(action)

        assert "192.168.1.100" not in agent._blocked_ips


class TestGuardianAgentAnalyzeThreats:
    """Tests for threat analysis."""

    @pytest.mark.asyncio
    async def test_analyze_threats_multi_vector(self, agent, mock_engine):
        """Test detection of multi-vector attack."""
        now = utc_now()

        # Create multiple alerts from same source
        agent._alerts = [
            SecurityAlert(
                category=EventCategory.SECURITY,
                event_type="security.port_scan",
                severity=EventSeverity.WARNING,
                source="guardian",
                title="Alert 1",
                timestamp=now,
                threat_type="port_scan",
                data={"source_ip": "192.168.1.100"},
            ),
            SecurityAlert(
                category=EventCategory.SECURITY,
                event_type="security.brute_force",
                severity=EventSeverity.ERROR,
                source="guardian",
                title="Alert 2",
                timestamp=now,
                threat_type="brute_force",
                data={"source_ip": "192.168.1.100"},
            ),
            SecurityAlert(
                category=EventCategory.SECURITY,
                event_type="security.c2",
                severity=EventSeverity.ERROR,
                source="guardian",
                title="Alert 3",
                timestamp=now,
                threat_type="c2_communication",
                data={"source_ip": "192.168.1.100"},
            ),
        ]

        await agent._analyze_threats()

        # Should detect multi-vector attack
        multi_vector_alerts = [a for a in agent._alerts if "multi" in a.title.lower()]
        assert len(multi_vector_alerts) >= 1


class TestGuardianAgentCleanup:
    """Tests for data cleanup."""

    @pytest.mark.asyncio
    async def test_cleanup_old_data(self, agent):
        """Test cleanup of old tracking data."""
        old_time = utc_now() - timedelta(hours=2)

        agent._connection_counts["old_ip"] = [old_time] * 10
        agent._failed_auths["old_ip"] = [old_time] * 5

        await agent._cleanup_old_data()

        # Old data should be removed
        assert "old_ip" not in agent._connection_counts
        assert "old_ip" not in agent._failed_auths


class TestGuardianAgentProperties:
    """Tests for agent properties."""

    def test_blocked_ips_property(self, agent):
        """Test blocked_ips property returns copy."""
        agent._blocked_ips.add("192.168.1.100")
        blocked = agent.blocked_ips
        blocked.add("192.168.1.200")

        # Original should not be modified
        assert "192.168.1.200" not in agent._blocked_ips

    def test_quarantined_devices_property(self, agent):
        """Test quarantined_devices property returns copy."""
        agent._quarantined_devices.add("device-1")
        quarantined = agent.quarantined_devices
        quarantined.add("device-2")

        # Original should not be modified
        assert "device-2" not in agent._quarantined_devices

    def test_stats_property(self, agent):
        """Test stats property."""
        agent._blocked_ips.add("192.168.1.100")
        agent._quarantined_devices.add("device-1")

        stats = agent.stats

        assert stats["blocked_ips"] == 1
        assert stats["quarantined_devices"] == 1
        assert "alerts_today" in stats
        assert "total_alerts" in stats


class TestGuardianAgentGetRelevantState:
    """Tests for _get_relevant_state."""

    @pytest.mark.asyncio
    async def test_get_relevant_state(self, agent):
        """Test getting relevant state."""
        agent._blocked_ips.add("192.168.1.100")
        agent._quarantined_devices.add("device-1")

        state = await agent._get_relevant_state()

        assert "192.168.1.100" in state["blocked_ips"]
        assert "device-1" in state["quarantined_devices"]


class TestGuardianAgentAnalyze:
    """Tests for analyze method."""

    @pytest.mark.asyncio
    async def test_analyze_returns_none(self, agent):
        """Test that analyze returns None."""
        event = Event(
            category=EventCategory.SECURITY,
            event_type="test",
            severity=EventSeverity.INFO,
            source="test",
            title="Test",
        )

        result = await agent.analyze(event)

        assert result is None


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
