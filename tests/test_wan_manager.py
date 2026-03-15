"""
Tests for WAN Manager and connection management.

Tests cover connection tracking, failover logic, bandwidth monitoring,
and integration with router for actual failover.
"""
import asyncio
import pytest
from datetime import datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

from sentinel.integrations.wan.manager import WANManager, FailoverEvent
from sentinel.integrations.wan.connection import (
    WANConnection,
    ConnectionType,
    ConnectionStatus,
    BandwidthMetrics,
    ConnectionQuality,
)


@pytest.fixture
def default_config():
    """Default WAN manager configuration."""
    return {
        "monitor_interval": 30,
        "speedtest_interval": 3600,
        "failover_threshold_ms": 200,
        "failover_packet_loss_threshold": 5.0,
        "failover_consecutive_failures": 3,
        "ping_targets": ["8.8.8.8", "1.1.1.1"],
        "dns_test_domain": "google.com",
    }


@pytest.fixture
def wan_manager(default_config):
    """Create a WAN manager instance."""
    return WANManager(default_config)


@pytest.fixture
def primary_connection():
    """Create a primary WAN connection."""
    conn = WANConnection(
        name="Primary Fiber",
        isp_name="Test ISP",
        connection_type=ConnectionType.FIBER,
        interface_name="ether1",
        gateway_ip="192.168.1.1",
        is_primary=True,
        priority=10,
    )
    conn.bandwidth.contracted_download_mbps = 1000
    conn.bandwidth.contracted_upload_mbps = 1000
    conn.monthly_cost = 99.99
    return conn


@pytest.fixture
def backup_connection():
    """Create a backup WAN connection."""
    conn = WANConnection(
        name="Backup Cable",
        isp_name="Backup ISP",
        connection_type=ConnectionType.CABLE,
        interface_name="ether2",
        gateway_ip="192.168.2.1",
        is_backup=True,
        priority=20,
    )
    conn.bandwidth.contracted_download_mbps = 500
    conn.bandwidth.contracted_upload_mbps = 50
    conn.monthly_cost = 59.99
    return conn


class TestWANManagerConfiguration:
    """Tests for WAN manager configuration and validation."""

    def test_valid_configuration(self, default_config):
        """Test manager creation with valid config."""
        manager = WANManager(default_config)
        assert manager.monitor_interval == 30
        assert manager.speedtest_interval == 3600
        assert manager.failover_latency_threshold_ms == 200

    def test_invalid_monitor_interval(self):
        """Test that invalid monitor interval raises error."""
        with pytest.raises(ValueError, match="monitor_interval must be >= 5"):
            WANManager({"monitor_interval": 2})

    def test_invalid_speedtest_interval(self):
        """Test that invalid speedtest interval raises error."""
        with pytest.raises(ValueError, match="speedtest_interval must be >= 60"):
            WANManager({"speedtest_interval": 30})

    def test_invalid_failover_threshold(self):
        """Test that invalid failover threshold raises error."""
        with pytest.raises(ValueError, match="failover_threshold_ms must be > 0"):
            WANManager({"failover_threshold_ms": -1})

    def test_invalid_packet_loss_threshold(self):
        """Test that invalid packet loss threshold raises error."""
        with pytest.raises(ValueError, match="failover_packet_loss_threshold must be 0-100"):
            WANManager({"failover_packet_loss_threshold": 150})

    def test_invalid_consecutive_failures(self):
        """Test that invalid consecutive failures raises error."""
        with pytest.raises(ValueError, match="failover_consecutive_failures must be >= 1"):
            WANManager({"failover_consecutive_failures": 0})

    def test_empty_ping_targets(self):
        """Test that empty ping targets raises error."""
        with pytest.raises(ValueError, match="At least one ping_target is required"):
            WANManager({"ping_targets": []})

    def test_invalid_ping_target_ip(self):
        """Test that invalid ping target IP raises error."""
        with pytest.raises(ValueError, match="Invalid ping target IP"):
            WANManager({"ping_targets": ["not.an.ip.address"]})


class TestWANConnectionModel:
    """Tests for WAN connection model."""

    def test_connection_creation(self, primary_connection):
        """Test connection creation with defaults."""
        assert primary_connection.name == "Primary Fiber"
        assert primary_connection.connection_type == ConnectionType.FIBER
        assert primary_connection.is_primary is True
        assert primary_connection.status == ConnectionStatus.UNKNOWN

    def test_connection_status_change(self, primary_connection):
        """Test status change updates timestamp."""
        primary_connection.set_status(ConnectionStatus.UP)
        assert primary_connection.status == ConnectionStatus.UP
        assert primary_connection.last_status_change is not None

    def test_connection_is_up(self, primary_connection):
        """Test is_up property."""
        primary_connection.status = ConnectionStatus.UP
        assert primary_connection.is_up is True

        primary_connection.status = ConnectionStatus.FAILOVER
        assert primary_connection.is_up is True

        primary_connection.status = ConnectionStatus.DOWN
        assert primary_connection.is_up is False

    def test_connection_is_healthy(self, primary_connection):
        """Test is_healthy property."""
        primary_connection.status = ConnectionStatus.UP
        primary_connection.quality.quality_score = 80
        assert primary_connection.is_healthy is True

        primary_connection.quality.quality_score = 50
        assert primary_connection.is_healthy is False

    def test_connection_serialization(self, primary_connection):
        """Test to_dict and from_dict."""
        data = primary_connection.to_dict()
        restored = WANConnection.from_dict(data)

        assert restored.name == primary_connection.name
        assert restored.isp_name == primary_connection.isp_name
        assert restored.connection_type == primary_connection.connection_type
        assert restored.is_primary == primary_connection.is_primary


class TestBandwidthMetrics:
    """Tests for bandwidth metrics."""

    def test_download_utilization(self):
        """Test download utilization calculation."""
        metrics = BandwidthMetrics(
            contracted_download_mbps=100,
            current_download_mbps=50
        )
        assert metrics.download_utilization_percent == 50.0

    def test_download_utilization_zero_contracted(self):
        """Test utilization with zero contracted bandwidth."""
        metrics = BandwidthMetrics(
            contracted_download_mbps=0,
            current_download_mbps=50
        )
        assert metrics.download_utilization_percent == 0.0

    def test_monthly_usage(self):
        """Test monthly usage calculation."""
        metrics = BandwidthMetrics(
            bytes_downloaded_month=1024**3,  # 1 GB
            bytes_uploaded_month=512 * 1024**2  # 512 MB
        )
        assert abs(metrics.monthly_usage_gb - 1.5) < 0.01

    def test_cap_usage_percent(self):
        """Test data cap usage percentage."""
        metrics = BandwidthMetrics(
            bytes_downloaded_month=500 * 1024**3,  # 500 GB
            bytes_uploaded_month=0,
            monthly_cap_gb=1000
        )
        assert metrics.cap_usage_percent == 50.0

    def test_cap_usage_no_cap(self):
        """Test cap usage with no cap set."""
        metrics = BandwidthMetrics()
        assert metrics.cap_usage_percent is None


class TestConnectionQuality:
    """Tests for connection quality metrics."""

    def test_quality_score_perfect(self):
        """Test quality score with perfect metrics."""
        quality = ConnectionQuality(
            latency_ms=10,
            jitter_ms=1,
            packet_loss_percent=0,
            uptime_percent_30d=100
        )
        score = quality.calculate_quality_score()
        assert score == 100.0

    def test_quality_score_high_latency(self):
        """Test quality score with high latency."""
        quality = ConnectionQuality(
            latency_ms=150,
            jitter_ms=1,
            packet_loss_percent=0,
            uptime_percent_30d=100
        )
        score = quality.calculate_quality_score()
        assert score < 100.0
        assert score >= 70.0  # Should still be usable

    def test_quality_score_packet_loss(self):
        """Test quality score with packet loss."""
        quality = ConnectionQuality(
            latency_ms=20,
            jitter_ms=1,
            packet_loss_percent=5,
            uptime_percent_30d=100
        )
        score = quality.calculate_quality_score()
        assert score < 100.0

    def test_quality_score_poor_uptime(self):
        """Test quality score with poor uptime."""
        quality = ConnectionQuality(
            latency_ms=20,
            jitter_ms=1,
            packet_loss_percent=0,
            uptime_percent_30d=90
        )
        score = quality.calculate_quality_score()
        assert score < 100.0


class TestWANManagerConnections:
    """Tests for connection management."""

    @pytest.mark.asyncio
    async def test_add_connection(self, wan_manager, primary_connection):
        """Test adding a connection."""
        # Mock the check connection
        with patch.object(wan_manager, '_check_connection', return_value=ConnectionStatus.UP):
            await wan_manager.add_connection(primary_connection)

        assert primary_connection.id in wan_manager._connections
        assert wan_manager.get_connection(primary_connection.name) == primary_connection

    @pytest.mark.asyncio
    async def test_remove_connection(self, wan_manager, primary_connection, backup_connection):
        """Test removing a connection."""
        with patch.object(wan_manager, '_check_connection', return_value=ConnectionStatus.UP):
            await wan_manager.add_connection(primary_connection)
            await wan_manager.add_connection(backup_connection)

        result = await wan_manager.remove_connection(primary_connection.id)
        assert result is True
        assert primary_connection.id not in wan_manager._connections

    def test_get_connection_by_uuid(self, wan_manager, primary_connection):
        """Test getting connection by UUID."""
        wan_manager._connections[primary_connection.id] = primary_connection
        result = wan_manager.get_connection(str(primary_connection.id))
        assert result == primary_connection

    def test_get_connection_by_name(self, wan_manager, primary_connection):
        """Test getting connection by name."""
        wan_manager._connections[primary_connection.id] = primary_connection
        result = wan_manager.get_connection("Primary Fiber")
        assert result == primary_connection

    def test_get_connection_by_interface(self, wan_manager, primary_connection):
        """Test getting connection by interface name."""
        wan_manager._connections[primary_connection.id] = primary_connection
        result = wan_manager.get_connection("ether1")
        assert result == primary_connection

    def test_get_connections_sorted_by_priority(self, wan_manager, primary_connection, backup_connection):
        """Test that connections are sorted by priority."""
        wan_manager._connections[primary_connection.id] = primary_connection
        wan_manager._connections[backup_connection.id] = backup_connection

        connections = wan_manager.get_connections()
        assert connections[0].priority < connections[1].priority

    def test_get_primary_connection(self, wan_manager, primary_connection, backup_connection):
        """Test getting primary connection."""
        wan_manager._connections[primary_connection.id] = primary_connection
        wan_manager._connections[backup_connection.id] = backup_connection

        result = wan_manager.get_primary_connection()
        assert result == primary_connection


class TestWANManagerFailover:
    """Tests for failover logic."""

    @pytest.mark.asyncio
    async def test_failover_to_backup(self, wan_manager, primary_connection, backup_connection):
        """Test failover from primary to backup."""
        # Setup connections
        primary_connection.status = ConnectionStatus.DOWN
        backup_connection.status = ConnectionStatus.UP
        backup_connection.quality.quality_score = 80

        wan_manager._connections[primary_connection.id] = primary_connection
        wan_manager._connections[backup_connection.id] = backup_connection
        wan_manager._active_connection_id = primary_connection.id

        # Trigger failover
        new_active = await wan_manager._failover("Primary down")

        assert new_active == backup_connection
        assert wan_manager._active_connection_id == backup_connection.id
        assert len(wan_manager._failover_events) == 1

    @pytest.mark.asyncio
    async def test_failover_no_alternatives(self, wan_manager, primary_connection):
        """Test failover with no alternatives available."""
        primary_connection.status = ConnectionStatus.DOWN
        wan_manager._connections[primary_connection.id] = primary_connection
        wan_manager._active_connection_id = primary_connection.id

        result = await wan_manager._failover("Primary down")
        assert result is None

    @pytest.mark.asyncio
    async def test_force_failover(self, wan_manager, primary_connection, backup_connection):
        """Test manual force failover."""
        primary_connection.status = ConnectionStatus.UP
        backup_connection.status = ConnectionStatus.UP

        wan_manager._connections[primary_connection.id] = primary_connection
        wan_manager._connections[backup_connection.id] = backup_connection
        wan_manager._active_connection_id = primary_connection.id

        result = await wan_manager.force_failover(backup_connection.id)
        assert result == backup_connection
        assert wan_manager._active_connection_id == backup_connection.id


class TestFailoverEvent:
    """Tests for failover event recording."""

    def test_failover_event_creation(self, primary_connection, backup_connection):
        """Test failover event creation."""
        event = FailoverEvent(
            from_connection=primary_connection,
            to_connection=backup_connection,
            reason="Primary degraded"
        )

        assert event.from_connection_id == primary_connection.id
        assert event.to_connection_id == backup_connection.id
        assert event.reason == "Primary degraded"
        assert event.timestamp is not None

    def test_failover_event_serialization(self, primary_connection, backup_connection):
        """Test failover event serialization."""
        event = FailoverEvent(
            from_connection=primary_connection,
            to_connection=backup_connection,
            reason="Test"
        )

        data = event.to_dict()
        assert data["from_connection_name"] == "Primary Fiber"
        assert data["to_connection_name"] == "Backup Cable"
        assert data["reason"] == "Test"


class TestWANManagerStatus:
    """Tests for status reporting."""

    @pytest.mark.asyncio
    async def test_get_status(self, wan_manager, primary_connection, backup_connection):
        """Test status report generation."""
        primary_connection.status = ConnectionStatus.UP
        backup_connection.status = ConnectionStatus.STANDBY

        wan_manager._connections[primary_connection.id] = primary_connection
        wan_manager._connections[backup_connection.id] = backup_connection
        wan_manager._active_connection_id = primary_connection.id

        status = await wan_manager.get_status()

        assert status["active_connection"]["name"] == "Primary Fiber"
        assert len(status["connections"]) == 2
        assert status["summary"]["total_connections"] == 2
        assert status["summary"]["healthy_connections"] >= 0

    def test_get_sla_report(self, wan_manager, primary_connection):
        """Test SLA report generation."""
        primary_connection.bandwidth.last_speedtest_download = 950
        wan_manager._connections[primary_connection.id] = primary_connection

        report = wan_manager.get_sla_report()

        assert "Primary Fiber" in report
        assert report["Primary Fiber"]["sla_compliance_percent"] == 95.0

    def test_get_cost_report(self, wan_manager, primary_connection, backup_connection):
        """Test cost report generation."""
        wan_manager._connections[primary_connection.id] = primary_connection
        wan_manager._connections[backup_connection.id] = backup_connection

        report = wan_manager.get_cost_report()

        assert report["total_monthly_cost"] == pytest.approx(159.98, 0.01)
        assert report["total_contracted_download_mbps"] == 1500
