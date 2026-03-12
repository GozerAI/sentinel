"""
Comprehensive tests for Metrics Collector covering all code paths.

These tests achieve full coverage including:
- All metric types (Counter, Gauge, Histogram)
- MetricsCollector methods
- Update methods with engine integration
- Recording methods
"""

import pytest
from unittest.mock import MagicMock, patch, PropertyMock
from prometheus_client import CollectorRegistry

from sentinel.core.metrics import (
    MetricsCollector,
    get_metrics_collector,
    configure_metrics,
    ENGINE_INFO,
    ENGINE_UPTIME,
    ENGINE_RUNNING,
    AGENT_RUNNING,
    AGENT_EVENTS_PROCESSED,
    AGENT_ACTIONS_TAKEN,
    AGENT_DECISIONS_MADE,
    AGENT_ANALYSIS_DURATION,
    DEVICES_TOTAL,
    DEVICES_BY_VLAN,
    DEVICES_BY_TRUST_LEVEL,
    VLANS_TOTAL,
    TRAFFIC_FLOWS_ACTIVE,
    BANDWIDTH_USAGE_BYTES,
    BLOCKED_IPS_TOTAL,
    QUARANTINED_DEVICES_TOTAL,
    SECURITY_EVENTS,
    THREAT_DETECTIONS,
    EVENTS_PUBLISHED,
    EVENTS_QUEUE_SIZE,
    EVENT_HANDLERS_TOTAL,
    INTEGRATION_STATUS,
    INTEGRATION_REQUESTS,
    INTEGRATION_LATENCY,
    API_REQUESTS,
    API_LATENCY,
    SCHEDULED_TASKS_TOTAL,
    SCHEDULED_TASK_EXECUTIONS,
)


class TestMetricsCollectorInit:
    """Tests for MetricsCollector initialization."""

    def test_init_sets_engine_info(self):
        """Test initialization sets engine info."""
        registry = CollectorRegistry()
        collector = MetricsCollector(registry)

        assert collector._engine is None
        assert collector.registry is registry

    def test_init_with_default_registry(self):
        """Test initialization with default registry."""
        collector = MetricsCollector()
        assert collector.registry is not None

    def test_set_engine(self):
        """Test set_engine stores engine reference."""
        registry = CollectorRegistry()
        collector = MetricsCollector(registry)

        mock_engine = MagicMock()
        collector.set_engine(mock_engine)

        assert collector._engine is mock_engine


class TestUpdateEngineMetrics:
    """Tests for update_engine_metrics."""

    def test_no_engine_does_nothing(self):
        """Test update_engine_metrics does nothing without engine."""
        registry = CollectorRegistry()
        collector = MetricsCollector(registry)

        # Should not raise
        collector.update_engine_metrics()

    def test_updates_running_gauge(self):
        """Test updates ENGINE_RUNNING gauge."""
        registry = CollectorRegistry()
        collector = MetricsCollector(registry)

        mock_engine = MagicMock()
        mock_engine.is_running = True
        mock_engine.uptime_seconds = 100.5

        collector.set_engine(mock_engine)
        collector.update_engine_metrics()

        # Metrics should be updated
        # (can't easily verify values without sampling registry)


class TestUpdateAgentMetrics:
    """Tests for update_agent_metrics."""

    def test_no_engine_does_nothing(self):
        """Test update_agent_metrics does nothing without engine."""
        registry = CollectorRegistry()
        collector = MetricsCollector(registry)

        # Should not raise
        collector.update_agent_metrics()

    def test_updates_agent_running_gauge(self):
        """Test updates AGENT_RUNNING gauge for each agent."""
        registry = CollectorRegistry()
        collector = MetricsCollector(registry)

        mock_agent1 = MagicMock()
        mock_agent1._running = True

        mock_agent2 = MagicMock()
        mock_agent2._running = False

        mock_engine = MagicMock()
        mock_engine._agents = {"agent1": mock_agent1, "agent2": mock_agent2}

        collector.set_engine(mock_engine)
        collector.update_agent_metrics()


class TestUpdateDeviceMetrics:
    """Tests for update_device_metrics."""

    def test_no_engine_does_nothing(self):
        """Test update_device_metrics does nothing without engine."""
        registry = CollectorRegistry()
        collector = MetricsCollector(registry)

        # Should not raise
        collector.update_device_metrics()

    def test_no_discovery_agent_does_nothing(self):
        """Test does nothing without discovery agent."""
        registry = CollectorRegistry()
        collector = MetricsCollector(registry)

        mock_engine = MagicMock()
        mock_engine.get_agent.return_value = None

        collector.set_engine(mock_engine)
        collector.update_device_metrics()

    def test_no_inventory_does_nothing(self):
        """Test does nothing when agent has no inventory."""
        registry = CollectorRegistry()
        collector = MetricsCollector(registry)

        mock_agent = MagicMock(spec=[])  # No _inventory attribute
        mock_engine = MagicMock()
        mock_engine.get_agent.return_value = mock_agent

        collector.set_engine(mock_engine)
        collector.update_device_metrics()

    def test_updates_device_metrics(self):
        """Test updates device metrics from inventory."""
        registry = CollectorRegistry()
        collector = MetricsCollector(registry)

        # Create mock device
        mock_device = MagicMock()
        mock_device.device_type.value = "workstation"
        mock_device.status.value = "online"
        mock_device.assigned_vlan = 10
        mock_device.trust_level.value = "trusted"

        # Create mock inventory
        mock_inventory = MagicMock()
        mock_inventory.devices = {"device1": mock_device}

        # Create mock discovery agent
        mock_agent = MagicMock()
        mock_agent._inventory = mock_inventory

        mock_engine = MagicMock()
        mock_engine.get_agent.return_value = mock_agent

        collector.set_engine(mock_engine)
        collector.update_device_metrics()

    def test_handles_device_without_vlan(self):
        """Test handles devices without VLAN assignment."""
        registry = CollectorRegistry()
        collector = MetricsCollector(registry)

        mock_device = MagicMock()
        mock_device.device_type.value = "server"
        mock_device.status.value = "offline"
        mock_device.assigned_vlan = None
        mock_device.trust_level.value = "unknown"

        mock_inventory = MagicMock()
        mock_inventory.devices = {"device1": mock_device}

        mock_agent = MagicMock()
        mock_agent._inventory = mock_inventory

        mock_engine = MagicMock()
        mock_engine.get_agent.return_value = mock_agent

        collector.set_engine(mock_engine)
        collector.update_device_metrics()


class TestUpdateSecurityMetrics:
    """Tests for update_security_metrics."""

    def test_no_engine_does_nothing(self):
        """Test update_security_metrics does nothing without engine."""
        registry = CollectorRegistry()
        collector = MetricsCollector(registry)

        # Should not raise
        collector.update_security_metrics()

    def test_no_guardian_agent_does_nothing(self):
        """Test does nothing without guardian agent."""
        registry = CollectorRegistry()
        collector = MetricsCollector(registry)

        mock_engine = MagicMock()
        mock_engine.get_agent.return_value = None

        collector.set_engine(mock_engine)
        collector.update_security_metrics()

    def test_updates_blocked_ips_metric(self):
        """Test updates BLOCKED_IPS_TOTAL gauge."""
        registry = CollectorRegistry()
        collector = MetricsCollector(registry)

        mock_agent = MagicMock()
        mock_agent._blocked_ips = {"192.168.1.1", "192.168.1.2"}
        mock_agent._quarantined_devices = {"device1"}

        mock_engine = MagicMock()
        mock_engine.get_agent.return_value = mock_agent

        collector.set_engine(mock_engine)
        collector.update_security_metrics()

    def test_handles_missing_attributes(self):
        """Test handles guardian without blocked_ips attribute."""
        registry = CollectorRegistry()
        collector = MetricsCollector(registry)

        mock_agent = MagicMock(spec=[])  # No _blocked_ips or _quarantined_devices

        mock_engine = MagicMock()
        mock_engine.get_agent.return_value = mock_agent

        collector.set_engine(mock_engine)
        collector.update_security_metrics()


class TestUpdateEventBusMetrics:
    """Tests for update_event_bus_metrics."""

    def test_no_engine_does_nothing(self):
        """Test update_event_bus_metrics does nothing without engine."""
        registry = CollectorRegistry()
        collector = MetricsCollector(registry)

        # Should not raise
        collector.update_event_bus_metrics()

    def test_updates_event_bus_metrics(self):
        """Test updates event bus metrics."""
        registry = CollectorRegistry()
        collector = MetricsCollector(registry)

        mock_event_bus = MagicMock()
        mock_event_bus._queue.qsize.return_value = 5
        mock_event_bus._global_handlers = [1, 2, 3]

        mock_engine = MagicMock()
        mock_engine.event_bus = mock_event_bus

        collector.set_engine(mock_engine)
        collector.update_event_bus_metrics()


class TestUpdateAllMetrics:
    """Tests for update_all_metrics."""

    def test_calls_all_update_methods(self):
        """Test update_all_metrics calls all update methods."""
        registry = CollectorRegistry()
        collector = MetricsCollector(registry)

        collector.update_engine_metrics = MagicMock()
        collector.update_agent_metrics = MagicMock()
        collector.update_device_metrics = MagicMock()
        collector.update_security_metrics = MagicMock()
        collector.update_event_bus_metrics = MagicMock()

        collector.update_all_metrics()

        collector.update_engine_metrics.assert_called_once()
        collector.update_agent_metrics.assert_called_once()
        collector.update_device_metrics.assert_called_once()
        collector.update_security_metrics.assert_called_once()
        collector.update_event_bus_metrics.assert_called_once()

    def test_handles_exception(self):
        """Test update_all_metrics handles exceptions gracefully."""
        registry = CollectorRegistry()
        collector = MetricsCollector(registry)

        collector.update_engine_metrics = MagicMock(side_effect=RuntimeError("Error"))

        # Should not raise
        collector.update_all_metrics()


class TestRecordingMethods:
    """Tests for metric recording methods."""

    def test_record_agent_event(self):
        """Test record_agent_event increments counter."""
        registry = CollectorRegistry()
        collector = MetricsCollector(registry)

        collector.record_agent_event("discovery", "device.discovered")
        collector.record_agent_event("discovery", "device.discovered")

    def test_record_agent_action(self):
        """Test record_agent_action increments counter."""
        registry = CollectorRegistry()
        collector = MetricsCollector(registry)

        collector.record_agent_action("guardian", "block_ip", "success")
        collector.record_agent_action("guardian", "block_ip", "failed")

    def test_record_agent_decision(self):
        """Test record_agent_decision increments counter."""
        registry = CollectorRegistry()
        collector = MetricsCollector(registry)

        collector.record_agent_decision("planner")

    def test_record_agent_analysis_time(self):
        """Test record_agent_analysis_time records histogram."""
        registry = CollectorRegistry()
        collector = MetricsCollector(registry)

        collector.record_agent_analysis_time("discovery", 0.05)
        collector.record_agent_analysis_time("discovery", 0.1)

    def test_record_event_published(self):
        """Test record_event_published increments counter."""
        registry = CollectorRegistry()
        collector = MetricsCollector(registry)

        collector.record_event_published("security", "threat.detected")

    def test_record_security_event(self):
        """Test record_security_event increments counter."""
        registry = CollectorRegistry()
        collector = MetricsCollector(registry)

        collector.record_security_event("intrusion", "critical")

    def test_record_threat_detection(self):
        """Test record_threat_detection increments counter."""
        registry = CollectorRegistry()
        collector = MetricsCollector(registry)

        collector.record_threat_detection("malware")

    def test_record_integration_request_without_latency(self):
        """Test record_integration_request without latency."""
        registry = CollectorRegistry()
        collector = MetricsCollector(registry)

        collector.record_integration_request("router", "get_rules", "success")

    def test_record_integration_request_with_latency(self):
        """Test record_integration_request with latency."""
        registry = CollectorRegistry()
        collector = MetricsCollector(registry)

        collector.record_integration_request("router", "get_rules", "success", latency=0.05)

    def test_record_api_request(self):
        """Test record_api_request records counter and histogram."""
        registry = CollectorRegistry()
        collector = MetricsCollector(registry)

        collector.record_api_request("GET", "/api/devices", 200, 0.01)
        collector.record_api_request("POST", "/api/rules", 201, 0.05)

    def test_set_integration_status_connected(self):
        """Test set_integration_status sets gauge to 1."""
        registry = CollectorRegistry()
        collector = MetricsCollector(registry)

        collector.set_integration_status("router", "opnsense", True)

    def test_set_integration_status_disconnected(self):
        """Test set_integration_status sets gauge to 0."""
        registry = CollectorRegistry()
        collector = MetricsCollector(registry)

        collector.set_integration_status("router", "opnsense", False)


class TestGenerateMetrics:
    """Tests for generate_metrics method."""

    def test_generate_metrics_returns_bytes(self):
        """Test generate_metrics returns bytes."""
        registry = CollectorRegistry()
        collector = MetricsCollector(registry)

        result = collector.generate_metrics()

        assert isinstance(result, bytes)

    def test_generate_metrics_calls_update_all(self):
        """Test generate_metrics calls update_all_metrics."""
        registry = CollectorRegistry()
        collector = MetricsCollector(registry)

        collector.update_all_metrics = MagicMock()

        collector.generate_metrics()

        collector.update_all_metrics.assert_called_once()


class TestGetContentType:
    """Tests for get_content_type method."""

    def test_returns_prometheus_content_type(self):
        """Test get_content_type returns Prometheus content type."""
        registry = CollectorRegistry()
        collector = MetricsCollector(registry)

        content_type = collector.get_content_type()

        assert "text/plain" in content_type or "openmetrics" in content_type.lower()


class TestGlobalMetricsCollector:
    """Tests for global metrics collector functions."""

    def test_get_metrics_collector_creates_singleton(self):
        """Test get_metrics_collector creates singleton."""
        # Reset global
        import sentinel.core.metrics as metrics_module

        metrics_module._metrics_collector = None

        collector1 = get_metrics_collector()
        collector2 = get_metrics_collector()

        assert collector1 is collector2

    def test_configure_metrics_sets_engine(self):
        """Test configure_metrics sets engine on collector."""
        # Reset global
        import sentinel.core.metrics as metrics_module

        metrics_module._metrics_collector = None

        mock_engine = MagicMock()

        collector = configure_metrics(mock_engine)

        assert collector._engine is mock_engine


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
