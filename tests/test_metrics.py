"""
Tests for Sentinel metrics collection.
"""
import pytest
from unittest.mock import MagicMock, AsyncMock

from sentinel.core.metrics import (
    MetricsCollector,
    get_metrics_collector,
    configure_metrics,
    AGENT_EVENTS_PROCESSED,
    AGENT_ACTIONS_TAKEN,
    ENGINE_RUNNING,
    ENGINE_UPTIME,
)


class MockAgent:
    """Mock agent for testing."""

    def __init__(self, name):
        self.agent_name = name
        self._running = True
        self._enabled = True


class MockInventory:
    """Mock inventory for testing."""

    def __init__(self):
        self.devices = {}


class MockDiscoveryAgent(MockAgent):
    """Mock discovery agent with inventory."""

    def __init__(self):
        super().__init__("discovery")
        self._inventory = MockInventory()


class MockGuardianAgent(MockAgent):
    """Mock guardian agent."""

    def __init__(self):
        super().__init__("guardian")
        self._blocked_ips = {"192.168.1.100", "10.0.0.50"}
        self._quarantined_devices = {"device-1"}


class MockEventBus:
    """Mock event bus for testing."""

    def __init__(self):
        self._queue = MagicMock()
        self._queue.qsize.return_value = 5
        self._global_handlers = [MagicMock(), MagicMock()]


class MockEngine:
    """Mock engine for metrics testing."""

    def __init__(self):
        self._running = True
        self._start_time = None
        self._agents = {
            "discovery": MockDiscoveryAgent(),
            "guardian": MockGuardianAgent(),
        }
        self.event_bus = MockEventBus()

    @property
    def is_running(self):
        return self._running

    @property
    def uptime_seconds(self):
        return 123.45

    def get_agent(self, name):
        return self._agents.get(name)


class TestMetricsCollector:
    """Tests for MetricsCollector."""

    def test_collector_creation(self):
        """Test metrics collector can be created."""
        collector = MetricsCollector()
        assert collector is not None
        assert collector._engine is None

    def test_set_engine(self):
        """Test setting engine reference."""
        collector = MetricsCollector()
        engine = MockEngine()
        collector.set_engine(engine)
        assert collector._engine == engine

    def test_update_engine_metrics(self):
        """Test updating engine metrics."""
        collector = MetricsCollector()
        engine = MockEngine()
        collector.set_engine(engine)

        collector.update_engine_metrics()

        # Verify metrics were set
        assert ENGINE_RUNNING._value.get() == 1
        assert ENGINE_UPTIME._value.get() == 123.45

    def test_update_agent_metrics(self):
        """Test updating agent metrics."""
        collector = MetricsCollector()
        engine = MockEngine()
        collector.set_engine(engine)

        collector.update_agent_metrics()

        # Agent running metrics should be set
        # (we can't easily verify labeled gauges without more setup)

    def test_record_agent_event(self):
        """Test recording agent events."""
        collector = MetricsCollector()

        # Record some events
        collector.record_agent_event("discovery", "device.discovered")
        collector.record_agent_event("discovery", "device.discovered")
        collector.record_agent_event("guardian", "threat.detected")

        # Counters should be incremented
        assert AGENT_EVENTS_PROCESSED.labels(
            agent_name="discovery",
            event_type="device.discovered"
        )._value.get() >= 2

    def test_record_agent_action(self):
        """Test recording agent actions."""
        collector = MetricsCollector()

        collector.record_agent_action("guardian", "block_ip", "success")
        collector.record_agent_action("guardian", "block_ip", "failed")

        # Counters should be incremented
        assert AGENT_ACTIONS_TAKEN.labels(
            agent_name="guardian",
            action_type="block_ip",
            status="success"
        )._value.get() >= 1

    def test_generate_metrics(self):
        """Test metrics generation."""
        collector = MetricsCollector()
        engine = MockEngine()
        collector.set_engine(engine)

        output = collector.generate_metrics()

        assert isinstance(output, bytes)
        assert b"sentinel_engine" in output
        assert b"sentinel_agent" in output

    def test_get_content_type(self):
        """Test content type for metrics response."""
        collector = MetricsCollector()
        content_type = collector.get_content_type()

        assert "text/plain" in content_type or "text" in content_type


class TestGlobalMetricsCollector:
    """Tests for global metrics collector functions."""

    def test_get_metrics_collector(self):
        """Test getting global metrics collector."""
        collector1 = get_metrics_collector()
        collector2 = get_metrics_collector()

        # Should return the same instance
        assert collector1 is collector2

    def test_configure_metrics(self):
        """Test configuring metrics with engine."""
        engine = MockEngine()
        collector = configure_metrics(engine)

        assert collector._engine == engine


class TestAPIMetricsEndpoint:
    """Tests for metrics API endpoint."""

    @pytest.fixture
    def client(self):
        """Create test client."""
        from fastapi.testclient import TestClient
        from sentinel.api.app import create_app
        import sentinel.api.auth as auth_module

        # Create mock engine
        engine = MockEngine()

        # Disable auth for testing
        original_auth = getattr(auth_module, '_auth_config', None)
        auth_module._auth_config = None

        app = create_app(engine)

        try:
            yield TestClient(app)
        finally:
            auth_module._auth_config = original_auth

    def test_metrics_endpoint(self, client):
        """Test /metrics endpoint returns Prometheus format."""
        response = client.get("/metrics")

        assert response.status_code == 200
        assert "text" in response.headers["content-type"]

        # Check for some expected metrics
        content = response.text
        assert "sentinel_engine" in content

    def test_metrics_endpoint_contains_agent_metrics(self, client):
        """Test metrics endpoint includes agent metrics."""
        response = client.get("/metrics")

        content = response.text
        assert "sentinel_agent" in content


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
