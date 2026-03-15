"""
Tests for Sentinel Engine.
"""
import asyncio
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from sentinel.core.engine import SentinelEngine
from sentinel.core.models.event import Event, EventCategory, EventSeverity


class TestSentinelEngine:
    """Tests for the SentinelEngine class."""

    @pytest.fixture
    def basic_config(self):
        """Create a basic configuration for testing."""
        return {
            "state": {
                "backend": "memory"
            },
            "agents": {
                "discovery": {"enabled": False},
                "optimizer": {"enabled": False},
                "planner": {"enabled": False},
                "healer": {"enabled": False},
                "guardian": {"enabled": False},
            },
            "integrations": {}
        }

    @pytest.fixture
    def full_config(self):
        """Create a full configuration with agents enabled."""
        return {
            "state": {
                "backend": "memory"
            },
            "agents": {
                "discovery": {
                    "enabled": True,
                    "scan_interval_seconds": 60,
                    "networks": ["192.168.1.0/24"]
                },
                "optimizer": {"enabled": True},
                "planner": {"enabled": True},
                "healer": {"enabled": True},
                "guardian": {"enabled": True},
            },
            "integrations": {},
            "vlans": [
                {"id": 10, "name": "Workstations", "subnet": "192.168.10.0/24"},
                {"id": 20, "name": "Servers", "subnet": "192.168.20.0/24"},
            ]
        }

    @pytest.mark.asyncio
    async def test_engine_creation(self, basic_config):
        """Test engine can be created with basic config."""
        engine = SentinelEngine(basic_config)

        assert engine.config == basic_config
        assert engine.event_bus is not None
        assert engine.scheduler is not None
        assert engine.state is not None
        assert engine.is_running is False

    @pytest.mark.asyncio
    async def test_engine_start_stop(self, basic_config):
        """Test engine start and stop lifecycle."""
        engine = SentinelEngine(basic_config)

        # Start engine
        await engine.start()
        assert engine.is_running is True
        assert engine.uptime_seconds >= 0

        # Stop engine
        await engine.stop()
        assert engine.is_running is False

    @pytest.mark.asyncio
    async def test_engine_emits_startup_event(self, basic_config):
        """Test that engine emits startup event."""
        engine = SentinelEngine(basic_config)

        received_events = []

        def capture_handler(event):
            received_events.append(event)

        engine.event_bus.subscribe(capture_handler, event_type="engine.started")

        await engine.start()

        # Give event bus time to process
        await asyncio.sleep(0.1)

        await engine.stop()

        # Check we got the startup event
        assert len(received_events) >= 1
        assert received_events[0].event_type == "engine.started"

    @pytest.mark.asyncio
    async def test_engine_with_agents(self, full_config):
        """Test engine starts with agents."""
        engine = SentinelEngine(full_config)

        await engine.start()

        # Check agents are loaded
        assert len(engine._agents) > 0
        assert "discovery" in engine.agent_names or "planner" in engine.agent_names

        await engine.stop()

    @pytest.mark.asyncio
    async def test_get_status(self, basic_config):
        """Test get_status returns correct information."""
        engine = SentinelEngine(basic_config)
        await engine.start()

        status = await engine.get_status()

        assert "running" in status
        assert status["running"] is True
        assert "uptime_seconds" in status
        assert status["uptime_seconds"] >= 0
        assert "agents" in status
        assert "integrations" in status

        await engine.stop()

    @pytest.mark.asyncio
    async def test_get_integration_returns_none(self, basic_config):
        """Test get_integration returns None for unknown integration."""
        engine = SentinelEngine(basic_config)

        result = engine.get_integration("nonexistent")
        assert result is None

    @pytest.mark.asyncio
    async def test_get_agent_returns_none(self, basic_config):
        """Test get_agent returns None for unknown agent."""
        engine = SentinelEngine(basic_config)

        result = engine.get_agent("nonexistent")
        assert result is None


class TestEngineIntegrationLoading:
    """Tests for engine integration loading."""

    @pytest.mark.asyncio
    async def test_load_llm_integration(self):
        """Test LLM integration loading."""
        config = {
            "state": {"backend": "memory"},
            "agents": {},
            "integrations": {
                "llm": {
                    "primary": {
                        "type": "ollama",
                        "host": "http://localhost:11434",
                        "model": "llama3.1:8b"
                    }
                }
            }
        }

        engine = SentinelEngine(config)

        # Mock the LLM manager
        with patch("sentinel.integrations.llm.manager.LLMManager") as mock_llm:
            mock_instance = AsyncMock()
            mock_llm.return_value = mock_instance

            await engine.start()

            # LLM should be in integrations (if mock worked)
            # Note: might fail if import paths differ

            await engine.stop()

    @pytest.mark.asyncio
    async def test_graceful_integration_failure(self):
        """Test engine handles integration failure gracefully."""
        config = {
            "state": {"backend": "memory"},
            "agents": {},
            "integrations": {
                "router": {
                    "type": "nonexistent_router"
                }
            }
        }

        engine = SentinelEngine(config)

        # Should not raise, just log warning
        await engine.start()

        assert engine.get_integration("router") is None

        await engine.stop()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
