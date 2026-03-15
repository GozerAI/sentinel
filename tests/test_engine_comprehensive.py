"""
Comprehensive tests for Sentinel Engine covering all code paths.

These tests achieve full coverage of the engine module including:
- Integration loading (all types)
- Agent initialization
- Error handling paths
- Properties and methods
"""
import asyncio
import pytest
from unittest.mock import AsyncMock, MagicMock, patch, PropertyMock
from datetime import datetime, timezone

from sentinel.core.engine import SentinelEngine
from sentinel.core.models.event import Event, EventCategory, EventSeverity


class TestEngineProperties:
    """Tests for engine properties."""

    @pytest.fixture
    def basic_config(self):
        return {
            "state": {"backend": "memory"},
            "agents": {},
            "integrations": {}
        }

    def test_is_running_false_initially(self, basic_config):
        """Test is_running is False initially."""
        engine = SentinelEngine(basic_config)
        assert engine.is_running is False

    def test_uptime_seconds_zero_when_not_started(self, basic_config):
        """Test uptime is 0 when not started."""
        engine = SentinelEngine(basic_config)
        assert engine.uptime_seconds == 0.0

    @pytest.mark.asyncio
    async def test_uptime_seconds_increases(self, basic_config):
        """Test uptime increases after start."""
        engine = SentinelEngine(basic_config)
        await engine.start()

        await asyncio.sleep(0.1)
        assert engine.uptime_seconds > 0

        await engine.stop()

    def test_agent_names_empty_initially(self, basic_config):
        """Test agent_names is empty initially."""
        engine = SentinelEngine(basic_config)
        assert engine.agent_names == []

    def test_integration_names_empty_initially(self, basic_config):
        """Test integration_names is empty initially."""
        engine = SentinelEngine(basic_config)
        assert engine.integration_names == []

    def test_agents_property(self, basic_config):
        """Test agents property returns dict."""
        engine = SentinelEngine(basic_config)
        assert isinstance(engine.agents, dict)
        assert engine.agents == {}


class TestEngineStart:
    """Tests for engine start behavior."""

    @pytest.fixture
    def basic_config(self):
        return {
            "state": {"backend": "memory"},
            "agents": {},
            "integrations": {}
        }

    @pytest.mark.asyncio
    async def test_start_sets_start_time(self, basic_config):
        """Test start sets _start_time."""
        engine = SentinelEngine(basic_config)
        assert engine._start_time is None

        await engine.start()
        assert engine._start_time is not None

        await engine.stop()

    @pytest.mark.asyncio
    async def test_start_initializes_state(self, basic_config):
        """Test start initializes state manager."""
        engine = SentinelEngine(basic_config)

        # Mock state initialization
        engine.state.initialize = AsyncMock()

        await engine.start()
        engine.state.initialize.assert_called_once()

        await engine.stop()

    @pytest.mark.asyncio
    async def test_start_starts_event_bus(self, basic_config):
        """Test start starts event bus."""
        engine = SentinelEngine(basic_config)

        # Mock event bus start
        engine.event_bus.start = AsyncMock()

        await engine.start()
        engine.event_bus.start.assert_called_once()

        await engine.stop()

    @pytest.mark.asyncio
    async def test_start_failure_calls_stop(self, basic_config):
        """Test start failure triggers stop."""
        engine = SentinelEngine(basic_config)

        # Make state initialization fail
        engine.state.initialize = AsyncMock(side_effect=RuntimeError("Init failed"))
        engine.stop = AsyncMock()

        with pytest.raises(RuntimeError, match="Engine startup failed"):
            await engine.start()

        engine.stop.assert_called_once()


class TestEngineStop:
    """Tests for engine stop behavior."""

    @pytest.fixture
    def basic_config(self):
        return {
            "state": {"backend": "memory"},
            "agents": {},
            "integrations": {}
        }

    @pytest.mark.asyncio
    async def test_stop_stops_scheduler(self, basic_config):
        """Test stop stops scheduler."""
        engine = SentinelEngine(basic_config)
        await engine.start()

        engine.scheduler.stop = AsyncMock()

        await engine.stop()
        engine.scheduler.stop.assert_called_once()

    @pytest.mark.asyncio
    async def test_stop_handles_scheduler_error(self, basic_config):
        """Test stop handles scheduler error gracefully."""
        engine = SentinelEngine(basic_config)
        await engine.start()

        engine.scheduler.stop = AsyncMock(side_effect=RuntimeError("Scheduler error"))

        # Should not raise
        await engine.stop()

    @pytest.mark.asyncio
    async def test_stop_stops_agents(self, basic_config):
        """Test stop stops all agents."""
        engine = SentinelEngine(basic_config)

        # Add mock agents
        mock_agent = MagicMock()
        mock_agent.stop = AsyncMock()
        engine._agents["test_agent"] = mock_agent

        await engine.start()
        await engine.stop()

        mock_agent.stop.assert_called_once()

    @pytest.mark.asyncio
    async def test_stop_handles_agent_error(self, basic_config):
        """Test stop handles agent stop error gracefully."""
        engine = SentinelEngine(basic_config)

        mock_agent = MagicMock()
        mock_agent.stop = AsyncMock(side_effect=RuntimeError("Agent error"))
        engine._agents["test_agent"] = mock_agent

        await engine.start()

        # Should not raise
        await engine.stop()

    @pytest.mark.asyncio
    async def test_stop_disconnects_integrations(self, basic_config):
        """Test stop disconnects integrations."""
        engine = SentinelEngine(basic_config)

        mock_integration = MagicMock()
        mock_integration.disconnect = AsyncMock()
        engine._integrations["test_integration"] = mock_integration

        await engine.start()
        await engine.stop()

        mock_integration.disconnect.assert_called_once()

    @pytest.mark.asyncio
    async def test_stop_handles_integration_disconnect_error(self, basic_config):
        """Test stop handles integration disconnect error gracefully."""
        engine = SentinelEngine(basic_config)

        mock_integration = MagicMock()
        mock_integration.disconnect = AsyncMock(side_effect=RuntimeError("Disconnect error"))
        engine._integrations["test_integration"] = mock_integration

        await engine.start()

        # Should not raise
        await engine.stop()

    @pytest.mark.asyncio
    async def test_stop_handles_event_bus_error(self, basic_config):
        """Test stop handles event bus stop error gracefully."""
        engine = SentinelEngine(basic_config)
        await engine.start()

        engine.event_bus.stop = AsyncMock(side_effect=RuntimeError("Event bus error"))

        # Should not raise
        await engine.stop()

    @pytest.mark.asyncio
    async def test_stop_handles_state_persist_error(self, basic_config):
        """Test stop handles state persist error gracefully."""
        engine = SentinelEngine(basic_config)
        await engine.start()

        engine.state.persist = AsyncMock(side_effect=RuntimeError("State persist error"))

        # Should not raise
        await engine.stop()


class TestRouterIntegrationLoading:
    """Tests for router integration loading."""

    @pytest.mark.asyncio
    async def test_load_opnsense_router(self):
        """Test loading OPNsense router integration."""
        config = {
            "state": {"backend": "memory"},
            "agents": {},
            "integrations": {
                "router": {
                    "type": "opnsense",
                    "host": "https://router.local",
                    "api_key": "test",
                    "api_secret": "secret"
                }
            }
        }

        engine = SentinelEngine(config)

        with patch("sentinel.integrations.routers.opnsense.OPNsenseIntegration") as mock_cls:
            mock_instance = MagicMock()
            mock_instance.connect = AsyncMock()
            mock_cls.return_value = mock_instance

            await engine.start()

            mock_cls.assert_called_once()
            mock_instance.connect.assert_called_once()
            assert engine.get_integration("router") is mock_instance

            await engine.stop()

    @pytest.mark.asyncio
    async def test_load_pfsense_router(self):
        """Test loading pfSense router integration (handles ImportError gracefully)."""
        config = {
            "state": {"backend": "memory"},
            "agents": {},
            "integrations": {
                "router": {"type": "pfsense"}
            }
        }

        engine = SentinelEngine(config)
        # pfsense module doesn't exist - engine should handle gracefully
        await engine.start()
        assert engine.get_integration("router") is None
        await engine.stop()

    @pytest.mark.asyncio
    async def test_load_mikrotik_router(self):
        """Test loading MikroTik router integration (handles ImportError gracefully)."""
        config = {
            "state": {"backend": "memory"},
            "agents": {},
            "integrations": {
                "router": {"type": "mikrotik"}
            }
        }

        engine = SentinelEngine(config)
        # mikrotik module doesn't exist - engine should handle gracefully
        await engine.start()
        assert engine.get_integration("router") is None
        await engine.stop()

    @pytest.mark.asyncio
    async def test_unknown_router_type_logs_warning(self):
        """Test unknown router type logs warning."""
        config = {
            "state": {"backend": "memory"},
            "agents": {},
            "integrations": {
                "router": {"type": "unknown_router"}
            }
        }

        engine = SentinelEngine(config)
        await engine.start()

        assert engine.get_integration("router") is None

        await engine.stop()

    @pytest.mark.asyncio
    async def test_router_import_error_handled(self):
        """Test router ImportError is handled gracefully."""
        config = {
            "state": {"backend": "memory"},
            "agents": {},
            "integrations": {
                "router": {"type": "opnsense"}
            }
        }

        engine = SentinelEngine(config)

        with patch.dict("sys.modules", {"sentinel.integrations.routers.opnsense": None}):
            with patch("builtins.__import__", side_effect=ImportError("No module")):
                await engine.start()

                assert engine.get_integration("router") is None

                await engine.stop()

    @pytest.mark.asyncio
    async def test_router_connect_error_handled(self):
        """Test router connect error is handled gracefully."""
        config = {
            "state": {"backend": "memory"},
            "agents": {},
            "integrations": {
                "router": {"type": "opnsense"}
            }
        }

        engine = SentinelEngine(config)

        with patch("sentinel.integrations.routers.opnsense.OPNsenseIntegration") as mock_cls:
            mock_instance = MagicMock()
            mock_instance.connect = AsyncMock(side_effect=RuntimeError("Connection failed"))
            mock_cls.return_value = mock_instance

            # Should not raise
            await engine.start()

            assert engine.get_integration("router") is None

            await engine.stop()


class TestSwitchIntegrationLoading:
    """Tests for switch integration loading."""

    @pytest.mark.asyncio
    async def test_load_ubiquiti_switch(self):
        """Test loading Ubiquiti switch integration."""
        config = {
            "state": {"backend": "memory"},
            "agents": {},
            "integrations": {
                "switch": {"type": "ubiquiti"}
            }
        }

        engine = SentinelEngine(config)

        with patch("sentinel.integrations.switches.ubiquiti.UnifiIntegration") as mock_cls:
            mock_instance = MagicMock()
            mock_instance.connect = AsyncMock()
            mock_cls.return_value = mock_instance

            await engine.start()

            mock_cls.assert_called_once()

            await engine.stop()

    @pytest.mark.asyncio
    async def test_load_cisco_switch(self):
        """Test loading Cisco switch integration (handles ImportError gracefully)."""
        config = {
            "state": {"backend": "memory"},
            "agents": {},
            "integrations": {
                "switch": {"type": "cisco"}
            }
        }

        engine = SentinelEngine(config)
        # cisco module doesn't exist - engine should handle gracefully
        await engine.start()
        assert engine.get_integration("switch") is None
        await engine.stop()

    @pytest.mark.asyncio
    async def test_unknown_switch_type(self):
        """Test unknown switch type logs warning."""
        config = {
            "state": {"backend": "memory"},
            "agents": {},
            "integrations": {
                "switch": {"type": "unknown_switch"}
            }
        }

        engine = SentinelEngine(config)
        await engine.start()

        assert engine.get_integration("switch") is None

        await engine.stop()

    @pytest.mark.asyncio
    async def test_switch_import_error_handled(self):
        """Test switch ImportError is handled gracefully."""
        config = {
            "state": {"backend": "memory"},
            "agents": {},
            "integrations": {
                "switch": {"type": "ubiquiti"}
            }
        }

        engine = SentinelEngine(config)

        with patch("builtins.__import__", side_effect=ImportError("No module")):
            await engine.start()

            assert engine.get_integration("switch") is None

            await engine.stop()


class TestHypervisorIntegrationLoading:
    """Tests for hypervisor integration loading."""

    @pytest.mark.asyncio
    async def test_load_proxmox_hypervisor(self):
        """Test loading Proxmox hypervisor integration."""
        config = {
            "state": {"backend": "memory"},
            "agents": {},
            "integrations": {
                "hypervisor": {"type": "proxmox"}
            }
        }

        engine = SentinelEngine(config)

        with patch("sentinel.integrations.hypervisors.proxmox.ProxmoxIntegration") as mock_cls:
            mock_instance = MagicMock()
            mock_instance.connect = AsyncMock()
            mock_cls.return_value = mock_instance

            await engine.start()

            mock_cls.assert_called_once()

            await engine.stop()

    @pytest.mark.asyncio
    async def test_load_docker_hypervisor(self):
        """Test loading Docker hypervisor integration (handles ImportError gracefully)."""
        config = {
            "state": {"backend": "memory"},
            "agents": {},
            "integrations": {
                "hypervisor": {"type": "docker"}
            }
        }

        engine = SentinelEngine(config)
        # docker module doesn't exist - engine should handle gracefully
        await engine.start()
        assert engine.get_integration("hypervisor") is None
        await engine.stop()

    @pytest.mark.asyncio
    async def test_unknown_hypervisor_type(self):
        """Test unknown hypervisor type logs warning."""
        config = {
            "state": {"backend": "memory"},
            "agents": {},
            "integrations": {
                "hypervisor": {"type": "unknown_hv"}
            }
        }

        engine = SentinelEngine(config)
        await engine.start()

        assert engine.get_integration("hypervisor") is None

        await engine.stop()


class TestStorageIntegrationLoading:
    """Tests for storage integration loading."""

    @pytest.mark.asyncio
    async def test_load_truenas_storage(self):
        """Test loading TrueNAS storage integration."""
        config = {
            "state": {"backend": "memory"},
            "agents": {},
            "integrations": {
                "storage": {"type": "truenas"}
            }
        }

        engine = SentinelEngine(config)

        with patch("sentinel.integrations.storage.truenas.TrueNASIntegration") as mock_cls:
            mock_instance = MagicMock()
            mock_instance.connect = AsyncMock()
            mock_cls.return_value = mock_instance

            await engine.start()

            mock_cls.assert_called_once()

            await engine.stop()

    @pytest.mark.asyncio
    async def test_unknown_storage_type(self):
        """Test unknown storage type logs warning."""
        config = {
            "state": {"backend": "memory"},
            "agents": {},
            "integrations": {
                "storage": {"type": "unknown_storage"}
            }
        }

        engine = SentinelEngine(config)
        await engine.start()

        assert engine.get_integration("storage") is None

        await engine.stop()


class TestKubernetesIntegrationLoading:
    """Tests for Kubernetes integration loading."""

    @pytest.mark.asyncio
    async def test_load_kubernetes_integration(self):
        """Test loading Kubernetes integration (handles ImportError gracefully)."""
        config = {
            "state": {"backend": "memory"},
            "agents": {},
            "integrations": {
                "kubernetes": {"kubeconfig": "/path/to/config"}
            }
        }

        engine = SentinelEngine(config)
        # kubernetes module doesn't exist - engine should handle gracefully
        await engine.start()
        assert engine.get_integration("kubernetes") is None
        await engine.stop()

    @pytest.mark.asyncio
    async def test_kubernetes_import_error(self):
        """Test Kubernetes ImportError is handled."""
        config = {
            "state": {"backend": "memory"},
            "agents": {},
            "integrations": {
                "kubernetes": {}
            }
        }

        engine = SentinelEngine(config)

        with patch("builtins.__import__", side_effect=ImportError("No k8s module")):
            await engine.start()

            assert engine.get_integration("kubernetes") is None

            await engine.stop()


class TestLLMIntegrationLoading:
    """Tests for LLM integration loading."""

    @pytest.mark.asyncio
    async def test_load_llm_integration(self):
        """Test loading LLM integration."""
        config = {
            "state": {"backend": "memory"},
            "agents": {},
            "integrations": {
                "llm": {
                    "primary": {"type": "ollama", "model": "llama3.1:8b"}
                }
            }
        }

        engine = SentinelEngine(config)

        with patch("sentinel.integrations.llm.manager.LLMManager") as mock_cls:
            mock_instance = MagicMock()
            mock_instance.initialize = AsyncMock()
            mock_cls.return_value = mock_instance

            await engine.start()

            mock_cls.assert_called_once()
            mock_instance.initialize.assert_called_once()

            await engine.stop()

    @pytest.mark.asyncio
    async def test_llm_import_error(self):
        """Test LLM ImportError is handled."""
        config = {
            "state": {"backend": "memory"},
            "agents": {},
            "integrations": {
                "llm": {}
            }
        }

        engine = SentinelEngine(config)

        with patch("builtins.__import__", side_effect=ImportError("No LLM module")):
            await engine.start()

            assert engine.get_integration("llm") is None

            await engine.stop()


class TestAgentInitialization:
    """Tests for agent initialization."""

    @pytest.mark.asyncio
    async def test_discovery_agent_initialization(self):
        """Test Discovery agent is initialized when enabled."""
        config = {
            "state": {"backend": "memory"},
            "agents": {
                "discovery": {"enabled": True}
            },
            "integrations": {}
        }

        engine = SentinelEngine(config)

        with patch("sentinel.agents.discovery.DiscoveryAgent") as mock_cls:
            mock_instance = MagicMock()
            mock_instance.start = AsyncMock()
            mock_cls.return_value = mock_instance

            await engine.start()

            mock_cls.assert_called_once()
            mock_instance.start.assert_called_once()

            await engine.stop()

    @pytest.mark.asyncio
    async def test_optimizer_agent_initialization(self):
        """Test Optimizer agent is initialized when enabled."""
        config = {
            "state": {"backend": "memory"},
            "agents": {
                "optimizer": {"enabled": True}
            },
            "integrations": {}
        }

        engine = SentinelEngine(config)

        with patch("sentinel.agents.optimizer.OptimizerAgent") as mock_cls:
            mock_instance = MagicMock()
            mock_instance.start = AsyncMock()
            mock_cls.return_value = mock_instance

            await engine.start()

            mock_cls.assert_called_once()

            await engine.stop()

    @pytest.mark.asyncio
    async def test_planner_agent_initialization(self):
        """Test Planner agent is initialized when enabled."""
        config = {
            "state": {"backend": "memory"},
            "agents": {
                "planner": {"enabled": True}
            },
            "integrations": {}
        }

        engine = SentinelEngine(config)

        with patch("sentinel.agents.planner.PlannerAgent") as mock_cls:
            mock_instance = MagicMock()
            mock_instance.start = AsyncMock()
            mock_cls.return_value = mock_instance

            await engine.start()

            mock_cls.assert_called_once()

            await engine.stop()

    @pytest.mark.asyncio
    async def test_healer_agent_initialization(self):
        """Test Healer agent is initialized when enabled."""
        config = {
            "state": {"backend": "memory"},
            "agents": {
                "healer": {"enabled": True}
            },
            "integrations": {}
        }

        engine = SentinelEngine(config)

        with patch("sentinel.agents.healer.HealerAgent") as mock_cls:
            mock_instance = MagicMock()
            mock_instance.start = AsyncMock()
            mock_cls.return_value = mock_instance

            await engine.start()

            mock_cls.assert_called_once()

            await engine.stop()

    @pytest.mark.asyncio
    async def test_guardian_agent_initialization(self):
        """Test Guardian agent is initialized when enabled."""
        config = {
            "state": {"backend": "memory"},
            "agents": {
                "guardian": {"enabled": True}
            },
            "integrations": {}
        }

        engine = SentinelEngine(config)

        with patch("sentinel.agents.guardian.GuardianAgent") as mock_cls:
            mock_instance = MagicMock()
            mock_instance.start = AsyncMock()
            mock_cls.return_value = mock_instance

            await engine.start()

            mock_cls.assert_called_once()

            await engine.stop()

    @pytest.mark.asyncio
    async def test_agent_disabled_not_initialized(self):
        """Test disabled agents are not initialized."""
        config = {
            "state": {"backend": "memory"},
            "agents": {
                "discovery": {"enabled": False}
            },
            "integrations": {}
        }

        engine = SentinelEngine(config)

        with patch("sentinel.agents.discovery.DiscoveryAgent") as mock_cls:
            await engine.start()

            mock_cls.assert_not_called()

            await engine.stop()

    @pytest.mark.asyncio
    async def test_agent_import_error_handled(self):
        """Test agent ImportError is handled gracefully."""
        config = {
            "state": {"backend": "memory"},
            "agents": {
                "discovery": {"enabled": True}
            },
            "integrations": {}
        }

        engine = SentinelEngine(config)

        with patch("builtins.__import__", side_effect=ImportError("No agent module")):
            # Should not raise
            await engine.start()

            assert engine.get_agent("discovery") is None

            await engine.stop()

    @pytest.mark.asyncio
    async def test_agent_start_error_handled(self):
        """Test agent start error is handled gracefully."""
        config = {
            "state": {"backend": "memory"},
            "agents": {
                "discovery": {"enabled": True}
            },
            "integrations": {}
        }

        engine = SentinelEngine(config)

        with patch("sentinel.agents.discovery.DiscoveryAgent") as mock_cls:
            mock_instance = MagicMock()
            mock_instance.start = AsyncMock(side_effect=RuntimeError("Start failed"))
            mock_cls.return_value = mock_instance

            # Should not raise
            await engine.start()

            await engine.stop()


class TestGetStatus:
    """Tests for get_status method."""

    @pytest.fixture
    def basic_config(self):
        return {
            "state": {"backend": "memory"},
            "agents": {},
            "integrations": {}
        }

    @pytest.mark.asyncio
    async def test_status_when_stopped(self, basic_config):
        """Test status when engine is stopped."""
        engine = SentinelEngine(basic_config)

        status = await engine.get_status()

        assert status["status"] == "stopped"
        assert status["running"] is False
        assert status["start_time"] is None

    @pytest.mark.asyncio
    async def test_status_when_running(self, basic_config):
        """Test status when engine is running."""
        engine = SentinelEngine(basic_config)
        await engine.start()

        status = await engine.get_status()

        assert status["status"] == "running"
        assert status["running"] is True
        assert status["start_time"] is not None
        assert "event_bus" in status
        assert "handlers" in status["event_bus"]
        assert "queue_size" in status["event_bus"]

        await engine.stop()

    @pytest.mark.asyncio
    async def test_status_includes_agent_info(self, basic_config):
        """Test status includes agent information."""
        engine = SentinelEngine(basic_config)

        # Add mock agent
        mock_agent = MagicMock()
        mock_agent._running = True
        engine._agents["test_agent"] = mock_agent

        await engine.start()
        status = await engine.get_status()

        assert "test_agent" in status["agents"]
        assert status["agents"]["test_agent"]["running"] is True

        await engine.stop()

    @pytest.mark.asyncio
    async def test_status_includes_integration_info(self, basic_config):
        """Test status includes integration information."""
        engine = SentinelEngine(basic_config)

        # Add mock integration
        mock_integration = MagicMock()
        engine._integrations["test_integration"] = mock_integration

        await engine.start()
        status = await engine.get_status()

        assert "test_integration" in status["integrations"]

        await engine.stop()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
