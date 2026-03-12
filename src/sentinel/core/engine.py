"""
Sentinel Core Engine - Main orchestration component.

This module contains the central orchestration engine for the Sentinel platform.
It coordinates all subsystems, manages agents, and provides unified state access.

The engine now includes CTO-level capabilities:
- Agent Factory for dynamic agent creation
- Strategy Agent for high-level decision making
- Learning System for outcome-based improvement
- Agent Registry for inter-agent communication
"""

import asyncio
import logging
from datetime import datetime
from typing import Optional, TYPE_CHECKING

from sentinel.core.utils import utc_now
from sentinel.core.event_bus import EventBus
from sentinel.core.scheduler import Scheduler
from sentinel.core.state import StateManager
from sentinel.core.models.event import Event, EventCategory, EventSeverity

if TYPE_CHECKING:
    from sentinel.agents.base import BaseAgent
    from sentinel.agents.factory import AgentFactory
    from sentinel.agents.registry import AgentRegistry
    from sentinel.agents.strategy import StrategyAgent
    from sentinel.core.learning import LearningSystem
    from sentinel.integrations.base import BaseIntegration

logger = logging.getLogger(__name__)


class SentinelEngine:
    """
    Central orchestration engine for the Sentinel platform.

    The SentinelEngine is the heart of the Sentinel platform. It:
    - Initializes and coordinates all subsystems
    - Manages the AI agent council
    - Handles event routing via the event bus
    - Provides unified state access
    - Manages integrations with external systems

    Attributes:
        config: Configuration dictionary
        event_bus: Central event bus for inter-component communication
        scheduler: Task scheduler for periodic operations
        state: Global state manager

    Example:
        ```python
        config = load_config("config/homelab.yaml")
        engine = SentinelEngine(config)
        await engine.start()

        # Engine is now running all agents
        # ...

        await engine.stop()
        ```
    """

    def __init__(self, config: dict):
        """
        Initialize the Sentinel engine.

        Args:
            config: Configuration dictionary containing all settings
        """
        self.config = config
        self.event_bus = EventBus()
        self.scheduler = Scheduler()
        self.state = StateManager(config.get("state", {}))

        self._agents: dict[str, "BaseAgent"] = {}
        self._integrations: dict[str, "BaseIntegration"] = {}

        self._running = False
        self._start_time: Optional[datetime] = None

        # CTO Architecture components (initialized during start)
        self.agent_factory: Optional["AgentFactory"] = None
        self.agent_registry: Optional["AgentRegistry"] = None
        self.learning_system: Optional["LearningSystem"] = None
        self.strategy_agent: Optional["StrategyAgent"] = None

        # CTO mode configuration
        self._cto_mode = config.get("cto_mode", {}).get("enabled", True)

    async def start(self) -> None:
        """
        Start the Sentinel engine and all subsystems.

        This method:
        1. Initializes the state manager
        2. Starts the event bus
        3. Loads and connects integrations
        4. Initializes and starts all enabled agents
        5. Starts the scheduler

        Raises:
            RuntimeError: If engine fails to start
        """
        logger.info("Starting Sentinel Engine...")

        self._start_time = utc_now()
        self._running = True

        try:
            # Initialize state
            await self.state.initialize()
            logger.debug("State manager initialized")

            # Start event bus
            await self.event_bus.start()
            logger.debug("Event bus started")

            # Load integrations
            await self._load_integrations()

            # Initialize CTO components if enabled
            if self._cto_mode:
                await self._initialize_cto_components()

            # Initialize agents
            await self._initialize_agents()

            # Start Strategy Agent if CTO mode enabled
            if self._cto_mode and self.strategy_agent:
                await self.strategy_agent.start()
                logger.info("Strategy Agent started - CTO mode active")

            # Start scheduler
            await self.scheduler.start()
            logger.debug("Scheduler started")

            # Emit startup event
            await self.event_bus.publish(
                Event(
                    category=EventCategory.SYSTEM,
                    event_type="engine.started",
                    severity=EventSeverity.INFO,
                    source="sentinel.engine",
                    title="Sentinel Engine Started",
                    description=f"Engine started with {len(self._agents)} agents and {len(self._integrations)} integrations (CTO mode: {self._cto_mode})",
                )
            )

            logger.info(
                f"Sentinel Engine started successfully - "
                f"{len(self._agents)} agents, {len(self._integrations)} integrations"
                f"{' (CTO mode active)' if self._cto_mode else ''}"
            )

        except Exception as e:
            logger.error(f"Failed to start Sentinel Engine: {e}")
            await self.stop()
            raise RuntimeError(f"Engine startup failed: {e}")

    async def stop(self) -> None:
        """
        Gracefully stop the engine and all subsystems.

        This method ensures clean shutdown by:
        1. Stopping the scheduler
        2. Stopping all agents
        3. Disconnecting integrations
        4. Stopping the event bus
        5. Persisting state
        """
        logger.info("Stopping Sentinel Engine...")

        self._running = False

        # Stop Strategy Agent first
        if self.strategy_agent:
            try:
                await self.strategy_agent.stop()
                logger.debug("Strategy Agent stopped")
            except Exception as e:
                logger.error(f"Error stopping Strategy Agent: {e}")

        # Stop scheduler
        try:
            await self.scheduler.stop()
        except Exception as e:
            logger.error(f"Error stopping scheduler: {e}")

        # Stop agents
        for name, agent in self._agents.items():
            try:
                await agent.stop()
                logger.debug(f"Agent '{name}' stopped")
            except Exception as e:
                logger.error(f"Error stopping agent '{name}': {e}")

        # Stop CTO components
        await self._stop_cto_components()

        # Disconnect integrations
        for name, integration in self._integrations.items():
            try:
                await integration.disconnect()
                logger.debug(f"Integration '{name}' disconnected")
            except Exception as e:
                logger.error(f"Error disconnecting integration '{name}': {e}")

        # Stop event bus
        try:
            await self.event_bus.stop()
        except Exception as e:
            logger.error(f"Error stopping event bus: {e}")

        # Persist state
        try:
            await self.state.persist()
        except Exception as e:
            logger.error(f"Error persisting state: {e}")

        logger.info("Sentinel Engine stopped")

    async def _initialize_cto_components(self) -> None:
        """Initialize CTO architecture components."""
        logger.info("Initializing CTO architecture components...")

        try:
            # Initialize Agent Registry
            from sentinel.agents.registry import AgentRegistry

            self.agent_registry = AgentRegistry(self)
            await self.agent_registry.start()
            logger.debug("Agent Registry initialized")

            # Initialize Agent Factory
            from sentinel.agents.factory import AgentFactory

            self.agent_factory = AgentFactory(self)
            logger.debug("Agent Factory initialized")

            # Initialize Learning System
            from sentinel.core.learning import LearningSystem

            learning_config = self.config.get("learning", {})
            self.learning_system = LearningSystem(self, learning_config)
            await self.learning_system.start()
            logger.debug("Learning System initialized")

            # Initialize Strategy Agent
            from sentinel.agents.strategy import StrategyAgent

            strategy_config = self.config.get("strategy", {})
            self.strategy_agent = StrategyAgent(self, strategy_config)
            logger.debug("Strategy Agent initialized")

            logger.info("CTO architecture components initialized successfully")

        except Exception as e:
            logger.error(f"Failed to initialize CTO components: {e}")
            # CTO components are optional, don't fail startup
            self._cto_mode = False

    async def _stop_cto_components(self) -> None:
        """Stop CTO architecture components."""
        if self.learning_system:
            try:
                await self.learning_system.stop()
                logger.debug("Learning System stopped")
            except Exception as e:
                logger.error(f"Error stopping Learning System: {e}")

        if self.agent_registry:
            try:
                await self.agent_registry.stop()
                logger.debug("Agent Registry stopped")
            except Exception as e:
                logger.error(f"Error stopping Agent Registry: {e}")

    async def _load_integrations(self) -> None:
        """Load and connect configured integrations."""
        integration_config = self.config.get("integrations", {})

        # Router integration
        if "router" in integration_config:
            await self._load_router_integration(integration_config["router"])

        # Switch integration
        if "switch" in integration_config:
            await self._load_switch_integration(integration_config["switch"])

        # Hypervisor integration
        if "hypervisor" in integration_config:
            await self._load_hypervisor_integration(integration_config["hypervisor"])

        # Storage integration
        if "storage" in integration_config:
            await self._load_storage_integration(integration_config["storage"])

        # Kubernetes integration
        if "kubernetes" in integration_config:
            await self._load_kubernetes_integration(integration_config["kubernetes"])

        # LLM integration
        if "llm" in integration_config:
            await self._load_llm_integration(integration_config["llm"])

    async def _load_router_integration(self, config: dict) -> None:
        """Load router integration based on type."""
        router_type = config.get("type", "").lower()

        try:
            if router_type == "opnsense":
                from sentinel.integrations.routers.opnsense import OPNsenseIntegration

                integration = OPNsenseIntegration(config)
            elif router_type == "pfsense":
                from sentinel.integrations.routers.pfsense import PfsenseIntegration

                integration = PfsenseIntegration(config)
            elif router_type == "mikrotik":
                from sentinel.integrations.routers.mikrotik import MikroTikIntegration

                integration = MikroTikIntegration(config)
            else:
                logger.warning(f"Unknown router type: {router_type}")
                return

            await integration.connect()
            self._integrations["router"] = integration
            logger.info(f"Router integration '{router_type}' connected")

        except ImportError as e:
            logger.warning(f"Router integration '{router_type}' not available: {e}")
        except Exception as e:
            logger.error(f"Failed to connect router integration: {e}")

    async def _load_switch_integration(self, config: dict) -> None:
        """Load switch integration based on type."""
        switch_type = config.get("type", "").lower()

        try:
            if switch_type == "ubiquiti":
                from sentinel.integrations.switches.ubiquiti import UnifiIntegration

                integration = UnifiIntegration(config)
            elif switch_type == "cisco":
                from sentinel.integrations.switches.cisco import CiscoIntegration

                integration = CiscoIntegration(config)
            else:
                logger.warning(f"Unknown switch type: {switch_type}")
                return

            await integration.connect()
            self._integrations["switch"] = integration
            logger.info(f"Switch integration '{switch_type}' connected")

        except ImportError as e:
            logger.warning(f"Switch integration '{switch_type}' not available: {e}")
        except Exception as e:
            logger.error(f"Failed to connect switch integration: {e}")

    async def _load_hypervisor_integration(self, config: dict) -> None:
        """Load hypervisor integration based on type."""
        hv_type = config.get("type", "").lower()

        try:
            if hv_type == "proxmox":
                from sentinel.integrations.hypervisors.proxmox import ProxmoxIntegration

                integration = ProxmoxIntegration(config)
            elif hv_type == "docker":
                from sentinel.integrations.hypervisors.docker import DockerIntegration

                integration = DockerIntegration(config)
            else:
                logger.warning(f"Unknown hypervisor type: {hv_type}")
                return

            await integration.connect()
            self._integrations["hypervisor"] = integration
            logger.info(f"Hypervisor integration '{hv_type}' connected")

        except ImportError as e:
            logger.warning(f"Hypervisor integration '{hv_type}' not available: {e}")
        except Exception as e:
            logger.error(f"Failed to connect hypervisor integration: {e}")

    async def _load_storage_integration(self, config: dict) -> None:
        """Load storage integration based on type."""
        storage_type = config.get("type", "").lower()

        try:
            if storage_type == "truenas":
                from sentinel.integrations.storage.truenas import TrueNASIntegration

                integration = TrueNASIntegration(config)
            else:
                logger.warning(f"Unknown storage type: {storage_type}")
                return

            await integration.connect()
            self._integrations["storage"] = integration
            logger.info(f"Storage integration '{storage_type}' connected")

        except ImportError as e:
            logger.warning(f"Storage integration '{storage_type}' not available: {e}")
        except Exception as e:
            logger.error(f"Failed to connect storage integration: {e}")

    async def _load_kubernetes_integration(self, config: dict) -> None:
        """Load Kubernetes integration."""
        try:
            from sentinel.integrations.kubernetes.k3s import K3sIntegration

            integration = K3sIntegration(config)
            await integration.connect()
            self._integrations["kubernetes"] = integration
            logger.info("Kubernetes integration connected")

        except ImportError as e:
            logger.warning(f"Kubernetes integration not available: {e}")
        except Exception as e:
            logger.error(f"Failed to connect Kubernetes integration: {e}")

    async def _load_llm_integration(self, config: dict) -> None:
        """Load LLM integration with primary and fallback."""
        try:
            from sentinel.integrations.llm.manager import LLMManager

            integration = LLMManager(config)
            await integration.initialize()
            self._integrations["llm"] = integration
            logger.info("LLM integration initialized")

        except ImportError as e:
            logger.warning(f"LLM integration not available: {e}")
        except Exception as e:
            logger.error(f"Failed to initialize LLM integration: {e}")

    async def _initialize_agents(self) -> None:
        """Initialize AI agents based on configuration."""
        agent_config = self.config.get("agents", {})

        # Discovery Agent
        if agent_config.get("discovery", {}).get("enabled", True):
            try:
                from sentinel.agents.discovery import DiscoveryAgent

                self._agents["discovery"] = DiscoveryAgent(
                    engine=self, config=agent_config.get("discovery", {})
                )
            except ImportError as e:
                logger.warning(f"Discovery agent not available: {e}")

        # Optimizer Agent
        if agent_config.get("optimizer", {}).get("enabled", True):
            try:
                from sentinel.agents.optimizer import OptimizerAgent

                self._agents["optimizer"] = OptimizerAgent(
                    engine=self, config=agent_config.get("optimizer", {})
                )
            except ImportError as e:
                logger.warning(f"Optimizer agent not available: {e}")

        # Planner Agent
        if agent_config.get("planner", {}).get("enabled", True):
            try:
                from sentinel.agents.planner import PlannerAgent

                self._agents["planner"] = PlannerAgent(
                    engine=self, config=agent_config.get("planner", {})
                )
            except ImportError as e:
                logger.warning(f"Planner agent not available: {e}")

        # Healer Agent
        if agent_config.get("healer", {}).get("enabled", True):
            try:
                from sentinel.agents.healer import HealerAgent

                self._agents["healer"] = HealerAgent(
                    engine=self, config=agent_config.get("healer", {})
                )
            except ImportError as e:
                logger.warning(f"Healer agent not available: {e}")

        # Guardian Agent
        if agent_config.get("guardian", {}).get("enabled", True):
            try:
                from sentinel.agents.guardian import GuardianAgent

                self._agents["guardian"] = GuardianAgent(
                    engine=self, config=agent_config.get("guardian", {})
                )
            except ImportError as e:
                logger.warning(f"Guardian agent not available: {e}")

        # Start all agents and register with registry
        for name, agent in self._agents.items():
            try:
                await agent.start()

                # Register with agent registry if available
                if self.agent_registry:
                    await self.agent_registry.register(agent)

                logger.info(f"Agent '{name}' started")
            except Exception as e:
                logger.error(f"Failed to start agent '{name}': {e}")

    def get_integration(self, name: str) -> Optional["BaseIntegration"]:
        """
        Get an integration by name.

        Args:
            name: Integration name (router, switch, llm, etc.)

        Returns:
            Integration instance or None if not found
        """
        return self._integrations.get(name)

    def get_agent(self, name: str) -> Optional["BaseAgent"]:
        """
        Get an agent by name.

        Args:
            name: Agent name (discovery, optimizer, planner, etc.)

        Returns:
            Agent instance or None if not found
        """
        return self._agents.get(name)

    @property
    def is_running(self) -> bool:
        """Check if engine is running."""
        return self._running

    @property
    def uptime_seconds(self) -> float:
        """Get engine uptime in seconds."""
        if self._start_time:
            return (utc_now() - self._start_time).total_seconds()
        return 0.0

    @property
    def agents(self) -> dict[str, "BaseAgent"]:
        """Get dictionary of active agents."""
        return self._agents

    @property
    def agent_names(self) -> list[str]:
        """Get list of active agent names."""
        return list(self._agents.keys())

    @property
    def integration_names(self) -> list[str]:
        """Get list of active integration names."""
        return list(self._integrations.keys())

    async def get_status(self) -> dict:
        """
        Get comprehensive engine status.

        Returns:
            Dictionary with engine status information
        """
        status = {
            "status": "running" if self._running else "stopped",
            "running": self._running,
            "uptime_seconds": self.uptime_seconds,
            "start_time": self._start_time.isoformat() if self._start_time else None,
            "cto_mode": self._cto_mode,
            "agents": {name: {"running": agent._running} for name, agent in self._agents.items()},
            "integrations": {
                name: True for name in self._integrations.keys()  # Would check actual status
            },
            "event_bus": {
                "handlers": len(self.event_bus._global_handlers),
                "queue_size": self.event_bus._queue.qsize(),
            },
        }

        # Add CTO component status
        if self._cto_mode:
            status["cto_components"] = {
                "agent_factory": self.agent_factory.stats if self.agent_factory else None,
                "agent_registry": self.agent_registry.stats if self.agent_registry else None,
                "learning_system": self.learning_system.stats if self.learning_system else None,
                "strategy_agent": self.strategy_agent.stats if self.strategy_agent else None,
            }

        return status

    # =========================================================================
    # CTO Interface Methods
    # =========================================================================

    async def spawn_agent(self, template_name: str, config: dict = None) -> Optional[str]:
        """
        Spawn a new agent dynamically.

        Args:
            template_name: Name of agent template to use
            config: Optional configuration overrides

        Returns:
            Agent instance ID if successful, None otherwise
        """
        if not self.agent_factory:
            logger.warning("Agent Factory not available - CTO mode may be disabled")
            return None

        try:
            instance = await self.agent_factory.create_agent(
                template_name=template_name, config=config, auto_start=True
            )
            return str(instance.id)
        except Exception as e:
            logger.error(f"Failed to spawn agent: {e}")
            return None

    async def retire_agent(self, agent_id: str, reason: str = "") -> bool:
        """
        Retire a dynamically spawned agent.

        Args:
            agent_id: ID of agent to retire
            reason: Reason for retirement

        Returns:
            True if successfully retired
        """
        if not self.agent_factory:
            logger.warning("Agent Factory not available")
            return False

        from uuid import UUID

        try:
            return await self.agent_factory.retire_agent(UUID(agent_id), reason)
        except Exception as e:
            logger.error(f"Failed to retire agent: {e}")
            return False

    async def ask_strategy(self, query: str) -> str:
        """
        Ask the Strategy Agent for analysis.

        Args:
            query: Strategic question to analyze

        Returns:
            Strategy Agent's analysis response
        """
        if not self.strategy_agent:
            return "Strategy Agent not available - CTO mode may be disabled"

        try:
            return await self.strategy_agent.request_agent_analysis(query)
        except Exception as e:
            logger.error(f"Strategy analysis failed: {e}")
            return f"Analysis failed: {e}"

    def get_learning_recommendations(self, agent_name: str, action_type: str = None) -> list[dict]:
        """
        Get learning recommendations for an agent.

        Args:
            agent_name: Name of agent
            action_type: Specific action type (optional)

        Returns:
            List of recommendations
        """
        if not self.learning_system:
            return []

        import asyncio

        loop = asyncio.get_event_loop()
        if loop.is_running():
            # Can't await in sync context, return empty
            return []

        return loop.run_until_complete(
            self.learning_system.get_recommendations(agent_name, action_type)
        )

    async def get_capabilities(self) -> dict[str, list[str]]:
        """
        Get all available agent capabilities.

        Returns:
            Dict mapping capability names to agent names that provide them
        """
        if not self.agent_registry:
            return {}

        return self.agent_registry.get_all_capabilities()

    async def invoke_capability(
        self, capability_name: str, parameters: dict, agent_name: str = "any"
    ) -> any:
        """
        Invoke a capability on an agent.

        Args:
            capability_name: Name of capability to invoke
            parameters: Parameters for the capability
            agent_name: Specific agent or "any"

        Returns:
            Result from capability
        """
        if not self.agent_registry:
            raise RuntimeError("Agent Registry not available")

        return await self.agent_registry.invoke_capability(
            agent_name=agent_name, capability_name=capability_name, parameters=parameters
        )

    @property
    def is_cto_mode(self) -> bool:
        """Check if CTO mode is active."""
        return self._cto_mode

    @property
    def strategic_goals(self) -> list:
        """Get current strategic goals."""
        if self.strategy_agent:
            return self.strategy_agent.goals
        return []
