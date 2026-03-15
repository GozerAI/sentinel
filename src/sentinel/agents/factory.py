"""
Agent Factory for dynamic agent creation and management.

This module enables Sentinel to create, modify, and manage agents dynamically
based on emerging threats, opportunities, or operational needs.
"""
import asyncio
import importlib
import inspect
import logging
from datetime import datetime
from typing import Optional, Type, Any, TYPE_CHECKING
from uuid import UUID, uuid4
from pathlib import Path

from sentinel.agents.base import BaseAgent
from sentinel.core.utils import utc_now
from sentinel.core.models.event import Event, EventCategory, EventSeverity

if TYPE_CHECKING:
    from sentinel.core.engine import SentinelEngine

logger = logging.getLogger(__name__)


class AgentTemplate:
    """
    Template for creating new agent types dynamically.

    Attributes:
        name: Unique template name
        description: Human-readable description
        base_class: Base agent class to inherit from
        capabilities: List of capabilities this agent has
        required_integrations: Integrations needed by this agent
        event_subscriptions: Events this agent should subscribe to
        default_config: Default configuration values
    """

    def __init__(
        self,
        name: str,
        description: str,
        base_class: Type[BaseAgent] = BaseAgent,
        capabilities: list[str] = None,
        required_integrations: list[str] = None,
        event_subscriptions: list[str] = None,
        default_config: dict = None
    ):
        self.id = uuid4()
        self.name = name
        self.description = description
        self.base_class = base_class
        self.capabilities = capabilities or []
        self.required_integrations = required_integrations or []
        self.event_subscriptions = event_subscriptions or []
        self.default_config = default_config or {}
        self.created_at = utc_now()

    def to_dict(self) -> dict:
        """Convert template to dictionary."""
        return {
            "id": str(self.id),
            "name": self.name,
            "description": self.description,
            "base_class": self.base_class.__name__,
            "capabilities": self.capabilities,
            "required_integrations": self.required_integrations,
            "event_subscriptions": self.event_subscriptions,
            "default_config": self.default_config,
            "created_at": self.created_at.isoformat()
        }


class AgentInstance:
    """
    Tracks a running agent instance.

    Attributes:
        agent: The actual agent object
        template: Template used to create the agent
        started_at: When the agent was started
        status: Current status (running, stopped, error)
        metrics: Performance metrics
    """

    def __init__(
        self,
        agent: BaseAgent,
        template: Optional[AgentTemplate] = None,
        parent_id: Optional[UUID] = None
    ):
        self.id = agent.id
        self.agent = agent
        self.template = template
        self.parent_id = parent_id
        self.created_at = utc_now()
        self.started_at: Optional[datetime] = None
        self.stopped_at: Optional[datetime] = None
        self.status = "created"
        self.error: Optional[str] = None

        # Metrics
        self.actions_taken = 0
        self.decisions_made = 0
        self.errors_encountered = 0
        self.last_activity: Optional[datetime] = None

    async def start(self) -> None:
        """Start the agent instance."""
        try:
            await self.agent.start()
            self.started_at = utc_now()
            self.status = "running"
            logger.info(f"Agent instance {self.id} ({self.agent.agent_name}) started")
        except Exception as e:
            self.status = "error"
            self.error = str(e)
            logger.error(f"Failed to start agent {self.id}: {e}")
            raise

    async def stop(self) -> None:
        """Stop the agent instance."""
        try:
            await self.agent.stop()
            self.stopped_at = utc_now()
            self.status = "stopped"
            logger.info(f"Agent instance {self.id} ({self.agent.agent_name}) stopped")
        except Exception as e:
            self.error = str(e)
            logger.error(f"Failed to stop agent {self.id}: {e}")
            raise

    def update_metrics(self) -> None:
        """Update metrics from agent stats."""
        stats = self.agent.stats
        self.actions_taken = stats.get("total_actions", 0)
        self.decisions_made = stats.get("total_decisions", 0)
        self.last_activity = utc_now()

    def to_dict(self) -> dict:
        """Convert instance to dictionary."""
        return {
            "id": str(self.id),
            "agent_name": self.agent.agent_name,
            "agent_description": self.agent.agent_description,
            "template_id": str(self.template.id) if self.template else None,
            "parent_id": str(self.parent_id) if self.parent_id else None,
            "status": self.status,
            "created_at": self.created_at.isoformat(),
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "stopped_at": self.stopped_at.isoformat() if self.stopped_at else None,
            "error": self.error,
            "metrics": {
                "actions_taken": self.actions_taken,
                "decisions_made": self.decisions_made,
                "errors_encountered": self.errors_encountered,
                "last_activity": self.last_activity.isoformat() if self.last_activity else None
            }
        }


class AgentFactory:
    """
    Factory for creating and managing agents dynamically.

    The AgentFactory enables Sentinel to:
    - Create new agents from templates
    - Spawn specialized agents for specific threats
    - Clone existing agents with modifications
    - Retire agents that are no longer needed
    - Track all agent instances and their lifecycle

    Example:
        ```python
        factory = AgentFactory(engine)

        # Register a template
        template = AgentTemplate(
            name="port_scanner",
            description="Scans network ports for vulnerabilities",
            capabilities=["port_scan", "vulnerability_detection"],
            required_integrations=["router"]
        )
        factory.register_template(template)

        # Create an agent from template
        agent = await factory.create_agent(
            template_name="port_scanner",
            config={"scan_interval": 300}
        )
        ```
    """

    def __init__(self, engine: "SentinelEngine"):
        """
        Initialize the agent factory.

        Args:
            engine: Reference to the Sentinel engine
        """
        self.engine = engine

        # Registry of available agent templates
        self._templates: dict[str, AgentTemplate] = {}

        # Registry of agent classes
        self._agent_classes: dict[str, Type[BaseAgent]] = {}

        # Active agent instances
        self._instances: dict[UUID, AgentInstance] = {}

        # Built-in agent class mapping
        self._builtin_agents = {
            "discovery": "sentinel.agents.discovery.DiscoveryAgent",
            "guardian": "sentinel.agents.guardian.GuardianAgent",
            "planner": "sentinel.agents.planner.PlannerAgent",
            "optimizer": "sentinel.agents.optimizer.OptimizerAgent",
            "healer": "sentinel.agents.healer.HealerAgent",
            "testing": "sentinel.agents.testing.TestingAgent",
        }

        # Load built-in agents
        self._load_builtin_agents()

    def _load_builtin_agents(self) -> None:
        """Load built-in agent classes."""
        for name, module_path in self._builtin_agents.items():
            try:
                module_name, class_name = module_path.rsplit(".", 1)
                module = importlib.import_module(module_name)
                agent_class = getattr(module, class_name)
                self._agent_classes[name] = agent_class

                # Create template from built-in agent
                template = AgentTemplate(
                    name=name,
                    description=agent_class.agent_description,
                    base_class=agent_class,
                    capabilities=getattr(agent_class, "capabilities", []),
                    default_config={}
                )
                self._templates[name] = template

                logger.debug(f"Loaded built-in agent: {name}")

            except Exception as e:
                logger.warning(f"Failed to load built-in agent {name}: {e}")

    def register_template(self, template: AgentTemplate) -> None:
        """
        Register a new agent template.

        Args:
            template: Agent template to register
        """
        if template.name in self._templates:
            logger.warning(f"Overwriting existing template: {template.name}")

        self._templates[template.name] = template
        logger.info(f"Registered agent template: {template.name}")

    def register_agent_class(self, name: str, agent_class: Type[BaseAgent]) -> None:
        """
        Register a new agent class.

        Args:
            name: Name to register the class under
            agent_class: Agent class to register
        """
        if not issubclass(agent_class, BaseAgent):
            raise ValueError(f"{agent_class} must be a subclass of BaseAgent")

        self._agent_classes[name] = agent_class
        logger.info(f"Registered agent class: {name}")

    async def create_agent(
        self,
        template_name: str,
        config: Optional[dict] = None,
        parent_id: Optional[UUID] = None,
        auto_start: bool = True
    ) -> AgentInstance:
        """
        Create a new agent instance from a template.

        Args:
            template_name: Name of template to use
            config: Configuration overrides
            parent_id: ID of parent agent (if spawned by another agent)
            auto_start: Whether to start the agent immediately

        Returns:
            AgentInstance tracking the new agent

        Raises:
            ValueError: If template not found
        """
        template = self._templates.get(template_name)
        if not template:
            raise ValueError(f"Template not found: {template_name}")

        # Check required integrations
        for integration in template.required_integrations:
            if not self.engine.get_integration(integration):
                logger.warning(
                    f"Required integration '{integration}' not available for {template_name}"
                )

        # Merge configuration
        agent_config = {**template.default_config, **(config or {})}

        # Get the agent class
        agent_class = self._agent_classes.get(template_name, template.base_class)

        # Create agent instance
        agent = agent_class(self.engine, agent_config)
        instance = AgentInstance(agent, template, parent_id)

        # Register instance
        self._instances[instance.id] = instance

        # Publish creation event
        await self.engine.event_bus.publish(Event(
            category=EventCategory.AGENT,
            event_type="agent.created",
            severity=EventSeverity.INFO,
            source="sentinel.agents.factory",
            title=f"Agent Created: {agent.agent_name}",
            description=f"Created new agent instance from template '{template_name}'",
            data=instance.to_dict()
        ))

        # Auto-start if requested
        if auto_start:
            await instance.start()

        logger.info(f"Created agent '{agent.agent_name}' from template '{template_name}'")
        return instance

    async def create_specialized_agent(
        self,
        name: str,
        description: str,
        capabilities: list[str],
        analyze_function: callable,
        execute_function: callable,
        subscribe_events: list[str] = None,
        config: dict = None,
        parent_id: Optional[UUID] = None
    ) -> AgentInstance:
        """
        Create a specialized agent dynamically with custom behavior.

        This allows creating purpose-built agents at runtime without
        defining a new class.

        Args:
            name: Agent name
            description: Agent description
            capabilities: List of capabilities
            analyze_function: Async function for event analysis
            execute_function: Async function for action execution
            subscribe_events: Event types to subscribe to
            config: Agent configuration
            parent_id: Parent agent ID

        Returns:
            AgentInstance for the new specialized agent
        """
        # Create a dynamic agent class
        class DynamicAgent(BaseAgent):
            agent_name = name
            agent_description = description

            async def _subscribe_events(self):
                for event_type in (subscribe_events or []):
                    self.engine.event_bus.subscribe(
                        self._handle_event,
                        event_type=event_type
                    )

            async def _handle_event(self, event: Event):
                decision = await self.analyze(event)
                if decision:
                    self._decisions.append(decision)

            async def analyze(self, event: Event):
                return await analyze_function(self, event)

            async def _do_execute(self, action):
                return await execute_function(self, action)

        # Register the dynamic class
        self.register_agent_class(name, DynamicAgent)

        # Create template
        template = AgentTemplate(
            name=name,
            description=description,
            base_class=DynamicAgent,
            capabilities=capabilities,
            event_subscriptions=subscribe_events or [],
            default_config=config or {}
        )
        self.register_template(template)

        # Create and return instance
        return await self.create_agent(
            template_name=name,
            config=config,
            parent_id=parent_id,
            auto_start=True
        )

    async def clone_agent(
        self,
        instance_id: UUID,
        config_overrides: Optional[dict] = None,
        auto_start: bool = True
    ) -> AgentInstance:
        """
        Clone an existing agent instance.

        Args:
            instance_id: ID of agent to clone
            config_overrides: Configuration changes for clone
            auto_start: Whether to start the clone

        Returns:
            New AgentInstance cloned from original
        """
        original = self._instances.get(instance_id)
        if not original:
            raise ValueError(f"Agent instance not found: {instance_id}")

        # Merge original config with overrides
        new_config = {**original.agent.config, **(config_overrides or {})}

        # Create new instance from same template
        template_name = original.template.name if original.template else original.agent.agent_name

        return await self.create_agent(
            template_name=template_name,
            config=new_config,
            parent_id=original.id,
            auto_start=auto_start
        )

    async def retire_agent(self, instance_id: UUID, reason: str = "") -> bool:
        """
        Retire an agent instance.

        Args:
            instance_id: ID of agent to retire
            reason: Reason for retirement

        Returns:
            True if successfully retired
        """
        instance = self._instances.get(instance_id)
        if not instance:
            logger.warning(f"Cannot retire unknown agent: {instance_id}")
            return False

        try:
            # Stop the agent
            if instance.status == "running":
                await instance.stop()

            # Publish retirement event
            await self.engine.event_bus.publish(Event(
                category=EventCategory.AGENT,
                event_type="agent.retired",
                severity=EventSeverity.INFO,
                source="sentinel.agents.factory",
                title=f"Agent Retired: {instance.agent.agent_name}",
                description=reason or f"Agent {instance.id} was retired",
                data={
                    "instance_id": str(instance_id),
                    "agent_name": instance.agent.agent_name,
                    "reason": reason,
                    "final_metrics": instance.to_dict()["metrics"]
                }
            ))

            # Remove from active instances
            del self._instances[instance_id]

            logger.info(f"Retired agent {instance_id}: {reason}")
            return True

        except Exception as e:
            logger.error(f"Failed to retire agent {instance_id}: {e}")
            return False

    async def spawn_for_threat(
        self,
        threat_type: str,
        threat_data: dict,
        parent_agent: Optional[UUID] = None
    ) -> Optional[AgentInstance]:
        """
        Spawn a specialized agent to handle a specific threat.

        Args:
            threat_type: Type of threat detected
            threat_data: Data about the threat
            parent_agent: Agent that detected the threat

        Returns:
            New agent instance if spawned, None otherwise
        """
        # Map threat types to appropriate agent templates
        threat_agent_map = {
            "port_scan": "guardian",
            "brute_force": "guardian",
            "malware": "guardian",
            "ddos": "guardian",
            "unauthorized_device": "discovery",
            "vlan_violation": "planner",
            "bandwidth_abuse": "optimizer",
            "service_failure": "healer",
        }

        template_name = threat_agent_map.get(threat_type)
        if not template_name:
            logger.warning(f"No agent template for threat type: {threat_type}")
            return None

        # Configure agent specifically for this threat
        threat_config = {
            "threat_focus": threat_type,
            "threat_data": threat_data,
            "priority": "high",
            "auto_execute_threshold": 0.85,  # Lower threshold for threat response
        }

        instance = await self.create_agent(
            template_name=template_name,
            config=threat_config,
            parent_id=parent_agent,
            auto_start=True
        )

        logger.info(f"Spawned {template_name} agent for {threat_type} threat")
        return instance

    def get_instance(self, instance_id: UUID) -> Optional[AgentInstance]:
        """Get an agent instance by ID."""
        return self._instances.get(instance_id)

    def get_instances_by_template(self, template_name: str) -> list[AgentInstance]:
        """Get all instances of a specific template."""
        return [
            inst for inst in self._instances.values()
            if inst.template and inst.template.name == template_name
        ]

    def get_running_instances(self) -> list[AgentInstance]:
        """Get all running agent instances."""
        return [
            inst for inst in self._instances.values()
            if inst.status == "running"
        ]

    def get_all_instances(self) -> list[AgentInstance]:
        """Get all agent instances."""
        return list(self._instances.values())

    def get_templates(self) -> list[AgentTemplate]:
        """Get all registered templates."""
        return list(self._templates.values())

    def get_template(self, name: str) -> Optional[AgentTemplate]:
        """Get a template by name."""
        return self._templates.get(name)

    @property
    def stats(self) -> dict:
        """Get factory statistics."""
        instances = self._instances.values()
        return {
            "templates_registered": len(self._templates),
            "agent_classes_registered": len(self._agent_classes),
            "total_instances": len(self._instances),
            "running_instances": len([i for i in instances if i.status == "running"]),
            "stopped_instances": len([i for i in instances if i.status == "stopped"]),
            "error_instances": len([i for i in instances if i.status == "error"]),
            "total_actions": sum(i.actions_taken for i in instances),
            "total_decisions": sum(i.decisions_made for i in instances)
        }
