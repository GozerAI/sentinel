"""
Agent Registry for centralized agent management and communication.

This module provides a central registry for all agents in the Sentinel platform,
enabling discovery, communication, and coordination between agents.
"""

import asyncio
import logging
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Optional, Callable, Awaitable, Any, TYPE_CHECKING
from uuid import UUID, uuid4

from sentinel.core.utils import utc_now
from sentinel.core.models.event import Event, EventCategory, EventSeverity

if TYPE_CHECKING:
    from sentinel.core.engine import SentinelEngine
    from sentinel.agents.base import BaseAgent

logger = logging.getLogger(__name__)


class AgentCapability:
    """
    Represents a capability that an agent provides.

    Capabilities allow agents to advertise what they can do,
    enabling other agents to request services.
    """

    def __init__(
        self,
        name: str,
        description: str,
        handler: Callable[..., Awaitable[Any]],
        input_schema: dict = None,
        output_schema: dict = None,
    ):
        self.name = name
        self.description = description
        self.handler = handler
        self.input_schema = input_schema or {}
        self.output_schema = output_schema or {}

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "description": self.description,
            "input_schema": self.input_schema,
            "output_schema": self.output_schema,
        }


class AgentMessage:
    """
    Message passed between agents.

    Messages enable direct agent-to-agent communication
    for coordination and delegation.
    """

    def __init__(
        self,
        from_agent: UUID,
        to_agent: UUID,
        message_type: str,
        payload: dict,
        reply_to: Optional[UUID] = None,
        timeout: float = 30.0,
    ):
        self.id = uuid4()
        self.from_agent = from_agent
        self.to_agent = to_agent
        self.message_type = message_type
        self.payload = payload
        self.reply_to = reply_to
        self.timeout = timeout
        self.created_at = utc_now()
        self.delivered_at: Optional[datetime] = None
        self.response: Optional[dict] = None
        self.error: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "id": str(self.id),
            "from_agent": str(self.from_agent),
            "to_agent": str(self.to_agent),
            "message_type": self.message_type,
            "payload": self.payload,
            "reply_to": str(self.reply_to) if self.reply_to else None,
            "created_at": self.created_at.isoformat(),
            "delivered_at": self.delivered_at.isoformat() if self.delivered_at else None,
        }


class AgentRegistration:
    """
    Registration record for an agent in the registry.
    """

    def __init__(self, agent_id: UUID, agent_name: str, agent_description: str, agent: "BaseAgent"):
        self.agent_id = agent_id
        self.agent_name = agent_name
        self.agent_description = agent_description
        self.agent = agent
        self.registered_at = utc_now()
        self.last_heartbeat = utc_now()
        self.status = "active"
        self.capabilities: dict[str, AgentCapability] = {}
        self.message_handlers: dict[str, Callable] = {}

        # Metrics
        self.messages_sent = 0
        self.messages_received = 0
        self.capability_invocations = 0

    def register_capability(self, capability: AgentCapability) -> None:
        """Register a capability for this agent."""
        self.capabilities[capability.name] = capability

    def register_message_handler(
        self, message_type: str, handler: Callable[[AgentMessage], Awaitable[dict]]
    ) -> None:
        """Register a handler for a message type."""
        self.message_handlers[message_type] = handler

    def update_heartbeat(self) -> None:
        """Update the last heartbeat timestamp."""
        self.last_heartbeat = utc_now()

    def to_dict(self) -> dict:
        return {
            "agent_id": str(self.agent_id),
            "agent_name": self.agent_name,
            "agent_description": self.agent_description,
            "registered_at": self.registered_at.isoformat(),
            "last_heartbeat": self.last_heartbeat.isoformat(),
            "status": self.status,
            "capabilities": [c.to_dict() for c in self.capabilities.values()],
            "metrics": {
                "messages_sent": self.messages_sent,
                "messages_received": self.messages_received,
                "capability_invocations": self.capability_invocations,
            },
        }


class AgentRegistry:
    """
    Central registry for all Sentinel agents.

    The registry provides:
    - Agent discovery and lookup
    - Capability advertisement and discovery
    - Inter-agent messaging
    - Health monitoring
    - Coordination primitives

    Example:
        ```python
        registry = AgentRegistry(engine)

        # Register an agent
        await registry.register(agent)

        # Register capabilities
        registry.register_capability(
            agent.id,
            AgentCapability(
                name="scan_network",
                description="Perform network scan",
                handler=agent.scan_network
            )
        )

        # Find agents with capability
        agents = registry.find_by_capability("scan_network")

        # Send message to another agent
        response = await registry.send_message(
            from_agent=agent.id,
            to_agent=target_id,
            message_type="request_scan",
            payload={"subnet": "192.168.1.0/24"}
        )

        # Invoke capability
        result = await registry.invoke_capability(
            "discovery",
            "scan_network",
            {"subnet": "192.168.1.0/24"}
        )
        ```
    """

    def __init__(self, engine: "SentinelEngine"):
        """
        Initialize the agent registry.

        Args:
            engine: Reference to the Sentinel engine
        """
        self.engine = engine

        # Agent registrations
        self._agents: dict[UUID, AgentRegistration] = {}
        self._agents_by_name: dict[str, list[UUID]] = defaultdict(list)

        # Message queues
        self._message_queues: dict[UUID, asyncio.Queue] = {}
        self._pending_responses: dict[UUID, asyncio.Future] = {}

        # Capability index
        self._capabilities: dict[str, list[UUID]] = defaultdict(list)

        # Coordination primitives
        self._locks: dict[str, asyncio.Lock] = {}
        self._semaphores: dict[str, asyncio.Semaphore] = {}

        # Health monitoring
        self._heartbeat_interval = 30  # seconds
        self._heartbeat_timeout = 90  # seconds
        self._monitor_task: Optional[asyncio.Task] = None

        self._running = False

    async def start(self) -> None:
        """Start the registry."""
        self._running = True
        self._monitor_task = asyncio.create_task(self._health_monitor_loop())
        logger.info("Agent registry started")

    async def stop(self) -> None:
        """Stop the registry."""
        self._running = False

        if self._monitor_task:
            self._monitor_task.cancel()
            try:
                await self._monitor_task
            except asyncio.CancelledError:
                pass

        # Clean up message processors
        for agent_id in list(self._message_queues.keys()):
            await self._cleanup_agent(agent_id)

        logger.info("Agent registry stopped")

    async def register(self, agent: "BaseAgent") -> AgentRegistration:
        """
        Register an agent with the registry.

        Args:
            agent: Agent to register

        Returns:
            AgentRegistration record
        """
        registration = AgentRegistration(
            agent_id=agent.id,
            agent_name=agent.agent_name,
            agent_description=agent.agent_description,
            agent=agent,
        )

        self._agents[agent.id] = registration
        self._agents_by_name[agent.agent_name].append(agent.id)

        # Create message queue for agent
        self._message_queues[agent.id] = asyncio.Queue()

        # Start message processor
        asyncio.create_task(self._message_processor(agent.id))

        # Publish registration event
        await self.engine.event_bus.publish(
            Event(
                category=EventCategory.AGENT,
                event_type="agent.registered",
                severity=EventSeverity.INFO,
                source="sentinel.agents.registry",
                title=f"Agent Registered: {agent.agent_name}",
                description=f"Agent {agent.id} registered with registry",
                data=registration.to_dict(),
            )
        )

        logger.info(f"Registered agent: {agent.agent_name} ({agent.id})")
        return registration

    async def unregister(self, agent_id: UUID) -> bool:
        """
        Unregister an agent from the registry.

        Args:
            agent_id: ID of agent to unregister

        Returns:
            True if successfully unregistered
        """
        registration = self._agents.get(agent_id)
        if not registration:
            return False

        await self._cleanup_agent(agent_id)

        # Remove from registrations
        del self._agents[agent_id]
        self._agents_by_name[registration.agent_name].remove(agent_id)

        # Remove from capability index
        for capability_name in registration.capabilities:
            if agent_id in self._capabilities[capability_name]:
                self._capabilities[capability_name].remove(agent_id)

        logger.info(f"Unregistered agent: {registration.agent_name} ({agent_id})")
        return True

    async def _cleanup_agent(self, agent_id: UUID) -> None:
        """Clean up resources for an agent."""
        # Cancel any pending responses
        for msg_id, future in list(self._pending_responses.items()):
            if not future.done():
                future.cancel()

        # Remove message queue
        if agent_id in self._message_queues:
            del self._message_queues[agent_id]

    def register_capability(self, agent_id: UUID, capability: AgentCapability) -> bool:
        """
        Register a capability for an agent.

        Args:
            agent_id: ID of the agent
            capability: Capability to register

        Returns:
            True if registered successfully
        """
        registration = self._agents.get(agent_id)
        if not registration:
            return False

        registration.register_capability(capability)
        self._capabilities[capability.name].append(agent_id)

        logger.debug(f"Registered capability {capability.name} for agent {agent_id}")
        return True

    def register_message_handler(
        self, agent_id: UUID, message_type: str, handler: Callable[[AgentMessage], Awaitable[dict]]
    ) -> bool:
        """
        Register a message handler for an agent.

        Args:
            agent_id: ID of the agent
            message_type: Type of message to handle
            handler: Async function to handle the message

        Returns:
            True if registered successfully
        """
        registration = self._agents.get(agent_id)
        if not registration:
            return False

        registration.register_message_handler(message_type, handler)
        return True

    def get_agent(self, agent_id: UUID) -> Optional[AgentRegistration]:
        """Get an agent registration by ID."""
        return self._agents.get(agent_id)

    def get_agents_by_name(self, agent_name: str) -> list[AgentRegistration]:
        """Get all agents with a given name."""
        agent_ids = self._agents_by_name.get(agent_name, [])
        return [self._agents[aid] for aid in agent_ids if aid in self._agents]

    def find_by_capability(self, capability_name: str) -> list[AgentRegistration]:
        """
        Find agents that have a specific capability.

        Args:
            capability_name: Name of capability to find

        Returns:
            List of agent registrations with the capability
        """
        agent_ids = self._capabilities.get(capability_name, [])
        return [
            self._agents[aid]
            for aid in agent_ids
            if aid in self._agents and self._agents[aid].status == "active"
        ]

    def get_all_capabilities(self) -> dict[str, list[str]]:
        """
        Get all registered capabilities and their providers.

        Returns:
            Dict mapping capability names to agent names
        """
        result = {}
        for capability_name, agent_ids in self._capabilities.items():
            result[capability_name] = [
                self._agents[aid].agent_name for aid in agent_ids if aid in self._agents
            ]
        return result

    async def send_message(
        self,
        from_agent: UUID,
        to_agent: UUID,
        message_type: str,
        payload: dict,
        timeout: float = 30.0,
        wait_response: bool = True,
    ) -> Optional[dict]:
        """
        Send a message from one agent to another.

        Args:
            from_agent: ID of sending agent
            to_agent: ID of receiving agent
            message_type: Type of message
            payload: Message payload
            timeout: Timeout in seconds
            wait_response: Whether to wait for response

        Returns:
            Response dict if waiting, None otherwise
        """
        # Validate agents
        if from_agent not in self._agents:
            raise ValueError(f"Sender agent not registered: {from_agent}")
        if to_agent not in self._agents:
            raise ValueError(f"Receiver agent not registered: {to_agent}")

        # Create message
        message = AgentMessage(
            from_agent=from_agent,
            to_agent=to_agent,
            message_type=message_type,
            payload=payload,
            timeout=timeout,
        )

        # Update metrics
        self._agents[from_agent].messages_sent += 1

        # Queue message
        queue = self._message_queues.get(to_agent)
        if not queue:
            raise RuntimeError(f"No message queue for agent: {to_agent}")

        if wait_response:
            # Create future for response
            future = asyncio.get_event_loop().create_future()
            self._pending_responses[message.id] = future

            await queue.put(message)

            try:
                return await asyncio.wait_for(future, timeout)
            except asyncio.TimeoutError:
                logger.warning(f"Message {message.id} timed out")
                return None
            finally:
                self._pending_responses.pop(message.id, None)
        else:
            await queue.put(message)
            return None

    async def broadcast(
        self,
        from_agent: UUID,
        message_type: str,
        payload: dict,
        target_capability: Optional[str] = None,
        target_agents: Optional[list[str]] = None,
    ) -> int:
        """
        Broadcast a message to multiple agents.

        Args:
            from_agent: ID of sending agent
            message_type: Type of message
            payload: Message payload
            target_capability: Only send to agents with this capability
            target_agents: Only send to agents with these names

        Returns:
            Number of agents message was sent to
        """
        targets = []

        if target_capability:
            targets = [r.agent_id for r in self.find_by_capability(target_capability)]
        elif target_agents:
            for name in target_agents:
                targets.extend(self._agents_by_name.get(name, []))
        else:
            targets = list(self._agents.keys())

        # Don't send to self
        targets = [t for t in targets if t != from_agent]

        for target in targets:
            try:
                await self.send_message(
                    from_agent=from_agent,
                    to_agent=target,
                    message_type=message_type,
                    payload=payload,
                    wait_response=False,
                )
            except Exception as e:
                logger.warning(f"Failed to broadcast to {target}: {e}")

        return len(targets)

    async def invoke_capability(
        self, agent_name: str, capability_name: str, parameters: dict, timeout: float = 30.0
    ) -> Any:
        """
        Invoke a capability on an agent.

        Args:
            agent_name: Name of agent (or "any" for any agent with capability)
            capability_name: Name of capability to invoke
            parameters: Parameters for the capability
            timeout: Timeout in seconds

        Returns:
            Result from capability handler

        Raises:
            ValueError: If no agent found with capability
        """
        # Find agent with capability
        if agent_name == "any":
            agents = self.find_by_capability(capability_name)
        else:
            agents = [
                r for r in self.get_agents_by_name(agent_name) if capability_name in r.capabilities
            ]

        if not agents:
            raise ValueError(f"No agent found with capability: {capability_name}")

        # Use first available agent
        registration = agents[0]
        capability = registration.capabilities[capability_name]

        # Update metrics
        registration.capability_invocations += 1

        # Invoke capability
        try:
            return await asyncio.wait_for(capability.handler(**parameters), timeout)
        except asyncio.TimeoutError:
            logger.warning(f"Capability {capability_name} timed out")
            raise

    async def _message_processor(self, agent_id: UUID) -> None:
        """Process messages for an agent."""
        queue = self._message_queues.get(agent_id)
        if not queue:
            return

        while self._running and agent_id in self._agents:
            try:
                message = await asyncio.wait_for(queue.get(), timeout=1.0)

                registration = self._agents.get(agent_id)
                if not registration:
                    continue

                # Update metrics
                registration.messages_received += 1
                message.delivered_at = utc_now()

                # Find handler
                handler = registration.message_handlers.get(message.message_type)
                if handler:
                    try:
                        response = await handler(message)
                        message.response = response

                        # Complete pending response if any
                        future = self._pending_responses.get(message.id)
                        if future and not future.done():
                            future.set_result(response)

                    except Exception as e:
                        message.error = str(e)
                        logger.error(f"Message handler error: {e}")

                        future = self._pending_responses.get(message.id)
                        if future and not future.done():
                            future.set_exception(e)
                else:
                    logger.warning(
                        f"No handler for message type {message.message_type} "
                        f"on agent {agent_id}"
                    )

            except asyncio.TimeoutError:
                continue
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Message processor error: {e}")

    async def _health_monitor_loop(self) -> None:
        """Monitor agent health via heartbeats."""
        while self._running:
            try:
                await asyncio.sleep(self._heartbeat_interval)

                now = utc_now()
                for agent_id, registration in list(self._agents.items()):
                    time_since_heartbeat = (now - registration.last_heartbeat).total_seconds()

                    if time_since_heartbeat > self._heartbeat_timeout:
                        if registration.status == "active":
                            registration.status = "unhealthy"
                            logger.warning(
                                f"Agent {registration.agent_name} ({agent_id}) "
                                f"marked unhealthy (no heartbeat for {time_since_heartbeat:.0f}s)"
                            )

                            await self.engine.event_bus.publish(
                                Event(
                                    category=EventCategory.AGENT,
                                    event_type="agent.unhealthy",
                                    severity=EventSeverity.WARNING,
                                    source="sentinel.agents.registry",
                                    title=f"Agent Unhealthy: {registration.agent_name}",
                                    description=f"No heartbeat for {time_since_heartbeat:.0f} seconds",
                                    data={"agent_id": str(agent_id)},
                                )
                            )

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Health monitor error: {e}")

    def heartbeat(self, agent_id: UUID) -> bool:
        """
        Record a heartbeat for an agent.

        Args:
            agent_id: ID of the agent

        Returns:
            True if heartbeat recorded
        """
        registration = self._agents.get(agent_id)
        if not registration:
            return False

        registration.update_heartbeat()

        # Restore healthy status if was unhealthy
        if registration.status == "unhealthy":
            registration.status = "active"
            logger.info(f"Agent {registration.agent_name} restored to active")

        return True

    def acquire_lock(self, name: str) -> asyncio.Lock:
        """
        Get or create a named lock for coordination.

        Args:
            name: Name of the lock

        Returns:
            asyncio.Lock instance
        """
        if name not in self._locks:
            self._locks[name] = asyncio.Lock()
        return self._locks[name]

    def get_semaphore(self, name: str, value: int = 1) -> asyncio.Semaphore:
        """
        Get or create a named semaphore for coordination.

        Args:
            name: Name of the semaphore
            value: Initial value if creating

        Returns:
            asyncio.Semaphore instance
        """
        if name not in self._semaphores:
            self._semaphores[name] = asyncio.Semaphore(value)
        return self._semaphores[name]

    def get_all_agents(self) -> list[AgentRegistration]:
        """Get all registered agents."""
        return list(self._agents.values())

    def get_active_agents(self) -> list[AgentRegistration]:
        """Get all active agents."""
        return [a for a in self._agents.values() if a.status == "active"]

    @property
    def stats(self) -> dict:
        """Get registry statistics."""
        agents = self._agents.values()
        return {
            "total_agents": len(self._agents),
            "active_agents": len([a for a in agents if a.status == "active"]),
            "unhealthy_agents": len([a for a in agents if a.status == "unhealthy"]),
            "total_capabilities": len(self._capabilities),
            "total_messages_sent": sum(a.messages_sent for a in agents),
            "total_messages_received": sum(a.messages_received for a in agents),
            "total_capability_invocations": sum(a.capability_invocations for a in agents),
        }
