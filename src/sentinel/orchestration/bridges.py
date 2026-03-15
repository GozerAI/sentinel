"""
Integration bridges for Sentinel.

Provides automatic coordination between discovery and management components:
- Auto-register discovered compute nodes with ComputeClusterManager
- Auto-configure integrations for discovered infrastructure
- Event-driven automation for infrastructure changes
"""
import asyncio
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional, Any, TYPE_CHECKING
from uuid import UUID

from sentinel.core.utils import utc_now
from sentinel.core.models.event import Event, EventCategory, EventSeverity

if TYPE_CHECKING:
    from sentinel.core.engine import SentinelEngine
    from sentinel.agents.discovery import DiscoveryAgent
    from sentinel.integrations.compute.cluster import ComputeClusterManager
    from sentinel.integrations.compute.node import ComputeNode, NodeRole

logger = logging.getLogger(__name__)


@dataclass
class BridgeAction:
    """Records an action taken by a bridge."""
    bridge_name: str
    action_type: str
    source_event: Optional[str] = None
    target_component: str = ""
    details: dict = field(default_factory=dict)
    success: bool = True
    error: str = ""
    timestamp: datetime = field(default_factory=utc_now)

    def to_dict(self) -> dict:
        return {
            "bridge_name": self.bridge_name,
            "action_type": self.action_type,
            "source_event": self.source_event,
            "target_component": self.target_component,
            "details": self.details,
            "success": self.success,
            "error": self.error,
            "timestamp": self.timestamp.isoformat(),
        }


class IntegrationBridge(ABC):
    """
    Base class for integration bridges.

    Bridges connect different Sentinel components and automate
    workflows between them based on events.
    """

    bridge_name: str = "base"

    def __init__(self, engine: 'SentinelEngine'):
        self.engine = engine
        self._enabled = True
        self._actions: list[BridgeAction] = []
        self._max_action_history = 100

    @abstractmethod
    async def start(self) -> None:
        """Start the bridge and subscribe to events."""
        pass

    @abstractmethod
    async def stop(self) -> None:
        """Stop the bridge and cleanup."""
        pass

    def record_action(self, action: BridgeAction) -> None:
        """Record an action taken by the bridge."""
        self._actions.append(action)
        if len(self._actions) > self._max_action_history:
            self._actions = self._actions[-self._max_action_history:]

    def get_action_history(self, limit: int = 50) -> list[BridgeAction]:
        """Get recent bridge actions."""
        return self._actions[-limit:]

    @property
    def enabled(self) -> bool:
        return self._enabled

    def enable(self) -> None:
        self._enabled = True
        logger.info(f"Bridge {self.bridge_name} enabled")

    def disable(self) -> None:
        self._enabled = False
        logger.info(f"Bridge {self.bridge_name} disabled")


class DiscoveryComputeBridge(IntegrationBridge):
    """
    Bridge between Discovery agent and Compute Cluster Manager.

    Automatically registers discovered Raspberry Pis and other compute
    nodes with the cluster manager for provisioning and management.

    Features:
    - Listens for infrastructure.discovered events
    - Auto-registers compute nodes (Raspberry Pi, servers)
    - Triggers SSH probe for detailed node info
    - Optionally auto-provisions k3s agents

    Configuration:
        - auto_register: Enable auto-registration (default: True)
        - auto_provision_k3s: Auto-install k3s on new nodes (default: False)
        - allowed_types: List of infrastructure types to register
    """

    bridge_name = "discovery_compute"

    def __init__(
        self,
        engine: 'SentinelEngine',
        config: dict = None
    ):
        super().__init__(engine)
        config = config or {}

        self.auto_register = config.get("auto_register", True)
        self.auto_provision_k3s = config.get("auto_provision_k3s", False)
        self.allowed_types = config.get("allowed_types", [
            "raspberry_pi",
            "proxmox",
            "esxi_vcenter",
        ])

        # References to components (set during start)
        self._discovery_agent: Optional['DiscoveryAgent'] = None
        self._cluster_manager: Optional['ComputeClusterManager'] = None

        # Track registered nodes to avoid duplicates
        self._registered_ips: set[str] = set()

    async def start(self) -> None:
        """Start the bridge and subscribe to discovery events."""
        # Get references to components
        self._discovery_agent = self.engine.get_agent("discovery")
        self._cluster_manager = self.engine.get_integration("compute_cluster")

        if not self._discovery_agent:
            logger.warning("Discovery agent not found - bridge will wait for it")

        if not self._cluster_manager:
            logger.warning("Compute cluster manager not found - bridge will wait for it")

        # Subscribe to infrastructure discovery events
        self.engine.event_bus.subscribe(
            self._handle_infrastructure_discovered,
            event_type="infrastructure.discovered"
        )

        logger.info(f"DiscoveryComputeBridge started (auto_register={self.auto_register})")

    async def stop(self) -> None:
        """Stop the bridge."""
        logger.info("DiscoveryComputeBridge stopped")

    async def _handle_infrastructure_discovered(self, event: Event) -> None:
        """Handle infrastructure discovery events."""
        if not self._enabled or not self.auto_register:
            return

        data = event.data
        infra_type = data.get("type")
        ip = data.get("ip")

        # Check if this is a compute node type we should register
        if infra_type not in self.allowed_types:
            logger.debug(f"Ignoring infrastructure type {infra_type} - not in allowed_types")
            return

        # Check if already registered
        if ip in self._registered_ips:
            logger.debug(f"Node {ip} already registered")
            return

        # Get cluster manager (might not have been available at start)
        if not self._cluster_manager:
            self._cluster_manager = self.engine.get_integration("compute_cluster")
            if not self._cluster_manager:
                logger.warning(f"Cannot register {ip} - cluster manager not available")
                return

        # Register the node
        await self._register_compute_node(data)

    async def _register_compute_node(self, infra_data: dict) -> None:
        """Register a discovered node with the cluster manager."""
        ip = infra_data.get("ip")
        mac = infra_data.get("mac", "")
        hostname = infra_data.get("hostname", "")
        infra_type = infra_data.get("type")

        action = BridgeAction(
            bridge_name=self.bridge_name,
            action_type="register_node",
            source_event="infrastructure.discovered",
            target_component="compute_cluster",
            details={
                "ip": ip,
                "mac": mac,
                "hostname": hostname,
                "type": infra_type,
            }
        )

        try:
            # Probe the node via SSH to get detailed info
            from sentinel.integrations.compute.node import ComputeNode, NodeRole, NodeStatus

            node = await self._cluster_manager._probe_node(ip)

            if node:
                # Set role based on infrastructure type
                if infra_type == "raspberry_pi":
                    node.add_role(NodeRole.WORKER)
                    node.labels["discovered_as"] = "raspberry_pi"
                elif infra_type == "proxmox":
                    node.add_role(NodeRole.CONTROLLER)
                    node.labels["discovered_as"] = "proxmox"

                # Register with cluster
                await self._cluster_manager.register_node(node)
                self._registered_ips.add(ip)

                action.success = True
                action.details["node_id"] = str(node.id)
                action.details["roles"] = [r.value for r in node.roles]

                logger.info(
                    f"Auto-registered compute node: {hostname or ip} "
                    f"(type={infra_type}, roles={node.roles})"
                )

                # Emit registration event
                await self.engine.event_bus.publish(Event(
                    category=EventCategory.NETWORK,
                    event_type="compute.node.registered",
                    severity=EventSeverity.INFO,
                    source=f"sentinel.orchestration.{self.bridge_name}",
                    title=f"Compute node registered: {hostname or ip}",
                    description=f"Auto-registered {infra_type} node with cluster manager",
                    data={
                        "node_id": str(node.id),
                        "ip": ip,
                        "hostname": hostname,
                        "type": infra_type,
                    }
                ))

                # Auto-provision k3s if enabled
                if self.auto_provision_k3s and infra_type == "raspberry_pi":
                    await self._auto_provision_k3s(node)

            else:
                action.success = False
                action.error = "SSH probe failed - node unreachable or not configured"
                logger.warning(f"Failed to probe node at {ip} - SSH may not be configured")

        except Exception as e:
            action.success = False
            action.error = str(e)
            logger.error(f"Failed to register compute node {ip}: {e}")

        self.record_action(action)

    async def _auto_provision_k3s(self, node: 'ComputeNode') -> None:
        """Auto-provision k3s on a new node."""
        action = BridgeAction(
            bridge_name=self.bridge_name,
            action_type="provision_k3s",
            target_component="compute_cluster",
            details={"node_id": str(node.id), "hostname": node.hostname}
        )

        try:
            # Check if k3s server exists
            if self._cluster_manager.k3s_server_url:
                # Provision as agent
                success = await self._cluster_manager.provision_k3s_agent(node)
                action.details["role"] = "agent"
            else:
                # First node becomes server
                success = await self._cluster_manager.provision_k3s_server(node)
                action.details["role"] = "server"

            action.success = success
            if success:
                logger.info(f"Auto-provisioned k3s on {node.hostname}")
            else:
                action.error = "k3s provisioning returned False"

        except Exception as e:
            action.success = False
            action.error = str(e)
            logger.error(f"Failed to auto-provision k3s on {node.hostname}: {e}")

        self.record_action(action)

    def get_registered_nodes(self) -> set[str]:
        """Get IPs of all registered nodes."""
        return self._registered_ips.copy()

    async def manual_register(self, ip: str) -> bool:
        """Manually trigger registration for a discovered node."""
        if not self._discovery_agent:
            self._discovery_agent = self.engine.get_agent("discovery")
            if not self._discovery_agent:
                logger.error("Discovery agent not available")
                return False

        # Get infrastructure data from discovery agent
        infra_data = self._discovery_agent.discovered_infrastructure.get(ip)
        if not infra_data:
            logger.error(f"No infrastructure data for {ip}")
            return False

        await self._register_compute_node(infra_data)
        return ip in self._registered_ips


class InfrastructureIntegrationBridge(IntegrationBridge):
    """
    Bridge between Discovery and Integration configuration.

    Automatically configures integrations for discovered infrastructure:
    - MikroTik routers → MikroTikIntegration
    - Synology NAS → SynologyIntegration (future)
    - UniFi devices → UniFiIntegration

    This enables Sentinel to automatically connect to and manage
    discovered network infrastructure.
    """

    bridge_name = "infrastructure_integration"

    def __init__(
        self,
        engine: 'SentinelEngine',
        config: dict = None
    ):
        super().__init__(engine)
        config = config or {}

        self.auto_configure = config.get("auto_configure", False)  # Disabled by default for security
        self.require_credentials = config.get("require_credentials", True)

        # Credential store (would integrate with secrets manager in production)
        self._credentials: dict[str, dict] = config.get("credentials", {})

        # Configured integrations
        self._configured: dict[str, str] = {}  # IP -> integration_name

    async def start(self) -> None:
        """Start the bridge."""
        self.engine.event_bus.subscribe(
            self._handle_infrastructure_discovered,
            event_type="infrastructure.discovered"
        )

        logger.info(f"InfrastructureIntegrationBridge started (auto_configure={self.auto_configure})")

    async def stop(self) -> None:
        """Stop the bridge."""
        logger.info("InfrastructureIntegrationBridge stopped")

    async def _handle_infrastructure_discovered(self, event: Event) -> None:
        """Handle infrastructure discovery for auto-configuration."""
        if not self._enabled or not self.auto_configure:
            return

        data = event.data
        infra_type = data.get("type")
        integration_type = data.get("integration_type")
        ip = data.get("ip")

        # Check if we have credentials for this device
        if self.require_credentials:
            creds = self._credentials.get(ip) or self._credentials.get(infra_type)
            if not creds:
                logger.info(
                    f"Discovered {infra_type} at {ip} but no credentials configured. "
                    f"Add credentials to auto-configure."
                )
                return
        else:
            creds = {}

        # Auto-configure integration
        await self._configure_integration(data, creds)

    async def _configure_integration(self, infra_data: dict, credentials: dict) -> None:
        """Configure an integration for discovered infrastructure."""
        infra_type = infra_data.get("type")
        integration_type = infra_data.get("integration_type")
        ip = infra_data.get("ip")

        action = BridgeAction(
            bridge_name=self.bridge_name,
            action_type="configure_integration",
            source_event="infrastructure.discovered",
            target_component=integration_type,
            details={"ip": ip, "type": infra_type}
        )

        try:
            if integration_type == "mikrotik":
                await self._configure_mikrotik(ip, credentials)
                action.success = True
            elif integration_type == "unifi":
                await self._configure_unifi(ip, credentials)
                action.success = True
            elif integration_type == "synology":
                # Future: Synology integration
                action.success = False
                action.error = "Synology integration not yet implemented"
            else:
                action.success = False
                action.error = f"Unknown integration type: {integration_type}"

        except Exception as e:
            action.success = False
            action.error = str(e)
            logger.error(f"Failed to configure {integration_type} at {ip}: {e}")

        self.record_action(action)

    async def _configure_mikrotik(self, ip: str, credentials: dict) -> None:
        """Configure MikroTik integration."""
        from sentinel.integrations.routers.mikrotik import MikroTikIntegration

        config = {
            "host": ip,
            "username": credentials.get("username", "admin"),
            "password": credentials.get("password", ""),
            "port": credentials.get("port", 443),
            "use_ssl": True,
            "verify_ssl": credentials.get("verify_ssl", False),
        }

        integration = MikroTikIntegration(config)
        await integration.connect()

        # Register with engine
        self.engine.register_integration("mikrotik", integration)
        self._configured[ip] = "mikrotik"

        logger.info(f"Auto-configured MikroTik integration for {ip}")

    async def _configure_unifi(self, ip: str, credentials: dict) -> None:
        """Configure UniFi integration."""
        # Future implementation
        logger.info(f"UniFi auto-configuration not yet implemented for {ip}")

    def add_credentials(self, identifier: str, credentials: dict) -> None:
        """Add credentials for auto-configuration."""
        self._credentials[identifier] = credentials
        logger.info(f"Added credentials for {identifier}")

    def get_configured_integrations(self) -> dict[str, str]:
        """Get all auto-configured integrations."""
        return self._configured.copy()
