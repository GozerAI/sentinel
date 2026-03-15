"""
Compute Cluster Manager for Sentinel.

Manages a fleet of compute nodes (Raspberry Pi, servers, VMs) as a
unified compute cluster. Handles:
- Node discovery and registration
- Health monitoring
- Workload distribution
- k3s/Docker orchestration
- SSH-based provisioning
"""
import asyncio
import logging
import json
from typing import Optional, Any, TYPE_CHECKING
from datetime import datetime, timedelta
from pathlib import Path
from uuid import UUID

import asyncssh

from sentinel.integrations.base import BaseIntegration
from sentinel.integrations.compute.node import (
    ComputeNode, NodeRole, NodeStatus, NodeResources, NodeMetrics
)
from sentinel.core.utils import utc_now

if TYPE_CHECKING:
    from sentinel.core.engine import SentinelEngine

logger = logging.getLogger(__name__)


class ComputeClusterManager(BaseIntegration):
    """
    Manages a cluster of compute nodes for Sentinel.

    Provides unified management of heterogeneous compute resources:
    - Raspberry Pi 5 fleet (your 10x RPi5 16GB units)
    - Workstations (Threadripper)
    - Virtual machines
    - Any SSH-accessible Linux system

    Features:
    - Automatic node discovery via network scanning
    - SSH-based provisioning and management
    - Health monitoring and alerting
    - k3s cluster orchestration
    - Docker container management
    - Workload scheduling for Sentinel agents

    Example:
        ```python
        cluster = ComputeClusterManager({
            "ssh_key_path": "/root/.ssh/id_rsa",
            "ssh_user": "pi",
            "scan_networks": ["192.168.1.0/24"]
        })

        await cluster.connect()

        # Discover nodes
        nodes = await cluster.discover_nodes()

        # Provision a node for k3s
        await cluster.provision_k3s_agent(node)

        # Deploy a container
        await cluster.deploy_container(
            node=node,
            image="sentinel/agent:latest",
            name="sentinel-agent"
        )
        ```
    """

    def __init__(self, config: dict):
        super().__init__(config)

        # SSH configuration with validation
        self.ssh_user = config.get("ssh_user", "pi")
        if not self.ssh_user:
            raise ValueError("SSH user is required")

        self.ssh_key_path = config.get("ssh_key_path")
        self._ssh_password = config.get("ssh_password")  # Prefixed with _ to discourage direct access

        # Validate SSH port
        self.ssh_port = config.get("ssh_port", 22)
        if not isinstance(self.ssh_port, int) or not 1 <= self.ssh_port <= 65535:
            raise ValueError(f"Invalid SSH port: {self.ssh_port}. Must be 1-65535")

        # Validate that at least one authentication method is provided
        if not self.ssh_key_path and not self._ssh_password:
            raise ValueError(
                "SSH authentication required: provide either 'ssh_key_path' or 'ssh_password'. "
                "SSH key authentication is recommended for security."
            )

        # Security warning for password authentication
        if self._ssh_password and not self.ssh_key_path:
            logger.warning(
                "Using SSH password authentication. "
                "SSH key authentication is more secure and recommended for production."
            )

        # Discovery configuration
        self.scan_networks = config.get("scan_networks", [])
        self.discovery_interval = config.get("discovery_interval", 300)
        if self.discovery_interval < 60:
            logger.warning(f"Discovery interval {self.discovery_interval}s is very short, may impact performance")

        # k3s configuration (sensitive - don't log tokens)
        self.k3s_server_url = config.get("k3s_server_url")
        self._k3s_token = config.get("k3s_token")  # Prefixed with _ for security

        # Persistence
        self.persistence_path = Path(config.get(
            "persistence_path",
            "/var/lib/sentinel/cluster.json"
        ))

        # Node registry
        self._nodes: dict[UUID, ComputeNode] = {}
        self._nodes_by_ip: dict[str, UUID] = {}
        self._nodes_by_hostname: dict[str, UUID] = {}

        # Background tasks
        self._monitor_task: Optional[asyncio.Task] = None
        self._discovery_task: Optional[asyncio.Task] = None

    @property
    def ssh_password(self) -> Optional[str]:
        """Get SSH password (read-only property to discourage storage)."""
        return self._ssh_password

    @property
    def k3s_token(self) -> Optional[str]:
        """Get k3s token (read-only property)."""
        return self._k3s_token

    @k3s_token.setter
    def k3s_token(self, value: str) -> None:
        """Set k3s token."""
        self._k3s_token = value

    async def connect(self) -> None:
        """Initialize the cluster manager."""
        # Load persisted nodes
        await self._load_nodes()

        # Verify connectivity to known nodes
        for node in list(self._nodes.values()):
            try:
                if await self._check_node_connectivity(node):
                    node.status = NodeStatus.ONLINE
                else:
                    node.status = NodeStatus.OFFLINE
            except Exception as e:
                logger.debug(f"Node {node.hostname} connectivity check failed: {e}")
                node.status = NodeStatus.OFFLINE

        # Start background tasks
        self._monitor_task = asyncio.create_task(self._monitor_loop())
        self._discovery_task = asyncio.create_task(self._discovery_loop())

        self._connected = True
        logger.info(f"Compute cluster manager started with {len(self._nodes)} nodes")

    async def disconnect(self) -> None:
        """Shutdown the cluster manager."""
        if self._monitor_task:
            self._monitor_task.cancel()
            try:
                await self._monitor_task
            except asyncio.CancelledError:
                pass

        if self._discovery_task:
            self._discovery_task.cancel()
            try:
                await self._discovery_task
            except asyncio.CancelledError:
                pass

        await self._persist_nodes()
        self._connected = False
        logger.info("Compute cluster manager stopped")

    async def health_check(self) -> bool:
        """Check cluster health."""
        online = sum(1 for n in self._nodes.values() if n.status == NodeStatus.ONLINE)
        return online > 0 or len(self._nodes) == 0

    # =========================================================================
    # Node Discovery
    # =========================================================================

    async def discover_nodes(self, network: str = None) -> list[ComputeNode]:
        """
        Discover compute nodes on the network.

        Uses ARP scanning and SSH probing to find potential nodes.

        Args:
            network: Network to scan (CIDR notation), or None for all configured

        Returns:
            List of discovered nodes
        """
        networks = [network] if network else self.scan_networks
        discovered = []

        for net in networks:
            logger.info(f"Scanning network {net} for compute nodes...")

            # Get IPs via ARP scan (would use router integration)
            # For now, we'll try known IPs or configured ranges
            ips = await self._scan_network(net)

            for ip in ips:
                if ip in self._nodes_by_ip:
                    continue  # Already known

                try:
                    node = await self._probe_node(ip)
                    if node:
                        await self.register_node(node)
                        discovered.append(node)
                        logger.info(f"Discovered node: {node.hostname} ({ip})")
                except Exception as e:
                    logger.debug(f"Failed to probe {ip}: {e}")

        return discovered

    async def _scan_network(self, network: str) -> list[str]:
        """Scan a network for potential nodes."""
        # In a real implementation, this would:
        # 1. Use the router integration to get ARP table
        # 2. Or perform an nmap scan
        # 3. Or use DHCP lease information

        # For now, return empty - discovery relies on manual registration
        # or router ARP table
        return []

    async def _probe_node(self, ip: str) -> Optional[ComputeNode]:
        """
        Probe a potential node via SSH.

        Args:
            ip: IP address to probe

        Returns:
            ComputeNode if successful, None otherwise
        """
        try:
            async with asyncssh.connect(
                ip,
                port=self.ssh_port,
                username=self.ssh_user,
                client_keys=[self.ssh_key_path] if self.ssh_key_path else None,
                password=self.ssh_password,
                known_hosts=None,
                connect_timeout=10
            ) as conn:
                # Get system information
                result = await conn.run("hostname", check=True)
                hostname = result.stdout.strip()

                # Get model info
                result = await conn.run(
                    "cat /proc/device-tree/model 2>/dev/null || "
                    "cat /sys/class/dmi/id/product_name 2>/dev/null || "
                    "echo 'Unknown'",
                    check=False
                )
                model = result.stdout.strip().replace('\x00', '')

                # Get MAC address
                result = await conn.run(
                    "cat /sys/class/net/eth0/address 2>/dev/null || "
                    "ip link show | grep -A1 'state UP' | grep ether | awk '{print $2}'",
                    check=False
                )
                mac = result.stdout.strip().split('\n')[0]

                # Get OS version
                result = await conn.run(
                    "cat /etc/os-release | grep PRETTY_NAME | cut -d'=' -f2 | tr -d '\"'",
                    check=False
                )
                os_version = result.stdout.strip()

                # Get resources
                resources = await self._get_node_resources(conn)

                node = ComputeNode(
                    hostname=hostname,
                    ip_address=ip,
                    mac_address=mac,
                    model=model,
                    os_version=os_version,
                    resources=resources,
                    status=NodeStatus.ONLINE,
                    ssh_user=self.ssh_user,
                    ssh_port=self.ssh_port,
                    ssh_key_path=self.ssh_key_path
                )

                # Detect if it's a Raspberry Pi
                if node.is_raspberry_pi:
                    node.labels["type"] = "raspberry-pi"
                    node.labels["generation"] = self._detect_rpi_generation(model)

                # Check for container runtime
                result = await conn.run("which docker", check=False)
                if result.exit_status == 0:
                    node.container_runtime = "docker"

                result = await conn.run("which k3s", check=False)
                if result.exit_status == 0:
                    result = await conn.run("k3s --version", check=False)
                    if result.exit_status == 0:
                        node.k8s_version = result.stdout.strip()

                return node

        except asyncssh.Error as e:
            logger.debug(f"SSH connection failed to {ip}: {e}")
            return None
        except Exception as e:
            logger.debug(f"Failed to probe {ip}: {e}")
            return None

    async def _get_node_resources(self, conn: asyncssh.SSHClientConnection) -> NodeResources:
        """Get resource information from a node via SSH."""
        resources = NodeResources()

        try:
            # CPU info
            result = await conn.run("nproc", check=False)
            if result.exit_status == 0:
                resources.cpu_cores = int(result.stdout.strip())

            result = await conn.run(
                "cat /proc/cpuinfo | grep 'model name' | head -1 | cut -d':' -f2",
                check=False
            )
            if result.exit_status == 0:
                resources.cpu_model = result.stdout.strip()

            # Memory info
            result = await conn.run(
                "free -m | grep Mem | awk '{print $2}'",
                check=False
            )
            if result.exit_status == 0:
                resources.memory_total_mb = int(result.stdout.strip())

            # Disk info
            result = await conn.run(
                "df -BG / | tail -1 | awk '{print $2}' | tr -d 'G'",
                check=False
            )
            if result.exit_status == 0:
                resources.disk_total_gb = float(result.stdout.strip())

        except Exception as e:
            logger.warning(f"Failed to get resources: {e}")

        return resources

    def _detect_rpi_generation(self, model: str) -> str:
        """Detect Raspberry Pi generation from model string."""
        model_lower = model.lower()
        if "pi 5" in model_lower:
            return "5"
        elif "pi 4" in model_lower:
            return "4"
        elif "pi 3" in model_lower:
            return "3"
        elif "pi 2" in model_lower:
            return "2"
        return "unknown"

    # =========================================================================
    # Node Management
    # =========================================================================

    async def register_node(self, node: ComputeNode) -> None:
        """Register a node with the cluster."""
        self._nodes[node.id] = node
        self._nodes_by_ip[node.ip_address] = node.id
        if node.hostname:
            self._nodes_by_hostname[node.hostname] = node.id

        await self._persist_nodes()
        logger.info(f"Registered node: {node.hostname} ({node.ip_address})")

    async def unregister_node(self, node_id: UUID) -> bool:
        """Unregister a node from the cluster."""
        node = self._nodes.get(node_id)
        if not node:
            return False

        del self._nodes[node_id]
        if node.ip_address in self._nodes_by_ip:
            del self._nodes_by_ip[node.ip_address]
        if node.hostname in self._nodes_by_hostname:
            del self._nodes_by_hostname[node.hostname]

        await self._persist_nodes()
        logger.info(f"Unregistered node: {node.hostname}")
        return True

    def get_node(self, identifier: str) -> Optional[ComputeNode]:
        """Get a node by IP, hostname, or UUID."""
        # Try as UUID
        try:
            uuid = UUID(identifier)
            return self._nodes.get(uuid)
        except ValueError:
            pass

        # Try as IP
        if identifier in self._nodes_by_ip:
            return self._nodes.get(self._nodes_by_ip[identifier])

        # Try as hostname
        if identifier in self._nodes_by_hostname:
            return self._nodes.get(self._nodes_by_hostname[identifier])

        return None

    def get_nodes(self, role: NodeRole = None, status: NodeStatus = None) -> list[ComputeNode]:
        """Get nodes filtered by role and/or status."""
        nodes = list(self._nodes.values())

        if role:
            nodes = [n for n in nodes if n.has_role(role)]
        if status:
            nodes = [n for n in nodes if n.status == status]

        return nodes

    def get_online_nodes(self) -> list[ComputeNode]:
        """Get all online nodes."""
        return self.get_nodes(status=NodeStatus.ONLINE)

    def get_raspberry_pis(self) -> list[ComputeNode]:
        """Get all Raspberry Pi nodes."""
        return [n for n in self._nodes.values() if n.is_raspberry_pi]

    # =========================================================================
    # Node Operations via SSH
    # =========================================================================

    async def execute_on_node(
        self,
        node: ComputeNode,
        command: str,
        timeout: int = 30
    ) -> tuple[int, str, str]:
        """
        Execute a command on a node via SSH.

        Args:
            node: Target node
            command: Command to execute
            timeout: Command timeout in seconds

        Returns:
            Tuple of (exit_code, stdout, stderr)
        """
        try:
            async with asyncssh.connect(
                node.ip_address,
                port=node.ssh_port,
                username=node.ssh_user,
                client_keys=[node.ssh_key_path] if node.ssh_key_path else None,
                password=self.ssh_password,
                known_hosts=None,
                connect_timeout=10
            ) as conn:
                result = await asyncio.wait_for(
                    conn.run(command, check=False),
                    timeout=timeout
                )
                return result.exit_status, result.stdout, result.stderr

        except Exception as e:
            logger.error(f"Failed to execute on {node.hostname}: {e}")
            return -1, "", str(e)

    async def execute_on_all(
        self,
        command: str,
        role: NodeRole = None,
        parallel: bool = True
    ) -> dict[str, tuple[int, str, str]]:
        """
        Execute a command on multiple nodes.

        Args:
            command: Command to execute
            role: Only execute on nodes with this role
            parallel: Execute in parallel (default True)

        Returns:
            Dict mapping hostname to (exit_code, stdout, stderr)
        """
        nodes = self.get_nodes(role=role, status=NodeStatus.ONLINE)
        results = {}

        if parallel:
            tasks = [
                self.execute_on_node(node, command)
                for node in nodes
            ]
            task_results = await asyncio.gather(*tasks, return_exceptions=True)

            for node, result in zip(nodes, task_results):
                if isinstance(result, Exception):
                    results[node.hostname] = (-1, "", str(result))
                else:
                    results[node.hostname] = result
        else:
            for node in nodes:
                results[node.hostname] = await self.execute_on_node(node, command)

        return results

    async def reboot_node(self, node: ComputeNode) -> bool:
        """Reboot a node."""
        exit_code, _, _ = await self.execute_on_node(node, "sudo reboot")
        if exit_code in [0, -1]:  # -1 because connection will drop
            node.status = NodeStatus.OFFLINE
            return True
        return False

    async def shutdown_node(self, node: ComputeNode) -> bool:
        """Shutdown a node."""
        exit_code, _, _ = await self.execute_on_node(node, "sudo shutdown now")
        if exit_code in [0, -1]:
            node.status = NodeStatus.OFFLINE
            return True
        return False

    # =========================================================================
    # Container Operations
    # =========================================================================

    async def deploy_container(
        self,
        node: ComputeNode,
        image: str,
        name: str,
        ports: dict[int, int] = None,
        environment: dict[str, str] = None,
        volumes: dict[str, str] = None,
        restart_policy: str = "unless-stopped"
    ) -> bool:
        """
        Deploy a Docker container on a node.

        Args:
            node: Target node
            image: Container image
            name: Container name
            ports: Port mappings {host_port: container_port}
            environment: Environment variables
            volumes: Volume mappings {host_path: container_path}
            restart_policy: Docker restart policy

        Returns:
            True if successful
        """
        cmd_parts = ["docker", "run", "-d", "--name", name]

        # Restart policy
        cmd_parts.extend(["--restart", restart_policy])

        # Ports
        if ports:
            for host_port, container_port in ports.items():
                cmd_parts.extend(["-p", f"{host_port}:{container_port}"])

        # Environment
        if environment:
            for key, value in environment.items():
                cmd_parts.extend(["-e", f"{key}={value}"])

        # Volumes
        if volumes:
            for host_path, container_path in volumes.items():
                cmd_parts.extend(["-v", f"{host_path}:{container_path}"])

        cmd_parts.append(image)
        command = " ".join(cmd_parts)

        exit_code, stdout, stderr = await self.execute_on_node(node, command)

        if exit_code == 0:
            logger.info(f"Deployed container {name} on {node.hostname}")
            return True
        else:
            logger.error(f"Failed to deploy container: {stderr}")
            return False

    async def stop_container(self, node: ComputeNode, name: str) -> bool:
        """Stop a container on a node."""
        exit_code, _, _ = await self.execute_on_node(node, f"docker stop {name}")
        return exit_code == 0

    async def remove_container(self, node: ComputeNode, name: str) -> bool:
        """Remove a container from a node."""
        exit_code, _, _ = await self.execute_on_node(
            node,
            f"docker rm -f {name}"
        )
        return exit_code == 0

    async def get_containers(self, node: ComputeNode) -> list[dict]:
        """Get list of containers on a node."""
        exit_code, stdout, _ = await self.execute_on_node(
            node,
            "docker ps -a --format '{{.ID}}|{{.Names}}|{{.Image}}|{{.Status}}'"
        )

        if exit_code != 0:
            return []

        containers = []
        for line in stdout.strip().split('\n'):
            if line:
                parts = line.split('|')
                if len(parts) >= 4:
                    containers.append({
                        "id": parts[0],
                        "name": parts[1],
                        "image": parts[2],
                        "status": parts[3]
                    })

        return containers

    # =========================================================================
    # k3s Operations
    # =========================================================================

    async def provision_k3s_server(self, node: ComputeNode) -> bool:
        """
        Provision a node as k3s server (control plane).

        Args:
            node: Target node

        Returns:
            True if successful
        """
        # Install k3s server
        install_cmd = (
            "curl -sfL https://get.k3s.io | "
            "sh -s - server --write-kubeconfig-mode=644"
        )

        exit_code, stdout, stderr = await self.execute_on_node(
            node, install_cmd, timeout=300
        )

        if exit_code != 0:
            logger.error(f"Failed to install k3s server: {stderr}")
            return False

        # Get the token for agents
        exit_code, token, _ = await self.execute_on_node(
            node, "sudo cat /var/lib/rancher/k3s/server/node-token"
        )

        if exit_code == 0:
            self.k3s_token = token.strip()
            self.k3s_server_url = f"https://{node.ip_address}:6443"

        node.add_role(NodeRole.CONTROLLER)
        node.k8s_version = "k3s"
        node.provisioned_at = utc_now()

        await self._persist_nodes()
        logger.info(f"Provisioned k3s server on {node.hostname}")

        return True

    async def provision_k3s_agent(self, node: ComputeNode) -> bool:
        """
        Provision a node as k3s agent (worker).

        Requires a k3s server to be already running.

        Args:
            node: Target node

        Returns:
            True if successful
        """
        if not self.k3s_server_url or not self.k3s_token:
            logger.error("No k3s server configured")
            return False

        # Install k3s agent
        install_cmd = (
            f"curl -sfL https://get.k3s.io | "
            f"K3S_URL={self.k3s_server_url} "
            f"K3S_TOKEN={self.k3s_token} "
            f"sh -s - agent"
        )

        exit_code, stdout, stderr = await self.execute_on_node(
            node, install_cmd, timeout=300
        )

        if exit_code != 0:
            logger.error(f"Failed to install k3s agent: {stderr}")
            return False

        node.add_role(NodeRole.WORKER)
        node.k8s_version = "k3s"
        node.provisioned_at = utc_now()

        await self._persist_nodes()
        logger.info(f"Provisioned k3s agent on {node.hostname}")

        return True

    # =========================================================================
    # Monitoring
    # =========================================================================

    async def _check_node_connectivity(self, node: ComputeNode) -> bool:
        """Check if a node is reachable via SSH."""
        try:
            async with asyncssh.connect(
                node.ip_address,
                port=node.ssh_port,
                username=node.ssh_user,
                client_keys=[node.ssh_key_path] if node.ssh_key_path else None,
                password=self.ssh_password,
                known_hosts=None,
                connect_timeout=5
            ) as conn:
                result = await conn.run("echo ok", check=True)
                return result.stdout.strip() == "ok"
        except Exception as e:
            logger.debug(f"Node connectivity check failed for {node.ip_address}: {e}")
            return False

    async def _get_node_metrics(self, node: ComputeNode) -> NodeMetrics:
        """Get current metrics from a node."""
        metrics = NodeMetrics()

        try:
            async with asyncssh.connect(
                node.ip_address,
                port=node.ssh_port,
                username=node.ssh_user,
                client_keys=[node.ssh_key_path] if node.ssh_key_path else None,
                password=self.ssh_password,
                known_hosts=None,
                connect_timeout=10
            ) as conn:
                # CPU usage
                result = await conn.run(
                    "top -bn1 | grep 'Cpu(s)' | awk '{print $2}' | cut -d'%' -f1",
                    check=False
                )
                if result.exit_status == 0:
                    try:
                        metrics.cpu_usage_percent = float(result.stdout.strip())
                    except ValueError:
                        pass

                # Memory usage
                result = await conn.run(
                    "free | grep Mem | awk '{print ($3/$2) * 100.0}'",
                    check=False
                )
                if result.exit_status == 0:
                    try:
                        metrics.memory_usage_percent = float(result.stdout.strip())
                    except ValueError:
                        pass

                # Temperature (for Raspberry Pi)
                result = await conn.run(
                    "cat /sys/class/thermal/thermal_zone0/temp 2>/dev/null",
                    check=False
                )
                if result.exit_status == 0:
                    try:
                        metrics.temperature_celsius = int(result.stdout.strip()) / 1000.0
                    except ValueError:
                        pass

                # Uptime
                result = await conn.run(
                    "cat /proc/uptime | awk '{print $1}'",
                    check=False
                )
                if result.exit_status == 0:
                    try:
                        metrics.uptime_seconds = int(float(result.stdout.strip()))
                    except ValueError:
                        pass

                # Load average
                result = await conn.run("cat /proc/loadavg", check=False)
                if result.exit_status == 0:
                    parts = result.stdout.strip().split()
                    if len(parts) >= 3:
                        metrics.load_average_1m = float(parts[0])
                        metrics.load_average_5m = float(parts[1])
                        metrics.load_average_15m = float(parts[2])

        except Exception as e:
            logger.warning(f"Failed to get metrics from {node.hostname}: {e}")

        return metrics

    async def _monitor_loop(self) -> None:
        """Background task to monitor nodes."""
        while True:
            try:
                await asyncio.sleep(60)  # Check every minute

                for node in self._nodes.values():
                    # Check connectivity
                    if await self._check_node_connectivity(node):
                        node.status = NodeStatus.ONLINE
                        node.last_seen = utc_now()

                        # Get metrics
                        metrics = await self._get_node_metrics(node)
                        node.update_metrics(metrics)
                    else:
                        if node.status == NodeStatus.ONLINE:
                            node.status = NodeStatus.OFFLINE
                            logger.warning(f"Node {node.hostname} went offline")

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Monitor loop error: {e}")

    async def _discovery_loop(self) -> None:
        """Background task for periodic node discovery."""
        while True:
            try:
                await asyncio.sleep(self.discovery_interval)
                await self.discover_nodes()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Discovery loop error: {e}")

    # =========================================================================
    # Persistence
    # =========================================================================

    async def _persist_nodes(self) -> None:
        """Save nodes to disk."""
        try:
            self.persistence_path.parent.mkdir(parents=True, exist_ok=True)

            data = {
                "nodes": [node.to_dict() for node in self._nodes.values()],
                "k3s_server_url": self.k3s_server_url,
                "k3s_token": self.k3s_token,
                "persisted_at": utc_now().isoformat()
            }

            with open(self.persistence_path, 'w') as f:
                json.dump(data, f, indent=2)

        except Exception as e:
            logger.error(f"Failed to persist nodes: {e}")

    async def _load_nodes(self) -> None:
        """Load nodes from disk."""
        try:
            if not self.persistence_path.exists():
                return

            with open(self.persistence_path, 'r') as f:
                data = json.load(f)

            self.k3s_server_url = data.get("k3s_server_url")
            self.k3s_token = data.get("k3s_token")

            for node_data in data.get("nodes", []):
                node = ComputeNode.from_dict(node_data)
                self._nodes[node.id] = node
                self._nodes_by_ip[node.ip_address] = node.id
                if node.hostname:
                    self._nodes_by_hostname[node.hostname] = node.id

            logger.info(f"Loaded {len(self._nodes)} nodes from persistence")

        except Exception as e:
            logger.error(f"Failed to load nodes: {e}")

    @property
    def stats(self) -> dict:
        """Get cluster statistics."""
        nodes = list(self._nodes.values())
        return {
            "total_nodes": len(nodes),
            "online_nodes": len([n for n in nodes if n.status == NodeStatus.ONLINE]),
            "offline_nodes": len([n for n in nodes if n.status == NodeStatus.OFFLINE]),
            "raspberry_pis": len([n for n in nodes if n.is_raspberry_pi]),
            "total_cpu_cores": sum(n.resources.cpu_cores for n in nodes),
            "total_memory_gb": sum(n.resources.memory_total_mb for n in nodes) / 1024,
            "total_storage_gb": sum(n.resources.disk_total_gb for n in nodes)
        }
