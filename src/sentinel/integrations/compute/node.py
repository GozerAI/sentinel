"""
Compute Node representation for Sentinel.

Represents a single compute node in a cluster, whether it's a
Raspberry Pi, server, or virtual machine.
"""
import asyncio
import logging
from enum import Enum
from typing import Optional, Any
from datetime import datetime
from dataclasses import dataclass, field
from uuid import UUID, uuid4

from sentinel.core.utils import utc_now

logger = logging.getLogger(__name__)


class NodeRole(Enum):
    """Roles a compute node can fulfill."""
    CONTROLLER = "controller"  # k3s server, cluster management
    WORKER = "worker"  # k3s agent, workload execution
    STORAGE = "storage"  # Distributed storage (Longhorn, etc.)
    MONITORING = "monitoring"  # Prometheus, Grafana
    GATEWAY = "gateway"  # Ingress, load balancer
    AGENT = "agent"  # Sentinel agent runner
    GENERAL = "general"  # General purpose compute


class NodeStatus(Enum):
    """Current status of a compute node."""
    UNKNOWN = "unknown"
    DISCOVERING = "discovering"
    ONLINE = "online"
    OFFLINE = "offline"
    DEGRADED = "degraded"
    PROVISIONING = "provisioning"
    DRAINING = "draining"
    MAINTENANCE = "maintenance"


@dataclass
class NodeResources:
    """Resource information for a compute node."""
    cpu_cores: int = 0
    cpu_model: str = ""
    cpu_frequency_mhz: int = 0
    memory_total_mb: int = 0
    memory_available_mb: int = 0
    disk_total_gb: float = 0
    disk_available_gb: float = 0
    gpu_model: str = ""
    gpu_memory_mb: int = 0


@dataclass
class NodeMetrics:
    """Current metrics for a compute node."""
    cpu_usage_percent: float = 0.0
    memory_usage_percent: float = 0.0
    disk_usage_percent: float = 0.0
    network_rx_bytes: int = 0
    network_tx_bytes: int = 0
    temperature_celsius: float = 0.0
    load_average_1m: float = 0.0
    load_average_5m: float = 0.0
    load_average_15m: float = 0.0
    uptime_seconds: int = 0
    timestamp: datetime = field(default_factory=utc_now)


@dataclass
class ComputeNode:
    """
    Represents a compute node in the Sentinel infrastructure.

    Can be a Raspberry Pi, server, VM, or any Linux-based compute unit.
    Sentinel manages these nodes for running agents, services, and workloads.

    Attributes:
        id: Unique identifier
        hostname: Node hostname
        ip_address: Primary IP address
        mac_address: MAC address for identification
        roles: Assigned roles for this node
        status: Current status
        resources: Hardware resources
        metrics: Current performance metrics
        labels: Key-value labels for categorization
        annotations: Additional metadata
    """

    id: UUID = field(default_factory=uuid4)
    hostname: str = ""
    ip_address: str = ""
    mac_address: str = ""
    model: str = ""  # e.g., "Raspberry Pi 5", "Threadripper Pro"
    os_version: str = ""

    roles: list[NodeRole] = field(default_factory=list)
    status: NodeStatus = NodeStatus.UNKNOWN
    resources: NodeResources = field(default_factory=NodeResources)
    metrics: NodeMetrics = field(default_factory=NodeMetrics)

    labels: dict[str, str] = field(default_factory=dict)
    annotations: dict[str, Any] = field(default_factory=dict)

    # SSH access (for provisioning and monitoring)
    ssh_user: str = "pi"
    ssh_port: int = 22
    ssh_key_path: Optional[str] = None

    # Timestamps
    discovered_at: datetime = field(default_factory=utc_now)
    last_seen: datetime = field(default_factory=utc_now)
    provisioned_at: Optional[datetime] = None

    # Container runtime
    container_runtime: str = ""  # docker, containerd, etc.
    k8s_version: str = ""
    k8s_node_name: str = ""

    def __post_init__(self):
        if not self.roles:
            self.roles = [NodeRole.GENERAL]

    def to_dict(self) -> dict:
        """Serialize node to dictionary."""
        return {
            "id": str(self.id),
            "hostname": self.hostname,
            "ip_address": self.ip_address,
            "mac_address": self.mac_address,
            "model": self.model,
            "os_version": self.os_version,
            "roles": [r.value for r in self.roles],
            "status": self.status.value,
            "resources": {
                "cpu_cores": self.resources.cpu_cores,
                "cpu_model": self.resources.cpu_model,
                "memory_total_mb": self.resources.memory_total_mb,
                "disk_total_gb": self.resources.disk_total_gb,
                "gpu_model": self.resources.gpu_model
            },
            "metrics": {
                "cpu_usage_percent": self.metrics.cpu_usage_percent,
                "memory_usage_percent": self.metrics.memory_usage_percent,
                "temperature_celsius": self.metrics.temperature_celsius,
                "uptime_seconds": self.metrics.uptime_seconds
            },
            "labels": self.labels,
            "last_seen": self.last_seen.isoformat(),
            "container_runtime": self.container_runtime,
            "k8s_version": self.k8s_version
        }

    @classmethod
    def from_dict(cls, data: dict) -> "ComputeNode":
        """Deserialize node from dictionary."""
        node = cls(
            id=UUID(data["id"]) if "id" in data else uuid4(),
            hostname=data.get("hostname", ""),
            ip_address=data.get("ip_address", ""),
            mac_address=data.get("mac_address", ""),
            model=data.get("model", ""),
            os_version=data.get("os_version", "")
        )

        if "roles" in data:
            node.roles = [NodeRole(r) for r in data["roles"]]
        if "status" in data:
            node.status = NodeStatus(data["status"])
        if "labels" in data:
            node.labels = data["labels"]

        return node

    @property
    def is_raspberry_pi(self) -> bool:
        """Check if this node is a Raspberry Pi."""
        return "raspberry" in self.model.lower() or "rpi" in self.model.lower()

    @property
    def is_healthy(self) -> bool:
        """Check if node is in a healthy state."""
        return self.status in [NodeStatus.ONLINE, NodeStatus.DEGRADED]

    @property
    def is_available(self) -> bool:
        """Check if node is available for workloads."""
        return self.status == NodeStatus.ONLINE

    def has_role(self, role: NodeRole) -> bool:
        """Check if node has a specific role."""
        return role in self.roles

    def add_role(self, role: NodeRole) -> None:
        """Add a role to this node."""
        if role not in self.roles:
            self.roles.append(role)

    def remove_role(self, role: NodeRole) -> None:
        """Remove a role from this node."""
        if role in self.roles:
            self.roles.remove(role)

    def update_metrics(self, metrics: NodeMetrics) -> None:
        """Update node metrics."""
        self.metrics = metrics
        self.last_seen = utc_now()

        # Update status based on metrics
        if metrics.cpu_usage_percent > 90 or metrics.memory_usage_percent > 90:
            self.status = NodeStatus.DEGRADED
        elif self.status == NodeStatus.DEGRADED:
            self.status = NodeStatus.ONLINE

    def __repr__(self) -> str:
        return f"ComputeNode({self.hostname}, {self.ip_address}, {self.status.value})"
