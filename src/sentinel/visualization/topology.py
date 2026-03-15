"""
Network topology visualization for Sentinel.

Generates interactive network topology graphs from discovered devices,
infrastructure, and their relationships.
"""
import logging
import math
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional, Any, TYPE_CHECKING
from uuid import UUID, uuid4

from sentinel.core.utils import utc_now

if TYPE_CHECKING:
    from sentinel.agents.discovery import DiscoveryAgent
    from sentinel.core.models.device import Device, DeviceType

logger = logging.getLogger(__name__)


class NodeType(Enum):
    """Types of nodes in the topology graph."""
    ROUTER = "router"
    SWITCH = "switch"
    ACCESS_POINT = "access_point"
    FIREWALL = "firewall"
    SERVER = "server"
    NAS = "nas"
    WORKSTATION = "workstation"
    LAPTOP = "laptop"
    MOBILE = "mobile"
    IOT = "iot"
    CAMERA = "camera"
    PRINTER = "printer"
    RASPBERRY_PI = "raspberry_pi"
    VIRTUAL_MACHINE = "vm"
    CONTAINER = "container"
    CLOUD = "cloud"
    INTERNET = "internet"
    UNKNOWN = "unknown"


class EdgeType(Enum):
    """Types of edges (connections) in the topology graph."""
    ETHERNET = "ethernet"
    WIFI = "wifi"
    FIBER = "fiber"
    VIRTUAL = "virtual"
    VPN = "vpn"
    TRUNK = "trunk"
    UPLINK = "uplink"
    UNKNOWN = "unknown"


class GraphLayout(Enum):
    """Layout algorithms for the graph."""
    HIERARCHICAL = "hierarchical"  # Tree-like, router at top
    FORCE_DIRECTED = "force_directed"  # Physics-based
    CIRCULAR = "circular"  # Nodes in a circle
    RADIAL = "radial"  # Concentric circles by hop count
    GRID = "grid"  # Grid layout by VLAN
    CUSTOM = "custom"  # User-defined positions


@dataclass
class GraphNode:
    """A node in the topology graph."""
    id: str
    label: str
    node_type: NodeType = NodeType.UNKNOWN

    # Device info
    ip_address: str = ""
    mac_address: str = ""
    hostname: str = ""
    vendor: str = ""

    # Network info
    vlan: Optional[int] = None
    subnet: str = ""

    # Status
    status: str = "unknown"  # online, offline, degraded
    is_infrastructure: bool = False
    is_gateway: bool = False

    # Visual properties
    x: float = 0.0
    y: float = 0.0
    size: float = 1.0
    color: str = "#666666"
    icon: str = ""
    group: str = ""

    # Metadata
    metadata: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "label": self.label,
            "type": self.node_type.value,
            "ip": self.ip_address,
            "mac": self.mac_address,
            "hostname": self.hostname,
            "vendor": self.vendor,
            "vlan": self.vlan,
            "subnet": self.subnet,
            "status": self.status,
            "is_infrastructure": self.is_infrastructure,
            "is_gateway": self.is_gateway,
            "x": self.x,
            "y": self.y,
            "size": self.size,
            "color": self.color,
            "icon": self.icon,
            "group": self.group,
            "metadata": self.metadata,
        }


@dataclass
class GraphEdge:
    """An edge (connection) in the topology graph."""
    id: str
    source: str  # Node ID
    target: str  # Node ID
    edge_type: EdgeType = EdgeType.UNKNOWN

    # Connection info
    port_source: str = ""
    port_target: str = ""
    bandwidth_mbps: float = 0.0
    latency_ms: float = 0.0

    # Status
    status: str = "unknown"  # up, down, degraded
    utilization_percent: float = 0.0

    # Visual properties
    width: float = 1.0
    color: str = "#999999"
    style: str = "solid"  # solid, dashed, dotted
    label: str = ""
    animated: bool = False

    # Metadata
    metadata: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "source": self.source,
            "target": self.target,
            "type": self.edge_type.value,
            "port_source": self.port_source,
            "port_target": self.port_target,
            "bandwidth_mbps": self.bandwidth_mbps,
            "latency_ms": self.latency_ms,
            "status": self.status,
            "utilization_percent": self.utilization_percent,
            "width": self.width,
            "color": self.color,
            "style": self.style,
            "label": self.label,
            "animated": self.animated,
            "metadata": self.metadata,
        }


@dataclass
class TopologyGraph:
    """Complete topology graph."""
    nodes: list[GraphNode] = field(default_factory=list)
    edges: list[GraphEdge] = field(default_factory=list)
    layout: GraphLayout = GraphLayout.HIERARCHICAL

    # Graph metadata
    name: str = "Network Topology"
    description: str = ""
    generated_at: datetime = field(default_factory=utc_now)

    # Bounds
    width: float = 1000.0
    height: float = 800.0

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "description": self.description,
            "generated_at": self.generated_at.isoformat(),
            "layout": self.layout.value,
            "width": self.width,
            "height": self.height,
            "nodes": [n.to_dict() for n in self.nodes],
            "edges": [e.to_dict() for e in self.edges],
            "stats": {
                "node_count": len(self.nodes),
                "edge_count": len(self.edges),
                "vlans": list(set(n.vlan for n in self.nodes if n.vlan)),
            }
        }

    def get_node(self, node_id: str) -> Optional[GraphNode]:
        """Get node by ID."""
        for node in self.nodes:
            if node.id == node_id:
                return node
        return None

    def get_edges_for_node(self, node_id: str) -> list[GraphEdge]:
        """Get all edges connected to a node."""
        return [e for e in self.edges if e.source == node_id or e.target == node_id]


# Color schemes for different node types
NODE_COLORS = {
    NodeType.ROUTER: "#e74c3c",      # Red
    NodeType.SWITCH: "#3498db",      # Blue
    NodeType.ACCESS_POINT: "#9b59b6", # Purple
    NodeType.FIREWALL: "#e67e22",     # Orange
    NodeType.SERVER: "#2ecc71",       # Green
    NodeType.NAS: "#1abc9c",          # Teal
    NodeType.WORKSTATION: "#34495e",  # Dark gray
    NodeType.LAPTOP: "#7f8c8d",       # Gray
    NodeType.MOBILE: "#f39c12",       # Yellow
    NodeType.IOT: "#95a5a6",          # Light gray
    NodeType.CAMERA: "#c0392b",       # Dark red
    NodeType.PRINTER: "#8e44ad",      # Dark purple
    NodeType.RASPBERRY_PI: "#c0392b", # Raspberry color
    NodeType.VIRTUAL_MACHINE: "#16a085", # Dark teal
    NodeType.CONTAINER: "#27ae60",    # Emerald
    NodeType.CLOUD: "#3498db",        # Blue
    NodeType.INTERNET: "#2c3e50",     # Dark blue
    NodeType.UNKNOWN: "#bdc3c7",      # Silver
}

# Edge colors by status
EDGE_COLORS = {
    "up": "#27ae60",      # Green
    "down": "#e74c3c",    # Red
    "degraded": "#f39c12", # Yellow
    "unknown": "#95a5a6",  # Gray
}


class TopologyVisualizer:
    """
    Generates network topology visualizations from Sentinel data.

    Features:
    - Build graph from discovery data
    - Multiple layout algorithms
    - VLAN-based grouping
    - Status-based coloring
    - Export to various formats

    Example:
        ```python
        visualizer = TopologyVisualizer()

        # Build from discovery agent
        graph = await visualizer.build_from_discovery(discovery_agent)

        # Apply layout
        visualizer.apply_layout(graph, GraphLayout.HIERARCHICAL)

        # Export
        json_data = visualizer.to_json(graph)
        svg_content = visualizer.to_svg(graph)
        ```
    """

    def __init__(self, config: dict = None):
        config = config or {}

        self.default_layout = GraphLayout(
            config.get("default_layout", "hierarchical")
        )
        self.include_offline = config.get("include_offline", True)
        self.group_by_vlan = config.get("group_by_vlan", True)

    async def build_from_discovery(
        self,
        discovery_agent: 'DiscoveryAgent',
        include_infrastructure: bool = True
    ) -> TopologyGraph:
        """
        Build topology graph from discovery agent data.

        Args:
            discovery_agent: The discovery agent with device inventory
            include_infrastructure: Include discovered infrastructure

        Returns:
            TopologyGraph with nodes and edges
        """
        graph = TopologyGraph(
            name="Network Topology",
            description=f"Generated from {len(discovery_agent.inventory.devices)} devices",
        )

        # Add gateway/router node (assumed to be at top)
        gateway = GraphNode(
            id="gateway",
            label="Gateway",
            node_type=NodeType.ROUTER,
            is_gateway=True,
            is_infrastructure=True,
            color=NODE_COLORS[NodeType.ROUTER],
        )
        graph.nodes.append(gateway)

        # Add internet node
        internet = GraphNode(
            id="internet",
            label="Internet",
            node_type=NodeType.INTERNET,
            color=NODE_COLORS[NodeType.INTERNET],
        )
        graph.nodes.append(internet)

        # Connect gateway to internet
        graph.edges.append(GraphEdge(
            id="gateway-internet",
            source="gateway",
            target="internet",
            edge_type=EdgeType.UPLINK,
            status="up",
            color=EDGE_COLORS["up"],
        ))

        # Add infrastructure devices
        if include_infrastructure:
            for ip, infra in discovery_agent.discovered_infrastructure.items():
                node = self._create_infrastructure_node(infra)
                graph.nodes.append(node)

                # Connect to gateway
                graph.edges.append(GraphEdge(
                    id=f"gateway-{node.id}",
                    source="gateway",
                    target=node.id,
                    edge_type=EdgeType.ETHERNET,
                    status="up",
                    color=EDGE_COLORS["up"],
                ))

        # Add devices from inventory
        for device in discovery_agent.inventory.devices.values():
            if not self.include_offline and device.status.value == "offline":
                continue

            node = self._create_device_node(device)
            graph.nodes.append(node)

            # Connect to gateway (or appropriate switch if known)
            graph.edges.append(GraphEdge(
                id=f"gateway-{node.id}",
                source="gateway",
                target=node.id,
                edge_type=EdgeType.ETHERNET,
                status="up" if device.status.value == "online" else "down",
                color=EDGE_COLORS.get(
                    "up" if device.status.value == "online" else "down",
                    EDGE_COLORS["unknown"]
                ),
            ))

        # Apply default layout
        self.apply_layout(graph, self.default_layout)

        return graph

    def _create_device_node(self, device: 'Device') -> GraphNode:
        """Create a graph node from a device."""
        from sentinel.core.models.device import DeviceType

        # Map DeviceType to NodeType
        type_map = {
            DeviceType.NETWORK: NodeType.SWITCH,
            DeviceType.SERVER: NodeType.SERVER,
            DeviceType.WORKSTATION: NodeType.WORKSTATION,
            DeviceType.STORAGE: NodeType.NAS,
            DeviceType.IOT: NodeType.IOT,
            DeviceType.CAMERA: NodeType.CAMERA,
            DeviceType.PRINTER: NodeType.PRINTER,
            DeviceType.MOBILE: NodeType.MOBILE,
            DeviceType.VIRTUAL_MACHINE: NodeType.VIRTUAL_MACHINE,
            DeviceType.CONTAINER: NodeType.CONTAINER,
        }

        node_type = type_map.get(device.device_type, NodeType.UNKNOWN)

        # Create label
        if device.hostname:
            label = device.hostname
        elif device.primary_ip:
            label = device.primary_ip
        else:
            label = device.primary_mac or "Unknown"

        return GraphNode(
            id=str(device.id),
            label=label,
            node_type=node_type,
            ip_address=device.primary_ip or "",
            mac_address=device.primary_mac or "",
            hostname=device.hostname or "",
            vendor=device.fingerprint.vendor or "",
            vlan=device.assigned_vlan,
            status=device.status.value,
            color=NODE_COLORS.get(node_type, NODE_COLORS[NodeType.UNKNOWN]),
            group=f"vlan_{device.assigned_vlan}" if device.assigned_vlan else "default",
            metadata={
                "device_type": device.device_type.value,
                "first_seen": device.first_seen.isoformat() if device.first_seen else None,
                "last_seen": device.last_seen.isoformat() if device.last_seen else None,
            }
        )

    def _create_infrastructure_node(self, infra: dict) -> GraphNode:
        """Create a graph node from infrastructure data."""
        infra_type = infra.get("type", "unknown")

        # Map infrastructure type to node type
        type_map = {
            "mikrotik": NodeType.ROUTER,
            "ubiquiti_unifi": NodeType.SWITCH,
            "synology_nas": NodeType.NAS,
            "qnap_nas": NodeType.NAS,
            "raspberry_pi": NodeType.RASPBERRY_PI,
            "proxmox": NodeType.SERVER,
            "esxi_vcenter": NodeType.SERVER,
            "truenas": NodeType.NAS,
            "mokerlink_switch": NodeType.SWITCH,
        }

        node_type = type_map.get(infra_type, NodeType.UNKNOWN)

        return GraphNode(
            id=f"infra-{infra.get('ip', uuid4())}",
            label=infra.get("hostname") or infra.get("ip", "Unknown"),
            node_type=node_type,
            ip_address=infra.get("ip", ""),
            mac_address=infra.get("mac", ""),
            hostname=infra.get("hostname", ""),
            is_infrastructure=True,
            status="online",
            color=NODE_COLORS.get(node_type, NODE_COLORS[NodeType.UNKNOWN]),
            group="infrastructure",
            metadata={
                "type": infra_type,
                "integration_type": infra.get("integration_type"),
                "confidence": infra.get("confidence", 0),
            }
        )

    def apply_layout(self, graph: TopologyGraph, layout: GraphLayout) -> None:
        """Apply a layout algorithm to position nodes."""
        graph.layout = layout

        if layout == GraphLayout.HIERARCHICAL:
            self._layout_hierarchical(graph)
        elif layout == GraphLayout.FORCE_DIRECTED:
            self._layout_force_directed(graph)
        elif layout == GraphLayout.CIRCULAR:
            self._layout_circular(graph)
        elif layout == GraphLayout.RADIAL:
            self._layout_radial(graph)
        elif layout == GraphLayout.GRID:
            self._layout_grid(graph)

    def _layout_hierarchical(self, graph: TopologyGraph) -> None:
        """Tree-like layout with gateway at top."""
        # Find gateway and internet nodes
        gateway = graph.get_node("gateway")
        internet = graph.get_node("internet")

        # Position internet and gateway at top
        if internet:
            internet.x = graph.width / 2
            internet.y = 50

        if gateway:
            gateway.x = graph.width / 2
            gateway.y = 150

        # Get other nodes and group by type
        other_nodes = [n for n in graph.nodes if n.id not in ["gateway", "internet"]]

        # Separate infrastructure and regular devices
        infra_nodes = [n for n in other_nodes if n.is_infrastructure]
        device_nodes = [n for n in other_nodes if not n.is_infrastructure]

        # Layout infrastructure in second row
        if infra_nodes:
            spacing = graph.width / (len(infra_nodes) + 1)
            for i, node in enumerate(infra_nodes):
                node.x = spacing * (i + 1)
                node.y = 280

        # Group devices by VLAN and layout in rows
        if self.group_by_vlan:
            vlan_groups: dict[Optional[int], list[GraphNode]] = {}
            for node in device_nodes:
                vlan = node.vlan
                if vlan not in vlan_groups:
                    vlan_groups[vlan] = []
                vlan_groups[vlan].append(node)

            y_pos = 400
            for vlan, nodes in sorted(vlan_groups.items(), key=lambda x: x[0] or 9999):
                spacing = graph.width / (len(nodes) + 1)
                for i, node in enumerate(nodes):
                    node.x = spacing * (i + 1)
                    node.y = y_pos
                y_pos += 120
        else:
            # Simple grid for all devices
            cols = int(math.ceil(math.sqrt(len(device_nodes))))
            spacing_x = graph.width / (cols + 1)
            spacing_y = 100

            for i, node in enumerate(device_nodes):
                col = i % cols
                row = i // cols
                node.x = spacing_x * (col + 1)
                node.y = 400 + spacing_y * row

    def _layout_force_directed(self, graph: TopologyGraph) -> None:
        """Physics-based force-directed layout."""
        # Simple spring-embedder simulation
        iterations = 50
        k = math.sqrt(graph.width * graph.height / len(graph.nodes))  # Optimal distance

        # Initialize random positions
        import random
        for node in graph.nodes:
            if node.id not in ["gateway", "internet"]:
                node.x = random.uniform(100, graph.width - 100)
                node.y = random.uniform(200, graph.height - 100)

        # Fix gateway and internet positions
        gateway = graph.get_node("gateway")
        internet = graph.get_node("internet")
        if internet:
            internet.x = graph.width / 2
            internet.y = 50
        if gateway:
            gateway.x = graph.width / 2
            gateway.y = 150

        # Run simulation
        for _ in range(iterations):
            # Calculate repulsive forces between all nodes
            for i, node1 in enumerate(graph.nodes):
                if node1.id in ["gateway", "internet"]:
                    continue
                for node2 in graph.nodes[i + 1:]:
                    if node2.id in ["gateway", "internet"]:
                        continue

                    dx = node1.x - node2.x
                    dy = node1.y - node2.y
                    dist = max(math.sqrt(dx * dx + dy * dy), 1)

                    # Repulsive force
                    force = k * k / dist
                    fx = dx / dist * force
                    fy = dy / dist * force

                    node1.x += fx * 0.1
                    node1.y += fy * 0.1
                    node2.x -= fx * 0.1
                    node2.y -= fy * 0.1

            # Calculate attractive forces along edges
            for edge in graph.edges:
                source = graph.get_node(edge.source)
                target = graph.get_node(edge.target)
                if not source or not target:
                    continue
                if source.id in ["gateway", "internet"] or target.id in ["gateway", "internet"]:
                    continue

                dx = target.x - source.x
                dy = target.y - source.y
                dist = max(math.sqrt(dx * dx + dy * dy), 1)

                # Attractive force
                force = dist / k
                fx = dx / dist * force
                fy = dy / dist * force

                source.x += fx * 0.1
                source.y += fy * 0.1
                target.x -= fx * 0.1
                target.y -= fy * 0.1

            # Keep nodes in bounds
            for node in graph.nodes:
                node.x = max(50, min(graph.width - 50, node.x))
                node.y = max(50, min(graph.height - 50, node.y))

    def _layout_circular(self, graph: TopologyGraph) -> None:
        """Nodes arranged in a circle."""
        center_x = graph.width / 2
        center_y = graph.height / 2
        radius = min(graph.width, graph.height) / 2 - 100

        # Gateway at center
        gateway = graph.get_node("gateway")
        if gateway:
            gateway.x = center_x
            gateway.y = center_y

        # Other nodes in circle
        other_nodes = [n for n in graph.nodes if n.id != "gateway"]
        angle_step = 2 * math.pi / max(len(other_nodes), 1)

        for i, node in enumerate(other_nodes):
            angle = i * angle_step - math.pi / 2  # Start from top
            node.x = center_x + radius * math.cos(angle)
            node.y = center_y + radius * math.sin(angle)

    def _layout_radial(self, graph: TopologyGraph) -> None:
        """Concentric circles by hop count from gateway."""
        center_x = graph.width / 2
        center_y = graph.height / 2

        # Gateway at center
        gateway = graph.get_node("gateway")
        if gateway:
            gateway.x = center_x
            gateway.y = center_y

        # Group nodes by their distance from gateway (hop count)
        # For now, simple: infrastructure = ring 1, devices = ring 2
        other_nodes = [n for n in graph.nodes if n.id not in ["gateway", "internet"]]
        infra_nodes = [n for n in other_nodes if n.is_infrastructure]
        device_nodes = [n for n in other_nodes if not n.is_infrastructure]

        # Internet above
        internet = graph.get_node("internet")
        if internet:
            internet.x = center_x
            internet.y = 50

        # Ring 1: Infrastructure
        radius1 = 150
        if infra_nodes:
            angle_step = 2 * math.pi / len(infra_nodes)
            for i, node in enumerate(infra_nodes):
                angle = i * angle_step - math.pi / 2
                node.x = center_x + radius1 * math.cos(angle)
                node.y = center_y + radius1 * math.sin(angle)

        # Ring 2: Devices
        radius2 = 300
        if device_nodes:
            angle_step = 2 * math.pi / len(device_nodes)
            for i, node in enumerate(device_nodes):
                angle = i * angle_step - math.pi / 2
                node.x = center_x + radius2 * math.cos(angle)
                node.y = center_y + radius2 * math.sin(angle)

    def _layout_grid(self, graph: TopologyGraph) -> None:
        """Grid layout grouped by VLAN."""
        # Similar to hierarchical but strictly grid-based
        self._layout_hierarchical(graph)

    def to_json(self, graph: TopologyGraph) -> dict:
        """Export graph to JSON format."""
        return graph.to_dict()

    def get_vlan_summary(self, graph: TopologyGraph) -> dict:
        """Get summary of VLANs in the graph."""
        vlan_summary = {}

        for node in graph.nodes:
            vlan = node.vlan or "unassigned"
            if vlan not in vlan_summary:
                vlan_summary[vlan] = {
                    "count": 0,
                    "nodes": [],
                    "types": {},
                }

            vlan_summary[vlan]["count"] += 1
            vlan_summary[vlan]["nodes"].append(node.id)

            node_type = node.node_type.value
            if node_type not in vlan_summary[vlan]["types"]:
                vlan_summary[vlan]["types"][node_type] = 0
            vlan_summary[vlan]["types"][node_type] += 1

        return vlan_summary

    def get_node_connections(self, graph: TopologyGraph, node_id: str) -> dict:
        """Get all connections for a specific node."""
        edges = graph.get_edges_for_node(node_id)

        connections = {
            "node_id": node_id,
            "total_connections": len(edges),
            "inbound": [],
            "outbound": [],
        }

        for edge in edges:
            if edge.target == node_id:
                connections["inbound"].append({
                    "from": edge.source,
                    "type": edge.edge_type.value,
                    "status": edge.status,
                })
            else:
                connections["outbound"].append({
                    "to": edge.target,
                    "type": edge.edge_type.value,
                    "status": edge.status,
                })

        return connections
