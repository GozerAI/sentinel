"""
Graph exporters for network topology visualization.

Provides export capabilities to various formats:
- JSON: For web frontends and APIs
- DOT: For Graphviz rendering
- D3: For D3.js interactive visualizations
- SVG: For static images
- Mermaid: For documentation
"""
import json
import html
import logging
from abc import ABC, abstractmethod
from typing import Optional, TextIO
from pathlib import Path

from sentinel.visualization.topology import (
    TopologyGraph,
    GraphNode,
    GraphEdge,
    NodeType,
    EdgeType,
    NODE_COLORS,
    EDGE_COLORS,
)

logger = logging.getLogger(__name__)


class GraphExporter(ABC):
    """Base class for graph exporters."""

    @abstractmethod
    def export(self, graph: TopologyGraph) -> str:
        """Export graph to string format."""
        pass

    def export_to_file(self, graph: TopologyGraph, path: str | Path) -> None:
        """Export graph to a file."""
        content = self.export(graph)
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)
        logger.info(f"Exported graph to {path}")


class JSONExporter(GraphExporter):
    """
    Export topology graph to JSON format.

    Produces JSON suitable for web frontends and APIs.
    Includes full node/edge data and graph metadata.

    Example output:
        {
            "name": "Network Topology",
            "nodes": [...],
            "edges": [...],
            "stats": {...}
        }
    """

    def __init__(self, indent: int = 2, include_positions: bool = True):
        """
        Initialize JSON exporter.

        Args:
            indent: JSON indentation (0 for compact)
            include_positions: Include x/y coordinates
        """
        self.indent = indent
        self.include_positions = include_positions

    def export(self, graph: TopologyGraph) -> str:
        """Export graph to JSON string."""
        data = graph.to_dict()

        if not self.include_positions:
            for node in data.get("nodes", []):
                node.pop("x", None)
                node.pop("y", None)

        return json.dumps(data, indent=self.indent if self.indent > 0 else None)

    def export_nodes_only(self, graph: TopologyGraph) -> str:
        """Export only nodes as JSON array."""
        nodes = [n.to_dict() for n in graph.nodes]
        return json.dumps(nodes, indent=self.indent if self.indent > 0 else None)

    def export_edges_only(self, graph: TopologyGraph) -> str:
        """Export only edges as JSON array."""
        edges = [e.to_dict() for e in graph.edges]
        return json.dumps(edges, indent=self.indent if self.indent > 0 else None)


class DOTExporter(GraphExporter):
    """
    Export topology graph to Graphviz DOT format.

    Produces DOT files that can be rendered with Graphviz tools
    (dot, neato, fdp, etc.) to create PNG, SVG, or PDF images.

    Example output:
        digraph NetworkTopology {
            rankdir=TB;
            node [shape=box];
            "gateway" [label="Gateway" color="#e74c3c"];
            "device1" [label="Server1"];
            "gateway" -> "device1";
        }
    """

    def __init__(
        self,
        directed: bool = False,
        rankdir: str = "TB",
        include_labels: bool = True,
        include_colors: bool = True,
        node_shape: str = "box",
        splines: str = "ortho",
    ):
        """
        Initialize DOT exporter.

        Args:
            directed: Use directed graph (digraph) vs undirected (graph)
            rankdir: Graph direction (TB=top-bottom, LR=left-right)
            include_labels: Include node labels
            include_colors: Include color attributes
            node_shape: Default node shape (box, ellipse, circle, etc.)
            splines: Edge routing (ortho, polyline, curved, etc.)
        """
        self.directed = directed
        self.rankdir = rankdir
        self.include_labels = include_labels
        self.include_colors = include_colors
        self.node_shape = node_shape
        self.splines = splines

    def export(self, graph: TopologyGraph) -> str:
        """Export graph to DOT format string."""
        lines = []

        # Graph declaration
        graph_type = "digraph" if self.directed else "graph"
        edge_op = "->" if self.directed else "--"

        lines.append(f'{graph_type} "{graph.name}" {{')

        # Graph attributes
        lines.append(f"    rankdir={self.rankdir};")
        lines.append(f"    splines={self.splines};")
        lines.append(f'    node [shape={self.node_shape}, fontname="Arial"];')
        lines.append(f'    edge [fontname="Arial", fontsize=10];')
        lines.append("")

        # Add subgraphs for VLANs
        vlan_groups = self._group_by_vlan(graph)

        for vlan, nodes in vlan_groups.items():
            if vlan is not None:
                lines.append(f'    subgraph cluster_vlan_{vlan} {{')
                lines.append(f'        label="VLAN {vlan}";')
                lines.append(f'        style=dashed;')
                lines.append(f'        color="#888888";')

                for node in nodes:
                    node_def = self._format_node(node)
                    lines.append(f"        {node_def}")

                lines.append("    }")
                lines.append("")
            else:
                # Nodes without VLAN
                for node in nodes:
                    node_def = self._format_node(node)
                    lines.append(f"    {node_def}")
                lines.append("")

        # Add edges
        lines.append("    // Edges")
        for edge in graph.edges:
            edge_def = self._format_edge(edge, edge_op)
            lines.append(f"    {edge_def}")

        lines.append("}")

        return "\n".join(lines)

    def _format_node(self, node: GraphNode) -> str:
        """Format a node for DOT output."""
        attrs = []

        if self.include_labels:
            label = html.escape(node.label)
            if node.ip_address:
                label += f"\\n{node.ip_address}"
            attrs.append(f'label="{label}"')

        if self.include_colors:
            attrs.append(f'color="{node.color}"')
            attrs.append(f'fillcolor="{node.color}20"')
            attrs.append("style=filled")

        # Special shapes for certain node types
        shape_map = {
            NodeType.ROUTER: "diamond",
            NodeType.SWITCH: "box",
            NodeType.SERVER: "box3d",
            NodeType.NAS: "cylinder",
            NodeType.WORKSTATION: "box",
            NodeType.LAPTOP: "note",
            NodeType.MOBILE: "ellipse",
            NodeType.IOT: "pentagon",
            NodeType.CAMERA: "octagon",
            NodeType.INTERNET: "cloud",
            NodeType.RASPBERRY_PI: "component",
        }

        if node.node_type in shape_map:
            attrs.append(f"shape={shape_map[node.node_type]}")

        attrs_str = ", ".join(attrs)
        node_id = self._safe_id(node.id)

        return f'"{node_id}" [{attrs_str}];'

    def _format_edge(self, edge: GraphEdge, edge_op: str) -> str:
        """Format an edge for DOT output."""
        attrs = []

        if edge.label:
            attrs.append(f'label="{html.escape(edge.label)}"')

        if self.include_colors:
            color = EDGE_COLORS.get(edge.status, "#999999")
            attrs.append(f'color="{color}"')

        # Edge style
        if edge.style == "dashed":
            attrs.append("style=dashed")
        elif edge.style == "dotted":
            attrs.append("style=dotted")

        # Animated edges get a special style
        if edge.animated:
            attrs.append("penwidth=2")

        attrs_str = ", ".join(attrs) if attrs else ""
        source_id = self._safe_id(edge.source)
        target_id = self._safe_id(edge.target)

        if attrs_str:
            return f'"{source_id}" {edge_op} "{target_id}" [{attrs_str}];'
        else:
            return f'"{source_id}" {edge_op} "{target_id}";'

    def _safe_id(self, node_id: str) -> str:
        """Make node ID safe for DOT format."""
        return node_id.replace("-", "_").replace(".", "_")

    def _group_by_vlan(self, graph: TopologyGraph) -> dict[Optional[int], list[GraphNode]]:
        """Group nodes by VLAN."""
        groups: dict[Optional[int], list[GraphNode]] = {}

        for node in graph.nodes:
            vlan = node.vlan
            if vlan not in groups:
                groups[vlan] = []
            groups[vlan].append(node)

        return groups


class D3Exporter(GraphExporter):
    """
    Export topology graph for D3.js visualization.

    Produces JSON structured specifically for D3.js force-directed
    graph layouts, with additional data for interactive features.

    Example output:
        {
            "nodes": [{"id": "...", "group": 1, "size": 10}],
            "links": [{"source": "...", "target": "...", "value": 1}]
        }
    """

    def __init__(
        self,
        node_size_by: str = "connections",
        link_strength_by: str = "bandwidth",
        include_groups: bool = True,
    ):
        """
        Initialize D3 exporter.

        Args:
            node_size_by: Property to determine node size (connections, type, fixed)
            link_strength_by: Property to determine link strength (bandwidth, fixed)
            include_groups: Include group numbers for coloring
        """
        self.node_size_by = node_size_by
        self.link_strength_by = link_strength_by
        self.include_groups = include_groups

    def export(self, graph: TopologyGraph) -> str:
        """Export graph to D3.js JSON format."""
        data = self._build_d3_data(graph)
        return json.dumps(data, indent=2)

    def _build_d3_data(self, graph: TopologyGraph) -> dict:
        """Build D3.js compatible data structure."""
        # Map node types to group numbers for coloring
        type_groups = {
            NodeType.INTERNET: 0,
            NodeType.ROUTER: 1,
            NodeType.SWITCH: 2,
            NodeType.FIREWALL: 3,
            NodeType.SERVER: 4,
            NodeType.NAS: 5,
            NodeType.WORKSTATION: 6,
            NodeType.LAPTOP: 7,
            NodeType.MOBILE: 8,
            NodeType.IOT: 9,
            NodeType.CAMERA: 10,
            NodeType.PRINTER: 11,
            NodeType.RASPBERRY_PI: 12,
            NodeType.VIRTUAL_MACHINE: 13,
            NodeType.CONTAINER: 14,
            NodeType.UNKNOWN: 15,
        }

        # Count connections for each node
        connection_counts = {}
        for edge in graph.edges:
            connection_counts[edge.source] = connection_counts.get(edge.source, 0) + 1
            connection_counts[edge.target] = connection_counts.get(edge.target, 0) + 1

        # Build nodes
        nodes = []
        for node in graph.nodes:
            d3_node = {
                "id": node.id,
                "label": node.label,
                "type": node.node_type.value,
                "ip": node.ip_address,
                "mac": node.mac_address,
                "status": node.status,
                "color": node.color,
            }

            # Calculate size
            if self.node_size_by == "connections":
                d3_node["size"] = 5 + connection_counts.get(node.id, 0) * 2
            elif self.node_size_by == "type":
                # Infrastructure nodes are larger
                if node.is_infrastructure or node.is_gateway:
                    d3_node["size"] = 15
                else:
                    d3_node["size"] = 8
            else:
                d3_node["size"] = 10

            # Add group for coloring
            if self.include_groups:
                d3_node["group"] = type_groups.get(node.node_type, 15)

            # Add VLAN info
            if node.vlan:
                d3_node["vlan"] = node.vlan

            # Fixed position for gateway/internet
            if node.is_gateway or node.node_type == NodeType.INTERNET:
                d3_node["fx"] = node.x
                d3_node["fy"] = node.y

            nodes.append(d3_node)

        # Build links (D3 uses "links" not "edges")
        links = []
        for edge in graph.edges:
            d3_link = {
                "source": edge.source,
                "target": edge.target,
                "type": edge.edge_type.value,
                "status": edge.status,
                "color": edge.color,
            }

            # Calculate link strength/value
            if self.link_strength_by == "bandwidth":
                d3_link["value"] = max(1, edge.bandwidth_mbps / 100)
            else:
                d3_link["value"] = 1

            if edge.label:
                d3_link["label"] = edge.label

            links.append(d3_link)

        return {
            "nodes": nodes,
            "links": links,
            "metadata": {
                "name": graph.name,
                "generated_at": graph.generated_at.isoformat(),
                "layout": graph.layout.value,
                "node_count": len(nodes),
                "link_count": len(links),
            },
        }

    def export_with_html(self, graph: TopologyGraph, title: str = "Network Topology") -> str:
        """
        Export complete HTML page with D3.js visualization.

        Returns a standalone HTML file that can be opened in a browser.
        """
        data = self._build_d3_data(graph)

        html_template = f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{html.escape(title)}</title>
    <script src="https://d3js.org/d3.v7.min.js"></script>
    <style>
        body {{
            font-family: Arial, sans-serif;
            margin: 0;
            padding: 0;
            background: #1a1a2e;
            color: #eee;
        }}
        #graph-container {{
            width: 100vw;
            height: 100vh;
        }}
        .node {{
            cursor: pointer;
        }}
        .node circle {{
            stroke: #fff;
            stroke-width: 2px;
        }}
        .node text {{
            font-size: 10px;
            fill: #fff;
            text-anchor: middle;
            dominant-baseline: central;
            pointer-events: none;
        }}
        .link {{
            stroke-opacity: 0.6;
        }}
        .tooltip {{
            position: absolute;
            background: rgba(0, 0, 0, 0.9);
            border: 1px solid #444;
            border-radius: 4px;
            padding: 10px;
            font-size: 12px;
            pointer-events: none;
            z-index: 1000;
        }}
        .tooltip .label {{ font-weight: bold; color: #3498db; }}
        .tooltip .ip {{ color: #2ecc71; }}
        .tooltip .type {{ color: #e74c3c; }}
        #legend {{
            position: absolute;
            top: 10px;
            right: 10px;
            background: rgba(0, 0, 0, 0.8);
            padding: 15px;
            border-radius: 5px;
            font-size: 12px;
        }}
        #legend h3 {{
            margin: 0 0 10px 0;
            font-size: 14px;
        }}
        .legend-item {{
            display: flex;
            align-items: center;
            margin: 5px 0;
        }}
        .legend-color {{
            width: 12px;
            height: 12px;
            border-radius: 50%;
            margin-right: 8px;
        }}
        #controls {{
            position: absolute;
            bottom: 10px;
            left: 10px;
            background: rgba(0, 0, 0, 0.8);
            padding: 10px;
            border-radius: 5px;
        }}
        #controls button {{
            margin: 2px;
            padding: 5px 10px;
            cursor: pointer;
        }}
    </style>
</head>
<body>
    <div id="graph-container"></div>

    <div id="legend">
        <h3>Node Types</h3>
        <div class="legend-item"><div class="legend-color" style="background: #e74c3c"></div>Router</div>
        <div class="legend-item"><div class="legend-color" style="background: #3498db"></div>Switch</div>
        <div class="legend-item"><div class="legend-color" style="background: #2ecc71"></div>Server</div>
        <div class="legend-item"><div class="legend-color" style="background: #1abc9c"></div>NAS</div>
        <div class="legend-item"><div class="legend-color" style="background: #c0392b"></div>Raspberry Pi</div>
        <div class="legend-item"><div class="legend-color" style="background: #95a5a6"></div>IoT Device</div>
        <div class="legend-item"><div class="legend-color" style="background: #bdc3c7"></div>Unknown</div>
    </div>

    <div id="controls">
        <button onclick="resetZoom()">Reset Zoom</button>
        <button onclick="toggleLabels()">Toggle Labels</button>
    </div>

    <script>
        const graphData = {json.dumps(data)};

        const width = window.innerWidth;
        const height = window.innerHeight;

        // Create SVG
        const svg = d3.select("#graph-container")
            .append("svg")
            .attr("width", width)
            .attr("height", height);

        // Add zoom behavior
        const g = svg.append("g");

        const zoom = d3.zoom()
            .scaleExtent([0.1, 10])
            .on("zoom", (event) => g.attr("transform", event.transform));

        svg.call(zoom);

        // Create force simulation
        const simulation = d3.forceSimulation(graphData.nodes)
            .force("link", d3.forceLink(graphData.links).id(d => d.id).distance(100))
            .force("charge", d3.forceManyBody().strength(-200))
            .force("center", d3.forceCenter(width / 2, height / 2))
            .force("collision", d3.forceCollide().radius(d => d.size + 5));

        // Create links
        const link = g.append("g")
            .attr("class", "links")
            .selectAll("line")
            .data(graphData.links)
            .enter()
            .append("line")
            .attr("class", "link")
            .attr("stroke", d => d.color || "#999")
            .attr("stroke-width", d => Math.sqrt(d.value));

        // Create nodes
        const node = g.append("g")
            .attr("class", "nodes")
            .selectAll(".node")
            .data(graphData.nodes)
            .enter()
            .append("g")
            .attr("class", "node")
            .call(d3.drag()
                .on("start", dragstarted)
                .on("drag", dragged)
                .on("end", dragended));

        // Node circles
        node.append("circle")
            .attr("r", d => d.size)
            .attr("fill", d => d.color);

        // Node labels
        let showLabels = true;
        const labels = node.append("text")
            .attr("dy", d => d.size + 12)
            .text(d => d.label);

        // Tooltip
        const tooltip = d3.select("body").append("div")
            .attr("class", "tooltip")
            .style("display", "none");

        node.on("mouseover", (event, d) => {{
            tooltip.style("display", "block")
                .html(`
                    <div class="label">${{d.label}}</div>
                    <div class="ip">IP: ${{d.ip || 'N/A'}}</div>
                    <div class="type">Type: ${{d.type}}</div>
                    ${{d.vlan ? `<div>VLAN: ${{d.vlan}}</div>` : ''}}
                    <div>Status: ${{d.status}}</div>
                `)
                .style("left", (event.pageX + 10) + "px")
                .style("top", (event.pageY + 10) + "px");
        }})
        .on("mouseout", () => tooltip.style("display", "none"));

        // Update positions on tick
        simulation.on("tick", () => {{
            link
                .attr("x1", d => d.source.x)
                .attr("y1", d => d.source.y)
                .attr("x2", d => d.target.x)
                .attr("y2", d => d.target.y);

            node.attr("transform", d => `translate(${{d.x}},${{d.y}})`);
        }});

        // Drag functions
        function dragstarted(event, d) {{
            if (!event.active) simulation.alphaTarget(0.3).restart();
            d.fx = d.x;
            d.fy = d.y;
        }}

        function dragged(event, d) {{
            d.fx = event.x;
            d.fy = event.y;
        }}

        function dragended(event, d) {{
            if (!event.active) simulation.alphaTarget(0);
            if (!d.fixed) {{
                d.fx = null;
                d.fy = null;
            }}
        }}

        // Control functions
        function resetZoom() {{
            svg.transition().duration(750).call(zoom.transform, d3.zoomIdentity);
        }}

        function toggleLabels() {{
            showLabels = !showLabels;
            labels.style("display", showLabels ? "block" : "none");
        }}
    </script>
</body>
</html>'''

        return html_template


class SVGExporter(GraphExporter):
    """
    Export topology graph to SVG format.

    Produces a static SVG image of the network topology
    that can be embedded in documents or viewed in browsers.
    """

    def __init__(
        self,
        width: int = 1200,
        height: int = 800,
        background: str = "#ffffff",
        font_family: str = "Arial, sans-serif",
    ):
        """
        Initialize SVG exporter.

        Args:
            width: SVG width in pixels
            height: SVG height in pixels
            background: Background color
            font_family: Font for labels
        """
        self.width = width
        self.height = height
        self.background = background
        self.font_family = font_family

    def export(self, graph: TopologyGraph) -> str:
        """Export graph to SVG string."""
        lines = [
            f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {self.width} {self.height}">',
            f'  <rect width="100%" height="100%" fill="{self.background}"/>',
            "",
            "  <!-- Edges -->",
            '  <g class="edges">',
        ]

        # Draw edges first (behind nodes)
        for edge in graph.edges:
            source = graph.get_node(edge.source)
            target = graph.get_node(edge.target)
            if source and target:
                stroke_dash = ""
                if edge.style == "dashed":
                    stroke_dash = 'stroke-dasharray="5,5"'
                elif edge.style == "dotted":
                    stroke_dash = 'stroke-dasharray="2,2"'

                lines.append(
                    f'    <line x1="{source.x}" y1="{source.y}" '
                    f'x2="{target.x}" y2="{target.y}" '
                    f'stroke="{edge.color}" stroke-width="{edge.width}" {stroke_dash}/>'
                )

        lines.extend([
            "  </g>",
            "",
            "  <!-- Nodes -->",
            '  <g class="nodes">',
        ])

        # Draw nodes
        for node in graph.nodes:
            radius = node.size * 5 + 10  # Scale up for visibility
            lines.append(f'    <g transform="translate({node.x},{node.y})">')

            # Node shape based on type
            if node.node_type == NodeType.ROUTER:
                # Diamond for router
                points = f"{0},{-radius} {radius},{0} {0},{radius} {-radius},{0}"
                lines.append(f'      <polygon points="{points}" fill="{node.color}" stroke="#fff" stroke-width="2"/>')
            elif node.node_type == NodeType.NAS:
                # Cylinder for storage
                lines.append(f'      <ellipse cx="0" cy="{-radius/2}" rx="{radius*0.8}" ry="{radius/4}" fill="{node.color}"/>')
                lines.append(f'      <rect x="{-radius*0.8}" y="{-radius/2}" width="{radius*1.6}" height="{radius}" fill="{node.color}"/>')
                lines.append(f'      <ellipse cx="0" cy="{radius/2}" rx="{radius*0.8}" ry="{radius/4}" fill="{node.color}" stroke="#fff" stroke-width="2"/>')
            else:
                # Circle for most nodes
                lines.append(f'      <circle r="{radius}" fill="{node.color}" stroke="#fff" stroke-width="2"/>')

            # Label
            label = html.escape(node.label[:15])  # Truncate long labels
            lines.append(f'      <text y="{radius + 15}" text-anchor="middle" '
                        f'font-family="{self.font_family}" font-size="10" fill="#333">{label}</text>')

            lines.append("    </g>")

        lines.extend([
            "  </g>",
            "</svg>",
        ])

        return "\n".join(lines)


class MermaidExporter(GraphExporter):
    """
    Export topology graph to Mermaid diagram format.

    Produces Mermaid flowchart syntax that can be embedded
    in Markdown documents and rendered by GitHub, GitLab, etc.

    Example output:
        ```mermaid
        flowchart TD
            gateway[Gateway]
            server1[Server 1]
            gateway --> server1
        ```
    """

    def __init__(self, direction: str = "TD", theme: str = "default"):
        """
        Initialize Mermaid exporter.

        Args:
            direction: Graph direction (TD=top-down, LR=left-right, etc.)
            theme: Mermaid theme
        """
        self.direction = direction
        self.theme = theme

    def export(self, graph: TopologyGraph) -> str:
        """Export graph to Mermaid format string."""
        lines = [f"flowchart {self.direction}"]

        # Define node shapes based on type
        shape_map = {
            NodeType.ROUTER: ("{{", "}}"),      # Hexagon
            NodeType.SWITCH: ("[", "]"),         # Rectangle
            NodeType.SERVER: ("([", "])"),       # Stadium
            NodeType.NAS: ("[(", ")]"),          # Cylinder
            NodeType.INTERNET: ("((", "))"),     # Circle
            NodeType.WORKSTATION: ("[", "]"),
            NodeType.IOT: (">", "]"),            # Asymmetric
        }

        default_shape = ("[", "]")

        # Add nodes with labels
        for node in graph.nodes:
            node_id = self._safe_id(node.id)
            label = node.label.replace('"', "'")

            shape = shape_map.get(node.node_type, default_shape)
            lines.append(f"    {node_id}{shape[0]}\"{label}\"{shape[1]}")

        lines.append("")

        # Add edges
        for edge in graph.edges:
            source_id = self._safe_id(edge.source)
            target_id = self._safe_id(edge.target)

            # Edge style based on status
            if edge.status == "down":
                arrow = "-.-x"
            elif edge.status == "degraded":
                arrow = "-.->|degraded|"
            else:
                arrow = "-->"

            if edge.label:
                lines.append(f"    {source_id} {arrow}|{edge.label}| {target_id}")
            else:
                lines.append(f"    {source_id} {arrow} {target_id}")

        return "\n".join(lines)

    def export_with_wrapper(self, graph: TopologyGraph) -> str:
        """Export with Markdown code fence wrapper."""
        content = self.export(graph)
        return f"```mermaid\n{content}\n```"

    def _safe_id(self, node_id: str) -> str:
        """Make node ID safe for Mermaid format."""
        return node_id.replace("-", "_").replace(".", "_").replace(" ", "_")


class CytoscapeExporter(GraphExporter):
    """
    Export topology graph to Cytoscape.js JSON format.

    Produces JSON suitable for the Cytoscape.js library,
    an alternative to D3 for network visualization.
    """

    def export(self, graph: TopologyGraph) -> str:
        """Export graph to Cytoscape.js format."""
        elements = []

        # Add nodes
        for node in graph.nodes:
            elements.append({
                "data": {
                    "id": node.id,
                    "label": node.label,
                    "type": node.node_type.value,
                    "ip": node.ip_address,
                    "mac": node.mac_address,
                    "vlan": node.vlan,
                    "status": node.status,
                    "color": node.color,
                },
                "position": {
                    "x": node.x,
                    "y": node.y,
                },
                "classes": [node.node_type.value, node.status],
            })

        # Add edges
        for edge in graph.edges:
            elements.append({
                "data": {
                    "id": edge.id,
                    "source": edge.source,
                    "target": edge.target,
                    "type": edge.edge_type.value,
                    "status": edge.status,
                    "color": edge.color,
                },
                "classes": [edge.edge_type.value, edge.status],
            })

        result = {
            "elements": elements,
            "style": self._get_default_style(),
            "layout": {
                "name": "preset",  # Use positions from data
            },
        }

        return json.dumps(result, indent=2)

    def _get_default_style(self) -> list:
        """Get default Cytoscape.js stylesheet."""
        return [
            {
                "selector": "node",
                "style": {
                    "label": "data(label)",
                    "background-color": "data(color)",
                    "text-valign": "bottom",
                    "text-margin-y": 5,
                },
            },
            {
                "selector": "edge",
                "style": {
                    "line-color": "data(color)",
                    "target-arrow-color": "data(color)",
                    "curve-style": "bezier",
                },
            },
            {
                "selector": ".router",
                "style": {"shape": "diamond"},
            },
            {
                "selector": ".server",
                "style": {"shape": "rectangle"},
            },
            {
                "selector": ".down",
                "style": {"opacity": 0.5, "line-style": "dashed"},
            },
        ]
