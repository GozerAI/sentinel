"""
Tests for network visualization module.

Tests cover topology generation, layout algorithms, and export formats.
"""

import json
import pytest
from datetime import datetime
from unittest.mock import MagicMock, AsyncMock, patch
from uuid import uuid4

from sentinel.visualization.topology import (
    TopologyVisualizer,
    TopologyGraph,
    GraphNode,
    GraphEdge,
    GraphLayout,
    NodeType,
    EdgeType,
    NODE_COLORS,
    EDGE_COLORS,
)
from sentinel.visualization.exporters import (
    JSONExporter,
    DOTExporter,
    D3Exporter,
    SVGExporter,
    MermaidExporter,
    CytoscapeExporter,
)


# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def sample_graph():
    """Create a sample topology graph for testing."""
    graph = TopologyGraph(
        name="Test Topology",
        description="Test network",
    )

    # Add nodes
    gateway = GraphNode(
        id="gateway",
        label="Gateway Router",
        node_type=NodeType.ROUTER,
        ip_address="192.168.1.1",
        is_gateway=True,
        is_infrastructure=True,
        color=NODE_COLORS[NodeType.ROUTER],
    )
    graph.nodes.append(gateway)

    internet = GraphNode(
        id="internet",
        label="Internet",
        node_type=NodeType.INTERNET,
        color=NODE_COLORS[NodeType.INTERNET],
    )
    graph.nodes.append(internet)

    server = GraphNode(
        id="server1",
        label="Web Server",
        node_type=NodeType.SERVER,
        ip_address="192.168.1.10",
        vlan=100,
        color=NODE_COLORS[NodeType.SERVER],
    )
    graph.nodes.append(server)

    nas = GraphNode(
        id="nas1",
        label="NAS Storage",
        node_type=NodeType.NAS,
        ip_address="192.168.1.20",
        vlan=100,
        color=NODE_COLORS[NodeType.NAS],
    )
    graph.nodes.append(nas)

    iot = GraphNode(
        id="iot1",
        label="Smart Camera",
        node_type=NodeType.CAMERA,
        ip_address="192.168.50.10",
        vlan=50,
        color=NODE_COLORS[NodeType.CAMERA],
    )
    graph.nodes.append(iot)

    # Add edges
    graph.edges.append(
        GraphEdge(
            id="gateway-internet",
            source="gateway",
            target="internet",
            edge_type=EdgeType.UPLINK,
            status="up",
            color=EDGE_COLORS["up"],
        )
    )

    graph.edges.append(
        GraphEdge(
            id="gateway-server1",
            source="gateway",
            target="server1",
            edge_type=EdgeType.ETHERNET,
            status="up",
            bandwidth_mbps=1000,
            color=EDGE_COLORS["up"],
        )
    )

    graph.edges.append(
        GraphEdge(
            id="gateway-nas1",
            source="gateway",
            target="nas1",
            edge_type=EdgeType.ETHERNET,
            status="up",
            bandwidth_mbps=10000,
            color=EDGE_COLORS["up"],
        )
    )

    graph.edges.append(
        GraphEdge(
            id="gateway-iot1",
            source="gateway",
            target="iot1",
            edge_type=EdgeType.WIFI,
            status="up",
            color=EDGE_COLORS["up"],
        )
    )

    return graph


@pytest.fixture
def mock_discovery_agent():
    """Create a mock discovery agent with devices."""
    agent = MagicMock()
    agent.inventory = MagicMock()
    agent.inventory.devices = {}
    agent.discovered_infrastructure = {}
    return agent


@pytest.fixture
def visualizer():
    """Create a topology visualizer."""
    return TopologyVisualizer()


# =============================================================================
# Tests - GraphNode
# =============================================================================


class TestGraphNode:
    """Tests for GraphNode dataclass."""

    def test_node_creation(self):
        """Test creating a graph node."""
        node = GraphNode(
            id="test-node",
            label="Test Node",
            node_type=NodeType.SERVER,
        )
        assert node.id == "test-node"
        assert node.label == "Test Node"
        assert node.node_type == NodeType.SERVER

    def test_node_defaults(self):
        """Test default values."""
        node = GraphNode(id="test", label="Test")
        assert node.node_type == NodeType.UNKNOWN
        assert node.ip_address == ""
        assert node.mac_address == ""
        assert node.vlan is None
        assert node.status == "unknown"
        assert node.is_infrastructure is False
        assert node.is_gateway is False
        assert node.x == 0.0
        assert node.y == 0.0

    def test_node_to_dict(self):
        """Test node serialization."""
        node = GraphNode(
            id="test",
            label="Test",
            node_type=NodeType.SERVER,
            ip_address="192.168.1.1",
            vlan=100,
        )
        data = node.to_dict()

        assert data["id"] == "test"
        assert data["label"] == "Test"
        assert data["type"] == "server"
        assert data["ip"] == "192.168.1.1"
        assert data["vlan"] == 100


# =============================================================================
# Tests - GraphEdge
# =============================================================================


class TestGraphEdge:
    """Tests for GraphEdge dataclass."""

    def test_edge_creation(self):
        """Test creating a graph edge."""
        edge = GraphEdge(
            id="edge1",
            source="node1",
            target="node2",
        )
        assert edge.id == "edge1"
        assert edge.source == "node1"
        assert edge.target == "node2"

    def test_edge_defaults(self):
        """Test default values."""
        edge = GraphEdge(id="test", source="a", target="b")
        assert edge.edge_type == EdgeType.UNKNOWN
        assert edge.bandwidth_mbps == 0.0
        assert edge.status == "unknown"
        assert edge.style == "solid"

    def test_edge_to_dict(self):
        """Test edge serialization."""
        edge = GraphEdge(
            id="edge1",
            source="node1",
            target="node2",
            edge_type=EdgeType.ETHERNET,
            bandwidth_mbps=1000,
            status="up",
        )
        data = edge.to_dict()

        assert data["id"] == "edge1"
        assert data["source"] == "node1"
        assert data["target"] == "node2"
        assert data["type"] == "ethernet"
        assert data["bandwidth_mbps"] == 1000


# =============================================================================
# Tests - TopologyGraph
# =============================================================================


class TestTopologyGraph:
    """Tests for TopologyGraph dataclass."""

    def test_graph_creation(self, sample_graph):
        """Test graph creation."""
        assert sample_graph.name == "Test Topology"
        assert len(sample_graph.nodes) == 5
        assert len(sample_graph.edges) == 4

    def test_get_node(self, sample_graph):
        """Test getting node by ID."""
        node = sample_graph.get_node("gateway")
        assert node is not None
        assert node.id == "gateway"

        # Non-existent node
        assert sample_graph.get_node("nonexistent") is None

    def test_get_edges_for_node(self, sample_graph):
        """Test getting edges for a node."""
        edges = sample_graph.get_edges_for_node("gateway")
        assert len(edges) == 4  # Connected to all other nodes

        edges = sample_graph.get_edges_for_node("server1")
        assert len(edges) == 1

    def test_to_dict(self, sample_graph):
        """Test graph serialization."""
        data = sample_graph.to_dict()

        assert data["name"] == "Test Topology"
        assert data["layout"] == "hierarchical"
        assert len(data["nodes"]) == 5
        assert len(data["edges"]) == 4
        assert "stats" in data
        assert data["stats"]["node_count"] == 5
        assert data["stats"]["edge_count"] == 4


# =============================================================================
# Tests - TopologyVisualizer
# =============================================================================


class TestTopologyVisualizer:
    """Tests for TopologyVisualizer."""

    def test_visualizer_creation(self, visualizer):
        """Test visualizer creation."""
        assert visualizer.default_layout == GraphLayout.HIERARCHICAL
        assert visualizer.include_offline is True
        assert visualizer.group_by_vlan is True

    def test_visualizer_custom_config(self):
        """Test visualizer with custom config."""
        visualizer = TopologyVisualizer(
            {
                "default_layout": "circular",
                "include_offline": False,
                "group_by_vlan": False,
            }
        )
        assert visualizer.default_layout == GraphLayout.CIRCULAR
        assert visualizer.include_offline is False
        assert visualizer.group_by_vlan is False

    @pytest.mark.asyncio
    async def test_build_from_discovery(self, visualizer, mock_discovery_agent):
        """Test building graph from discovery agent."""
        graph = await visualizer.build_from_discovery(mock_discovery_agent)

        # Should have at least gateway and internet nodes
        assert len(graph.nodes) >= 2
        assert graph.get_node("gateway") is not None
        assert graph.get_node("internet") is not None

    def test_to_json(self, visualizer, sample_graph):
        """Test JSON export."""
        data = visualizer.to_json(sample_graph)
        assert isinstance(data, dict)
        assert "nodes" in data
        assert "edges" in data

    def test_get_vlan_summary(self, visualizer, sample_graph):
        """Test VLAN summary generation."""
        summary = visualizer.get_vlan_summary(sample_graph)

        # Should have VLAN 100, 50, and unassigned
        assert 100 in summary or "100" in summary
        assert 50 in summary or "50" in summary
        assert None in summary or "unassigned" in summary

    def test_get_node_connections(self, visualizer, sample_graph):
        """Test node connection retrieval."""
        connections = visualizer.get_node_connections(sample_graph, "gateway")

        assert connections["node_id"] == "gateway"
        assert connections["total_connections"] == 4


# =============================================================================
# Tests - Layout Algorithms
# =============================================================================


class TestLayoutAlgorithms:
    """Tests for layout algorithms."""

    def test_hierarchical_layout(self, visualizer, sample_graph):
        """Test hierarchical layout."""
        visualizer.apply_layout(sample_graph, GraphLayout.HIERARCHICAL)

        # Gateway should be near top
        gateway = sample_graph.get_node("gateway")
        server = sample_graph.get_node("server1")

        assert gateway.y < server.y  # Gateway above server

    def test_circular_layout(self, visualizer, sample_graph):
        """Test circular layout."""
        visualizer.apply_layout(sample_graph, GraphLayout.CIRCULAR)

        # All nodes should have positions
        for node in sample_graph.nodes:
            assert node.x != 0 or node.y != 0

    def test_radial_layout(self, visualizer, sample_graph):
        """Test radial layout."""
        visualizer.apply_layout(sample_graph, GraphLayout.RADIAL)

        # Gateway should be near center
        gateway = sample_graph.get_node("gateway")
        center_x = sample_graph.width / 2
        center_y = sample_graph.height / 2

        # Gateway should be close to center
        assert abs(gateway.x - center_x) < 50
        assert abs(gateway.y - center_y) < 50

    def test_force_directed_layout(self, visualizer, sample_graph):
        """Test force-directed layout."""
        visualizer.apply_layout(sample_graph, GraphLayout.FORCE_DIRECTED)

        # Nodes should be within bounds
        for node in sample_graph.nodes:
            assert 0 <= node.x <= sample_graph.width
            assert 0 <= node.y <= sample_graph.height

    def test_grid_layout(self, visualizer, sample_graph):
        """Test grid layout."""
        visualizer.apply_layout(sample_graph, GraphLayout.GRID)

        # All nodes should have positions
        for node in sample_graph.nodes:
            assert node.x >= 0
            assert node.y >= 0


# =============================================================================
# Tests - JSONExporter
# =============================================================================


class TestJSONExporter:
    """Tests for JSON exporter."""

    def test_export_json(self, sample_graph):
        """Test JSON export."""
        exporter = JSONExporter()
        result = exporter.export(sample_graph)

        data = json.loads(result)
        assert "nodes" in data
        assert "edges" in data
        assert len(data["nodes"]) == 5

    def test_export_compact(self, sample_graph):
        """Test compact JSON export."""
        exporter = JSONExporter(indent=0)
        result = exporter.export(sample_graph)

        # Should not have newlines in compact mode
        assert result.count("\n") == 0

    def test_export_without_positions(self, sample_graph):
        """Test JSON export without positions."""
        exporter = JSONExporter(include_positions=False)
        result = exporter.export(sample_graph)

        data = json.loads(result)
        for node in data["nodes"]:
            assert "x" not in node
            assert "y" not in node

    def test_export_nodes_only(self, sample_graph):
        """Test exporting only nodes."""
        exporter = JSONExporter()
        result = exporter.export_nodes_only(sample_graph)

        data = json.loads(result)
        assert isinstance(data, list)
        assert len(data) == 5

    def test_export_edges_only(self, sample_graph):
        """Test exporting only edges."""
        exporter = JSONExporter()
        result = exporter.export_edges_only(sample_graph)

        data = json.loads(result)
        assert isinstance(data, list)
        assert len(data) == 4


# =============================================================================
# Tests - DOTExporter
# =============================================================================


class TestDOTExporter:
    """Tests for Graphviz DOT exporter."""

    def test_export_dot(self, sample_graph):
        """Test DOT export."""
        exporter = DOTExporter()
        result = exporter.export(sample_graph)

        assert "graph" in result or "digraph" in result
        assert "gateway" in result
        assert "server1" in result

    def test_export_directed(self, sample_graph):
        """Test directed graph export."""
        exporter = DOTExporter(directed=True)
        result = exporter.export(sample_graph)

        assert "digraph" in result
        assert "->" in result

    def test_export_undirected(self, sample_graph):
        """Test undirected graph export."""
        exporter = DOTExporter(directed=False)
        result = exporter.export(sample_graph)

        assert "graph" in result
        assert "--" in result

    def test_export_with_colors(self, sample_graph):
        """Test DOT export with colors."""
        exporter = DOTExporter(include_colors=True)
        result = exporter.export(sample_graph)

        assert "color=" in result
        assert "fillcolor=" in result

    def test_export_without_colors(self, sample_graph):
        """Test DOT export without colors."""
        exporter = DOTExporter(include_colors=False)
        result = exporter.export(sample_graph)

        assert "fillcolor=" not in result

    def test_vlan_subgraphs(self, sample_graph):
        """Test VLAN subgraph generation."""
        exporter = DOTExporter()
        result = exporter.export(sample_graph)

        # Should have subgraph for VLAN 100
        assert "cluster_vlan_100" in result


# =============================================================================
# Tests - D3Exporter
# =============================================================================


class TestD3Exporter:
    """Tests for D3.js exporter."""

    def test_export_d3(self, sample_graph):
        """Test D3 export."""
        exporter = D3Exporter()
        result = exporter.export(sample_graph)

        data = json.loads(result)
        assert "nodes" in data
        assert "links" in data  # D3 uses "links" not "edges"
        assert "metadata" in data

    def test_d3_node_structure(self, sample_graph):
        """Test D3 node structure."""
        exporter = D3Exporter()
        result = exporter.export(sample_graph)

        data = json.loads(result)
        node = data["nodes"][0]

        assert "id" in node
        assert "label" in node
        assert "type" in node
        assert "size" in node
        assert "group" in node

    def test_d3_link_structure(self, sample_graph):
        """Test D3 link structure."""
        exporter = D3Exporter()
        result = exporter.export(sample_graph)

        data = json.loads(result)
        link = data["links"][0]

        assert "source" in link
        assert "target" in link
        assert "value" in link

    def test_d3_node_size_by_connections(self, sample_graph):
        """Test node sizing by connection count."""
        exporter = D3Exporter(node_size_by="connections")
        result = exporter.export(sample_graph)

        data = json.loads(result)
        # Gateway should be largest (4 connections)
        gateway = next(n for n in data["nodes"] if n["id"] == "gateway")
        server = next(n for n in data["nodes"] if n["id"] == "server1")

        assert gateway["size"] > server["size"]

    def test_d3_html_export(self, sample_graph):
        """Test complete HTML export."""
        exporter = D3Exporter()
        result = exporter.export_with_html(sample_graph, title="Test Graph")

        assert "<!DOCTYPE html>" in result
        assert "<title>Test Graph</title>" in result
        assert "d3.v7.min.js" in result
        assert "force" in result  # Force simulation


# =============================================================================
# Tests - SVGExporter
# =============================================================================


class TestSVGExporter:
    """Tests for SVG exporter."""

    def test_export_svg(self, sample_graph):
        """Test SVG export."""
        # Apply layout first
        visualizer = TopologyVisualizer()
        visualizer.apply_layout(sample_graph, GraphLayout.HIERARCHICAL)

        exporter = SVGExporter()
        result = exporter.export(sample_graph)

        assert "<svg" in result
        assert "</svg>" in result
        assert "xmlns" in result

    def test_svg_dimensions(self, sample_graph):
        """Test SVG dimensions."""
        visualizer = TopologyVisualizer()
        visualizer.apply_layout(sample_graph, GraphLayout.HIERARCHICAL)

        exporter = SVGExporter(width=800, height=600)
        result = exporter.export(sample_graph)

        assert 'viewBox="0 0 800 600"' in result

    def test_svg_background(self, sample_graph):
        """Test SVG background color."""
        visualizer = TopologyVisualizer()
        visualizer.apply_layout(sample_graph, GraphLayout.HIERARCHICAL)

        exporter = SVGExporter(background="#f0f0f0")
        result = exporter.export(sample_graph)

        assert "#f0f0f0" in result

    def test_svg_contains_nodes(self, sample_graph):
        """Test that SVG contains node representations."""
        visualizer = TopologyVisualizer()
        visualizer.apply_layout(sample_graph, GraphLayout.HIERARCHICAL)

        exporter = SVGExporter()
        result = exporter.export(sample_graph)

        # Should have circle, polygon, or other shape elements
        assert "<circle" in result or "<polygon" in result


# =============================================================================
# Tests - MermaidExporter
# =============================================================================


class TestMermaidExporter:
    """Tests for Mermaid exporter."""

    def test_export_mermaid(self, sample_graph):
        """Test Mermaid export."""
        exporter = MermaidExporter()
        result = exporter.export(sample_graph)

        assert "flowchart" in result
        assert "gateway" in result
        assert "-->" in result

    def test_mermaid_direction(self, sample_graph):
        """Test Mermaid direction."""
        exporter = MermaidExporter(direction="LR")
        result = exporter.export(sample_graph)

        assert "flowchart LR" in result

    def test_mermaid_with_wrapper(self, sample_graph):
        """Test Mermaid with code fence wrapper."""
        exporter = MermaidExporter()
        result = exporter.export_with_wrapper(sample_graph)

        assert result.startswith("```mermaid\n")
        assert result.endswith("\n```")


# =============================================================================
# Tests - CytoscapeExporter
# =============================================================================


class TestCytoscapeExporter:
    """Tests for Cytoscape.js exporter."""

    def test_export_cytoscape(self, sample_graph):
        """Test Cytoscape export."""
        visualizer = TopologyVisualizer()
        visualizer.apply_layout(sample_graph, GraphLayout.HIERARCHICAL)

        exporter = CytoscapeExporter()
        result = exporter.export(sample_graph)

        data = json.loads(result)
        assert "elements" in data
        assert "style" in data
        assert "layout" in data

    def test_cytoscape_element_structure(self, sample_graph):
        """Test Cytoscape element structure."""
        visualizer = TopologyVisualizer()
        visualizer.apply_layout(sample_graph, GraphLayout.HIERARCHICAL)

        exporter = CytoscapeExporter()
        result = exporter.export(sample_graph)

        data = json.loads(result)
        elements = data["elements"]

        # Find a node element
        node_element = next(e for e in elements if "position" in e)

        assert "data" in node_element
        assert "position" in node_element
        assert "classes" in node_element


# =============================================================================
# Tests - Export to File
# =============================================================================


class TestExportToFile:
    """Tests for file export functionality."""

    def test_export_to_file(self, sample_graph, tmp_path):
        """Test exporting to file."""
        exporter = JSONExporter()
        file_path = tmp_path / "topology.json"

        exporter.export_to_file(sample_graph, file_path)

        assert file_path.exists()
        with open(file_path) as f:
            data = json.load(f)
        assert len(data["nodes"]) == 5


# =============================================================================
# Tests - Node Type Colors
# =============================================================================


class TestNodeColors:
    """Tests for node color mappings."""

    def test_all_node_types_have_colors(self):
        """Test that all node types have color mappings."""
        for node_type in NodeType:
            assert node_type in NODE_COLORS, f"Missing color for {node_type}"

    def test_edge_status_colors(self):
        """Test edge status colors."""
        assert "up" in EDGE_COLORS
        assert "down" in EDGE_COLORS
        assert "degraded" in EDGE_COLORS
        assert "unknown" in EDGE_COLORS


# =============================================================================
# Tests - Edge Cases
# =============================================================================


class TestEdgeCases:
    """Tests for edge cases and error handling."""

    def test_empty_graph(self):
        """Test handling empty graph."""
        graph = TopologyGraph(name="Empty")
        exporter = JSONExporter()
        result = exporter.export(graph)

        data = json.loads(result)
        assert data["nodes"] == []
        assert data["edges"] == []

    def test_single_node_graph(self):
        """Test graph with single node."""
        graph = TopologyGraph(name="Single")
        graph.nodes.append(GraphNode(id="only", label="Only Node"))

        visualizer = TopologyVisualizer()
        visualizer.apply_layout(graph, GraphLayout.CIRCULAR)

        assert graph.nodes[0].x >= 0
        assert graph.nodes[0].y >= 0

    def test_disconnected_nodes(self):
        """Test graph with disconnected nodes."""
        graph = TopologyGraph(name="Disconnected")
        graph.nodes.append(GraphNode(id="a", label="Node A"))
        graph.nodes.append(GraphNode(id="b", label="Node B"))
        # No edges

        exporter = DOTExporter()
        result = exporter.export(graph)

        assert "a" in result
        assert "b" in result

    def test_special_characters_in_labels(self):
        """Test handling special characters in labels."""
        graph = TopologyGraph(name="Special")
        graph.nodes.append(GraphNode(id="test", label='Node "with" <special> & chars'))

        # DOT export should escape properly
        exporter = DOTExporter()
        result = exporter.export(graph)
        assert "test" in result

        # SVG export should escape properly
        visualizer = TopologyVisualizer()
        visualizer.apply_layout(graph, GraphLayout.HIERARCHICAL)
        svg_exporter = SVGExporter()
        svg_result = svg_exporter.export(graph)
        assert "<svg" in svg_result
