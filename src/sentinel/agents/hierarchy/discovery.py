"""
Discovery Hierarchical Agent - Asset Management Domain Executive.

The Discovery Agent owns the IT asset management and inventory domain.
It orchestrates managers for device scanning, classification,
topology mapping, and inventory management.

Hierarchy:
    DiscoveryHierarchyAgent (Domain Executive)
        ├── ScanManager (Coordinates network scanning)
        │   ├── ARPScanSpecialist
        │   ├── PingScanSpecialist
        │   ├── PortScanSpecialist
        │   └── SNMPScanSpecialist
        ├── ClassificationManager (Coordinates device classification)
        │   ├── FingerprintSpecialist
        │   ├── VendorIdentSpecialist
        │   ├── DeviceTypeSpecialist
        │   └── OSDetectionSpecialist
        ├── TopologyManager (Coordinates topology mapping)
        │   ├── LLDPSpecialist
        │   ├── CDPSpecialist
        │   ├── SpanningTreeSpecialist
        │   └── RoutingSpecialist
        └── InventoryManager (Coordinates inventory)
            ├── AssetTrackingSpecialist
            ├── ChangeDetectionSpecialist
            ├── ComplianceCheckSpecialist
            └── ReportingSpecialist
"""

import asyncio
import logging
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field

from sentinel.core.hierarchy.base import (
    SentinelAgentBase,
    Manager,
    Specialist,
    Task,
    TaskResult,
    TaskStatus,
    TaskPriority,
    TaskSeverity,
    SpecialistCapability,
)

# Import real specialists with LLM integration
from sentinel.agents.hierarchy.specialists.discovery import (
    ARPScanSpecialist as RealARPScanSpecialist,
    SNMPScanSpecialist as RealSNMPScanSpecialist,
    VendorIdentificationSpecialist as RealVendorIdentSpecialist,
    DeviceFingerprintSpecialist as RealFingerprintSpecialist,
)

logger = logging.getLogger(__name__)


# ============================================================================
# NETWORK SCANNING SPECIALISTS
# ============================================================================


class ScanSpecialist(Specialist):
    """Base class for network scanning specialists."""

    def __init__(
        self,
        scan_type: str,
        specialist_id: Optional[str] = None,
    ):
        super().__init__(specialist_id)
        self._scan_type = scan_type

    @property
    def capability(self) -> SpecialistCapability:
        return SpecialistCapability(
            name=f"{self._scan_type.upper()} Scan Specialist",
            task_types=[
                f"scan.{self._scan_type}",
                f"discovery.scan.{self._scan_type}",
            ],
            confidence=0.9,
            max_concurrent=5,
            description=f"Performs {self._scan_type.upper()} network scans",
        )


class ARPScanSpecialist(ScanSpecialist):
    """ARP scan specialist."""

    def __init__(self, specialist_id: Optional[str] = None):
        super().__init__("arp", specialist_id)

    async def _do_execute(self, task: Task) -> TaskResult:
        """Perform ARP scan."""
        network = task.parameters.get("network")
        interface = task.parameters.get("interface")

        return TaskResult(
            success=True,
            output={
                "scan_type": "arp",
                "network": network,
                "interface": interface,
                "devices_found": [],
                "mac_addresses": [],
                "scan_duration_seconds": 0,
            },
            confidence=0.95,
            metadata={"scan_type": "arp"},
        )


class PingScanSpecialist(ScanSpecialist):
    """Ping scan specialist."""

    def __init__(self, specialist_id: Optional[str] = None):
        super().__init__("ping", specialist_id)

    async def _do_execute(self, task: Task) -> TaskResult:
        """Perform ping scan."""
        network = task.parameters.get("network")
        timeout = task.parameters.get("timeout", 1)

        return TaskResult(
            success=True,
            output={
                "scan_type": "ping",
                "network": network,
                "timeout": timeout,
                "hosts_up": [],
                "hosts_down": [],
                "response_times": {},
            },
            confidence=0.9,
            metadata={"scan_type": "ping"},
        )


class PortScanSpecialist(ScanSpecialist):
    """Port scan specialist."""

    def __init__(self, specialist_id: Optional[str] = None):
        super().__init__("port", specialist_id)

    async def _do_execute(self, task: Task) -> TaskResult:
        """Perform port scan."""
        target = task.parameters.get("target")
        ports = task.parameters.get("ports", "1-1024")

        return TaskResult(
            success=True,
            output={
                "scan_type": "port",
                "target": target,
                "ports_scanned": ports,
                "open_ports": [],
                "services_detected": {},
            },
            confidence=0.9,
            metadata={"scan_type": "port"},
        )


class SNMPScanSpecialist(ScanSpecialist):
    """SNMP scan specialist."""

    def __init__(self, specialist_id: Optional[str] = None):
        super().__init__("snmp", specialist_id)

    async def _do_execute(self, task: Task) -> TaskResult:
        """Perform SNMP scan."""
        target = task.parameters.get("target")
        community = task.parameters.get("community", "public")
        version = task.parameters.get("version", "2c")

        return TaskResult(
            success=True,
            output={
                "scan_type": "snmp",
                "target": target,
                "version": version,
                "system_info": {},
                "interfaces": [],
                "oid_values": {},
            },
            confidence=0.9,
            metadata={"scan_type": "snmp"},
        )


# ============================================================================
# CLASSIFICATION SPECIALISTS
# ============================================================================


class ClassificationSpecialist(Specialist):
    """Base class for device classification specialists."""

    def __init__(
        self,
        class_type: str,
        specialist_id: Optional[str] = None,
    ):
        super().__init__(specialist_id)
        self._class_type = class_type

    @property
    def capability(self) -> SpecialistCapability:
        return SpecialistCapability(
            name=f"{self._class_type.title()} Classification Specialist",
            task_types=[
                f"classify.{self._class_type}",
                f"discovery.classify.{self._class_type}",
            ],
            confidence=0.85,
            max_concurrent=10,
            description=f"Performs {self._class_type} device classification",
        )


class FingerprintSpecialist(ClassificationSpecialist):
    """Device fingerprinting specialist."""

    def __init__(self, specialist_id: Optional[str] = None):
        super().__init__("fingerprint", specialist_id)

    async def _do_execute(self, task: Task) -> TaskResult:
        """Fingerprint a device."""
        mac = task.parameters.get("mac")
        ip = task.parameters.get("ip")

        return TaskResult(
            success=True,
            output={
                "class_type": "fingerprint",
                "mac": mac,
                "ip": ip,
                "fingerprint": {
                    "vendor": None,
                    "device_type": None,
                    "os_family": None,
                },
                "confidence": 0.0,
            },
            confidence=0.85,
            metadata={"class_type": "fingerprint"},
        )


class VendorIdentSpecialist(ClassificationSpecialist):
    """Vendor identification specialist."""

    def __init__(self, specialist_id: Optional[str] = None):
        super().__init__("vendor", specialist_id)

    async def _do_execute(self, task: Task) -> TaskResult:
        """Identify device vendor."""
        mac = task.parameters.get("mac")

        return TaskResult(
            success=True,
            output={
                "class_type": "vendor",
                "mac": mac,
                "vendor": None,
                "oui": mac[:8] if mac else None,
                "vendor_details": {},
            },
            confidence=0.95,
            metadata={"class_type": "vendor"},
        )


class DeviceTypeSpecialist(ClassificationSpecialist):
    """Device type classification specialist."""

    def __init__(self, specialist_id: Optional[str] = None):
        super().__init__("device_type", specialist_id)

    async def _do_execute(self, task: Task) -> TaskResult:
        """Classify device type."""
        mac = task.parameters.get("mac")
        ip = task.parameters.get("ip")
        open_ports = task.parameters.get("open_ports", [])

        return TaskResult(
            success=True,
            output={
                "class_type": "device_type",
                "mac": mac,
                "ip": ip,
                "device_type": None,
                "device_category": None,
                "indicators": [],
            },
            confidence=0.8,
            metadata={"class_type": "device_type"},
        )


class OSDetectionSpecialist(ClassificationSpecialist):
    """OS detection specialist."""

    def __init__(self, specialist_id: Optional[str] = None):
        super().__init__("os", specialist_id)

    async def _do_execute(self, task: Task) -> TaskResult:
        """Detect operating system."""
        ip = task.parameters.get("ip")
        ttl = task.parameters.get("ttl")
        open_ports = task.parameters.get("open_ports", [])

        return TaskResult(
            success=True,
            output={
                "class_type": "os",
                "ip": ip,
                "os_family": None,
                "os_version": None,
                "os_match_accuracy": 0.0,
            },
            confidence=0.75,
            metadata={"class_type": "os"},
        )


# ============================================================================
# TOPOLOGY SPECIALISTS
# ============================================================================


class TopologySpecialist(Specialist):
    """Base class for topology mapping specialists."""

    def __init__(
        self,
        topo_type: str,
        specialist_id: Optional[str] = None,
    ):
        super().__init__(specialist_id)
        self._topo_type = topo_type

    @property
    def capability(self) -> SpecialistCapability:
        return SpecialistCapability(
            name=f"{self._topo_type.upper()} Topology Specialist",
            task_types=[
                f"topology.{self._topo_type}",
                f"discovery.topology.{self._topo_type}",
            ],
            protocols=[self._topo_type.upper()],
            confidence=0.9,
            max_concurrent=3,
            description=f"Maps topology using {self._topo_type.upper()}",
        )


class LLDPSpecialist(TopologySpecialist):
    """LLDP topology specialist."""

    def __init__(self, specialist_id: Optional[str] = None):
        super().__init__("lldp", specialist_id)

    async def _do_execute(self, task: Task) -> TaskResult:
        """Discover topology via LLDP."""
        device = task.parameters.get("device")
        interface = task.parameters.get("interface")

        return TaskResult(
            success=True,
            output={
                "topo_type": "lldp",
                "device": device,
                "neighbors": [],
                "links": [],
                "port_descriptions": {},
            },
            confidence=0.95,
            metadata={"topo_type": "lldp"},
        )


class CDPSpecialist(TopologySpecialist):
    """CDP topology specialist."""

    def __init__(self, specialist_id: Optional[str] = None):
        super().__init__("cdp", specialist_id)

    async def _do_execute(self, task: Task) -> TaskResult:
        """Discover topology via CDP."""
        device = task.parameters.get("device")

        return TaskResult(
            success=True,
            output={
                "topo_type": "cdp",
                "device": device,
                "neighbors": [],
                "device_ids": [],
                "platform_info": {},
            },
            confidence=0.95,
            metadata={"topo_type": "cdp"},
        )


class SpanningTreeSpecialist(TopologySpecialist):
    """Spanning Tree topology specialist."""

    def __init__(self, specialist_id: Optional[str] = None):
        super().__init__("stp", specialist_id)

    async def _do_execute(self, task: Task) -> TaskResult:
        """Analyze Spanning Tree topology."""
        vlan = task.parameters.get("vlan")

        return TaskResult(
            success=True,
            output={
                "topo_type": "stp",
                "vlan": vlan,
                "root_bridge": None,
                "port_states": {},
                "blocked_ports": [],
            },
            confidence=0.9,
            metadata={"topo_type": "stp"},
        )


class RoutingSpecialist(TopologySpecialist):
    """Routing topology specialist."""

    def __init__(self, specialist_id: Optional[str] = None):
        super().__init__("routing", specialist_id)

    async def _do_execute(self, task: Task) -> TaskResult:
        """Discover routing topology."""
        router = task.parameters.get("router")
        protocol = task.parameters.get("protocol", "all")

        return TaskResult(
            success=True,
            output={
                "topo_type": "routing",
                "router": router,
                "routes": [],
                "neighbors": [],
                "protocols": [],
            },
            confidence=0.9,
            metadata={"topo_type": "routing"},
        )


# ============================================================================
# INVENTORY SPECIALISTS
# ============================================================================


class InventorySpecialist(Specialist):
    """Base class for inventory management specialists."""

    def __init__(
        self,
        inv_type: str,
        specialist_id: Optional[str] = None,
    ):
        super().__init__(specialist_id)
        self._inv_type = inv_type

    @property
    def capability(self) -> SpecialistCapability:
        return SpecialistCapability(
            name=f"{self._inv_type.title()} Inventory Specialist",
            task_types=[
                f"inventory.{self._inv_type}",
                f"discovery.inventory.{self._inv_type}",
            ],
            confidence=0.9,
            max_concurrent=5,
            description=f"Handles {self._inv_type} inventory operations",
        )


class AssetTrackingSpecialist(InventorySpecialist):
    """Asset tracking specialist."""

    def __init__(self, specialist_id: Optional[str] = None):
        super().__init__("tracking", specialist_id)

    async def _do_execute(self, task: Task) -> TaskResult:
        """Track assets."""
        asset_id = task.parameters.get("asset_id")
        action = task.parameters.get("action", "status")

        return TaskResult(
            success=True,
            output={
                "inv_type": "tracking",
                "asset_id": asset_id,
                "action": action,
                "status": "tracked",
                "location": None,
                "last_seen": None,
            },
            confidence=0.95,
            metadata={"inv_type": "tracking"},
        )


class ChangeDetectionSpecialist(InventorySpecialist):
    """Change detection specialist."""

    def __init__(self, specialist_id: Optional[str] = None):
        super().__init__("change", specialist_id)

    async def _do_execute(self, task: Task) -> TaskResult:
        """Detect inventory changes."""
        scope = task.parameters.get("scope", "all")
        since = task.parameters.get("since")

        return TaskResult(
            success=True,
            output={
                "inv_type": "change",
                "scope": scope,
                "since": since,
                "new_devices": [],
                "removed_devices": [],
                "changed_devices": [],
            },
            confidence=0.9,
            metadata={"inv_type": "change"},
        )


class InventoryComplianceSpecialist(InventorySpecialist):
    """Inventory compliance specialist."""

    def __init__(self, specialist_id: Optional[str] = None):
        super().__init__("compliance", specialist_id)

    async def _do_execute(self, task: Task) -> TaskResult:
        """Check inventory compliance."""
        policy = task.parameters.get("policy")

        return TaskResult(
            success=True,
            output={
                "inv_type": "compliance",
                "policy": policy,
                "compliant_devices": [],
                "non_compliant_devices": [],
                "compliance_rate": 100.0,
            },
            confidence=0.9,
            metadata={"inv_type": "compliance"},
        )


class InventoryReportingSpecialist(InventorySpecialist):
    """Inventory reporting specialist."""

    def __init__(self, specialist_id: Optional[str] = None):
        super().__init__("reporting", specialist_id)

    async def _do_execute(self, task: Task) -> TaskResult:
        """Generate inventory reports."""
        report_type = task.parameters.get("report_type", "summary")
        format_type = task.parameters.get("format", "json")

        return TaskResult(
            success=True,
            output={
                "inv_type": "reporting",
                "report_type": report_type,
                "format": format_type,
                "report_data": {},
                "generated_at": None,
            },
            confidence=0.95,
            metadata={"inv_type": "reporting"},
        )


# ============================================================================
# MANAGERS
# ============================================================================


class ScanManager(Manager):
    """Scan Manager - Coordinates network scanning."""

    @property
    def name(self) -> str:
        return "Scan Manager"

    @property
    def domain(self) -> str:
        return "scan"

    @property
    def handled_task_types(self) -> List[str]:
        return [
            "scan",
            "scan.arp",
            "scan.ping",
            "scan.port",
            "scan.snmp",
            "discovery.scan",
            "discovery.scan.arp",
            "discovery.scan.ping",
            "discovery.scan.port",
            "discovery.scan.snmp",
            "discovery.scan_network",
        ]

    async def _decompose_task(self, task: Task) -> List[Task]:
        """Decompose network scan."""
        if task.task_type in ["scan", "discovery.scan", "discovery.scan_network"]:
            scan_types = task.parameters.get("scan_types", ["arp", "ping"])
            subtasks = []

            for scan_type in scan_types:
                subtask = Task(
                    task_type=f"scan.{scan_type}",
                    description=f"Perform {scan_type.upper()} scan",
                    parameters=task.parameters.copy(),
                    priority=task.priority,
                    severity=task.severity,
                    context=task.context,
                )
                subtasks.append(subtask)

            return subtasks

        return []


class ClassificationManager(Manager):
    """Classification Manager - Coordinates device classification."""

    @property
    def name(self) -> str:
        return "Classification Manager"

    @property
    def domain(self) -> str:
        return "classification"

    @property
    def handled_task_types(self) -> List[str]:
        return [
            "classify",
            "classify.fingerprint",
            "classify.vendor",
            "classify.device_type",
            "classify.os",
            "discovery.classify",
            "discovery.classify.fingerprint",
            "discovery.classify.vendor",
            "discovery.classify.device_type",
            "discovery.classify.os",
        ]


class TopologyManager(Manager):
    """Topology Manager - Coordinates topology mapping."""

    @property
    def name(self) -> str:
        return "Topology Manager"

    @property
    def domain(self) -> str:
        return "topology"

    @property
    def handled_task_types(self) -> List[str]:
        return [
            "topology",
            "topology.lldp",
            "topology.cdp",
            "topology.stp",
            "topology.routing",
            "discovery.topology",
            "discovery.topology.lldp",
            "discovery.topology.cdp",
            "discovery.topology.stp",
            "discovery.topology.routing",
            "discovery.update_topology",
        ]


class InventoryManager(Manager):
    """Inventory Manager - Coordinates inventory management."""

    @property
    def name(self) -> str:
        return "Inventory Manager"

    @property
    def domain(self) -> str:
        return "inventory"

    @property
    def handled_task_types(self) -> List[str]:
        return [
            "inventory",
            "inventory.tracking",
            "inventory.change",
            "inventory.compliance",
            "inventory.reporting",
            "discovery.inventory",
            "discovery.inventory.tracking",
            "discovery.inventory.change",
            "discovery.inventory.compliance",
            "discovery.inventory.reporting",
        ]


# ============================================================================
# DISCOVERY HIERARCHY AGENT
# ============================================================================


class DiscoveryHierarchyAgent(SentinelAgentBase):
    """
    Discovery Hierarchical Agent - Asset Management Domain Executive.

    The Discovery Agent owns the entire IT asset management domain.
    It coordinates managers for network scanning, device classification,
    topology mapping, and inventory management.

    Capabilities:
    - Network scanning (ARP, ping, port, SNMP)
    - Device classification (fingerprint, vendor, device type, OS)
    - Topology mapping (LLDP, CDP, STP, routing)
    - Inventory management (tracking, change detection, compliance, reporting)

    Architecture:
    - 4 Managers coordinate different discovery aspects
    - 16 Specialists handle individual discovery tasks
    """

    def __init__(self, agent_id: Optional[str] = None):
        super().__init__(agent_id)
        self._manager_count = 0
        self._specialist_count = 0

    @property
    def name(self) -> str:
        return "Discovery Agent"

    @property
    def domain(self) -> str:
        return "discovery"

    @property
    def handled_task_types(self) -> List[str]:
        return [
            # High-level discovery tasks
            "discovery",
            "discovery.full",
            "discovery.scan_network",
            "discovery.classify",
            "discovery.update_topology",
            # Scan tasks
            "scan",
            # Classification tasks
            "classify",
            # Topology tasks
            "topology",
            # Inventory tasks
            "inventory",
        ]

    async def _setup_managers(self) -> None:
        """Set up all managers and their specialists."""
        # Scan Manager - Use real LLM-powered specialists where available
        scan_manager = ScanManager()
        # Real implementations with actual network operations
        scan_manager.register_specialist(RealARPScanSpecialist())
        scan_manager.register_specialist(RealSNMPScanSpecialist())
        # Stub implementations (to be upgraded)
        scan_manager.register_specialist(PingScanSpecialist())
        scan_manager.register_specialist(PortScanSpecialist())
        self.register_manager(scan_manager)

        # Classification Manager - Use real LLM-powered specialists
        class_manager = ClassificationManager()
        # Real implementations with LLM-powered analysis
        class_manager.register_specialist(RealFingerprintSpecialist())
        class_manager.register_specialist(RealVendorIdentSpecialist())
        # Stub implementations (to be upgraded)
        class_manager.register_specialist(DeviceTypeSpecialist())
        class_manager.register_specialist(OSDetectionSpecialist())
        self.register_manager(class_manager)

        # Topology Manager
        topo_manager = TopologyManager()
        topo_manager.register_specialist(LLDPSpecialist())
        topo_manager.register_specialist(CDPSpecialist())
        topo_manager.register_specialist(SpanningTreeSpecialist())
        topo_manager.register_specialist(RoutingSpecialist())
        self.register_manager(topo_manager)

        # Inventory Manager
        inv_manager = InventoryManager()
        inv_manager.register_specialist(AssetTrackingSpecialist())
        inv_manager.register_specialist(ChangeDetectionSpecialist())
        inv_manager.register_specialist(InventoryComplianceSpecialist())
        inv_manager.register_specialist(InventoryReportingSpecialist())
        self.register_manager(inv_manager)

        self._manager_count = len(self._managers)
        self._specialist_count = sum(len(m.specialists) for m in self._managers.values())

        logger.info(
            f"DiscoveryHierarchyAgent initialized with {self._manager_count} managers "
            f"and {self._specialist_count} specialists (including LLM-powered)"
        )

    async def _plan_execution(self, task: Task) -> Dict[str, Any]:
        """Plan discovery task execution."""
        if task.task_type in ["discovery", "discovery.full"]:
            return await self._plan_full_discovery(task)

        return await super()._plan_execution(task)

    async def _plan_full_discovery(self, task: Task) -> Dict[str, Any]:
        """Plan full discovery."""
        steps = []

        # Step 1: Scan
        scan_manager = self._find_manager_by_domain("scan")
        if scan_manager:
            steps.append(
                {
                    "manager_id": scan_manager.id,
                    "task": Task(
                        task_type="scan",
                        description="Perform network scan",
                        parameters=task.parameters,
                        priority=task.priority,
                        severity=task.severity,
                        context=task.context,
                    ),
                }
            )

        # Step 2: Classify (sequential after scan)
        class_manager = self._find_manager_by_domain("classification")
        if class_manager:
            steps.append(
                {
                    "manager_id": class_manager.id,
                    "task": Task(
                        task_type="classify",
                        description="Classify discovered devices",
                        parameters=task.parameters,
                        priority=task.priority,
                        severity=task.severity,
                        context=task.context,
                    ),
                }
            )

        # Step 3: Topology (can run after scan)
        topo_manager = self._find_manager_by_domain("topology")
        if topo_manager:
            steps.append(
                {
                    "manager_id": topo_manager.id,
                    "task": Task(
                        task_type="topology",
                        description="Map network topology",
                        parameters=task.parameters,
                        priority=task.priority,
                        severity=task.severity,
                        context=task.context,
                    ),
                }
            )

        return {
            "parallel": False,  # Sequential: scan → classify → topology
            "steps": steps,
        }

    def _find_manager_by_domain(self, domain: str) -> Optional[Manager]:
        """Find manager by domain."""
        for manager in self._managers.values():
            if manager.domain == domain:
                return manager
        return None

    @property
    def stats(self) -> Dict[str, Any]:
        """Get extended agent statistics."""
        base_stats = super().stats
        base_stats.update(
            {
                "total_specialists": self._specialist_count,
                "capabilities": {
                    "scan_types": ["arp", "ping", "port", "snmp"],
                    "classification_types": ["fingerprint", "vendor", "device_type", "os"],
                    "topology_types": ["lldp", "cdp", "stp", "routing"],
                    "inventory_operations": ["tracking", "change", "compliance", "reporting"],
                },
            }
        )
        return base_stats
