"""
Optimizer Hierarchical Agent - Network Performance Domain Executive.

The Optimizer Agent owns the network performance and traffic engineering domain.
It orchestrates managers for QoS, traffic analysis, bandwidth management,
and network optimization.

Hierarchy:
    OptimizerHierarchyAgent (Domain Executive)
        ├── QoSManager (Coordinates QoS operations)
        │   ├── TrafficClassSpecialist
        │   ├── PolicyEnforcementSpecialist
        │   ├── QueueManagementSpecialist
        │   └── RateLimitingSpecialist
        ├── TrafficManager (Coordinates traffic analysis)
        │   ├── FlowAnalysisSpecialist
        │   ├── NetFlowSpecialist
        │   ├── PacketCaptureSpecialist
        │   └── ProtocolAnalysisSpecialist
        ├── BandwidthManager (Coordinates bandwidth)
        │   ├── BandwidthMonitorSpecialist
        │   ├── TrafficShaperSpecialist
        │   ├── CongestionSpecialist
        │   └── UtilizationSpecialist
        └── OptimizationManager (Coordinates optimization)
            ├── PathOptimizationSpecialist
            ├── LoadBalancingSpecialist
            ├── CacheOptimizationSpecialist
            └── CompressionSpecialist
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
from sentinel.agents.hierarchy.specialists.network import (
    TrafficAnalysisSpecialist as RealTrafficAnalysisSpecialist,
    QoSPolicySpecialist as RealQoSPolicySpecialist,
    BandwidthMonitorSpecialist as RealBandwidthMonitorSpecialist,
    PathOptimizationSpecialist as RealPathOptimizationSpecialist,
)

logger = logging.getLogger(__name__)


# ============================================================================
# QOS SPECIALISTS
# ============================================================================


class QoSSpecialist(Specialist):
    """Base class for QoS specialists."""

    def __init__(
        self,
        qos_type: str,
        specialist_id: Optional[str] = None,
    ):
        super().__init__(specialist_id)
        self._qos_type = qos_type

    @property
    def capability(self) -> SpecialistCapability:
        return SpecialistCapability(
            name=f"{self._qos_type.title()} QoS Specialist",
            task_types=[
                f"qos.{self._qos_type}",
                f"network.qos.{self._qos_type}",
            ],
            confidence=0.9,
            max_concurrent=3,
            description=f"Handles {self._qos_type} QoS operations",
        )


class TrafficClassSpecialist(QoSSpecialist):
    """Traffic classification specialist."""

    def __init__(self, specialist_id: Optional[str] = None):
        super().__init__("classification", specialist_id)

    async def _do_execute(self, task: Task) -> TaskResult:
        """Classify traffic."""
        traffic_type = task.parameters.get("traffic_type")
        rules = task.parameters.get("rules", [])

        return TaskResult(
            success=True,
            output={
                "qos_type": "classification",
                "traffic_type": traffic_type,
                "rules_applied": len(rules),
                "classification_map": {},
            },
            confidence=0.9,
            metadata={"qos_type": "classification"},
        )


class PolicyEnforcementSpecialist(QoSSpecialist):
    """QoS policy enforcement specialist."""

    def __init__(self, specialist_id: Optional[str] = None):
        super().__init__("policy", specialist_id)

    async def _do_execute(self, task: Task) -> TaskResult:
        """Enforce QoS policies."""
        policy = task.parameters.get("policy")
        target = task.parameters.get("target")

        return TaskResult(
            success=True,
            output={
                "qos_type": "policy",
                "policy": policy,
                "target": target,
                "enforced": True,
                "violations": [],
            },
            confidence=0.9,
            metadata={"qos_type": "policy"},
        )


class QueueManagementSpecialist(QoSSpecialist):
    """Queue management specialist."""

    def __init__(self, specialist_id: Optional[str] = None):
        super().__init__("queue", specialist_id)

    async def _do_execute(self, task: Task) -> TaskResult:
        """Manage traffic queues."""
        interface = task.parameters.get("interface")
        queue_config = task.parameters.get("config", {})

        return TaskResult(
            success=True,
            output={
                "qos_type": "queue",
                "interface": interface,
                "queues_configured": 0,
                "drop_policy": "tail",
            },
            confidence=0.9,
            metadata={"qos_type": "queue"},
        )


class RateLimitingSpecialist(QoSSpecialist):
    """Rate limiting specialist."""

    def __init__(self, specialist_id: Optional[str] = None):
        super().__init__("rate_limit", specialist_id)

    async def _do_execute(self, task: Task) -> TaskResult:
        """Apply rate limiting."""
        target = task.parameters.get("target")
        rate = task.parameters.get("rate")
        burst = task.parameters.get("burst")

        return TaskResult(
            success=True,
            output={
                "qos_type": "rate_limit",
                "target": target,
                "rate": rate,
                "burst": burst,
                "applied": True,
            },
            confidence=0.95,
            metadata={"qos_type": "rate_limit"},
        )


# ============================================================================
# TRAFFIC ANALYSIS SPECIALISTS
# ============================================================================


class TrafficAnalysisSpecialist(Specialist):
    """Base class for traffic analysis specialists."""

    def __init__(
        self,
        analysis_type: str,
        specialist_id: Optional[str] = None,
    ):
        super().__init__(specialist_id)
        self._analysis_type = analysis_type

    @property
    def capability(self) -> SpecialistCapability:
        return SpecialistCapability(
            name=f"{self._analysis_type.title()} Traffic Specialist",
            task_types=[
                f"traffic.{self._analysis_type}",
                f"network.traffic.{self._analysis_type}",
            ],
            confidence=0.9,
            max_concurrent=5,
            description=f"Performs {self._analysis_type} traffic analysis",
        )


class FlowAnalysisSpecialist(TrafficAnalysisSpecialist):
    """Flow analysis specialist."""

    def __init__(self, specialist_id: Optional[str] = None):
        super().__init__("flow", specialist_id)

    async def _do_execute(self, task: Task) -> TaskResult:
        """Analyze traffic flows."""
        source = task.parameters.get("source")
        dest = task.parameters.get("dest")
        time_range = task.parameters.get("time_range", "1h")

        return TaskResult(
            success=True,
            output={
                "analysis_type": "flow",
                "source": source,
                "dest": dest,
                "time_range": time_range,
                "flows": [],
                "total_bytes": 0,
                "total_packets": 0,
            },
            confidence=0.9,
            metadata={"analysis_type": "flow"},
        )


class NetFlowSpecialist(TrafficAnalysisSpecialist):
    """NetFlow analysis specialist."""

    def __init__(self, specialist_id: Optional[str] = None):
        super().__init__("netflow", specialist_id)

    async def _do_execute(self, task: Task) -> TaskResult:
        """Analyze NetFlow data."""
        exporter = task.parameters.get("exporter")
        time_range = task.parameters.get("time_range", "1h")

        return TaskResult(
            success=True,
            output={
                "analysis_type": "netflow",
                "exporter": exporter,
                "time_range": time_range,
                "top_talkers": [],
                "top_protocols": [],
                "bandwidth_by_app": {},
            },
            confidence=0.9,
            metadata={"analysis_type": "netflow"},
        )


class PacketCaptureSpecialist(TrafficAnalysisSpecialist):
    """Packet capture specialist."""

    def __init__(self, specialist_id: Optional[str] = None):
        super().__init__("capture", specialist_id)

    async def _do_execute(self, task: Task) -> TaskResult:
        """Capture and analyze packets."""
        interface = task.parameters.get("interface")
        filter_expr = task.parameters.get("filter", "")
        duration = task.parameters.get("duration_seconds", 60)

        return TaskResult(
            success=True,
            output={
                "analysis_type": "capture",
                "interface": interface,
                "filter": filter_expr,
                "duration_seconds": duration,
                "packets_captured": 0,
                "pcap_file": None,
            },
            confidence=0.85,
            metadata={"analysis_type": "capture"},
        )


class ProtocolAnalysisSpecialist(TrafficAnalysisSpecialist):
    """Protocol analysis specialist."""

    def __init__(self, specialist_id: Optional[str] = None):
        super().__init__("protocol", specialist_id)

    async def _do_execute(self, task: Task) -> TaskResult:
        """Analyze protocol distribution."""
        interface = task.parameters.get("interface")
        time_range = task.parameters.get("time_range", "1h")

        return TaskResult(
            success=True,
            output={
                "analysis_type": "protocol",
                "interface": interface,
                "time_range": time_range,
                "protocol_distribution": {},
                "application_breakdown": {},
            },
            confidence=0.9,
            metadata={"analysis_type": "protocol"},
        )


# ============================================================================
# BANDWIDTH SPECIALISTS
# ============================================================================


class BandwidthSpecialist(Specialist):
    """Base class for bandwidth management specialists."""

    def __init__(
        self,
        bw_type: str,
        specialist_id: Optional[str] = None,
    ):
        super().__init__(specialist_id)
        self._bw_type = bw_type

    @property
    def capability(self) -> SpecialistCapability:
        return SpecialistCapability(
            name=f"{self._bw_type.title()} Bandwidth Specialist",
            task_types=[
                f"bandwidth.{self._bw_type}",
                f"network.bandwidth.{self._bw_type}",
            ],
            confidence=0.9,
            max_concurrent=3,
            description=f"Handles {self._bw_type} bandwidth operations",
        )


class BandwidthMonitorSpecialist(BandwidthSpecialist):
    """Bandwidth monitoring specialist."""

    def __init__(self, specialist_id: Optional[str] = None):
        super().__init__("monitor", specialist_id)

    async def _do_execute(self, task: Task) -> TaskResult:
        """Monitor bandwidth."""
        interface = task.parameters.get("interface")
        interval = task.parameters.get("interval_seconds", 5)

        return TaskResult(
            success=True,
            output={
                "bw_type": "monitor",
                "interface": interface,
                "interval": interval,
                "current_bps": 0,
                "peak_bps": 0,
                "average_bps": 0,
            },
            confidence=0.95,
            metadata={"bw_type": "monitor"},
        )


class TrafficShaperSpecialist(BandwidthSpecialist):
    """Traffic shaping specialist."""

    def __init__(self, specialist_id: Optional[str] = None):
        super().__init__("shaping", specialist_id)

    async def _do_execute(self, task: Task) -> TaskResult:
        """Apply traffic shaping."""
        interface = task.parameters.get("interface")
        policy = task.parameters.get("policy")
        rate_limit = task.parameters.get("rate_limit")

        return TaskResult(
            success=True,
            output={
                "bw_type": "shaping",
                "interface": interface,
                "policy": policy,
                "rate_limit": rate_limit,
                "shaper_applied": True,
            },
            confidence=0.9,
            metadata={"bw_type": "shaping"},
        )


class CongestionSpecialist(BandwidthSpecialist):
    """Congestion management specialist."""

    def __init__(self, specialist_id: Optional[str] = None):
        super().__init__("congestion", specialist_id)

    async def _do_execute(self, task: Task) -> TaskResult:
        """Manage congestion."""
        interface = task.parameters.get("interface")
        algorithm = task.parameters.get("algorithm", "wred")

        return TaskResult(
            success=True,
            output={
                "bw_type": "congestion",
                "interface": interface,
                "algorithm": algorithm,
                "drop_probability": 0.0,
                "queue_depth": 0,
            },
            confidence=0.85,
            metadata={"bw_type": "congestion"},
        )


class UtilizationSpecialist(BandwidthSpecialist):
    """Utilization analysis specialist."""

    def __init__(self, specialist_id: Optional[str] = None):
        super().__init__("utilization", specialist_id)

    async def _do_execute(self, task: Task) -> TaskResult:
        """Analyze bandwidth utilization."""
        interface = task.parameters.get("interface")
        time_range = task.parameters.get("time_range", "24h")

        return TaskResult(
            success=True,
            output={
                "bw_type": "utilization",
                "interface": interface,
                "time_range": time_range,
                "avg_utilization": 0.0,
                "peak_utilization": 0.0,
                "utilization_history": [],
            },
            confidence=0.95,
            metadata={"bw_type": "utilization"},
        )


# ============================================================================
# OPTIMIZATION SPECIALISTS
# ============================================================================


class OptimizationSpecialist(Specialist):
    """Base class for optimization specialists."""

    def __init__(
        self,
        opt_type: str,
        specialist_id: Optional[str] = None,
    ):
        super().__init__(specialist_id)
        self._opt_type = opt_type

    @property
    def capability(self) -> SpecialistCapability:
        return SpecialistCapability(
            name=f"{self._opt_type.title()} Optimization Specialist",
            task_types=[
                f"optimize.{self._opt_type}",
                f"network.optimize.{self._opt_type}",
            ],
            confidence=0.85,
            max_concurrent=2,
            description=f"Handles {self._opt_type} optimization",
        )


class PathOptimizationSpecialist(OptimizationSpecialist):
    """Path optimization specialist."""

    def __init__(self, specialist_id: Optional[str] = None):
        super().__init__("path", specialist_id)

    async def _do_execute(self, task: Task) -> TaskResult:
        """Optimize network paths."""
        source = task.parameters.get("source")
        dest = task.parameters.get("dest")
        criteria = task.parameters.get("criteria", "latency")

        return TaskResult(
            success=True,
            output={
                "opt_type": "path",
                "source": source,
                "dest": dest,
                "criteria": criteria,
                "optimal_path": [],
                "improvement": 0.0,
            },
            confidence=0.8,
            metadata={"opt_type": "path"},
        )


class LoadBalancingSpecialist(OptimizationSpecialist):
    """Load balancing specialist."""

    def __init__(self, specialist_id: Optional[str] = None):
        super().__init__("load_balance", specialist_id)

    async def _do_execute(self, task: Task) -> TaskResult:
        """Configure load balancing."""
        pool = task.parameters.get("pool")
        algorithm = task.parameters.get("algorithm", "round_robin")
        members = task.parameters.get("members", [])

        return TaskResult(
            success=True,
            output={
                "opt_type": "load_balance",
                "pool": pool,
                "algorithm": algorithm,
                "members_count": len(members),
                "health_checks": {},
            },
            confidence=0.9,
            metadata={"opt_type": "load_balance"},
        )


class CacheOptimizationSpecialist(OptimizationSpecialist):
    """Cache optimization specialist."""

    def __init__(self, specialist_id: Optional[str] = None):
        super().__init__("cache", specialist_id)

    async def _do_execute(self, task: Task) -> TaskResult:
        """Optimize caching."""
        cache_type = task.parameters.get("cache_type", "dns")
        action = task.parameters.get("action", "tune")

        return TaskResult(
            success=True,
            output={
                "opt_type": "cache",
                "cache_type": cache_type,
                "action": action,
                "hit_rate": 0.0,
                "improvement": 0.0,
            },
            confidence=0.85,
            metadata={"opt_type": "cache"},
        )


class CompressionSpecialist(OptimizationSpecialist):
    """Compression optimization specialist."""

    def __init__(self, specialist_id: Optional[str] = None):
        super().__init__("compression", specialist_id)

    async def _do_execute(self, task: Task) -> TaskResult:
        """Configure compression."""
        interface = task.parameters.get("interface")
        algorithm = task.parameters.get("algorithm", "lz4")

        return TaskResult(
            success=True,
            output={
                "opt_type": "compression",
                "interface": interface,
                "algorithm": algorithm,
                "compression_ratio": 0.0,
                "bandwidth_saved_percent": 0.0,
            },
            confidence=0.85,
            metadata={"opt_type": "compression"},
        )


# ============================================================================
# MANAGERS
# ============================================================================


class QoSManager(Manager):
    """QoS Manager - Coordinates QoS operations."""

    @property
    def name(self) -> str:
        return "QoS Manager"

    @property
    def domain(self) -> str:
        return "qos"

    @property
    def handled_task_types(self) -> List[str]:
        return [
            "qos",
            "qos.classification",
            "qos.policy",
            "qos.queue",
            "qos.rate_limit",
            "network.qos",
            "network.qos.classification",
            "network.qos.policy",
            "network.qos.queue",
            "network.qos.rate_limit",
            "network.apply_qos",
            "network.remove_qos",
        ]


class TrafficManager(Manager):
    """Traffic Manager - Coordinates traffic analysis."""

    @property
    def name(self) -> str:
        return "Traffic Manager"

    @property
    def domain(self) -> str:
        return "traffic"

    @property
    def handled_task_types(self) -> List[str]:
        return [
            "traffic",
            "traffic.flow",
            "traffic.netflow",
            "traffic.capture",
            "traffic.protocol",
            "network.traffic",
            "network.traffic.flow",
            "network.traffic.netflow",
            "network.traffic.capture",
            "network.traffic.protocol",
            "network.analyze_traffic",
        ]


class BandwidthManager(Manager):
    """Bandwidth Manager - Coordinates bandwidth operations."""

    @property
    def name(self) -> str:
        return "Bandwidth Manager"

    @property
    def domain(self) -> str:
        return "bandwidth"

    @property
    def handled_task_types(self) -> List[str]:
        return [
            "bandwidth",
            "bandwidth.monitor",
            "bandwidth.shaping",
            "bandwidth.congestion",
            "bandwidth.utilization",
            "network.bandwidth",
            "network.bandwidth.monitor",
            "network.bandwidth.shaping",
            "network.bandwidth.congestion",
            "network.bandwidth.utilization",
        ]


class NetworkOptimizationManager(Manager):
    """Optimization Manager - Coordinates network optimization."""

    @property
    def name(self) -> str:
        return "Optimization Manager"

    @property
    def domain(self) -> str:
        return "optimization"

    @property
    def handled_task_types(self) -> List[str]:
        return [
            "optimize",
            "optimize.path",
            "optimize.load_balance",
            "optimize.cache",
            "optimize.compression",
            "network.optimize",
            "network.optimize.path",
            "network.optimize.load_balance",
            "network.optimize.cache",
            "network.optimize.compression",
        ]


# ============================================================================
# OPTIMIZER HIERARCHY AGENT
# ============================================================================


class OptimizerHierarchyAgent(SentinelAgentBase):
    """
    Optimizer Hierarchical Agent - Network Performance Domain Executive.

    The Optimizer Agent owns the entire network performance domain.
    It coordinates managers for QoS, traffic analysis, bandwidth management,
    and network optimization.

    Capabilities:
    - QoS (classification, policy, queue, rate limiting)
    - Traffic analysis (flow, NetFlow, capture, protocol)
    - Bandwidth (monitoring, shaping, congestion, utilization)
    - Optimization (path, load balancing, cache, compression)

    Architecture:
    - 4 Managers coordinate different network aspects
    - 16 Specialists handle individual network tasks
    """

    def __init__(self, agent_id: Optional[str] = None):
        super().__init__(agent_id)
        self._manager_count = 0
        self._specialist_count = 0

    @property
    def name(self) -> str:
        return "Optimizer Agent"

    @property
    def domain(self) -> str:
        return "network"

    @property
    def handled_task_types(self) -> List[str]:
        return [
            # High-level network tasks
            "network",
            "network.full",
            "network.apply_qos",
            "network.remove_qos",
            "network.analyze_traffic",
            # QoS tasks
            "qos",
            # Traffic tasks
            "traffic",
            # Bandwidth tasks
            "bandwidth",
            # Optimization tasks
            "optimize",
        ]

    async def _setup_managers(self) -> None:
        """Set up all managers and their specialists."""
        # QoS Manager - Use real LLM-powered specialists where available
        qos_manager = QoSManager()
        # Real implementation with LLM-powered policy generation
        qos_manager.register_specialist(RealQoSPolicySpecialist())
        # Stub implementations (to be upgraded)
        qos_manager.register_specialist(TrafficClassSpecialist())
        qos_manager.register_specialist(PolicyEnforcementSpecialist())
        qos_manager.register_specialist(QueueManagementSpecialist())
        qos_manager.register_specialist(RateLimitingSpecialist())
        self.register_manager(qos_manager)

        # Traffic Manager - Use real LLM-powered specialists
        traffic_manager = TrafficManager()
        # Real implementation with actual traffic analysis
        traffic_manager.register_specialist(RealTrafficAnalysisSpecialist())
        # Stub implementations (to be upgraded)
        traffic_manager.register_specialist(FlowAnalysisSpecialist())
        traffic_manager.register_specialist(NetFlowSpecialist())
        traffic_manager.register_specialist(PacketCaptureSpecialist())
        traffic_manager.register_specialist(ProtocolAnalysisSpecialist())
        self.register_manager(traffic_manager)

        # Bandwidth Manager - Use real LLM-powered specialists
        bw_manager = BandwidthManager()
        # Real implementation with actual bandwidth monitoring
        bw_manager.register_specialist(RealBandwidthMonitorSpecialist())
        # Stub implementations (to be upgraded)
        bw_manager.register_specialist(TrafficShaperSpecialist())
        bw_manager.register_specialist(CongestionSpecialist())
        bw_manager.register_specialist(UtilizationSpecialist())
        self.register_manager(bw_manager)

        # Optimization Manager - Use real LLM-powered specialists
        opt_manager = NetworkOptimizationManager()
        # Real implementation with LLM-powered path optimization
        opt_manager.register_specialist(RealPathOptimizationSpecialist())
        # Stub implementations (to be upgraded)
        opt_manager.register_specialist(LoadBalancingSpecialist())
        opt_manager.register_specialist(CacheOptimizationSpecialist())
        opt_manager.register_specialist(CompressionSpecialist())
        self.register_manager(opt_manager)

        self._manager_count = len(self._managers)
        self._specialist_count = sum(len(m.specialists) for m in self._managers.values())

        logger.info(
            f"OptimizerHierarchyAgent initialized with {self._manager_count} managers "
            f"and {self._specialist_count} specialists (including LLM-powered)"
        )

    async def _plan_execution(self, task: Task) -> Dict[str, Any]:
        """Plan network task execution."""
        if task.task_type in ["network", "network.full"]:
            return await self._plan_full_network(task)

        return await super()._plan_execution(task)

    async def _plan_full_network(self, task: Task) -> Dict[str, Any]:
        """Plan full network analysis."""
        steps = []
        network_aspects = task.parameters.get("aspects", ["traffic", "bandwidth"])

        for aspect in network_aspects:
            manager = self._find_manager_by_domain(aspect)
            if manager:
                steps.append(
                    {
                        "manager_id": manager.id,
                        "task": Task(
                            task_type=aspect,
                            description=f"Execute {aspect} analysis",
                            parameters=task.parameters,
                            priority=task.priority,
                            severity=task.severity,
                            context=task.context,
                        ),
                    }
                )

        return {
            "parallel": True,
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
                    "qos_operations": ["classification", "policy", "queue", "rate_limit"],
                    "traffic_analysis": ["flow", "netflow", "capture", "protocol"],
                    "bandwidth_operations": ["monitor", "shaping", "congestion", "utilization"],
                    "optimization_types": ["path", "load_balance", "cache", "compression"],
                },
            }
        )
        return base_stats
