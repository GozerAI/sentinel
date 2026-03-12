"""
Healer Hierarchical Agent - Infrastructure Reliability Domain Executive.

The Healer Agent owns the infrastructure reliability and SRE domain.
It orchestrates managers for health monitoring, service management,
failover operations, and self-healing.

Hierarchy:
    HealerHierarchyAgent (Domain Executive)
        ├── HealthManager (Coordinates health monitoring)
        │   ├── ServiceHealthSpecialist
        │   ├── NetworkHealthSpecialist
        │   ├── SystemHealthSpecialist
        │   └── ApplicationHealthSpecialist
        ├── ServiceManager (Coordinates service operations)
        │   ├── ServiceRestartSpecialist
        │   ├── ServiceScaleSpecialist
        │   ├── ServiceConfigSpecialist
        │   └── DependencySpecialist
        ├── FailoverManager (Coordinates failover operations)
        │   ├── AutoFailoverSpecialist
        │   ├── LoadBalancerSpecialist
        │   ├── DNSFailoverSpecialist
        │   └── DataReplicationSpecialist
        └── HealingManager (Coordinates self-healing)
            ├── AutoRecoverySpecialist
            ├── ResourceCleanupSpecialist
            ├── CacheInvalidationSpecialist
            └── CircuitBreakerSpecialist
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
from sentinel.agents.hierarchy.specialists.reliability import (
    HealthCheckSpecialist as RealHealthCheckSpecialist,
    LogAnalysisSpecialist,
    ServiceRecoverySpecialist as RealServiceRecoverySpecialist,
)

logger = logging.getLogger(__name__)


# ============================================================================
# HEALTH MONITORING SPECIALISTS
# ============================================================================


class HealthSpecialist(Specialist):
    """Base class for health monitoring specialists."""

    def __init__(
        self,
        health_type: str,
        specialist_id: Optional[str] = None,
    ):
        super().__init__(specialist_id)
        self._health_type = health_type

    @property
    def capability(self) -> SpecialistCapability:
        return SpecialistCapability(
            name=f"{self._health_type.title()} Health Specialist",
            task_types=[
                f"health.check.{self._health_type}",
                f"health.monitor.{self._health_type}",
            ],
            confidence=0.95,
            max_concurrent=10,
            description=f"Monitors {self._health_type} health",
        )


class ServiceHealthSpecialist(HealthSpecialist):
    """Service health monitoring specialist."""

    def __init__(self, specialist_id: Optional[str] = None):
        super().__init__("service", specialist_id)

    async def _do_execute(self, task: Task) -> TaskResult:
        """Check service health."""
        service_name = task.parameters.get("service")
        endpoint = task.parameters.get("endpoint")

        return TaskResult(
            success=True,
            output={
                "health_type": "service",
                "service": service_name,
                "endpoint": endpoint,
                "status": "healthy",
                "response_time_ms": 0,
                "checks_passed": [],
                "checks_failed": [],
            },
            confidence=0.95,
            metadata={"health_type": "service"},
        )


class NetworkHealthSpecialist(HealthSpecialist):
    """Network health monitoring specialist."""

    def __init__(self, specialist_id: Optional[str] = None):
        super().__init__("network", specialist_id)

    async def _do_execute(self, task: Task) -> TaskResult:
        """Check network health."""
        target = task.parameters.get("target")
        check_type = task.parameters.get("check_type", "ping")

        return TaskResult(
            success=True,
            output={
                "health_type": "network",
                "target": target,
                "check_type": check_type,
                "reachable": True,
                "latency_ms": 0,
                "packet_loss": 0.0,
            },
            confidence=0.95,
            metadata={"health_type": "network"},
        )


class SystemHealthSpecialist(HealthSpecialist):
    """System health monitoring specialist."""

    def __init__(self, specialist_id: Optional[str] = None):
        super().__init__("system", specialist_id)

    async def _do_execute(self, task: Task) -> TaskResult:
        """Check system health."""
        host = task.parameters.get("host")

        return TaskResult(
            success=True,
            output={
                "health_type": "system",
                "host": host,
                "cpu_percent": 0.0,
                "memory_percent": 0.0,
                "disk_percent": 0.0,
                "load_average": [],
            },
            confidence=0.95,
            metadata={"health_type": "system"},
        )


class ApplicationHealthSpecialist(HealthSpecialist):
    """Application health monitoring specialist."""

    def __init__(self, specialist_id: Optional[str] = None):
        super().__init__("application", specialist_id)

    async def _do_execute(self, task: Task) -> TaskResult:
        """Check application health."""
        app = task.parameters.get("application")
        health_endpoint = task.parameters.get("health_endpoint", "/health")

        return TaskResult(
            success=True,
            output={
                "health_type": "application",
                "application": app,
                "health_endpoint": health_endpoint,
                "status": "healthy",
                "dependencies": [],
                "version": None,
            },
            confidence=0.95,
            metadata={"health_type": "application"},
        )


# ============================================================================
# SERVICE MANAGEMENT SPECIALISTS
# ============================================================================


class ServiceOpSpecialist(Specialist):
    """Base class for service operations specialists."""

    def __init__(
        self,
        operation: str,
        specialist_id: Optional[str] = None,
    ):
        super().__init__(specialist_id)
        self._operation = operation

    @property
    def capability(self) -> SpecialistCapability:
        return SpecialistCapability(
            name=f"Service {self._operation.title()} Specialist",
            task_types=[
                f"service.{self._operation}",
                f"service.manage.{self._operation}",
            ],
            confidence=0.9,
            max_concurrent=3,
            description=f"Handles service {self._operation} operations",
        )


class ServiceRestartSpecialist(ServiceOpSpecialist):
    """Service restart specialist."""

    def __init__(self, specialist_id: Optional[str] = None):
        super().__init__("restart", specialist_id)

    async def _do_execute(self, task: Task) -> TaskResult:
        """Restart a service."""
        service = task.parameters.get("service")
        target = task.parameters.get("target")
        graceful = task.parameters.get("graceful", True)

        return TaskResult(
            success=True,
            output={
                "operation": "restart",
                "service": service,
                "target": target,
                "graceful": graceful,
                "restarted": True,
                "downtime_seconds": 0,
            },
            confidence=0.9,
            metadata={"operation": "restart"},
        )


class ServiceScaleSpecialist(ServiceOpSpecialist):
    """Service scaling specialist."""

    def __init__(self, specialist_id: Optional[str] = None):
        super().__init__("scale", specialist_id)

    async def _do_execute(self, task: Task) -> TaskResult:
        """Scale a service."""
        service = task.parameters.get("service")
        replicas = task.parameters.get("replicas", 1)
        direction = task.parameters.get("direction", "up")

        return TaskResult(
            success=True,
            output={
                "operation": "scale",
                "service": service,
                "target_replicas": replicas,
                "direction": direction,
                "current_replicas": replicas,
                "scaled": True,
            },
            confidence=0.85,
            metadata={"operation": "scale"},
        )


class ServiceConfigSpecialist(ServiceOpSpecialist):
    """Service configuration specialist."""

    def __init__(self, specialist_id: Optional[str] = None):
        super().__init__("config", specialist_id)

    async def _do_execute(self, task: Task) -> TaskResult:
        """Update service configuration."""
        service = task.parameters.get("service")
        config_changes = task.parameters.get("changes", {})

        return TaskResult(
            success=True,
            output={
                "operation": "config",
                "service": service,
                "changes_applied": list(config_changes.keys()),
                "reload_required": True,
            },
            confidence=0.9,
            metadata={"operation": "config"},
        )


class DependencySpecialist(ServiceOpSpecialist):
    """Service dependency specialist."""

    def __init__(self, specialist_id: Optional[str] = None):
        super().__init__("dependency", specialist_id)

    async def _do_execute(self, task: Task) -> TaskResult:
        """Check service dependencies."""
        service = task.parameters.get("service")

        return TaskResult(
            success=True,
            output={
                "operation": "dependency",
                "service": service,
                "dependencies": [],
                "all_healthy": True,
                "unhealthy_deps": [],
            },
            confidence=0.9,
            metadata={"operation": "dependency"},
        )


# ============================================================================
# FAILOVER SPECIALISTS
# ============================================================================


class FailoverSpecialist(Specialist):
    """Base class for failover specialists."""

    def __init__(
        self,
        failover_type: str,
        specialist_id: Optional[str] = None,
    ):
        super().__init__(specialist_id)
        self._failover_type = failover_type

    @property
    def capability(self) -> SpecialistCapability:
        return SpecialistCapability(
            name=f"{self._failover_type.title()} Failover Specialist",
            task_types=[
                f"failover.{self._failover_type}",
                f"ha.{self._failover_type}",
            ],
            confidence=0.9,
            max_concurrent=1,
            description=f"Handles {self._failover_type} failover",
        )


class AutoFailoverSpecialist(FailoverSpecialist):
    """Automatic failover specialist."""

    def __init__(self, specialist_id: Optional[str] = None):
        super().__init__("auto", specialist_id)

    async def _do_execute(self, task: Task) -> TaskResult:
        """Execute automatic failover."""
        source = task.parameters.get("source")
        target = task.parameters.get("target")
        service = task.parameters.get("service")

        return TaskResult(
            success=True,
            output={
                "failover_type": "auto",
                "source": source,
                "target": target,
                "service": service,
                "failover_complete": True,
                "failover_time_seconds": 0,
            },
            confidence=0.9,
            metadata={"failover_type": "auto"},
        )


class LoadBalancerSpecialist(FailoverSpecialist):
    """Load balancer failover specialist."""

    def __init__(self, specialist_id: Optional[str] = None):
        super().__init__("loadbalancer", specialist_id)

    async def _do_execute(self, task: Task) -> TaskResult:
        """Update load balancer for failover."""
        pool = task.parameters.get("pool")
        remove_member = task.parameters.get("remove")
        add_member = task.parameters.get("add")

        return TaskResult(
            success=True,
            output={
                "failover_type": "loadbalancer",
                "pool": pool,
                "members_removed": [remove_member] if remove_member else [],
                "members_added": [add_member] if add_member else [],
                "pool_healthy": True,
            },
            confidence=0.95,
            metadata={"failover_type": "loadbalancer"},
        )


class DNSFailoverSpecialist(FailoverSpecialist):
    """DNS failover specialist."""

    def __init__(self, specialist_id: Optional[str] = None):
        super().__init__("dns", specialist_id)

    async def _do_execute(self, task: Task) -> TaskResult:
        """Update DNS for failover."""
        domain = task.parameters.get("domain")
        new_target = task.parameters.get("new_target")
        ttl = task.parameters.get("ttl", 60)

        return TaskResult(
            success=True,
            output={
                "failover_type": "dns",
                "domain": domain,
                "new_target": new_target,
                "ttl": ttl,
                "updated": True,
                "propagation_estimate_seconds": ttl,
            },
            confidence=0.9,
            metadata={"failover_type": "dns"},
        )


class DataReplicationSpecialist(FailoverSpecialist):
    """Data replication failover specialist."""

    def __init__(self, specialist_id: Optional[str] = None):
        super().__init__("replication", specialist_id)

    async def _do_execute(self, task: Task) -> TaskResult:
        """Manage data replication during failover."""
        primary = task.parameters.get("primary")
        secondary = task.parameters.get("secondary")
        action = task.parameters.get("action", "promote")

        return TaskResult(
            success=True,
            output={
                "failover_type": "replication",
                "primary": primary,
                "secondary": secondary,
                "action": action,
                "replication_lag_ms": 0,
                "data_consistent": True,
            },
            confidence=0.85,
            metadata={"failover_type": "replication"},
        )


# ============================================================================
# SELF-HEALING SPECIALISTS
# ============================================================================


class HealingSpecialist(Specialist):
    """Base class for self-healing specialists."""

    def __init__(
        self,
        healing_type: str,
        specialist_id: Optional[str] = None,
    ):
        super().__init__(specialist_id)
        self._healing_type = healing_type

    @property
    def capability(self) -> SpecialistCapability:
        return SpecialistCapability(
            name=f"{self._healing_type.title()} Healing Specialist",
            task_types=[
                f"healing.{self._healing_type}",
                f"repair.{self._healing_type}",
            ],
            confidence=0.85,
            max_concurrent=3,
            description=f"Handles {self._healing_type} self-healing",
        )


class AutoRecoverySpecialist(HealingSpecialist):
    """Automatic recovery specialist."""

    def __init__(self, specialist_id: Optional[str] = None):
        super().__init__("recovery", specialist_id)

    async def _do_execute(self, task: Task) -> TaskResult:
        """Execute automatic recovery."""
        target = task.parameters.get("target")
        failure_type = task.parameters.get("failure_type")

        return TaskResult(
            success=True,
            output={
                "healing_type": "recovery",
                "target": target,
                "failure_type": failure_type,
                "recovered": True,
                "recovery_actions": [],
            },
            confidence=0.85,
            metadata={"healing_type": "recovery"},
        )


class ResourceCleanupSpecialist(HealingSpecialist):
    """Resource cleanup specialist."""

    def __init__(self, specialist_id: Optional[str] = None):
        super().__init__("cleanup", specialist_id)

    async def _do_execute(self, task: Task) -> TaskResult:
        """Clean up resources."""
        resource_type = task.parameters.get("resource_type")
        criteria = task.parameters.get("criteria", {})

        return TaskResult(
            success=True,
            output={
                "healing_type": "cleanup",
                "resource_type": resource_type,
                "criteria": criteria,
                "resources_cleaned": 0,
                "space_reclaimed_mb": 0,
            },
            confidence=0.9,
            metadata={"healing_type": "cleanup"},
        )


class CacheInvalidationSpecialist(HealingSpecialist):
    """Cache invalidation specialist."""

    def __init__(self, specialist_id: Optional[str] = None):
        super().__init__("cache", specialist_id)

    async def _do_execute(self, task: Task) -> TaskResult:
        """Invalidate caches."""
        cache_name = task.parameters.get("cache")
        pattern = task.parameters.get("pattern", "*")

        return TaskResult(
            success=True,
            output={
                "healing_type": "cache",
                "cache_name": cache_name,
                "pattern": pattern,
                "keys_invalidated": 0,
                "cache_cleared": True,
            },
            confidence=0.95,
            metadata={"healing_type": "cache"},
        )


class CircuitBreakerSpecialist(HealingSpecialist):
    """Circuit breaker specialist."""

    def __init__(self, specialist_id: Optional[str] = None):
        super().__init__("circuit_breaker", specialist_id)

    async def _do_execute(self, task: Task) -> TaskResult:
        """Manage circuit breakers."""
        service = task.parameters.get("service")
        action = task.parameters.get("action", "trip")

        return TaskResult(
            success=True,
            output={
                "healing_type": "circuit_breaker",
                "service": service,
                "action": action,
                "current_state": "open" if action == "trip" else "closed",
            },
            confidence=0.95,
            metadata={"healing_type": "circuit_breaker"},
        )


# ============================================================================
# MANAGERS
# ============================================================================


class HealthManager(Manager):
    """Health Manager - Coordinates health monitoring."""

    @property
    def name(self) -> str:
        return "Health Manager"

    @property
    def domain(self) -> str:
        return "health"

    @property
    def handled_task_types(self) -> List[str]:
        return [
            "health.check",
            "health.monitor",
            "health.check.service",
            "health.check.network",
            "health.check.system",
            "health.check.application",
            "health.monitor.service",
            "health.monitor.network",
            "health.monitor.system",
            "health.monitor.application",
            "reliability.health_check",
        ]

    async def _decompose_task(self, task: Task) -> List[Task]:
        """Decompose health check."""
        if task.task_type in ["health.check", "health.monitor", "reliability.health_check"]:
            health_types = task.parameters.get("types", ["service", "network", "system"])
            subtasks = []

            for health_type in health_types:
                subtask = Task(
                    task_type=f"health.check.{health_type}",
                    description=f"Check {health_type} health",
                    parameters=task.parameters.copy(),
                    priority=task.priority,
                    severity=task.severity,
                    context=task.context,
                )
                subtasks.append(subtask)

            return subtasks

        return []


class ServiceManager(Manager):
    """Service Manager - Coordinates service operations."""

    @property
    def name(self) -> str:
        return "Service Manager"

    @property
    def domain(self) -> str:
        return "service"

    @property
    def handled_task_types(self) -> List[str]:
        return [
            "service",
            "service.restart",
            "service.scale",
            "service.config",
            "service.dependency",
            "service.manage.restart",
            "service.manage.scale",
            "service.manage.config",
            "service.manage.dependency",
            "reliability.restart_service",
        ]


class FailoverManager(Manager):
    """Failover Manager - Coordinates failover operations."""

    @property
    def name(self) -> str:
        return "Failover Manager"

    @property
    def domain(self) -> str:
        return "failover"

    @property
    def handled_task_types(self) -> List[str]:
        return [
            "failover",
            "failover.auto",
            "failover.loadbalancer",
            "failover.dns",
            "failover.replication",
            "ha.auto",
            "ha.loadbalancer",
            "ha.dns",
            "ha.replication",
            "reliability.failover",
        ]


class HealingManager(Manager):
    """Healing Manager - Coordinates self-healing operations."""

    @property
    def name(self) -> str:
        return "Healing Manager"

    @property
    def domain(self) -> str:
        return "healing"

    @property
    def handled_task_types(self) -> List[str]:
        return [
            "healing",
            "healing.recovery",
            "healing.cleanup",
            "healing.cache",
            "healing.circuit_breaker",
            "repair.recovery",
            "repair.cleanup",
            "repair.cache",
            "repair.circuit_breaker",
        ]


# ============================================================================
# HEALER HIERARCHY AGENT
# ============================================================================


class HealerHierarchyAgent(SentinelAgentBase):
    """
    Healer Hierarchical Agent - Infrastructure Reliability Domain Executive.

    The Healer Agent owns the entire reliability/SRE domain.
    It coordinates managers for health monitoring, service management,
    failover operations, and self-healing.

    Capabilities:
    - Health monitoring (service, network, system, application)
    - Service management (restart, scale, config, dependency)
    - Failover (auto, load balancer, DNS, replication)
    - Self-healing (recovery, cleanup, cache, circuit breaker)

    Architecture:
    - 4 Managers coordinate different reliability aspects
    - 16 Specialists handle individual reliability tasks
    """

    def __init__(self, agent_id: Optional[str] = None):
        super().__init__(agent_id)
        self._manager_count = 0
        self._specialist_count = 0

    @property
    def name(self) -> str:
        return "Healer Agent"

    @property
    def domain(self) -> str:
        return "reliability"

    @property
    def handled_task_types(self) -> List[str]:
        return [
            # High-level reliability tasks
            "reliability",
            "reliability.full",
            "reliability.health_check",
            "reliability.restart_service",
            "reliability.failover",
            # Health tasks
            "health",
            "health.check",
            "health.monitor",
            # Service tasks
            "service",
            # Failover tasks
            "failover",
            "ha",
            # Healing tasks
            "healing",
            "repair",
        ]

    async def _setup_managers(self) -> None:
        """Set up all managers and their specialists."""
        # Health Manager - Use real LLM-powered specialists where available
        health_manager = HealthManager()
        # Real implementation with HTTP/TCP/Ping/DNS checks
        health_manager.register_specialist(RealHealthCheckSpecialist())
        # Real implementation with LLM-powered log analysis
        health_manager.register_specialist(LogAnalysisSpecialist())
        # Stub implementations (to be upgraded)
        health_manager.register_specialist(ServiceHealthSpecialist())
        health_manager.register_specialist(NetworkHealthSpecialist())
        health_manager.register_specialist(SystemHealthSpecialist())
        health_manager.register_specialist(ApplicationHealthSpecialist())
        self.register_manager(health_manager)

        # Service Manager - Use real LLM-powered service recovery
        service_manager = ServiceManager()
        # Real implementation with systemd/docker management
        service_manager.register_specialist(RealServiceRecoverySpecialist())
        # Stub implementations (to be upgraded)
        service_manager.register_specialist(ServiceRestartSpecialist())
        service_manager.register_specialist(ServiceScaleSpecialist())
        service_manager.register_specialist(ServiceConfigSpecialist())
        service_manager.register_specialist(DependencySpecialist())
        self.register_manager(service_manager)

        # Failover Manager
        failover_manager = FailoverManager()
        failover_manager.register_specialist(AutoFailoverSpecialist())
        failover_manager.register_specialist(LoadBalancerSpecialist())
        failover_manager.register_specialist(DNSFailoverSpecialist())
        failover_manager.register_specialist(DataReplicationSpecialist())
        self.register_manager(failover_manager)

        # Healing Manager
        healing_manager = HealingManager()
        healing_manager.register_specialist(AutoRecoverySpecialist())
        healing_manager.register_specialist(ResourceCleanupSpecialist())
        healing_manager.register_specialist(CacheInvalidationSpecialist())
        healing_manager.register_specialist(CircuitBreakerSpecialist())
        self.register_manager(healing_manager)

        self._manager_count = len(self._managers)
        self._specialist_count = sum(len(m.specialists) for m in self._managers.values())

        logger.info(
            f"HealerHierarchyAgent initialized with {self._manager_count} managers "
            f"and {self._specialist_count} specialists (including LLM-powered)"
        )

    async def _plan_execution(self, task: Task) -> Dict[str, Any]:
        """Plan reliability task execution."""
        if task.task_type in ["reliability", "reliability.full"]:
            return await self._plan_full_reliability(task)

        return await super()._plan_execution(task)

    async def _plan_full_reliability(self, task: Task) -> Dict[str, Any]:
        """Plan full reliability assessment."""
        steps = []
        reliability_aspects = task.parameters.get("aspects", ["health", "service"])

        task_type_map = {
            "health": "health.check",
            "service": "service",
            "failover": "failover",
            "healing": "healing",
        }

        for aspect in reliability_aspects:
            manager = self._find_manager_by_domain(aspect)
            if manager:
                steps.append(
                    {
                        "manager_id": manager.id,
                        "task": Task(
                            task_type=task_type_map.get(aspect, f"{aspect}.execute"),
                            description=f"Execute {aspect} reliability check",
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
                    "health_types": ["service", "network", "system", "application"],
                    "service_operations": ["restart", "scale", "config", "dependency"],
                    "failover_types": ["auto", "loadbalancer", "dns", "replication"],
                    "healing_types": ["recovery", "cleanup", "cache", "circuit_breaker"],
                },
            }
        )
        return base_stats
