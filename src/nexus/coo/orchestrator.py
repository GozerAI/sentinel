"""
Nexus COO Orchestrator - Chief Operating Officer for Autonomous Operations.

The COO is the top-level orchestrator that:
- Receives tasks from external sources (API, CLI, automation)
- Routes tasks to appropriate C-level executives (CIO or CTO)
- Coordinates cross-domain workflows
- Manages priorities and resource allocation
- Tracks overall system health and performance

Architecture:
    ┌─────────────────────────────────────────────────────────────────┐
    │                    External Interface                           │
    │              (API / CLI / Automation / Events)                 │
    └─────────────────────────────┬───────────────────────────────────┘
                                  │
    ┌─────────────────────────────▼───────────────────────────────────┐
    │                         COO Orchestrator                        │
    │                                                                 │
    │   ┌─────────────┐    ┌─────────────┐    ┌─────────────┐       │
    │   │   Router    │    │  Scheduler  │    │   Monitor   │       │
    │   └──────┬──────┘    └──────┬──────┘    └──────┬──────┘       │
    │          │                  │                  │               │
    └──────────┼──────────────────┼──────────────────┼───────────────┘
               │                  │                  │
    ┌──────────▼────────┐ ┌───────▼───────┐ ┌───────▼───────┐
    │  CIO (Sentinel)   │ │  CTO (Forge)  │ │   Analytics   │
    │  Infrastructure   │ │  Development  │ │   & Reports   │
    └───────────────────┘ └───────────────┘ └───────────────┘
"""

import asyncio
import logging
from datetime import datetime
from enum import Enum
from typing import Dict, List, Any, Optional, Callable, TYPE_CHECKING
from dataclasses import dataclass, field
from uuid import uuid4

if TYPE_CHECKING:
    from sentinel.nexus_agent import SentinelAgent
    from nexus.core.llm import LLMRouter

logger = logging.getLogger(__name__)


class TaskDomain(str, Enum):
    """Domain classification for task routing."""

    INFRASTRUCTURE = "infrastructure"  # Route to CIO
    SECURITY = "security"  # Route to CIO
    RELIABILITY = "reliability"  # Route to CIO
    NETWORK = "network"  # Route to CIO
    DISCOVERY = "discovery"  # Route to CIO
    DEVELOPMENT = "development"  # Route to CTO
    CODE = "code"  # Route to CTO
    BUILD = "build"  # Route to CTO
    DEPLOY = "deploy"  # Route to CTO
    REVIEW = "review"  # Route to CTO
    CROSS_DOMAIN = "cross_domain"  # Requires coordination
    UNKNOWN = "unknown"


class TaskPriority(str, Enum):
    """Task priority levels."""

    CRITICAL = "critical"  # Immediate execution
    HIGH = "high"  # Next in queue
    MEDIUM = "medium"  # Normal priority
    LOW = "low"  # Background/batch


@dataclass
class COOTask:
    """Task representation at COO level."""

    id: str = field(default_factory=lambda: str(uuid4()))
    task_type: str = ""
    description: str = ""
    domain: TaskDomain = TaskDomain.UNKNOWN
    priority: TaskPriority = TaskPriority.MEDIUM
    parameters: Dict[str, Any] = field(default_factory=dict)
    context: Dict[str, Any] = field(default_factory=dict)
    source: str = "api"  # api, cli, automation, event
    created_at: datetime = field(default_factory=datetime.now)
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    status: str = "pending"
    result: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    subtasks: List["COOTask"] = field(default_factory=list)


@dataclass
class COOConfig:
    """Configuration for COO orchestrator."""

    max_concurrent_tasks: int = 10
    task_timeout_seconds: int = 300
    enable_cross_domain: bool = True
    enable_task_caching: bool = True
    cache_ttl_seconds: int = 300


class COOOrchestrator:
    """
    Chief Operating Officer - Top-level orchestrator.

    The COO coordinates between domain executives (CIO, CTO) to:
    - Route tasks to appropriate domains
    - Execute cross-domain workflows
    - Monitor system-wide health
    - Track metrics and generate reports
    """

    def __init__(self, config: Optional[COOConfig] = None):
        """
        Initialize COO Orchestrator.

        Args:
            config: Optional configuration
        """
        self._config = config or COOConfig()
        self._initialized = False
        self._started_at: Optional[datetime] = None

        # Domain executives
        self._cio: Optional["SentinelAgent"] = None  # Infrastructure
        self._cto: Optional[Any] = None  # Development (Forge)

        # Task management
        self._task_queue: asyncio.PriorityQueue = asyncio.PriorityQueue()
        self._active_tasks: Dict[str, COOTask] = {}
        self._completed_tasks: Dict[str, COOTask] = {}

        # Metrics
        self._tasks_routed = 0
        self._tasks_completed = 0
        self._tasks_failed = 0
        self._domain_stats: Dict[str, Dict[str, int]] = {}

        # Task routing rules
        self._routing_rules = self._build_routing_rules()

    def _build_routing_rules(self) -> Dict[str, TaskDomain]:
        """Build task type to domain routing rules."""
        return {
            # CIO (Infrastructure) tasks
            "security": TaskDomain.SECURITY,
            "security.block_ip": TaskDomain.SECURITY,
            "security.quarantine": TaskDomain.SECURITY,
            "security.scan": TaskDomain.SECURITY,
            "threat": TaskDomain.SECURITY,
            "threat.detect": TaskDomain.SECURITY,
            "access": TaskDomain.SECURITY,
            "incident": TaskDomain.SECURITY,
            "compliance": TaskDomain.SECURITY,
            "reliability": TaskDomain.RELIABILITY,
            "reliability.health_check": TaskDomain.RELIABILITY,
            "reliability.restart_service": TaskDomain.RELIABILITY,
            "reliability.failover": TaskDomain.RELIABILITY,
            "health": TaskDomain.RELIABILITY,
            "healing": TaskDomain.RELIABILITY,
            "service": TaskDomain.RELIABILITY,
            "discovery": TaskDomain.DISCOVERY,
            "discovery.scan_network": TaskDomain.DISCOVERY,
            "discovery.classify": TaskDomain.DISCOVERY,
            "scan": TaskDomain.DISCOVERY,
            "inventory": TaskDomain.DISCOVERY,
            "topology": TaskDomain.DISCOVERY,
            "network": TaskDomain.NETWORK,
            "network.apply_qos": TaskDomain.NETWORK,
            "network.analyze_traffic": TaskDomain.NETWORK,
            "qos": TaskDomain.NETWORK,
            "traffic": TaskDomain.NETWORK,
            "bandwidth": TaskDomain.NETWORK,
            "optimize": TaskDomain.NETWORK,
            "infrastructure": TaskDomain.INFRASTRUCTURE,
            "infrastructure.firewall_rule": TaskDomain.INFRASTRUCTURE,
            "infrastructure.create_vlan": TaskDomain.INFRASTRUCTURE,
            # CTO (Development) tasks
            "code": TaskDomain.CODE,
            "code.generate": TaskDomain.CODE,
            "code.review": TaskDomain.CODE,
            "code.fix": TaskDomain.CODE,
            "code.refactor": TaskDomain.CODE,
            "development": TaskDomain.DEVELOPMENT,
            "development.plan": TaskDomain.DEVELOPMENT,
            "development.implement": TaskDomain.DEVELOPMENT,
            "build": TaskDomain.BUILD,
            "build.compile": TaskDomain.BUILD,
            "build.test": TaskDomain.BUILD,
            "build.package": TaskDomain.BUILD,
            "deploy": TaskDomain.DEPLOY,
            "deploy.staging": TaskDomain.DEPLOY,
            "deploy.production": TaskDomain.DEPLOY,
            "deploy.rollback": TaskDomain.DEPLOY,
            "review": TaskDomain.REVIEW,
            "review.security": TaskDomain.REVIEW,
            "review.performance": TaskDomain.REVIEW,
            "review.code": TaskDomain.REVIEW,
        }

    async def initialize(
        self, cio: Optional["SentinelAgent"] = None, cto: Optional[Any] = None
    ) -> bool:
        """
        Initialize the COO orchestrator.

        Args:
            cio: CIO (Sentinel) agent instance
            cto: CTO (Forge) agent instance

        Returns:
            True if initialization successful
        """
        if self._initialized:
            return True

        try:
            # Initialize CIO if provided
            if cio:
                self._cio = cio
                if not cio.is_initialized:
                    await cio.initialize()
                logger.info("COO: CIO (Sentinel) connected")

            # Initialize CTO if provided
            if cto:
                self._cto = cto
                if hasattr(cto, "initialize") and not getattr(cto, "is_initialized", False):
                    await cto.initialize()
                logger.info("COO: CTO (Forge) connected")

            self._initialized = True
            self._started_at = datetime.now()

            logger.info(
                f"COO Orchestrator initialized - "
                f"CIO: {'connected' if self._cio else 'not connected'}, "
                f"CTO: {'connected' if self._cto else 'not connected'}"
            )

            return True

        except Exception as e:
            logger.error(f"Failed to initialize COO: {e}")
            return False

    async def shutdown(self) -> None:
        """Shutdown the COO orchestrator."""
        try:
            # Cancel active tasks
            for task_id in list(self._active_tasks.keys()):
                self._active_tasks[task_id].status = "cancelled"

            # Shutdown domain executives
            if self._cio:
                await self._cio.shutdown()
            if self._cto and hasattr(self._cto, "shutdown"):
                await self._cto.shutdown()

            self._initialized = False
            logger.info("COO Orchestrator shutdown complete")

        except Exception as e:
            logger.error(f"Error during COO shutdown: {e}")

    def classify_task(self, task_type: str) -> TaskDomain:
        """
        Classify a task type to its domain.

        Args:
            task_type: Task type string (e.g., "security.block_ip")

        Returns:
            TaskDomain for routing
        """
        # Check exact match
        if task_type in self._routing_rules:
            return self._routing_rules[task_type]

        # Check prefix match
        if "." in task_type:
            prefix = task_type.split(".")[0]
            if prefix in self._routing_rules:
                return self._routing_rules[prefix]

        # Use heuristics for unknown types
        task_lower = task_type.lower()

        # CIO keywords
        cio_keywords = [
            "security",
            "threat",
            "firewall",
            "block",
            "quarantine",
            "health",
            "monitor",
            "scan",
            "network",
            "traffic",
            "qos",
            "device",
            "discovery",
            "inventory",
            "vlan",
            "infrastructure",
        ]

        # CTO keywords
        cto_keywords = [
            "code",
            "build",
            "deploy",
            "test",
            "review",
            "develop",
            "compile",
            "package",
            "release",
            "architecture",
            "api",
        ]

        for keyword in cio_keywords:
            if keyword in task_lower:
                return TaskDomain.INFRASTRUCTURE

        for keyword in cto_keywords:
            if keyword in task_lower:
                return TaskDomain.DEVELOPMENT

        return TaskDomain.UNKNOWN

    async def execute(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute a task by routing to appropriate domain executive.

        Args:
            task: Task specification with:
                - task_type: Type of task
                - parameters: Task parameters
                - priority: Optional priority
                - context: Optional context

        Returns:
            Result dictionary with status and output
        """
        if not self._initialized:
            init_success = await self.initialize()
            if not init_success:
                return {
                    "status": "failure",
                    "error": "COO not initialized",
                }

        # Create COO task
        coo_task = COOTask(
            task_type=task.get("task_type", ""),
            description=task.get("description", ""),
            parameters=task.get("parameters", {}),
            context=task.get("context", {}),
            priority=TaskPriority(task.get("priority", "medium")),
            source=task.get("source", "api"),
        )

        # Classify and route
        coo_task.domain = self.classify_task(coo_task.task_type)

        logger.info(
            f"COO routing task {coo_task.id}: {coo_task.task_type} -> {coo_task.domain.value}"
        )

        self._tasks_routed += 1
        self._active_tasks[coo_task.id] = coo_task
        coo_task.status = "in_progress"
        coo_task.started_at = datetime.now()

        try:
            # Route to appropriate executive
            result = await self._route_task(coo_task)

            coo_task.completed_at = datetime.now()
            coo_task.result = result

            if result.get("status") == "success":
                coo_task.status = "completed"
                self._tasks_completed += 1
            else:
                coo_task.status = "failed"
                coo_task.error = result.get("error")
                self._tasks_failed += 1

            # Track domain stats
            domain_key = coo_task.domain.value
            if domain_key not in self._domain_stats:
                self._domain_stats[domain_key] = {"completed": 0, "failed": 0}

            if coo_task.status == "completed":
                self._domain_stats[domain_key]["completed"] += 1
            else:
                self._domain_stats[domain_key]["failed"] += 1

            return {
                "status": coo_task.status,
                "task_id": coo_task.id,
                "domain": coo_task.domain.value,
                "result": result,
                "duration_ms": (
                    (coo_task.completed_at - coo_task.started_at).total_seconds() * 1000
                    if coo_task.completed_at and coo_task.started_at
                    else 0
                ),
            }

        except Exception as e:
            logger.error(f"COO task execution failed: {e}")
            coo_task.status = "failed"
            coo_task.error = str(e)
            self._tasks_failed += 1

            return {
                "status": "failure",
                "task_id": coo_task.id,
                "error": str(e),
            }

        finally:
            # Move to completed
            self._completed_tasks[coo_task.id] = coo_task
            self._active_tasks.pop(coo_task.id, None)

    async def _route_task(self, task: COOTask) -> Dict[str, Any]:
        """Route task to appropriate domain executive."""
        domain = task.domain

        # CIO domains
        if domain in [
            TaskDomain.INFRASTRUCTURE,
            TaskDomain.SECURITY,
            TaskDomain.RELIABILITY,
            TaskDomain.NETWORK,
            TaskDomain.DISCOVERY,
        ]:
            if not self._cio:
                return {
                    "status": "failure",
                    "error": "CIO (Sentinel) not available",
                }

            # Convert to CIO task format
            cio_task = {
                "task_id": task.id,
                "task_type": task.task_type,
                "parameters": task.parameters,
                "context": task.context,
            }

            return await self._cio.execute(cio_task)

        # CTO domains
        elif domain in [
            TaskDomain.DEVELOPMENT,
            TaskDomain.CODE,
            TaskDomain.BUILD,
            TaskDomain.DEPLOY,
            TaskDomain.REVIEW,
        ]:
            if not self._cto:
                return {
                    "status": "failure",
                    "error": "CTO (Forge) not available",
                }

            # Convert to CTO task format
            cto_task = {
                "task_id": task.id,
                "task_type": task.task_type,
                "parameters": task.parameters,
                "context": task.context,
            }

            if hasattr(self._cto, "execute"):
                return await self._cto.execute(cto_task)
            else:
                return {
                    "status": "failure",
                    "error": "CTO does not support task execution",
                }

        # Cross-domain tasks
        elif domain == TaskDomain.CROSS_DOMAIN:
            return await self._execute_cross_domain(task)

        # Unknown domain
        else:
            return {
                "status": "failure",
                "error": f"Unknown task domain: {domain}",
            }

    async def _execute_cross_domain(self, task: COOTask) -> Dict[str, Any]:
        """Execute a task that spans multiple domains."""
        if not self._config.enable_cross_domain:
            return {
                "status": "failure",
                "error": "Cross-domain execution disabled",
            }

        # Analyze task to determine required domains
        # This would typically use LLM to decompose the task

        # For now, return placeholder
        return {
            "status": "partial",
            "message": "Cross-domain execution not fully implemented",
            "subtasks": [],
        }

    async def execute_workflow(
        self, workflow: List[Dict[str, Any]], parallel: bool = False
    ) -> Dict[str, Any]:
        """
        Execute a multi-step workflow.

        Args:
            workflow: List of task specifications
            parallel: Whether to execute tasks in parallel

        Returns:
            Aggregated workflow result
        """
        results = []

        if parallel:
            # Execute all tasks in parallel
            tasks = [self.execute(task) for task in workflow]
            results = await asyncio.gather(*tasks, return_exceptions=True)
        else:
            # Execute sequentially
            for task in workflow:
                result = await self.execute(task)
                results.append(result)

                # Stop on failure unless configured otherwise
                if result.get("status") == "failure":
                    break

        # Aggregate results
        all_success = all(
            r.get("status") == "success" if isinstance(r, dict) else False for r in results
        )

        return {
            "status": "success" if all_success else "partial",
            "workflow_steps": len(workflow),
            "completed_steps": len(results),
            "results": results,
        }

    @property
    def stats(self) -> Dict[str, Any]:
        """Get COO statistics."""
        uptime = None
        if self._started_at:
            uptime = (datetime.now() - self._started_at).total_seconds()

        return {
            "status": "running" if self._initialized else "stopped",
            "uptime_seconds": uptime,
            "tasks_routed": self._tasks_routed,
            "tasks_completed": self._tasks_completed,
            "tasks_failed": self._tasks_failed,
            "success_rate": (
                self._tasks_completed / self._tasks_routed if self._tasks_routed > 0 else 0.0
            ),
            "active_tasks": len(self._active_tasks),
            "completed_tasks": len(self._completed_tasks),
            "domain_stats": self._domain_stats,
            "executives": {
                "cio": {
                    "connected": self._cio is not None,
                    "initialized": self._cio.is_initialized if self._cio else False,
                },
                "cto": {
                    "connected": self._cto is not None,
                    "initialized": (
                        getattr(self._cto, "is_initialized", False) if self._cto else False
                    ),
                },
            },
        }

    async def health_check(self) -> Dict[str, Any]:
        """Perform health check on COO and all executives."""
        health = {
            "status": "healthy" if self._initialized else "not_initialized",
            "coo": self.stats,
            "executives": {},
        }

        # Check CIO health
        if self._cio:
            try:
                cio_health = await self._cio.health_check()
                health["executives"]["cio"] = cio_health
            except Exception as e:
                health["executives"]["cio"] = {
                    "status": "error",
                    "error": str(e),
                }
        else:
            health["executives"]["cio"] = {"status": "not_connected"}

        # Check CTO health
        if self._cto and hasattr(self._cto, "health_check"):
            try:
                cto_health = await self._cto.health_check()
                health["executives"]["cto"] = cto_health
            except Exception as e:
                health["executives"]["cto"] = {
                    "status": "error",
                    "error": str(e),
                }
        else:
            health["executives"]["cto"] = {"status": "not_connected"}

        # Determine overall health
        cio_ok = health["executives"].get("cio", {}).get("status") in ["healthy", "degraded"]
        cto_ok = health["executives"].get("cto", {}).get("status") in [
            "healthy",
            "degraded",
            "not_connected",
        ]

        if self._initialized and cio_ok and cto_ok:
            health["status"] = "healthy"
        elif self._initialized:
            health["status"] = "degraded"
        else:
            health["status"] = "unhealthy"

        return health

    def get_supported_tasks(self) -> Dict[str, List[str]]:
        """Get all supported task types by domain."""
        cio_tasks = []
        cto_tasks = []

        if self._cio:
            cio_supported = self._cio.get_supported_tasks()
            for domain_tasks in cio_supported.values():
                cio_tasks.extend(domain_tasks)

        # CTO tasks (placeholder)
        cto_tasks = [
            "code.generate",
            "code.review",
            "code.fix",
            "code.refactor",
            "build.compile",
            "build.test",
            "build.package",
            "deploy.staging",
            "deploy.production",
            "deploy.rollback",
            "review.security",
            "review.performance",
            "review.code",
        ]

        return {
            "cio_infrastructure": cio_tasks,
            "cto_development": cto_tasks,
        }
