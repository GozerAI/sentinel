"""
Cost Manager Hierarchical Agent - Cost Operations Domain Executive.

The Cost Manager Agent owns the cost operations domain.
It orchestrates managers for budget tracking, cost optimization,
anomaly detection, and resource allocation.

Hierarchy:
    CostManagerHierarchyAgent (Domain Executive)
        ├── BudgetManager (Coordinates budget operations)
        │   ├── BudgetTrackingSpecialist
        │   ├── ForecastingSpecialist
        │   └── BudgetAlertSpecialist
        ├── OptimizationManager (Coordinates cost optimization)
        │   ├── CostOptimizationSpecialist
        │   ├── CostAnomalySpecialist
        │   └── RightSizingSpecialist
        └── AllocationManager (Coordinates cost allocation)
            ├── ResourceAllocationSpecialist
            ├── CostReportingSpecialist
            └── ChargebackSpecialist
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

# Import real LLM-powered specialists
from sentinel.agents.hierarchy.specialists.cost_management import (
    BudgetTrackingSpecialist as RealBudgetTrackingSpecialist,
    CostOptimizationSpecialist as RealCostOptimizationSpecialist,
    CostAnomalySpecialist as RealCostAnomalySpecialist,
    ResourceAllocationSpecialist as RealResourceAllocationSpecialist,
    CostReportingSpecialist as RealCostReportingSpecialist,
)

logger = logging.getLogger(__name__)


# ============================================================================
# STUB SPECIALISTS (To be upgraded to real implementations)
# ============================================================================


class ForecastingSpecialist(Specialist):
    """Forecasting specialist - provides detailed cost forecasts."""

    def __init__(self, specialist_id: Optional[str] = None):
        super().__init__(specialist_id)

    @property
    def capability(self) -> SpecialistCapability:
        return SpecialistCapability(
            name="Forecasting Specialist",
            task_types=[
                "cost.forecast.detailed",
                "cost.projection",
                "budget.forecast",
            ],
            confidence=0.8,
            max_concurrent=2,
            description="Provides detailed cost forecasting",
        )

    async def _do_execute(self, task: Task) -> TaskResult:
        """Generate forecast."""
        forecast_type = task.parameters.get("forecast_type", "standard")
        months = task.parameters.get("months", 3)

        return TaskResult(
            success=True,
            output={
                "forecast_type": forecast_type,
                "months": months,
                "forecast": [],
                "confidence": 0.8,
            },
            confidence=0.8,
            metadata={"forecast_type": forecast_type},
        )


class BudgetAlertSpecialist(Specialist):
    """Budget alert specialist - manages budget alerts."""

    def __init__(self, specialist_id: Optional[str] = None):
        super().__init__(specialist_id)

    @property
    def capability(self) -> SpecialistCapability:
        return SpecialistCapability(
            name="Budget Alert Specialist",
            task_types=[
                "cost.alert",
                "cost.alert.create",
                "cost.alert.status",
                "budget.alert",
            ],
            confidence=0.9,
            max_concurrent=3,
            description="Manages budget alerts and thresholds",
        )

    async def _do_execute(self, task: Task) -> TaskResult:
        """Manage alerts."""
        action = task.parameters.get("action", "status")
        budget_id = task.parameters.get("budget_id")

        return TaskResult(
            success=True,
            output={
                "action": action,
                "budget_id": budget_id,
                "alerts": [],
                "active_alerts": 0,
            },
            confidence=0.9,
            metadata={"action": action},
        )


class RightSizingSpecialist(Specialist):
    """Right-sizing specialist - detailed right-sizing analysis."""

    def __init__(self, specialist_id: Optional[str] = None):
        super().__init__(specialist_id)

    @property
    def capability(self) -> SpecialistCapability:
        return SpecialistCapability(
            name="Right-Sizing Specialist",
            task_types=[
                "cost.rightsize.detailed",
                "cost.rightsize.apply",
                "optimize.rightsize",
            ],
            confidence=0.85,
            max_concurrent=2,
            description="Performs detailed right-sizing analysis",
        )

    async def _do_execute(self, task: Task) -> TaskResult:
        """Right-size resources."""
        action = task.parameters.get("action", "analyze")
        resource_ids = task.parameters.get("resource_ids", [])

        return TaskResult(
            success=True,
            output={
                "action": action,
                "resources_analyzed": len(resource_ids),
                "recommendations": [],
            },
            confidence=0.85,
            metadata={"action": action},
        )


class ChargebackSpecialist(Specialist):
    """Chargeback specialist - manages detailed chargeback."""

    def __init__(self, specialist_id: Optional[str] = None):
        super().__init__(specialist_id)

    @property
    def capability(self) -> SpecialistCapability:
        return SpecialistCapability(
            name="Chargeback Specialist",
            task_types=[
                "cost.chargeback.detailed",
                "cost.chargeback.process",
                "allocation.chargeback",
            ],
            confidence=0.9,
            max_concurrent=2,
            description="Manages detailed chargeback processing",
        )

    async def _do_execute(self, task: Task) -> TaskResult:
        """Process chargeback."""
        action = task.parameters.get("action", "generate")
        period = task.parameters.get("period", "monthly")

        return TaskResult(
            success=True,
            output={
                "action": action,
                "period": period,
                "charges": [],
                "total": 0,
            },
            confidence=0.9,
            metadata={"action": action},
        )


# ============================================================================
# MANAGERS
# ============================================================================


class BudgetManager(Manager):
    """Budget Manager - Coordinates budget operations specialists."""

    @property
    def name(self) -> str:
        return "Budget Manager"

    @property
    def domain(self) -> str:
        return "budget"

    @property
    def handled_task_types(self) -> List[str]:
        return [
            "cost.budget",
            "cost.budget.status",
            "cost.budget.forecast",
            "cost.tracking",
            "cost.forecast",
            "cost.forecast.detailed",
            "cost.projection",
            "cost.alert",
            "cost.alert.create",
            "cost.alert.status",
            "budget.status",
            "budget.forecast",
            "budget.alert",
        ]

    async def _decompose_task(self, task: Task) -> List[Task]:
        """Decompose budget tasks."""
        if task.task_type == "cost.budget":
            action = task.parameters.get("action", "status")
            if action == "full_review":
                return [
                    Task(
                        task_type="cost.budget.status",
                        description="Get budget status",
                        parameters=task.parameters.copy(),
                        priority=task.priority,
                        severity=task.severity,
                        context=task.context,
                    ),
                    Task(
                        task_type="cost.budget.forecast",
                        description="Get budget forecast",
                        parameters=task.parameters.copy(),
                        priority=task.priority,
                        severity=task.severity,
                        context=task.context,
                    ),
                    Task(
                        task_type="cost.alert.status",
                        description="Check budget alerts",
                        parameters=task.parameters.copy(),
                        priority=task.priority,
                        severity=task.severity,
                        context=task.context,
                    ),
                ]
        return []


class OptimizationManager(Manager):
    """Optimization Manager - Coordinates cost optimization specialists."""

    @property
    def name(self) -> str:
        return "Optimization Manager"

    @property
    def domain(self) -> str:
        return "optimization"

    @property
    def handled_task_types(self) -> List[str]:
        return [
            "cost.optimize",
            "cost.rightsize",
            "cost.rightsize.detailed",
            "cost.rightsize.apply",
            "cost.recommendations",
            "cost.efficiency",
            "cost.anomaly",
            "cost.anomaly.detect",
            "cost.spike",
            "cost.reserved",
            "optimize.rightsize",
        ]

    async def _decompose_task(self, task: Task) -> List[Task]:
        """Decompose optimization tasks."""
        if task.task_type == "cost.optimize":
            action = task.parameters.get("action", "analyze")
            if action == "comprehensive":
                return [
                    Task(
                        task_type="cost.anomaly.detect",
                        description="Detect cost anomalies",
                        parameters=task.parameters.copy(),
                        priority=task.priority,
                        severity=task.severity,
                        context=task.context,
                    ),
                    Task(
                        task_type="cost.rightsize",
                        description="Analyze right-sizing opportunities",
                        parameters={**task.parameters, "action": "rightsize"},
                        priority=task.priority,
                        severity=task.severity,
                        context=task.context,
                    ),
                    Task(
                        task_type="cost.recommendations",
                        description="Generate cost recommendations",
                        parameters={**task.parameters, "action": "analyze"},
                        priority=task.priority,
                        severity=task.severity,
                        context=task.context,
                    ),
                ]
        return []


class AllocationManager(Manager):
    """Allocation Manager - Coordinates cost allocation specialists."""

    @property
    def name(self) -> str:
        return "Allocation Manager"

    @property
    def domain(self) -> str:
        return "allocation"

    @property
    def handled_task_types(self) -> List[str]:
        return [
            "cost.allocation",
            "cost.chargeback",
            "cost.chargeback.detailed",
            "cost.chargeback.process",
            "cost.showback",
            "cost.ownership",
            "cost.report",
            "cost.report.generate",
            "cost.summary",
            "cost.trends",
            "allocation.chargeback",
        ]

    async def _decompose_task(self, task: Task) -> List[Task]:
        """Decompose allocation tasks."""
        if task.task_type == "cost.allocation":
            action = task.parameters.get("action", "report")
            if action == "full":
                return [
                    Task(
                        task_type="cost.chargeback",
                        description="Generate chargeback report",
                        parameters=task.parameters.copy(),
                        priority=task.priority,
                        severity=task.severity,
                        context=task.context,
                    ),
                    Task(
                        task_type="cost.report",
                        description="Generate cost report",
                        parameters=task.parameters.copy(),
                        priority=task.priority,
                        severity=task.severity,
                        context=task.context,
                    ),
                ]
        return []


# ============================================================================
# COST MANAGER HIERARCHY AGENT
# ============================================================================


class CostManagerHierarchyAgent(SentinelAgentBase):
    """
    Cost Manager Hierarchical Agent - Cost Operations Domain Executive.

    The Cost Manager Agent owns the entire cost operations domain.
    It coordinates managers for budget tracking, cost optimization,
    anomaly detection, and resource allocation.

    Capabilities:
    - Budget management (tracking, forecasting, alerts)
    - Cost optimization (analysis, right-sizing, recommendations)
    - Cost allocation (chargeback, showback, reporting)

    Architecture:
    - 3 Managers coordinate different cost aspects
    - 9 Specialists handle individual cost tasks
    """

    def __init__(self, agent_id: Optional[str] = None):
        super().__init__(agent_id)
        self._manager_count = 0
        self._specialist_count = 0

    @property
    def name(self) -> str:
        return "Cost Manager Agent"

    @property
    def domain(self) -> str:
        return "cost"

    @property
    def handled_task_types(self) -> List[str]:
        return [
            # High-level cost tasks
            "cost",
            "cost.full",
            "cost.analysis",
            # Budget tasks
            "cost.budget",
            "cost.budget.status",
            "cost.budget.forecast",
            "cost.tracking",
            "cost.alert",
            # Optimization tasks
            "cost.optimize",
            "cost.rightsize",
            "cost.recommendations",
            "cost.anomaly",
            # Allocation tasks
            "cost.allocation",
            "cost.chargeback",
            "cost.report",
            # Generic
            "budget",
            "optimization",
            "allocation",
        ]

    async def _setup_managers(self) -> None:
        """Set up all managers and their specialists."""
        # Budget Manager - Use real LLM-powered specialists
        budget_manager = BudgetManager()
        # Real implementation with LLM
        budget_manager.register_specialist(RealBudgetTrackingSpecialist())
        # Stub implementations (to be upgraded)
        budget_manager.register_specialist(ForecastingSpecialist())
        budget_manager.register_specialist(BudgetAlertSpecialist())
        self.register_manager(budget_manager)

        # Optimization Manager - Use real LLM-powered specialists
        optimization_manager = OptimizationManager()
        # Real implementations with LLM
        optimization_manager.register_specialist(RealCostOptimizationSpecialist())
        optimization_manager.register_specialist(RealCostAnomalySpecialist())
        # Stub implementation (to be upgraded)
        optimization_manager.register_specialist(RightSizingSpecialist())
        self.register_manager(optimization_manager)

        # Allocation Manager - Use real LLM-powered specialists
        allocation_manager = AllocationManager()
        # Real implementations with LLM
        allocation_manager.register_specialist(RealResourceAllocationSpecialist())
        allocation_manager.register_specialist(RealCostReportingSpecialist())
        # Stub implementation (to be upgraded)
        allocation_manager.register_specialist(ChargebackSpecialist())
        self.register_manager(allocation_manager)

        self._manager_count = len(self._managers)
        self._specialist_count = sum(len(m.specialists) for m in self._managers.values())

        logger.info(
            f"CostManagerHierarchyAgent initialized with {self._manager_count} managers "
            f"and {self._specialist_count} specialists (including LLM-powered)"
        )

    async def _plan_execution(self, task: Task) -> Dict[str, Any]:
        """Plan cost task execution."""
        if task.task_type in ["cost", "cost.full", "cost.analysis"]:
            return await self._plan_full_cost_analysis(task)

        return await super()._plan_execution(task)

    async def _plan_full_cost_analysis(self, task: Task) -> Dict[str, Any]:
        """Plan full cost analysis."""
        steps = []
        cost_aspects = task.parameters.get("aspects", ["budget", "optimization", "allocation"])

        task_type_map = {
            "budget": "cost.budget",
            "optimization": "cost.optimize",
            "allocation": "cost.allocation",
        }

        for aspect in cost_aspects:
            manager = self._find_manager_by_domain(aspect)
            if manager:
                aspect_params = task.parameters.copy()
                aspect_params["action"] = "status" if aspect == "budget" else "analyze"

                steps.append(
                    {
                        "manager_id": manager.id,
                        "task": Task(
                            task_type=task_type_map.get(aspect, f"cost.{aspect}"),
                            description=f"Execute {aspect} cost analysis",
                            parameters=aspect_params,
                            priority=task.priority,
                            severity=task.severity,
                            context=task.context,
                        ),
                    }
                )

        return {
            "parallel": True,  # Cost aspects can run in parallel
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
                    "budget_operations": ["tracking", "forecasting", "alerts"],
                    "optimization_operations": ["analysis", "rightsize", "anomaly_detection"],
                    "allocation_operations": ["chargeback", "showback", "reporting"],
                },
            }
        )
        return base_stats
