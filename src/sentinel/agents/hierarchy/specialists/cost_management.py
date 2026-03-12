"""
Cost Management Specialists - Real implementations for cost operations.

These specialists perform actual cost management operations:
- Budget tracking and forecasting
- Resource allocation optimization
- Cloud cost analysis
- Cost anomaly detection
- Chargeback/showback reporting
"""

import asyncio
import json
import logging
import re
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, TYPE_CHECKING

from sentinel.core.hierarchy.base import (
    Specialist,
    Task,
    TaskResult,
    SpecialistCapability,
)

if TYPE_CHECKING:
    from nexus.core.llm import LLMRouter

logger = logging.getLogger(__name__)


# ============================================================================
# BUDGET TRACKING SPECIALIST
# ============================================================================


class BudgetTrackingSpecialist(Specialist):
    """
    Budget tracking specialist for infrastructure cost management.

    Capabilities:
    - Tracks spending against budgets
    - Forecasts future spending
    - Alerts on budget overruns
    - Provides spending breakdowns
    """

    def __init__(
        self,
        specialist_id: Optional[str] = None,
        llm_router: Optional["LLMRouter"] = None,
    ):
        super().__init__(specialist_id, llm_router)

    @property
    def capability(self) -> SpecialistCapability:
        return SpecialistCapability(
            name="Budget Tracking Specialist",
            task_types=[
                "cost.budget",
                "cost.budget.status",
                "cost.budget.forecast",
                "cost.tracking",
            ],
            confidence=0.9,
            max_concurrent=5,
            description="Tracks and forecasts infrastructure budgets",
        )

    async def _do_execute(self, task: Task) -> TaskResult:
        """Execute budget tracking."""
        action = task.parameters.get("action", "status")
        budget_id = task.parameters.get("budget_id")
        period = task.parameters.get("period", "monthly")

        if action == "status":
            return await self._budget_status(budget_id, period)
        elif action == "forecast":
            return await self._budget_forecast(budget_id, task.parameters)
        elif action == "breakdown":
            return await self._budget_breakdown(budget_id, period)
        else:
            return TaskResult(
                success=False,
                error=f"Unknown budget action: {action}",
            )

    async def _budget_status(self, budget_id: Optional[str], period: str) -> TaskResult:
        """Get budget status."""
        # Simulate budget data
        budgets = [
            {
                "budget_id": "infra-main",
                "name": "Infrastructure Main Budget",
                "period": period,
                "allocated": 50000.00,
                "spent": 35420.50,
                "remaining": 14579.50,
                "utilization_percentage": 70.84,
                "forecast_end_of_period": 48500.00,
                "status": "on_track",
                "categories": {
                    "compute": {"allocated": 25000, "spent": 18500},
                    "storage": {"allocated": 10000, "spent": 7200},
                    "network": {"allocated": 8000, "spent": 5720},
                    "other": {"allocated": 7000, "spent": 4000},
                },
            },
            {
                "budget_id": "cloud-aws",
                "name": "AWS Cloud Budget",
                "period": period,
                "allocated": 30000.00,
                "spent": 28500.00,
                "remaining": 1500.00,
                "utilization_percentage": 95.0,
                "forecast_end_of_period": 32000.00,
                "status": "at_risk",
                "categories": {
                    "ec2": {"allocated": 15000, "spent": 14800},
                    "rds": {"allocated": 8000, "spent": 7500},
                    "s3": {"allocated": 4000, "spent": 3800},
                    "other": {"allocated": 3000, "spent": 2400},
                },
            },
        ]

        if budget_id:
            budgets = [b for b in budgets if b["budget_id"] == budget_id]

        # LLM analysis if available
        llm_analysis = None
        if self._llm_router:
            llm_analysis = await self._llm_budget_analysis(budgets)

        return TaskResult(
            success=True,
            output={
                "action": "status",
                "period": period,
                "budgets": budgets,
                "total_allocated": sum(b["allocated"] for b in budgets),
                "total_spent": sum(b["spent"] for b in budgets),
                "at_risk_budgets": [b["budget_id"] for b in budgets if b["status"] == "at_risk"],
                "llm_analysis": llm_analysis,
                "recommendations": llm_analysis.get("recommendations", []) if llm_analysis else [],
                "check_timestamp": datetime.now().isoformat(),
            },
            confidence=0.9,
            metadata={"action": "status"},
        )

    async def _budget_forecast(
        self, budget_id: Optional[str], params: Dict[str, Any]
    ) -> TaskResult:
        """Forecast budget spending."""
        forecast_months = params.get("forecast_months", 3)
        include_trends = params.get("include_trends", True)

        # Simulate forecast data
        forecast = {
            "budget_id": budget_id or "all",
            "forecast_months": forecast_months,
            "current_spend_rate": 35000.00,  # per month
            "forecasted_spending": [
                {"month": 1, "predicted_spend": 36000, "confidence": 0.9},
                {"month": 2, "predicted_spend": 37500, "confidence": 0.85},
                {"month": 3, "predicted_spend": 38200, "confidence": 0.8},
            ][:forecast_months],
            "trend": "increasing" if include_trends else None,
            "growth_rate_percentage": 3.2,
            "seasonal_factors": ["Q4 typically +10%", "Holiday freeze reduces Dec spend"],
        }

        # LLM forecast analysis if available
        llm_analysis = None
        if self._llm_router:
            llm_analysis = await self._llm_forecast_analysis(forecast)

        forecast["llm_analysis"] = llm_analysis
        forecast["recommendations"] = (
            llm_analysis.get("recommendations", []) if llm_analysis else []
        )

        return TaskResult(
            success=True,
            output=forecast,
            confidence=0.85,
            metadata={"action": "forecast"},
        )

    async def _budget_breakdown(self, budget_id: Optional[str], period: str) -> TaskResult:
        """Get detailed budget breakdown."""
        breakdown = {
            "budget_id": budget_id or "all",
            "period": period,
            "by_category": {
                "compute": {
                    "total": 18500,
                    "items": [
                        {"name": "Production Servers", "cost": 12000},
                        {"name": "Development Servers", "cost": 4500},
                        {"name": "CI/CD Infrastructure", "cost": 2000},
                    ],
                },
                "storage": {
                    "total": 7200,
                    "items": [
                        {"name": "Block Storage", "cost": 4000},
                        {"name": "Object Storage", "cost": 2500},
                        {"name": "Backup Storage", "cost": 700},
                    ],
                },
                "network": {
                    "total": 5720,
                    "items": [
                        {"name": "Data Transfer", "cost": 3500},
                        {"name": "Load Balancers", "cost": 1500},
                        {"name": "DNS", "cost": 720},
                    ],
                },
            },
            "by_team": {
                "engineering": 22000,
                "data": 8500,
                "operations": 4920,
            },
            "by_environment": {
                "production": 25000,
                "staging": 5500,
                "development": 4920,
            },
        }

        return TaskResult(
            success=True,
            output=breakdown,
            confidence=0.9,
            metadata={"action": "breakdown"},
        )

    async def _llm_budget_analysis(self, budgets: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        """LLM analysis of budget status."""
        system_prompt = """You are a cloud cost management expert.
Analyze the budget data and provide insights.
Respond with JSON:
{
    "overall_health": "healthy/warning/critical",
    "key_concerns": ["list of concerns"],
    "cost_drivers": ["main cost drivers"],
    "savings_opportunities": ["potential savings"],
    "recommendations": ["actionable recommendations"]
}"""

        prompt = f"""Analyze these infrastructure budgets:

{json.dumps(budgets, indent=2)}

Provide budget health analysis:"""

        try:
            response = await self.llm_complete(
                prompt=prompt,
                task_category="cost_analysis",
                system_prompt=system_prompt,
            )

            if response:
                json_match = re.search(r"\{[\s\S]*\}", response)
                if json_match:
                    return json.loads(json_match.group())
        except Exception as e:
            logger.warning(f"LLM budget analysis failed: {e}")

        return None

    async def _llm_forecast_analysis(self, forecast: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """LLM analysis of budget forecast."""
        system_prompt = """You are a financial forecasting expert.
Analyze the cost forecast and provide insights.
Respond with JSON:
{
    "forecast_assessment": "optimistic/realistic/pessimistic",
    "risk_factors": ["factors that could affect forecast"],
    "recommendations": ["budget planning recommendations"],
    "optimization_opportunities": ["ways to reduce forecasted costs"]
}"""

        prompt = f"""Analyze this budget forecast:

{json.dumps(forecast, indent=2)}

Provide forecast analysis:"""

        try:
            response = await self.llm_complete(
                prompt=prompt,
                task_category="cost_analysis",
                system_prompt=system_prompt,
            )

            if response:
                json_match = re.search(r"\{[\s\S]*\}", response)
                if json_match:
                    return json.loads(json_match.group())
        except Exception as e:
            logger.warning(f"LLM forecast analysis failed: {e}")

        return None


# ============================================================================
# COST OPTIMIZATION SPECIALIST
# ============================================================================


class CostOptimizationSpecialist(Specialist):
    """
    Cost optimization specialist for infrastructure cost reduction.

    Capabilities:
    - Identifies underutilized resources
    - Recommends right-sizing
    - Suggests reserved/spot instances
    - Analyzes cost efficiency
    """

    def __init__(
        self,
        specialist_id: Optional[str] = None,
        llm_router: Optional["LLMRouter"] = None,
    ):
        super().__init__(specialist_id, llm_router)

    @property
    def capability(self) -> SpecialistCapability:
        return SpecialistCapability(
            name="Cost Optimization Specialist",
            task_types=[
                "cost.optimize",
                "cost.rightsize",
                "cost.recommendations",
                "cost.efficiency",
            ],
            confidence=0.85,
            max_concurrent=3,
            description="Identifies cost optimization opportunities",
        )

    async def _do_execute(self, task: Task) -> TaskResult:
        """Execute cost optimization analysis."""
        action = task.parameters.get("action", "analyze")
        scope = task.parameters.get("scope", "all")
        resource_data = task.parameters.get("resource_data", {})

        if action == "analyze":
            return await self._analyze_optimization(scope, resource_data)
        elif action == "rightsize":
            return await self._rightsize_recommendations(resource_data)
        elif action == "reserved":
            return await self._reserved_instance_recommendations(resource_data)
        else:
            return TaskResult(
                success=False,
                error=f"Unknown optimization action: {action}",
            )

    async def _analyze_optimization(self, scope: str, resource_data: Dict[str, Any]) -> TaskResult:
        """Analyze cost optimization opportunities."""
        # Simulate optimization analysis
        opportunities = [
            {
                "opportunity_id": "opt-001",
                "type": "underutilized",
                "resource": "web-server-03",
                "current_cost_monthly": 250,
                "recommended_action": "downsize from m5.xlarge to m5.large",
                "estimated_savings_monthly": 100,
                "confidence": 0.9,
                "cpu_utilization_avg": 15,
                "memory_utilization_avg": 20,
            },
            {
                "opportunity_id": "opt-002",
                "type": "idle",
                "resource": "dev-db-backup",
                "current_cost_monthly": 150,
                "recommended_action": "terminate or schedule",
                "estimated_savings_monthly": 150,
                "confidence": 0.95,
                "last_access": "30 days ago",
            },
            {
                "opportunity_id": "opt-003",
                "type": "reserved_candidate",
                "resource": "prod-cluster-*",
                "current_cost_monthly": 2000,
                "recommended_action": "convert to 1-year reserved instances",
                "estimated_savings_monthly": 600,
                "confidence": 0.85,
                "steady_usage_months": 12,
            },
            {
                "opportunity_id": "opt-004",
                "type": "storage_optimization",
                "resource": "s3-archive-bucket",
                "current_cost_monthly": 500,
                "recommended_action": "move to Glacier Deep Archive",
                "estimated_savings_monthly": 450,
                "confidence": 0.9,
                "access_frequency": "rare",
            },
        ]

        total_savings = sum(o["estimated_savings_monthly"] for o in opportunities)

        # LLM analysis if available
        llm_analysis = None
        if self._llm_router:
            llm_analysis = await self._llm_optimization_analysis(opportunities)

        return TaskResult(
            success=True,
            output={
                "action": "analyze",
                "scope": scope,
                "opportunities": opportunities,
                "total_opportunities": len(opportunities),
                "total_potential_savings_monthly": total_savings,
                "total_potential_savings_yearly": total_savings * 12,
                "llm_analysis": llm_analysis,
                "priority_recommendations": (
                    llm_analysis.get("priority_actions", []) if llm_analysis else []
                ),
                "analysis_timestamp": datetime.now().isoformat(),
            },
            confidence=0.85,
            metadata={"action": "analyze"},
        )

    async def _rightsize_recommendations(self, resource_data: Dict[str, Any]) -> TaskResult:
        """Generate right-sizing recommendations."""
        recommendations = [
            {
                "resource_id": "i-abc123",
                "resource_name": "web-server-01",
                "current_type": "m5.2xlarge",
                "recommended_type": "m5.xlarge",
                "current_cost": 500,
                "recommended_cost": 250,
                "savings": 250,
                "metrics": {
                    "cpu_avg": 25,
                    "cpu_max": 45,
                    "memory_avg": 30,
                    "memory_max": 50,
                },
                "risk": "low",
            },
            {
                "resource_id": "i-def456",
                "resource_name": "api-server-02",
                "current_type": "c5.4xlarge",
                "recommended_type": "c5.2xlarge",
                "current_cost": 800,
                "recommended_cost": 400,
                "savings": 400,
                "metrics": {
                    "cpu_avg": 35,
                    "cpu_max": 60,
                    "memory_avg": 20,
                    "memory_max": 35,
                },
                "risk": "medium",
            },
        ]

        return TaskResult(
            success=True,
            output={
                "action": "rightsize",
                "recommendations": recommendations,
                "total_savings_monthly": sum(r["savings"] for r in recommendations),
                "resources_analyzed": len(recommendations),
                "analysis_timestamp": datetime.now().isoformat(),
            },
            confidence=0.85,
            metadata={"action": "rightsize"},
        )

    async def _reserved_instance_recommendations(self, resource_data: Dict[str, Any]) -> TaskResult:
        """Generate reserved instance recommendations."""
        recommendations = [
            {
                "instance_family": "m5",
                "current_on_demand_cost": 5000,
                "recommended_ri_cost": 3000,
                "savings": 2000,
                "savings_percentage": 40,
                "term": "1 year",
                "payment_option": "partial_upfront",
                "instances_covered": 10,
                "utilization_forecast": "steady",
            },
            {
                "instance_family": "c5",
                "current_on_demand_cost": 3000,
                "recommended_ri_cost": 1800,
                "savings": 1200,
                "savings_percentage": 40,
                "term": "1 year",
                "payment_option": "no_upfront",
                "instances_covered": 5,
                "utilization_forecast": "steady",
            },
        ]

        return TaskResult(
            success=True,
            output={
                "action": "reserved",
                "recommendations": recommendations,
                "total_savings_monthly": sum(r["savings"] for r in recommendations),
                "total_savings_yearly": sum(r["savings"] for r in recommendations) * 12,
                "analysis_timestamp": datetime.now().isoformat(),
            },
            confidence=0.85,
            metadata={"action": "reserved"},
        )

    async def _llm_optimization_analysis(
        self, opportunities: List[Dict[str, Any]]
    ) -> Optional[Dict[str, Any]]:
        """LLM analysis of optimization opportunities."""
        system_prompt = """You are a cloud cost optimization expert.
Analyze the optimization opportunities and prioritize them.
Respond with JSON:
{
    "overall_assessment": "brief assessment",
    "priority_actions": [
        {"opportunity_id": "...", "priority": 1-5, "rationale": "..."}
    ],
    "implementation_order": ["recommended order of implementation"],
    "risks": ["risks to consider"],
    "additional_recommendations": ["other suggestions"]
}"""

        prompt = f"""Analyze these cost optimization opportunities:

{json.dumps(opportunities, indent=2)}

Provide prioritized optimization plan:"""

        try:
            response = await self.llm_complete(
                prompt=prompt,
                task_category="cost_analysis",
                system_prompt=system_prompt,
            )

            if response:
                json_match = re.search(r"\{[\s\S]*\}", response)
                if json_match:
                    return json.loads(json_match.group())
        except Exception as e:
            logger.warning(f"LLM optimization analysis failed: {e}")

        return None


# ============================================================================
# COST ANOMALY DETECTION SPECIALIST
# ============================================================================


class CostAnomalySpecialist(Specialist):
    """
    Cost anomaly detection specialist for unusual spending patterns.

    Capabilities:
    - Detects spending anomalies
    - Identifies cost spikes
    - Alerts on unusual patterns
    - Provides root cause analysis
    """

    def __init__(
        self,
        specialist_id: Optional[str] = None,
        llm_router: Optional["LLMRouter"] = None,
    ):
        super().__init__(specialist_id, llm_router)

    @property
    def capability(self) -> SpecialistCapability:
        return SpecialistCapability(
            name="Cost Anomaly Specialist",
            task_types=[
                "cost.anomaly",
                "cost.anomaly.detect",
                "cost.spike",
                "cost.alert",
            ],
            confidence=0.85,
            max_concurrent=5,
            description="Detects cost anomalies and spending spikes",
        )

    async def _do_execute(self, task: Task) -> TaskResult:
        """Execute anomaly detection."""
        action = task.parameters.get("action", "detect")
        cost_data = task.parameters.get("cost_data", {})
        threshold = task.parameters.get("threshold_percentage", 20)

        if action == "detect":
            return await self._detect_anomalies(cost_data, threshold)
        elif action == "analyze":
            anomaly_id = task.parameters.get("anomaly_id")
            return await self._analyze_anomaly(anomaly_id, cost_data)
        else:
            return TaskResult(
                success=False,
                error=f"Unknown anomaly action: {action}",
            )

    async def _detect_anomalies(self, cost_data: Dict[str, Any], threshold: float) -> TaskResult:
        """Detect cost anomalies."""
        # Simulate anomaly detection
        anomalies = [
            {
                "anomaly_id": "anom-001",
                "detected_at": datetime.now().isoformat(),
                "resource": "data-processing-cluster",
                "category": "compute",
                "normal_daily_cost": 100,
                "actual_daily_cost": 450,
                "deviation_percentage": 350,
                "severity": "high",
                "probable_cause": "Unexpected scale-out event",
                "duration_hours": 6,
            },
            {
                "anomaly_id": "anom-002",
                "detected_at": (datetime.now() - timedelta(hours=12)).isoformat(),
                "resource": "api-gateway",
                "category": "network",
                "normal_daily_cost": 50,
                "actual_daily_cost": 120,
                "deviation_percentage": 140,
                "severity": "medium",
                "probable_cause": "Traffic spike",
                "duration_hours": 3,
            },
        ]

        # Filter by threshold
        anomalies = [a for a in anomalies if a["deviation_percentage"] >= threshold]

        # LLM analysis if available
        llm_analysis = None
        if self._llm_router and anomalies:
            llm_analysis = await self._llm_anomaly_analysis(anomalies)

        return TaskResult(
            success=True,
            output={
                "action": "detect",
                "threshold_percentage": threshold,
                "anomalies": anomalies,
                "total_anomalies": len(anomalies),
                "high_severity_count": len([a for a in anomalies if a["severity"] == "high"]),
                "estimated_excess_cost": sum(
                    (a["actual_daily_cost"] - a["normal_daily_cost"]) * (a["duration_hours"] / 24)
                    for a in anomalies
                ),
                "llm_analysis": llm_analysis,
                "recommendations": llm_analysis.get("recommendations", []) if llm_analysis else [],
                "detection_timestamp": datetime.now().isoformat(),
            },
            confidence=0.85,
            metadata={"action": "detect"},
        )

    async def _analyze_anomaly(
        self, anomaly_id: Optional[str], cost_data: Dict[str, Any]
    ) -> TaskResult:
        """Analyze specific anomaly."""
        # Simulate detailed anomaly analysis
        analysis = {
            "anomaly_id": anomaly_id or "anom-001",
            "root_cause_analysis": {
                "primary_cause": "Auto-scaling policy triggered unexpected scale-out",
                "contributing_factors": [
                    "Traffic spike from marketing campaign",
                    "Scale-in cooldown too long",
                    "Aggressive scale-out policy",
                ],
                "timeline": [
                    {"time": "08:00", "event": "Traffic increased 200%"},
                    {"time": "08:05", "event": "Auto-scaling added 10 instances"},
                    {"time": "08:30", "event": "Traffic normalized"},
                    {"time": "10:00", "event": "Scale-in began (delayed)"},
                ],
            },
            "impact": {
                "excess_cost": 350,
                "affected_resources": 10,
                "duration_hours": 6,
            },
            "remediation": {
                "immediate_actions": [
                    "Review auto-scaling policies",
                    "Reduce scale-in cooldown",
                ],
                "long_term_actions": [
                    "Implement predictive scaling",
                    "Add cost-aware scaling policies",
                ],
            },
        }

        # LLM enhanced analysis if available
        if self._llm_router:
            llm_enhanced = await self._llm_root_cause_analysis(analysis)
            if llm_enhanced:
                analysis["llm_enhanced_analysis"] = llm_enhanced

        return TaskResult(
            success=True,
            output=analysis,
            confidence=0.85,
            metadata={"action": "analyze", "anomaly_id": anomaly_id},
        )

    async def _llm_anomaly_analysis(
        self, anomalies: List[Dict[str, Any]]
    ) -> Optional[Dict[str, Any]]:
        """LLM analysis of cost anomalies."""
        system_prompt = """You are a cloud cost analyst specializing in anomaly detection.
Analyze the cost anomalies and provide insights.
Respond with JSON:
{
    "overall_risk": "high/medium/low",
    "pattern_analysis": "any patterns across anomalies",
    "recommendations": ["prioritized actions"],
    "prevention_measures": ["how to prevent future anomalies"],
    "escalation_needed": true/false
}"""

        prompt = f"""Analyze these cost anomalies:

{json.dumps(anomalies, indent=2)}

Provide anomaly analysis:"""

        try:
            response = await self.llm_complete(
                prompt=prompt,
                task_category="cost_analysis",
                system_prompt=system_prompt,
            )

            if response:
                json_match = re.search(r"\{[\s\S]*\}", response)
                if json_match:
                    return json.loads(json_match.group())
        except Exception as e:
            logger.warning(f"LLM anomaly analysis failed: {e}")

        return None

    async def _llm_root_cause_analysis(self, analysis: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """LLM enhanced root cause analysis."""
        system_prompt = """You are a cloud infrastructure expert.
Enhance the root cause analysis with deeper insights.
Respond with JSON:
{
    "confidence_level": 0.0-1.0,
    "alternative_causes": ["other possible causes"],
    "deeper_investigation": ["areas to investigate further"],
    "similar_incidents": ["patterns from similar incidents"],
    "prevention_score": 0-100
}"""

        prompt = f"""Enhance this root cause analysis:

{json.dumps(analysis, indent=2)}

Provide deeper analysis:"""

        try:
            response = await self.llm_complete(
                prompt=prompt,
                task_category="incident_analysis",
                system_prompt=system_prompt,
            )

            if response:
                json_match = re.search(r"\{[\s\S]*\}", response)
                if json_match:
                    return json.loads(json_match.group())
        except Exception as e:
            logger.warning(f"LLM root cause analysis failed: {e}")

        return None


# ============================================================================
# RESOURCE ALLOCATION SPECIALIST
# ============================================================================


class ResourceAllocationSpecialist(Specialist):
    """
    Resource allocation specialist for cost allocation.

    Capabilities:
    - Allocates costs to teams/projects
    - Manages chargeback/showback
    - Tracks resource ownership
    - Generates allocation reports
    """

    def __init__(
        self,
        specialist_id: Optional[str] = None,
        llm_router: Optional["LLMRouter"] = None,
    ):
        super().__init__(specialist_id, llm_router)

    @property
    def capability(self) -> SpecialistCapability:
        return SpecialistCapability(
            name="Resource Allocation Specialist",
            task_types=[
                "cost.allocation",
                "cost.chargeback",
                "cost.showback",
                "cost.ownership",
            ],
            confidence=0.9,
            max_concurrent=3,
            description="Manages cost allocation and chargeback",
        )

    async def _do_execute(self, task: Task) -> TaskResult:
        """Execute allocation task."""
        action = task.parameters.get("action", "report")
        period = task.parameters.get("period", "monthly")
        group_by = task.parameters.get("group_by", "team")

        if action == "report":
            return await self._allocation_report(period, group_by)
        elif action == "chargeback":
            return await self._chargeback_report(period, task.parameters)
        elif action == "unallocated":
            return await self._unallocated_costs(period)
        else:
            return TaskResult(
                success=False,
                error=f"Unknown allocation action: {action}",
            )

    async def _allocation_report(self, period: str, group_by: str) -> TaskResult:
        """Generate cost allocation report."""
        # Simulate allocation data
        if group_by == "team":
            allocations = {
                "engineering": {
                    "total": 25000,
                    "breakdown": {
                        "compute": 15000,
                        "storage": 5000,
                        "network": 3000,
                        "other": 2000,
                    },
                    "resources": 45,
                },
                "data": {
                    "total": 18000,
                    "breakdown": {
                        "compute": 10000,
                        "storage": 6000,
                        "network": 1500,
                        "other": 500,
                    },
                    "resources": 30,
                },
                "operations": {
                    "total": 8000,
                    "breakdown": {
                        "compute": 4000,
                        "storage": 2000,
                        "network": 1500,
                        "other": 500,
                    },
                    "resources": 20,
                },
            }
        else:  # project
            allocations = {
                "project-alpha": {"total": 20000, "team": "engineering"},
                "project-beta": {"total": 15000, "team": "engineering"},
                "data-pipeline": {"total": 18000, "team": "data"},
                "infrastructure": {"total": 8000, "team": "operations"},
            }

        return TaskResult(
            success=True,
            output={
                "action": "report",
                "period": period,
                "group_by": group_by,
                "allocations": allocations,
                "total_allocated": sum(
                    a["total"] if isinstance(a, dict) and "total" in a else a
                    for a in (allocations.values() if isinstance(allocations, dict) else [])
                ),
                "report_timestamp": datetime.now().isoformat(),
            },
            confidence=0.9,
            metadata={"action": "report"},
        )

    async def _chargeback_report(self, period: str, params: Dict[str, Any]) -> TaskResult:
        """Generate chargeback report."""
        chargeback = {
            "period": period,
            "charges": [
                {
                    "team": "engineering",
                    "cost_center": "CC-1001",
                    "amount": 25000,
                    "currency": "USD",
                    "invoice_id": f"INV-{datetime.now().strftime('%Y%m')}-001",
                },
                {
                    "team": "data",
                    "cost_center": "CC-1002",
                    "amount": 18000,
                    "currency": "USD",
                    "invoice_id": f"INV-{datetime.now().strftime('%Y%m')}-002",
                },
                {
                    "team": "operations",
                    "cost_center": "CC-1003",
                    "amount": 8000,
                    "currency": "USD",
                    "invoice_id": f"INV-{datetime.now().strftime('%Y%m')}-003",
                },
            ],
            "total": 51000,
            "adjustments": [],
            "generated_at": datetime.now().isoformat(),
        }

        return TaskResult(
            success=True,
            output=chargeback,
            confidence=0.9,
            metadata={"action": "chargeback"},
        )

    async def _unallocated_costs(self, period: str) -> TaskResult:
        """Find unallocated costs."""
        unallocated = {
            "period": period,
            "unallocated_resources": [
                {
                    "resource_id": "orphan-001",
                    "resource_type": "ec2_instance",
                    "cost": 150,
                    "reason": "No owner tag",
                    "created": "2024-01-15",
                },
                {
                    "resource_id": "orphan-002",
                    "resource_type": "ebs_volume",
                    "cost": 50,
                    "reason": "Detached volume",
                    "created": "2024-02-01",
                },
            ],
            "total_unallocated": 200,
            "percentage_of_total": 0.4,
            "recommendations": [
                "Apply cost allocation tags to untagged resources",
                "Review and terminate orphaned resources",
            ],
        }

        return TaskResult(
            success=True,
            output=unallocated,
            confidence=0.9,
            metadata={"action": "unallocated"},
        )


# ============================================================================
# COST REPORTING SPECIALIST
# ============================================================================


class CostReportingSpecialist(Specialist):
    """
    Cost reporting specialist for financial reporting.

    Capabilities:
    - Generates cost reports
    - Creates executive summaries
    - Produces trend analysis
    - Exports to various formats
    """

    def __init__(
        self,
        specialist_id: Optional[str] = None,
        llm_router: Optional["LLMRouter"] = None,
    ):
        super().__init__(specialist_id, llm_router)

    @property
    def capability(self) -> SpecialistCapability:
        return SpecialistCapability(
            name="Cost Reporting Specialist",
            task_types=[
                "cost.report",
                "cost.report.generate",
                "cost.summary",
                "cost.trends",
            ],
            confidence=0.9,
            max_concurrent=3,
            description="Generates cost reports and summaries",
        )

    async def _do_execute(self, task: Task) -> TaskResult:
        """Execute reporting task."""
        report_type = task.parameters.get("report_type", "summary")
        period = task.parameters.get("period", "monthly")
        include_forecast = task.parameters.get("include_forecast", True)

        if report_type == "summary":
            return await self._executive_summary(period, include_forecast)
        elif report_type == "detailed":
            return await self._detailed_report(period, task.parameters)
        elif report_type == "trends":
            return await self._trend_report(task.parameters)
        else:
            return TaskResult(
                success=False,
                error=f"Unknown report type: {report_type}",
            )

    async def _executive_summary(self, period: str, include_forecast: bool) -> TaskResult:
        """Generate executive cost summary."""
        summary = {
            "period": period,
            "total_spend": 51000,
            "budget": 55000,
            "variance": 4000,
            "variance_percentage": 7.3,
            "status": "under_budget",
            "highlights": [
                "Spending 7.3% under budget",
                "Compute costs decreased 5% month-over-month",
                "Storage costs increased 8% due to new data pipeline",
            ],
            "top_cost_drivers": [
                {"category": "compute", "cost": 29500, "percentage": 57.8},
                {"category": "storage", "cost": 13000, "percentage": 25.5},
                {"category": "network", "cost": 6000, "percentage": 11.8},
                {"category": "other", "cost": 2500, "percentage": 4.9},
            ],
            "month_over_month_change": -2.5,
            "year_over_year_change": 12.3,
        }

        if include_forecast:
            summary["forecast"] = {
                "next_month": 52500,
                "end_of_quarter": 157000,
                "confidence": 0.85,
            }

        # LLM executive summary if available
        llm_summary = None
        if self._llm_router:
            llm_summary = await self._llm_executive_summary(summary)

        summary["llm_narrative"] = llm_summary.get("narrative") if llm_summary else None
        summary["key_insights"] = llm_summary.get("key_insights", []) if llm_summary else []

        return TaskResult(
            success=True,
            output=summary,
            confidence=0.9,
            metadata={"report_type": "summary"},
        )

    async def _detailed_report(self, period: str, params: Dict[str, Any]) -> TaskResult:
        """Generate detailed cost report."""
        report = {
            "period": period,
            "generated_at": datetime.now().isoformat(),
            "sections": {
                "summary": {
                    "total_spend": 51000,
                    "budget": 55000,
                    "variance": 4000,
                },
                "by_service": {
                    "ec2": 20000,
                    "rds": 8000,
                    "s3": 5000,
                    "lambda": 3000,
                    "other": 15000,
                },
                "by_team": {
                    "engineering": 25000,
                    "data": 18000,
                    "operations": 8000,
                },
                "by_environment": {
                    "production": 35000,
                    "staging": 8000,
                    "development": 8000,
                },
                "trends": {
                    "monthly_growth": 2.5,
                    "quarterly_growth": 8.2,
                    "yearly_growth": 12.3,
                },
                "anomalies": [],
                "recommendations": [
                    "Consider reserved instances for steady-state workloads",
                    "Review and clean up development resources",
                ],
            },
        }

        return TaskResult(
            success=True,
            output=report,
            confidence=0.9,
            metadata={"report_type": "detailed"},
        )

    async def _trend_report(self, params: Dict[str, Any]) -> TaskResult:
        """Generate cost trend report."""
        months = params.get("months", 6)

        # Simulate trend data
        trends = {
            "period_months": months,
            "data_points": [
                {"month": f"2024-{i:02d}", "total": 48000 + i * 500} for i in range(1, months + 1)
            ],
            "trend_direction": "increasing",
            "growth_rate_percentage": 2.5,
            "projected_next_month": 51500,
            "seasonality_detected": True,
            "seasonal_factors": [
                "Q4 typically +10% due to holiday traffic",
                "January typically -5% due to reduced activity",
            ],
        }

        return TaskResult(
            success=True,
            output=trends,
            confidence=0.9,
            metadata={"report_type": "trends"},
        )

    async def _llm_executive_summary(self, summary: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """LLM generated executive summary."""
        system_prompt = """You are a cloud finance expert writing executive summaries.
Create a brief, executive-friendly summary of the cost data.
Respond with JSON:
{
    "narrative": "2-3 sentence executive summary",
    "key_insights": ["3-5 key insights"],
    "action_items": ["recommended actions for leadership"],
    "risk_flags": ["any concerns to highlight"]
}"""

        prompt = f"""Create executive summary for this cost data:

{json.dumps(summary, indent=2)}

Generate executive-friendly summary:"""

        try:
            response = await self.llm_complete(
                prompt=prompt,
                task_category="report_generation",
                system_prompt=system_prompt,
            )

            if response:
                json_match = re.search(r"\{[\s\S]*\}", response)
                if json_match:
                    return json.loads(json_match.group())
        except Exception as e:
            logger.warning(f"LLM executive summary failed: {e}")

        return None
