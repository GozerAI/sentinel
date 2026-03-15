"""
Strategy Agent - The CTO Brain.

This agent provides high-level strategic reasoning for the Sentinel platform.
It analyzes the overall state of the network, identifies opportunities and threats,
and decides what agents should be created, modified, or retired.
"""
import asyncio
import logging
from datetime import datetime, timedelta
from typing import Optional, Any, TYPE_CHECKING
from uuid import UUID

from sentinel.agents.base import BaseAgent
from sentinel.core.utils import utc_now
from sentinel.core.models.event import (
    Event, EventCategory, EventSeverity,
    AgentAction, AgentDecision
)

if TYPE_CHECKING:
    from sentinel.core.engine import SentinelEngine
    from sentinel.agents.factory import AgentFactory, AgentInstance

logger = logging.getLogger(__name__)


class StrategicGoal:
    """
    Represents a high-level strategic goal.

    Goals can be:
    - Security: Protect the network from threats
    - Efficiency: Optimize resource utilization
    - Compliance: Ensure policy adherence
    - Resilience: Maintain system availability
    """

    def __init__(
        self,
        name: str,
        description: str,
        priority: int = 5,
        metrics: list[str] = None,
        target_values: dict = None
    ):
        self.id = UUID(int=hash(name) % (2**128))
        self.name = name
        self.description = description
        self.priority = priority  # 1-10, higher is more important
        self.metrics = metrics or []
        self.target_values = target_values or {}
        self.created_at = utc_now()
        self.achieved = False
        self.progress = 0.0  # 0.0 to 1.0

    def to_dict(self) -> dict:
        return {
            "id": str(self.id),
            "name": self.name,
            "description": self.description,
            "priority": self.priority,
            "metrics": self.metrics,
            "target_values": self.target_values,
            "achieved": self.achieved,
            "progress": self.progress
        }


class StrategicPlan:
    """
    A plan to achieve strategic goals.

    Plans consist of:
    - Goals to achieve
    - Actions to take
    - Agents to deploy
    - Timeline and checkpoints
    """

    def __init__(
        self,
        name: str,
        goals: list[StrategicGoal],
        actions: list[dict] = None
    ):
        self.id = UUID(int=hash(name + str(utc_now())) % (2**128))
        self.name = name
        self.goals = goals
        self.actions = actions or []
        self.created_at = utc_now()
        self.status = "pending"  # pending, active, completed, failed
        self.executed_actions: list[str] = []
        self.spawned_agents: list[UUID] = []

    def to_dict(self) -> dict:
        return {
            "id": str(self.id),
            "name": self.name,
            "goals": [g.to_dict() for g in self.goals],
            "actions": self.actions,
            "status": self.status,
            "executed_actions": self.executed_actions,
            "spawned_agents": [str(a) for a in self.spawned_agents]
        }


class StrategyAgent(BaseAgent):
    """
    Strategy Agent - The CTO of Sentinel.

    This agent provides high-level strategic oversight:
    - Analyzes overall network health and security posture
    - Identifies gaps in coverage or capability
    - Decides when to create new specialized agents
    - Coordinates between different agents
    - Makes long-term planning decisions
    - Learns from outcomes and adjusts strategies

    The Strategy Agent uses LLM reasoning for complex decisions
    that require understanding context and making judgment calls.
    """

    agent_name = "strategy"
    agent_description = "Strategic oversight and agent coordination"
    capabilities = [
        "strategic_planning",
        "agent_orchestration",
        "threat_assessment",
        "capability_analysis",
        "resource_allocation"
    ]

    def __init__(self, engine: "SentinelEngine", config: dict):
        super().__init__(engine, config)

        # Strategic configuration
        self.planning_interval = config.get("planning_interval", 300)  # 5 minutes
        self.review_interval = config.get("review_interval", 3600)  # 1 hour
        self.max_concurrent_agents = config.get("max_concurrent_agents", 20)

        # Strategic state
        self._goals: list[StrategicGoal] = []
        self._active_plans: list[StrategicPlan] = []
        self._threat_history: list[dict] = []
        self._performance_history: list[dict] = []

        # Agent coordination
        self._agent_assignments: dict[UUID, str] = {}  # agent_id -> task
        self._pending_reviews: list[UUID] = []

        # Initialize default goals
        self._initialize_default_goals()

    def _initialize_default_goals(self) -> None:
        """Set up default strategic goals."""
        self._goals = [
            StrategicGoal(
                name="network_security",
                description="Maintain zero-trust network security posture",
                priority=10,
                metrics=["threats_blocked", "unauthorized_access_attempts", "compliance_score"],
                target_values={"compliance_score": 0.95}
            ),
            StrategicGoal(
                name="network_visibility",
                description="Complete visibility into all network devices and traffic",
                priority=9,
                metrics=["devices_discovered", "unknown_devices", "coverage_percentage"],
                target_values={"coverage_percentage": 1.0, "unknown_devices": 0}
            ),
            StrategicGoal(
                name="service_availability",
                description="Ensure critical services remain available",
                priority=9,
                metrics=["uptime_percentage", "failed_health_checks", "recovery_time"],
                target_values={"uptime_percentage": 0.999}
            ),
            StrategicGoal(
                name="network_efficiency",
                description="Optimize network resource utilization",
                priority=7,
                metrics=["bandwidth_utilization", "latency_p95", "packet_loss"],
                target_values={"bandwidth_utilization": 0.7, "packet_loss": 0.001}
            ),
            StrategicGoal(
                name="segmentation_compliance",
                description="Proper VLAN segmentation for all device types",
                priority=8,
                metrics=["devices_segmented", "vlan_violations", "policy_adherence"],
                target_values={"policy_adherence": 1.0}
            )
        ]

    async def _subscribe_events(self) -> None:
        """Subscribe to strategic-level events."""
        # Subscribe to all agent events
        self.engine.event_bus.subscribe(
            self._handle_agent_event,
            category=EventCategory.AGENT
        )

        # Subscribe to security events
        self.engine.event_bus.subscribe(
            self._handle_security_event,
            category=EventCategory.SECURITY
        )

        # Subscribe to system events
        self.engine.event_bus.subscribe(
            self._handle_system_event,
            category=EventCategory.SYSTEM
        )

    async def _main_loop(self) -> None:
        """Main strategic planning loop."""
        last_planning = utc_now() - timedelta(seconds=self.planning_interval)
        last_review = utc_now() - timedelta(seconds=self.review_interval)

        while self._running:
            try:
                now = utc_now()

                # Regular planning cycle
                if (now - last_planning).total_seconds() >= self.planning_interval:
                    await self._strategic_planning_cycle()
                    last_planning = now

                # Periodic review
                if (now - last_review).total_seconds() >= self.review_interval:
                    await self._strategic_review()
                    last_review = now

                await asyncio.sleep(10)  # Check every 10 seconds

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Strategy loop error: {e}")
                await asyncio.sleep(60)

    async def _handle_agent_event(self, event: Event) -> None:
        """Handle events from other agents."""
        if event.event_type == "agent.action.executed":
            await self._record_agent_action(event)

        elif event.event_type == "agent.action.failed":
            await self._analyze_failure(event)

        elif event.event_type == "agent.confirmation_required":
            await self._evaluate_confirmation_request(event)

    async def _handle_security_event(self, event: Event) -> None:
        """Handle security events."""
        self._threat_history.append({
            "timestamp": event.timestamp.isoformat(),
            "type": event.event_type,
            "severity": event.severity.value,
            "data": event.data
        })

        # Keep only recent history
        if len(self._threat_history) > 1000:
            self._threat_history = self._threat_history[-500:]

        # Assess if we need additional agents
        if event.severity in [EventSeverity.HIGH, EventSeverity.CRITICAL]:
            await self._assess_threat_response(event)

    async def _handle_system_event(self, event: Event) -> None:
        """Handle system events."""
        if event.event_type == "system.resource.critical":
            await self._handle_resource_crisis(event)

    async def _strategic_planning_cycle(self) -> None:
        """Execute a strategic planning cycle."""
        logger.debug("Starting strategic planning cycle")

        # Gather current state
        state = await self._gather_strategic_state()

        # Evaluate goals
        goal_status = await self._evaluate_goals(state)

        # Identify gaps
        gaps = await self._identify_capability_gaps(state, goal_status)

        # Create plans for addressing gaps
        if gaps:
            await self._create_plans_for_gaps(gaps)

        # Execute active plans
        await self._execute_active_plans()

    async def _gather_strategic_state(self) -> dict:
        """Gather current state for strategic analysis."""
        factory = self._get_factory()

        state = {
            "timestamp": utc_now().isoformat(),
            "agents": {
                "total": len(factory.get_all_instances()) if factory else 0,
                "running": len(factory.get_running_instances()) if factory else 0,
                "by_type": {}
            },
            "threats": {
                "recent_count": len([
                    t for t in self._threat_history
                    if datetime.fromisoformat(t["timestamp"]) > utc_now() - timedelta(hours=1)
                ]),
                "critical_count": len([
                    t for t in self._threat_history
                    if t["severity"] in ["critical", "high"]
                ])
            },
            "integrations": {},
            "goals": [g.to_dict() for g in self._goals]
        }

        # Count agents by type
        if factory:
            for instance in factory.get_all_instances():
                agent_type = instance.agent.agent_name
                if agent_type not in state["agents"]["by_type"]:
                    state["agents"]["by_type"][agent_type] = 0
                state["agents"]["by_type"][agent_type] += 1

        # Check integration health
        for name in ["router", "switch", "hypervisor", "storage", "llm"]:
            integration = self.engine.get_integration(name)
            if integration:
                state["integrations"][name] = {
                    "connected": integration.connected,
                    "healthy": await integration.health_check() if integration.connected else False
                }

        return state

    async def _evaluate_goals(self, state: dict) -> dict:
        """Evaluate progress toward strategic goals."""
        goal_status = {}

        for goal in self._goals:
            status = {
                "name": goal.name,
                "priority": goal.priority,
                "progress": 0.0,
                "blockers": [],
                "recommendations": []
            }

            # Evaluate based on goal type
            if goal.name == "network_visibility":
                # Check if discovery agent is running and effective
                discovery_count = state["agents"]["by_type"].get("discovery", 0)
                if discovery_count == 0:
                    status["blockers"].append("No discovery agents running")
                    status["recommendations"].append("Spawn discovery agent")
                else:
                    status["progress"] = 0.5  # At least running

            elif goal.name == "network_security":
                guardian_count = state["agents"]["by_type"].get("guardian", 0)
                if guardian_count == 0:
                    status["blockers"].append("No guardian agents running")
                    status["recommendations"].append("Spawn guardian agent")
                elif state["threats"]["critical_count"] > 5:
                    status["recommendations"].append("Spawn additional guardian for threat surge")
                    status["progress"] = 0.3
                else:
                    status["progress"] = 0.8

            elif goal.name == "service_availability":
                healer_count = state["agents"]["by_type"].get("healer", 0)
                testing_count = state["agents"]["by_type"].get("testing", 0)
                if healer_count == 0:
                    status["recommendations"].append("Spawn healer agent")
                if testing_count == 0:
                    status["recommendations"].append("Spawn testing agent")
                status["progress"] = min(1.0, (healer_count + testing_count) / 2)

            goal.progress = status["progress"]
            goal_status[goal.name] = status

        return goal_status

    async def _identify_capability_gaps(self, state: dict, goal_status: dict) -> list[dict]:
        """Identify gaps in current capabilities."""
        gaps = []

        # Check for missing core agents
        core_agents = ["discovery", "guardian", "planner", "healer"]
        for agent_type in core_agents:
            if state["agents"]["by_type"].get(agent_type, 0) == 0:
                gaps.append({
                    "type": "missing_agent",
                    "agent_type": agent_type,
                    "priority": 10,
                    "reason": f"Core agent '{agent_type}' is not running"
                })

        # Check for overwhelmed agents
        for agent_type, count in state["agents"]["by_type"].items():
            # If we have threats and only one guardian, might need more
            if agent_type == "guardian" and count == 1:
                if state["threats"]["recent_count"] > 10:
                    gaps.append({
                        "type": "insufficient_capacity",
                        "agent_type": agent_type,
                        "priority": 8,
                        "reason": f"High threat volume ({state['threats']['recent_count']}) with single guardian"
                    })

        # Check integration coverage
        critical_integrations = ["router", "switch"]
        for integration in critical_integrations:
            if integration not in state["integrations"]:
                gaps.append({
                    "type": "missing_integration",
                    "integration": integration,
                    "priority": 9,
                    "reason": f"Critical integration '{integration}' not configured"
                })

        # Check goal blockers
        for goal_name, status in goal_status.items():
            for blocker in status["blockers"]:
                gaps.append({
                    "type": "goal_blocker",
                    "goal": goal_name,
                    "blocker": blocker,
                    "priority": self._goals[0].priority if self._goals else 5,
                    "recommendations": status["recommendations"]
                })

        return sorted(gaps, key=lambda x: x["priority"], reverse=True)

    async def _create_plans_for_gaps(self, gaps: list[dict]) -> None:
        """Create strategic plans to address capability gaps."""
        for gap in gaps[:3]:  # Address top 3 gaps
            if gap["type"] == "missing_agent":
                plan = StrategicPlan(
                    name=f"Deploy {gap['agent_type']} agent",
                    goals=[g for g in self._goals if gap['agent_type'] in g.name.lower()],
                    actions=[{
                        "action": "spawn_agent",
                        "template": gap["agent_type"],
                        "config": {}
                    }]
                )
                self._active_plans.append(plan)
                logger.info(f"Created plan to deploy {gap['agent_type']} agent")

            elif gap["type"] == "insufficient_capacity":
                plan = StrategicPlan(
                    name=f"Scale {gap['agent_type']} capacity",
                    goals=[],
                    actions=[{
                        "action": "spawn_agent",
                        "template": gap["agent_type"],
                        "config": {"focus": "overflow"}
                    }]
                )
                self._active_plans.append(plan)

    async def _execute_active_plans(self) -> None:
        """Execute active strategic plans."""
        factory = self._get_factory()
        if not factory:
            return

        for plan in self._active_plans:
            if plan.status != "pending":
                continue

            plan.status = "active"
            logger.info(f"Executing plan: {plan.name}")

            for action in plan.actions:
                if action["action"] == "spawn_agent":
                    try:
                        # Check capacity
                        if len(factory.get_running_instances()) >= self.max_concurrent_agents:
                            logger.warning("Max concurrent agents reached, deferring spawn")
                            continue

                        instance = await factory.create_agent(
                            template_name=action["template"],
                            config=action.get("config", {}),
                            parent_id=self.id,
                            auto_start=True
                        )
                        plan.spawned_agents.append(instance.id)
                        plan.executed_actions.append(f"spawned:{action['template']}")

                    except Exception as e:
                        logger.error(f"Failed to execute plan action: {e}")
                        plan.status = "failed"

            if plan.status == "active":
                plan.status = "completed"

    async def _strategic_review(self) -> None:
        """Periodic review of agent performance and strategy effectiveness."""
        logger.info("Starting strategic review")

        factory = self._get_factory()
        if not factory:
            return

        # Review each running agent
        for instance in factory.get_running_instances():
            instance.update_metrics()

            # Check for underperforming agents
            if instance.actions_taken == 0 and instance.started_at:
                runtime = (utc_now() - instance.started_at).total_seconds()
                if runtime > 3600:  # 1 hour with no actions
                    logger.info(
                        f"Agent {instance.id} has taken no actions in {runtime/3600:.1f} hours"
                    )
                    # Consider retiring or reconfiguring

            # Check for error-prone agents
            if instance.errors_encountered > 10:
                logger.warning(
                    f"Agent {instance.id} has encountered {instance.errors_encountered} errors"
                )

        # Update goal progress
        state = await self._gather_strategic_state()
        await self._evaluate_goals(state)

        # Clean up completed plans
        self._active_plans = [
            p for p in self._active_plans
            if p.status not in ["completed", "failed"]
        ]

    async def _assess_threat_response(self, event: Event) -> None:
        """Assess if current agents are sufficient for a threat."""
        factory = self._get_factory()
        if not factory:
            return

        # Get threat type from event
        threat_type = event.data.get("threat_type", "unknown")

        # Check if we already have agents handling this
        guardians = factory.get_instances_by_template("guardian")
        active_guardians = [g for g in guardians if g.status == "running"]

        if len(active_guardians) == 0:
            # No guardians, spawn one
            logger.warning("No guardian agents available for threat response")
            await factory.spawn_for_threat(
                threat_type=threat_type,
                threat_data=event.data,
                parent_agent=self.id
            )

        elif event.severity == EventSeverity.CRITICAL:
            # Critical threat, might need specialized response
            if len(active_guardians) < 3:
                await factory.spawn_for_threat(
                    threat_type=threat_type,
                    threat_data=event.data,
                    parent_agent=self.id
                )

    async def _handle_resource_crisis(self, event: Event) -> None:
        """Handle critical resource situations."""
        # Could spawn healer agents or take other recovery actions
        factory = self._get_factory()
        if factory:
            healers = factory.get_instances_by_template("healer")
            if len([h for h in healers if h.status == "running"]) == 0:
                await factory.create_agent(
                    template_name="healer",
                    config={"crisis_mode": True},
                    parent_id=self.id
                )

    async def _record_agent_action(self, event: Event) -> None:
        """Record agent action for learning."""
        self._performance_history.append({
            "timestamp": event.timestamp.isoformat(),
            "agent": event.data.get("agent_name"),
            "action": event.data.get("action_type"),
            "success": event.data.get("status") == "executed",
            "confidence": event.data.get("confidence")
        })

        # Keep history bounded
        if len(self._performance_history) > 10000:
            self._performance_history = self._performance_history[-5000:]

    async def _analyze_failure(self, event: Event) -> None:
        """Analyze agent action failures for strategic insights."""
        failure_data = {
            "agent": event.data.get("agent_name"),
            "action": event.data.get("action_type"),
            "error": event.data.get("error"),
            "timestamp": event.timestamp.isoformat()
        }

        logger.warning(f"Agent failure recorded: {failure_data}")

        # Could use LLM to analyze patterns and suggest improvements
        if self.llm_enabled and len(self._performance_history) > 100:
            # Periodic failure analysis with LLM
            pass

    async def _evaluate_confirmation_request(self, event: Event) -> None:
        """Evaluate if strategy agent should auto-approve certain actions."""
        # For now, let human confirmations flow through
        # Future: could auto-approve low-risk actions based on policy
        pass

    def _get_factory(self) -> Optional["AgentFactory"]:
        """Get the agent factory from engine."""
        return getattr(self.engine, 'agent_factory', None)

    async def analyze(self, event: Event) -> Optional[AgentDecision]:
        """Analyze events for strategic decisions."""
        # Most strategic analysis happens in the main loop
        return None

    async def _do_execute(self, action: AgentAction) -> dict:
        """Execute strategic actions."""
        if action.action_type == "spawn_agent":
            factory = self._get_factory()
            if factory:
                instance = await factory.create_agent(
                    template_name=action.parameters["template"],
                    config=action.parameters.get("config", {}),
                    parent_id=self.id
                )
                return {"spawned_agent_id": str(instance.id)}

        elif action.action_type == "retire_agent":
            factory = self._get_factory()
            if factory:
                success = await factory.retire_agent(
                    UUID(action.parameters["agent_id"]),
                    action.reasoning
                )
                return {"success": success}

        return {"status": "unknown_action"}

    async def request_agent_analysis(self, query: str) -> str:
        """
        Use LLM to analyze a strategic question.

        Args:
            query: Strategic question to analyze

        Returns:
            LLM analysis response
        """
        state = await self._gather_strategic_state()

        system_prompt = """You are the Strategy Agent for Sentinel, an AI-native network security platform.
        Your role is to provide strategic analysis and recommendations for network security and management.
        Consider the current state, goals, and constraints when making recommendations."""

        prompt = f"""Current State:
{state}

Active Goals:
{[g.to_dict() for g in self._goals]}

Question: {query}

Provide strategic analysis and specific recommendations."""

        return await self.query_llm(prompt, system_prompt, prefer_local=False)

    def add_goal(self, goal: StrategicGoal) -> None:
        """Add a new strategic goal."""
        self._goals.append(goal)
        logger.info(f"Added strategic goal: {goal.name}")

    def remove_goal(self, goal_name: str) -> bool:
        """Remove a strategic goal."""
        for i, goal in enumerate(self._goals):
            if goal.name == goal_name:
                del self._goals[i]
                logger.info(f"Removed strategic goal: {goal_name}")
                return True
        return False

    @property
    def goals(self) -> list[StrategicGoal]:
        """Get current strategic goals."""
        return self._goals.copy()

    @property
    def active_plans(self) -> list[StrategicPlan]:
        """Get active strategic plans."""
        return self._active_plans.copy()

    @property
    def stats(self) -> dict:
        """Get strategy agent statistics."""
        base_stats = super().stats
        base_stats.update({
            "goals": len(self._goals),
            "active_plans": len(self._active_plans),
            "threat_history_size": len(self._threat_history),
            "performance_history_size": len(self._performance_history),
            "agent_assignments": len(self._agent_assignments)
        })
        return base_stats
