"""
Testing Agent - Automated system health and issue detection.

This agent continuously monitors the Sentinel system for:
- Integration health issues
- Agent performance problems
- Event processing delays
- Resource utilization concerns
- Configuration inconsistencies
"""
import asyncio
import logging
from datetime import datetime, timedelta
from typing import Optional

from sentinel.core.utils import utc_now
from sentinel.agents.base import BaseAgent
from sentinel.core.models.event import (
    Event, EventCategory, EventSeverity,
    AgentAction, AgentDecision
)

logger = logging.getLogger(__name__)


class TestingAgent(BaseAgent):
    """
    Automated system health monitoring and issue detection agent.

    Monitors the overall health of the Sentinel platform by:
    - Checking integration connectivity
    - Monitoring agent performance metrics
    - Detecting event processing delays
    - Identifying configuration issues
    - Running self-diagnostic tests

    Configuration:
        testing:
            enabled: true
            health_check_interval_seconds: 60
            max_event_processing_delay_ms: 500
            auto_restart_failed_agents: true
            alert_on_integration_failure: true

    Events Published:
        - system.health.check: Periodic health check results
        - system.issue.detected: Issue found during monitoring
        - system.issue.resolved: Previously detected issue resolved
        - agent.performance.warning: Agent performance concerns

    Events Subscribed:
        - agent.action.*: Monitor agent actions
        - system.error: System error events
        - integration.status.*: Integration status changes
    """

    agent_name = "testing"
    agent_description = "Automated system health and issue detection"

    def __init__(self, engine, config: dict):
        super().__init__(engine, config)

        # Configuration
        self.health_check_interval = config.get("health_check_interval_seconds", 60)
        self.max_event_delay_ms = config.get("max_event_processing_delay_ms", 500)
        self.auto_restart_agents = config.get("auto_restart_failed_agents", False)
        self.alert_on_integration_failure = config.get("alert_on_integration_failure", True)

        # State
        self._detected_issues: dict[str, dict] = {}
        self._resolved_issues: list[dict] = []
        self._health_history: list[dict] = []
        self._agent_metrics: dict[str, dict] = {}
        self._last_health_check: Optional[datetime] = None

        # Performance tracking
        self._event_processing_times: list[float] = []
        self._integration_status: dict[str, dict] = {}

    async def _subscribe_events(self) -> None:
        """Subscribe to system monitoring events."""
        self.engine.event_bus.subscribe(
            self._handle_agent_action,
            event_type="agent.action.*"
        )
        self.engine.event_bus.subscribe(
            self._handle_system_error,
            event_type="system.error"
        )
        self.engine.event_bus.subscribe(
            self._handle_integration_status,
            event_type="integration.status.*"
        )

    async def _main_loop(self) -> None:
        """Main monitoring loop."""
        while self._running:
            try:
                now = utc_now()

                # Run health checks periodically
                if (
                    self._last_health_check is None or
                    (now - self._last_health_check).total_seconds() > self.health_check_interval
                ):
                    await self._run_system_health_check()
                    self._last_health_check = now

                # Check for stale issues
                await self._check_resolved_issues()

                # Clean up old data
                await self._cleanup_old_data()

                await asyncio.sleep(10)

            except Exception as e:
                logger.error(f"Testing agent loop error: {e}")
                await asyncio.sleep(30)

    async def _run_system_health_check(self) -> None:
        """Run comprehensive system health check."""
        logger.debug("Running system health check")
        issues_found = []

        # Check integration health
        integration_issues = await self._check_integrations()
        issues_found.extend(integration_issues)

        # Check agent health
        agent_issues = await self._check_agents()
        issues_found.extend(agent_issues)

        # Check event processing performance
        perf_issues = await self._check_event_performance()
        issues_found.extend(perf_issues)

        # Check resource utilization
        resource_issues = await self._check_resources()
        issues_found.extend(resource_issues)

        # Record health check result
        health_result = {
            "timestamp": utc_now().isoformat(),
            "issues_found": len(issues_found),
            "issues": issues_found,
            "integrations_checked": len(self._integration_status),
            "agents_checked": len(self._agent_metrics)
        }
        self._health_history.append(health_result)

        # Limit history
        if len(self._health_history) > 100:
            self._health_history = self._health_history[-100:]

        # Publish health check event
        severity = EventSeverity.INFO
        if issues_found:
            severity = EventSeverity.WARNING if len(issues_found) < 3 else EventSeverity.ERROR

        await self.engine.event_bus.publish(Event(
            category=EventCategory.SYSTEM,
            event_type="system.health.check",
            severity=severity,
            source=f"sentinel.agents.{self.agent_name}",
            title="System Health Check",
            description=f"Found {len(issues_found)} issues" if issues_found else "All systems healthy",
            data=health_result
        ))

    async def _check_integrations(self) -> list[dict]:
        """Check health of all integrations."""
        issues = []

        integration_types = ["router", "switch", "hypervisor", "storage", "llm"]

        for int_type in integration_types:
            integration = self.engine.get_integration(int_type)
            if not integration:
                continue

            try:
                # Check if integration is connected
                connected = getattr(integration, 'connected', True)
                if not connected:
                    issue = {
                        "type": "integration_disconnected",
                        "severity": "high",
                        "component": int_type,
                        "message": f"Integration {int_type} is disconnected"
                    }
                    issues.append(issue)
                    await self._record_issue(f"int_{int_type}_disconnected", issue)
                else:
                    await self._clear_issue(f"int_{int_type}_disconnected")

                # Check if integration has health check method
                if hasattr(integration, 'health_check'):
                    healthy = await integration.health_check()
                    if not healthy:
                        issue = {
                            "type": "integration_unhealthy",
                            "severity": "medium",
                            "component": int_type,
                            "message": f"Integration {int_type} health check failed"
                        }
                        issues.append(issue)
                        await self._record_issue(f"int_{int_type}_unhealthy", issue)
                    else:
                        await self._clear_issue(f"int_{int_type}_unhealthy")

                self._integration_status[int_type] = {
                    "connected": connected,
                    "healthy": connected and (not hasattr(integration, 'health_check') or healthy),
                    "last_check": utc_now().isoformat()
                }

            except Exception as e:
                issue = {
                    "type": "integration_error",
                    "severity": "high",
                    "component": int_type,
                    "message": f"Error checking {int_type}: {str(e)}"
                }
                issues.append(issue)
                await self._record_issue(f"int_{int_type}_error", issue)

        return issues

    async def _check_agents(self) -> list[dict]:
        """Check health of all agents."""
        issues = []

        # Get all registered agents
        agents = getattr(self.engine, '_agents', {})

        for agent_name, agent in agents.items():
            if agent_name == self.agent_name:
                continue  # Don't check ourselves

            try:
                # Check if agent is running
                running = getattr(agent, '_running', False)
                if not running:
                    issue = {
                        "type": "agent_stopped",
                        "severity": "high",
                        "component": agent_name,
                        "message": f"Agent {agent_name} is not running"
                    }
                    issues.append(issue)
                    await self._record_issue(f"agent_{agent_name}_stopped", issue)

                    # Auto-restart if configured
                    if self.auto_restart_agents:
                        await self._propose_agent_restart(agent_name)
                else:
                    await self._clear_issue(f"agent_{agent_name}_stopped")

                # Check agent metrics
                stats = getattr(agent, 'stats', {})
                if isinstance(stats, dict):
                    actions_per_min = stats.get('actions_this_minute', 0)

                    # Check for potential runaway agent
                    if actions_per_min > 50:
                        issue = {
                            "type": "agent_high_activity",
                            "severity": "medium",
                            "component": agent_name,
                            "message": f"Agent {agent_name} has high activity: {actions_per_min} actions/min"
                        }
                        issues.append(issue)
                        await self._record_issue(f"agent_{agent_name}_high_activity", issue)

                    self._agent_metrics[agent_name] = {
                        "running": running,
                        "stats": stats,
                        "last_check": utc_now().isoformat()
                    }

            except Exception as e:
                logger.warning(f"Error checking agent {agent_name}: {e}")

        return issues

    async def _check_event_performance(self) -> list[dict]:
        """Check event processing performance."""
        issues = []

        # Get event bus metrics if available
        event_bus = getattr(self.engine, 'event_bus', None)
        if not event_bus:
            return issues

        # Check queue depth
        queue_depth = getattr(event_bus, '_queue_depth', 0)
        if queue_depth > 100:
            issue = {
                "type": "event_queue_backlog",
                "severity": "medium",
                "component": "event_bus",
                "message": f"Event queue has {queue_depth} pending events"
            }
            issues.append(issue)
            await self._record_issue("event_queue_backlog", issue)
        else:
            await self._clear_issue("event_queue_backlog")

        # Check average processing time
        if self._event_processing_times:
            avg_time = sum(self._event_processing_times) / len(self._event_processing_times)
            if avg_time > self.max_event_delay_ms:
                issue = {
                    "type": "slow_event_processing",
                    "severity": "medium",
                    "component": "event_bus",
                    "message": f"Average event processing time: {avg_time:.1f}ms (threshold: {self.max_event_delay_ms}ms)"
                }
                issues.append(issue)
                await self._record_issue("slow_event_processing", issue)
            else:
                await self._clear_issue("slow_event_processing")

        return issues

    async def _check_resources(self) -> list[dict]:
        """Check system resource utilization."""
        issues = []

        # Get metrics from engine if available
        metrics = getattr(self.engine, 'metrics', None)
        if metrics:
            try:
                memory_usage = await metrics.get_value("system.memory.percent")
                if memory_usage and memory_usage > 90:
                    issue = {
                        "type": "high_memory",
                        "severity": "high",
                        "component": "system",
                        "message": f"System memory usage at {memory_usage}%"
                    }
                    issues.append(issue)
                    await self._record_issue("high_memory", issue)
                else:
                    await self._clear_issue("high_memory")

            except Exception as e:
                logger.debug(f"System metrics not available: {e}")

        return issues

    async def _record_issue(self, issue_id: str, issue: dict) -> None:
        """Record a detected issue."""
        if issue_id not in self._detected_issues:
            self._detected_issues[issue_id] = {
                **issue,
                "first_detected": utc_now().isoformat(),
                "occurrence_count": 1
            }

            # Publish issue detected event
            await self.engine.event_bus.publish(Event(
                category=EventCategory.SYSTEM,
                event_type="system.issue.detected",
                severity=EventSeverity.WARNING if issue.get("severity") == "medium" else EventSeverity.ERROR,
                source=f"sentinel.agents.{self.agent_name}",
                title=f"Issue Detected: {issue.get('type')}",
                description=issue.get("message"),
                data=self._detected_issues[issue_id]
            ))
        else:
            self._detected_issues[issue_id]["occurrence_count"] += 1
            self._detected_issues[issue_id]["last_seen"] = utc_now().isoformat()

    async def _clear_issue(self, issue_id: str) -> None:
        """Clear a resolved issue."""
        if issue_id in self._detected_issues:
            resolved_issue = self._detected_issues.pop(issue_id)
            resolved_issue["resolved_at"] = utc_now().isoformat()
            self._resolved_issues.append(resolved_issue)

            # Publish issue resolved event
            await self.engine.event_bus.publish(Event(
                category=EventCategory.SYSTEM,
                event_type="system.issue.resolved",
                severity=EventSeverity.INFO,
                source=f"sentinel.agents.{self.agent_name}",
                title=f"Issue Resolved: {resolved_issue.get('type')}",
                description=f"Previously detected issue has been resolved",
                data=resolved_issue
            ))

    async def _check_resolved_issues(self) -> None:
        """Check if any issues have automatically resolved."""
        # This is handled by individual check methods calling _clear_issue
        pass

    async def _cleanup_old_data(self) -> None:
        """Clean up old tracking data."""
        cutoff = utc_now() - timedelta(hours=24)

        # Clean old resolved issues
        self._resolved_issues = [
            issue for issue in self._resolved_issues
            if datetime.fromisoformat(issue.get("resolved_at", cutoff.isoformat())) > cutoff
        ]

        # Clean old processing times
        if len(self._event_processing_times) > 1000:
            self._event_processing_times = self._event_processing_times[-1000:]

    async def _propose_agent_restart(self, agent_name: str) -> None:
        """Propose restarting a stopped agent."""
        decision = AgentDecision(
            agent_name=self.agent_name,
            decision_type="agent_restart",
            input_state={"agent_name": agent_name},
            analysis=f"Agent {agent_name} is not running and auto-restart is enabled",
            options_considered=[
                {"action": "restart", "reason": "Agent stopped"},
                {"action": "ignore", "reason": "May be intentional"}
            ],
            selected_option={"action": "restart"},
            confidence=0.85
        )
        self._decisions.append(decision)

        await self.execute_action(
            action_type="restart_agent",
            target_type="agent",
            target_id=agent_name,
            parameters={"agent_name": agent_name},
            reasoning=f"Agent {agent_name} is stopped, proposing restart",
            confidence=0.85,
            reversible=False
        )

    async def _handle_agent_action(self, event: Event) -> None:
        """Handle agent action events to track performance."""
        agent_name = event.data.get("agent_name")
        if agent_name:
            if agent_name not in self._agent_metrics:
                self._agent_metrics[agent_name] = {"actions": 0}
            self._agent_metrics[agent_name]["actions"] = self._agent_metrics[agent_name].get("actions", 0) + 1
            self._agent_metrics[agent_name]["last_action"] = utc_now().isoformat()

    async def _handle_system_error(self, event: Event) -> None:
        """Handle system error events."""
        error = event.data
        component = error.get("component", "unknown")
        error_type = error.get("error_type", "unknown")

        issue = {
            "type": f"system_error_{error_type}",
            "severity": "high",
            "component": component,
            "message": error.get("message", "System error occurred"),
            "error_data": error
        }
        await self._record_issue(f"sys_error_{component}_{error_type}", issue)

    async def _handle_integration_status(self, event: Event) -> None:
        """Handle integration status change events."""
        integration = event.data.get("integration")
        status = event.data.get("status")

        if integration:
            self._integration_status[integration] = {
                "status": status,
                "last_update": utc_now().isoformat()
            }

            if status == "disconnected":
                issue = {
                    "type": "integration_disconnected",
                    "severity": "high",
                    "component": integration,
                    "message": f"Integration {integration} reported disconnected"
                }
                await self._record_issue(f"int_{integration}_status_disconnected", issue)
            elif status == "connected":
                await self._clear_issue(f"int_{integration}_status_disconnected")

    async def analyze(self, event: Event) -> Optional[AgentDecision]:
        """Analyze events for testing decisions."""
        # Most handling is done in event handlers
        return None

    async def _do_execute(self, action: AgentAction) -> dict:
        """Execute testing agent actions."""
        if action.action_type == "restart_agent":
            agent_name = action.parameters.get("agent_name")

            # Get the agent from engine
            agents = getattr(self.engine, '_agents', {})
            agent = agents.get(agent_name)

            if agent:
                try:
                    await agent.start()
                    return {"restarted": True, "agent_name": agent_name}
                except Exception as e:
                    return {"restarted": False, "error": str(e)}

            return {"restarted": False, "error": "Agent not found"}

        elif action.action_type == "clear_issue":
            issue_id = action.parameters.get("issue_id")
            if issue_id in self._detected_issues:
                await self._clear_issue(issue_id)
                return {"cleared": True, "issue_id": issue_id}
            return {"cleared": False, "error": "Issue not found"}

        raise ValueError(f"Unknown action type: {action.action_type}")

    async def _capture_rollback_data(self, action: AgentAction) -> Optional[dict]:
        """Capture state for rollback."""
        # Most testing actions are not reversible
        return None

    async def _do_rollback(self, action: AgentAction) -> None:
        """Rollback testing actions."""
        pass  # Most testing actions cannot be rolled back

    async def _get_relevant_state(self) -> dict:
        """Get state relevant to testing decisions."""
        return {
            "detected_issues": len(self._detected_issues),
            "resolved_issues": len(self._resolved_issues),
            "integration_status": self._integration_status,
            "agent_metrics": self._agent_metrics
        }

    @property
    def detected_issues(self) -> dict[str, dict]:
        """Get currently detected issues."""
        return self._detected_issues.copy()

    @property
    def resolved_issues(self) -> list[dict]:
        """Get recently resolved issues."""
        return self._resolved_issues.copy()

    @property
    def integration_status(self) -> dict[str, dict]:
        """Get integration status summary."""
        return self._integration_status.copy()

    @property
    def stats(self) -> dict:
        """Get testing agent statistics."""
        base = super().stats

        return {
            **base,
            "detected_issues": len(self._detected_issues),
            "resolved_issues_24h": len(self._resolved_issues),
            "health_checks": len(self._health_history),
            "integrations_monitored": len(self._integration_status),
            "agents_monitored": len(self._agent_metrics)
        }
