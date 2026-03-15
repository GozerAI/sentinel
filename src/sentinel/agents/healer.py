"""
Healer Agent - Self-repair and automated failover.

This agent monitors system health and performs:
- Health checks on all integrations
- Service recovery and restart
- Automated VM/container failover
- Resource optimization and rebalancing
- Predictive failure detection
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


class HealerAgent(BaseAgent):
    """
    Self-healing and recovery agent.

    Monitors infrastructure health and automatically recovers from failures.
    Works with hypervisor, storage, router, and switch integrations to
    detect problems and initiate recovery actions.

    Configuration:
        healer:
            enabled: true
            health_check_interval_seconds: 30
            auto_restart_services: true
            max_restart_attempts: 3
            auto_failover: true

    Events Published:
        - health.check.completed: After health check cycle
        - health.degraded: Component health degraded
        - health.recovered: Component recovered
        - service.restarted: Service was restarted
        - vm.migrated: VM was migrated

    Events Subscribed:
        - health.alert: External health alerts
        - service.down: Service failure notifications
        - resource.critical: Critical resource utilization
    """

    agent_name = "healer"
    agent_description = "Self-healing and automated recovery"

    def __init__(self, engine, config: dict):
        super().__init__(engine, config)

        # Configuration
        self.health_check_interval = config.get("health_check_interval_seconds", 30)
        self.auto_restart = config.get("auto_restart_services", True)
        self.max_restart_attempts = config.get("max_restart_attempts", 3)
        self.auto_failover = config.get("auto_failover", True)

        # State
        self._health_status: dict[str, dict] = {}
        self._restart_counts: dict[str, int] = {}
        self._last_restart: dict[str, datetime] = {}
        self._failure_predictions: list[dict] = []

        # Track last health check
        self._last_health_check: Optional[datetime] = None

    async def _subscribe_events(self) -> None:
        """Subscribe to health-related events."""
        self.engine.event_bus.subscribe(
            self._handle_health_alert,
            event_type="health.alert"
        )
        self.engine.event_bus.subscribe(
            self._handle_service_down,
            event_type="service.down"
        )
        self.engine.event_bus.subscribe(
            self._handle_resource_critical,
            event_type="resource.critical"
        )

    async def _main_loop(self) -> None:
        """Main health monitoring loop."""
        while self._running:
            try:
                now = utc_now()

                # Run health checks periodically
                if (
                    self._last_health_check is None or
                    (now - self._last_health_check).total_seconds() > self.health_check_interval
                ):
                    await self._run_health_checks()
                    self._last_health_check = now

                # Predictive analysis every 5 minutes
                if hasattr(self, '_last_predictive') and self._last_predictive:
                    if (now - self._last_predictive).total_seconds() > 300:
                        await self._predictive_analysis()
                        self._last_predictive = now
                else:
                    self._last_predictive = now

                await asyncio.sleep(10)

            except Exception as e:
                logger.error(f"Healer loop error: {e}")
                await asyncio.sleep(30)

    async def _run_health_checks(self) -> None:
        """Run health checks on all integrations."""
        logger.debug("Running health checks")

        checks = [
            ("router", self._check_router_health),
            ("switch", self._check_switch_health),
            ("hypervisor", self._check_hypervisor_health),
            ("storage", self._check_storage_health),
        ]

        for component, check_func in checks:
            try:
                status = await check_func()
                self._health_status[component] = {
                    "status": status,
                    "last_check": utc_now().isoformat(),
                    "healthy": status.get("healthy", False)
                }

                if not status.get("healthy", True):
                    await self._evaluate_recovery(component, status)

            except Exception as e:
                logger.error(f"Health check failed for {component}: {e}")
                self._health_status[component] = {
                    "status": {"error": str(e)},
                    "last_check": utc_now().isoformat(),
                    "healthy": False
                }

        # Persist health status
        await self.engine.state.set("healer:health_status", self._health_status)

        # Publish health check event
        await self.engine.event_bus.publish(Event(
            category=EventCategory.SYSTEM,
            event_type="health.check.completed",
            severity=EventSeverity.DEBUG,
            source=f"sentinel.agents.{self.agent_name}",
            title="Health check completed",
            description=f"Checked {len(checks)} components",
            data={"health_status": self._health_status}
        ))

    async def _check_router_health(self) -> dict:
        """Check router integration health."""
        integration = self.engine.get_integration("router")
        if not integration:
            return {"healthy": True, "message": "No router integration configured"}

        try:
            healthy = await integration.health_check()
            return {
                "healthy": healthy,
                "connected": integration.connected,
                "message": "OK" if healthy else "Health check failed"
            }
        except Exception as e:
            return {"healthy": False, "error": str(e)}

    async def _check_switch_health(self) -> dict:
        """Check switch integration health."""
        integration = self.engine.get_integration("switch")
        if not integration:
            return {"healthy": True, "message": "No switch integration configured"}

        try:
            healthy = await integration.health_check()
            return {
                "healthy": healthy,
                "connected": integration.connected,
                "message": "OK" if healthy else "Health check failed"
            }
        except Exception as e:
            return {"healthy": False, "error": str(e)}

    async def _check_hypervisor_health(self) -> dict:
        """Check hypervisor health including resource utilization."""
        integration = self.engine.get_integration("hypervisor")
        if not integration:
            return {"healthy": True, "message": "No hypervisor integration configured"}

        try:
            healthy = await integration.health_check()
            resources = await integration.get_host_resources()

            cpu_util = resources.get("cpu_percent", 0)
            mem_util = resources.get("memory_percent", 0)

            warnings = []
            if cpu_util > 90:
                warnings.append(f"High CPU: {cpu_util}%")
            if mem_util > 90:
                warnings.append(f"High memory: {mem_util}%")

            return {
                "healthy": healthy and not warnings,
                "connected": integration.connected,
                "cpu_percent": cpu_util,
                "memory_percent": mem_util,
                "warnings": warnings
            }
        except Exception as e:
            return {"healthy": False, "error": str(e)}

    async def _check_storage_health(self) -> dict:
        """Check storage system health."""
        integration = self.engine.get_integration("storage")
        if not integration:
            return {"healthy": True, "message": "No storage integration configured"}

        try:
            health = await integration.get_health()
            pools = await integration.get_pools()

            unhealthy_pools = [
                p for p in pools
                if p.get("status") not in ("ONLINE", "HEALTHY")
            ]

            return {
                "healthy": health.get("healthy", False) and not unhealthy_pools,
                "overall_status": health.get("status"),
                "pool_count": len(pools),
                "unhealthy_pools": [p.get("name") for p in unhealthy_pools]
            }
        except Exception as e:
            return {"healthy": False, "error": str(e)}

    async def _handle_health_alert(self, event: Event) -> None:
        """Handle external health alert events."""
        alert = event.data
        component = alert.get("component")
        status = alert.get("status")

        logger.warning(f"Health alert for {component}: {status}")

        if status == "unhealthy":
            await self._evaluate_recovery(component, alert)

    async def _handle_service_down(self, event: Event) -> None:
        """Handle service down events."""
        service = event.data.get("service")
        host = event.data.get("host")

        logger.error(f"Service {service} down on {host}")

        if self.auto_restart:
            await self._attempt_service_restart(service, host)

    async def _handle_resource_critical(self, event: Event) -> None:
        """Handle critical resource utilization events."""
        resource_type = event.data.get("resource_type")
        host = event.data.get("host")
        utilization = event.data.get("utilization")

        logger.warning(f"Critical {resource_type} on {host}: {utilization}%")

        await self._evaluate_resource_action(event.data)

    async def _evaluate_recovery(self, component: str, status: dict) -> None:
        """Evaluate and propose recovery action for unhealthy component."""
        error = status.get("error")
        warnings = status.get("warnings", [])

        if error:
            # Connection error - try reconnect
            decision = AgentDecision(
                agent_name=self.agent_name,
                decision_type="component_recovery",
                input_state={"component": component, "status": status},
                analysis=f"Component {component} has error: {error}. Proposing reconnection.",
                options_considered=[
                    {"action": "reconnect", "reason": "Restore connectivity"}
                ],
                selected_option={"action": "reconnect"},
                confidence=0.85
            )
            self._decisions.append(decision)

            await self.execute_action(
                action_type="reconnect",
                target_type="integration",
                target_id=component,
                parameters={"error": error},
                reasoning=f"Integration {component} has error: {error}",
                confidence=0.85,
                reversible=False
            )

        elif warnings:
            # Resource warnings - evaluate migration
            for warning in warnings:
                if "CPU" in warning or "memory" in warning:
                    await self._evaluate_resource_action({
                        "component": component,
                        "warning": warning
                    })

    async def _attempt_service_restart(self, service: str, host: str) -> None:
        """Attempt to restart a failed service with backoff."""
        service_key = f"{host}:{service}"

        # Check restart count
        restart_count = self._restart_counts.get(service_key, 0)
        last_restart = self._last_restart.get(service_key)

        # Reset counter if last restart was more than 1 hour ago
        if last_restart and utc_now() - last_restart > timedelta(hours=1):
            restart_count = 0

        if restart_count >= self.max_restart_attempts:
            logger.error(f"Max restart attempts reached for {service_key}")

            # Escalate
            await self.engine.event_bus.publish(Event(
                category=EventCategory.SYSTEM,
                event_type="service.restart.failed",
                severity=EventSeverity.CRITICAL,
                source=f"sentinel.agents.{self.agent_name}",
                title=f"Service restart failed: {service}",
                description=f"Max restart attempts ({self.max_restart_attempts}) reached for {service} on {host}",
                data={"service": service, "host": host, "attempts": restart_count}
            ))
            return

        # Propose restart with increasing confirmation requirement
        await self.execute_action(
            action_type="service_restart",
            target_type="service",
            target_id=service_key,
            parameters={
                "service": service,
                "host": host,
                "attempt": restart_count + 1
            },
            reasoning=f"Service {service} down on {host}, attempting restart ({restart_count + 1}/{self.max_restart_attempts})",
            confidence=0.90 if restart_count == 0 else 0.75,  # Lower confidence on retries
            reversible=False
        )

    async def _evaluate_resource_action(self, data: dict) -> None:
        """Evaluate appropriate action for resource issues."""
        resource_type = data.get("resource_type", "unknown")
        host = data.get("host", data.get("component"))
        utilization = data.get("utilization", 0)

        if resource_type == "cpu" and utilization > 95:
            await self._propose_vm_migration(host, "cpu")
        elif resource_type == "memory" and utilization > 95:
            await self._propose_vm_migration(host, "memory")
        elif resource_type == "disk" and utilization > 90:
            # Disk space - alert only
            await self.engine.event_bus.publish(Event(
                category=EventCategory.SYSTEM,
                event_type="resource.disk.warning",
                severity=EventSeverity.WARNING,
                source=f"sentinel.agents.{self.agent_name}",
                title=f"Disk space warning on {host}",
                description=f"Disk utilization at {utilization}%",
                data=data
            ))

    async def _propose_vm_migration(self, source_host: str, reason: str) -> None:
        """Propose migrating VMs from an overloaded host."""
        if not self.auto_failover:
            return

        hypervisor = self.engine.get_integration("hypervisor")
        if not hypervisor:
            return

        try:
            vms = await hypervisor.get_vms()
            host_vms = [v for v in vms if v.get("host") == source_host]

            if not host_vms:
                return

            # Find least loaded VM to migrate
            vm_to_migrate = min(host_vms, key=lambda v: v.get("cpu_usage", 0))

            decision = AgentDecision(
                agent_name=self.agent_name,
                decision_type="vm_migration",
                input_state={
                    "source_host": source_host,
                    "reason": reason,
                    "vms": host_vms
                },
                analysis=f"Host {source_host} overloaded ({reason}). Proposing migration of VM {vm_to_migrate.get('name')}.",
                options_considered=[
                    {"vm": v.get("name"), "cpu_usage": v.get("cpu_usage", 0)}
                    for v in host_vms
                ],
                selected_option={"vm": vm_to_migrate.get("name")},
                confidence=0.75
            )
            self._decisions.append(decision)

            await self.execute_action(
                action_type="vm_migration",
                target_type="vm",
                target_id=vm_to_migrate.get("id"),
                parameters={
                    "vm_name": vm_to_migrate.get("name"),
                    "source_host": source_host,
                    "target_host": "auto",
                    "reason": reason
                },
                reasoning=f"Host {source_host} overloaded ({reason}), proposing migration of VM {vm_to_migrate.get('name')}",
                confidence=0.75,
                reversible=True
            )

        except Exception as e:
            logger.error(f"Failed to evaluate VM migration: {e}")

    async def _predictive_analysis(self) -> None:
        """Perform predictive failure analysis based on trends."""
        # Analyze health trends to predict failures
        for component, status in self._health_status.items():
            if not status.get("healthy"):
                continue

            # Check for warning signs
            warnings = status.get("status", {}).get("warnings", [])
            if warnings:
                self._failure_predictions.append({
                    "component": component,
                    "prediction": "degraded",
                    "confidence": 0.6,
                    "warnings": warnings,
                    "timestamp": utc_now().isoformat()
                })

        # Clean old predictions
        cutoff = utc_now() - timedelta(hours=1)
        self._failure_predictions = [
            p for p in self._failure_predictions
            if datetime.fromisoformat(p["timestamp"]) > cutoff
        ]

    async def analyze(self, event: Event) -> Optional[AgentDecision]:
        """Analyze events for recovery decisions."""
        # Most handling is done in event handlers
        return None

    async def _do_execute(self, action: AgentAction) -> dict:
        """Execute healer actions."""
        if action.action_type == "reconnect":
            component = action.target_id
            integration = self.engine.get_integration(component)

            if integration:
                await integration.reconnect()
                return {"reconnected": True, "component": component}
            return {"reconnected": False, "error": "Integration not found"}

        elif action.action_type == "service_restart":
            service = action.parameters.get("service")
            host = action.parameters.get("host")
            service_key = f"{host}:{service}"

            logger.info(f"Restarting service {service} on {host}")

            # Update tracking
            self._restart_counts[service_key] = self._restart_counts.get(service_key, 0) + 1
            self._last_restart[service_key] = utc_now()

            # Try to restart via hypervisor (for VM-based services)
            hypervisor = self.engine.get_integration("hypervisor")
            if hypervisor:
                try:
                    # Check if this is a VM that needs restart
                    vms = await hypervisor.get_vms()
                    matching_vms = [v for v in vms if v.get("name") == service or service in v.get("name", "")]
                    if matching_vms:
                        vm = matching_vms[0]
                        vm_id = vm.get("id")
                        logger.info(f"Restarting VM {vm.get('name')} (ID: {vm_id}) for service {service}")
                        await hypervisor.stop_vm(vm_id)
                        await asyncio.sleep(5)
                        await hypervisor.start_vm(vm_id)
                        return {"restarted": True, "service": service, "host": host, "method": "vm_restart"}
                except Exception as e:
                    logger.warning(f"VM restart attempt failed: {e}")

            # Try to restart via router/switch command execution if supported
            router = self.engine.get_integration("router")
            if router and hasattr(router, "execute_command"):
                try:
                    # Execute systemctl restart on the target host
                    result = await router.execute_command(f"ssh {host} systemctl restart {service}")
                    if result.get("success"):
                        return {"restarted": True, "service": service, "host": host, "method": "ssh_systemctl"}
                except Exception as e:
                    logger.warning(f"SSH restart attempt failed: {e}")

            # Fallback: publish event for manual intervention
            logger.warning(
                f"No suitable integration found to restart service {service} on {host}. "
                f"Manual intervention may be required."
            )
            await self.engine.event_bus.publish(Event(
                category=EventCategory.SYSTEM,
                event_type="service.restart.manual_required",
                severity=EventSeverity.WARNING,
                source=f"sentinel.agents.{self.agent_name}",
                title=f"Manual restart needed: {service}",
                description=f"Service {service} on {host} needs manual restart - no suitable automation available",
                data={"service": service, "host": host}
            ))
            return {"restarted": False, "service": service, "host": host, "method": "manual_required"}

        elif action.action_type == "vm_migration":
            vm_id = action.target_id
            target_host = action.parameters.get("target_host")

            hypervisor = self.engine.get_integration("hypervisor")
            if hypervisor:
                success = await hypervisor.migrate_vm(vm_id, target_host)
                return {"migrated": success, "vm_id": vm_id}
            return {"migrated": False, "error": "No hypervisor integration"}

        elif action.action_type == "vm_restart":
            vm_id = action.target_id

            hypervisor = self.engine.get_integration("hypervisor")
            if hypervisor:
                await hypervisor.stop_vm(vm_id)
                await asyncio.sleep(5)
                await hypervisor.start_vm(vm_id)
                return {"restarted": True, "vm_id": vm_id}
            return {"restarted": False, "error": "No hypervisor integration"}

        raise ValueError(f"Unknown action type: {action.action_type}")

    async def _capture_rollback_data(self, action: AgentAction) -> Optional[dict]:
        """Capture state for rollback."""
        if action.action_type == "vm_migration":
            return {
                "action": "vm_migration",
                "vm_id": action.target_id,
                "original_host": action.parameters.get("source_host")
            }
        return None

    async def _do_rollback(self, action: AgentAction) -> None:
        """Rollback healer actions."""
        rollback = action.rollback_data or {}

        if rollback.get("action") == "vm_migration":
            vm_id = rollback.get("vm_id")
            original_host = rollback.get("original_host")

            hypervisor = self.engine.get_integration("hypervisor")
            if hypervisor and original_host:
                await hypervisor.migrate_vm(vm_id, original_host)

    async def _get_relevant_state(self) -> dict:
        """Get state relevant to healer decisions."""
        return {
            "health_status": self._health_status,
            "restart_counts": self._restart_counts,
            "failure_predictions": len(self._failure_predictions)
        }

    @property
    def stats(self) -> dict:
        """Get healer statistics."""
        base = super().stats

        healthy_count = sum(
            1 for s in self._health_status.values()
            if s.get("healthy", False)
        )

        return {
            **base,
            "components_monitored": len(self._health_status),
            "healthy_components": healthy_count,
            "restart_attempts": sum(self._restart_counts.values()),
            "failure_predictions": len(self._failure_predictions)
        }
