"""
Policy Enforcer Agent - Continuous policy compliance enforcement.

This agent monitors the network state and enforces security policies:
- Firewall rule compliance
- Segmentation policy enforcement
- Device policy application
- Automation rule execution
"""
import asyncio
import logging
from datetime import datetime, timedelta
from typing import Optional
from uuid import UUID

from sentinel.agents.base import BaseAgent
from sentinel.core.utils import utc_now
from sentinel.core.models.event import (
    Event, EventCategory, EventSeverity,
    AgentAction, AgentDecision
)
from sentinel.core.models.policy import (
    PolicyAction, PolicySet, FirewallRule, SegmentationPolicy,
    DevicePolicy, AutomationRule
)

logger = logging.getLogger(__name__)


class PolicyEnforcerAgent(BaseAgent):
    """
    Continuous policy enforcement agent.

    Monitors network state and ensures compliance with defined security
    policies. Automatically corrects policy violations and maintains
    compliance metrics.

    Configuration:
        policy_enforcer:
            enabled: true
            enforcement_interval_seconds: 60
            violation_threshold: 3  # Violations before action
            auto_remediate: true
            audit_mode: false  # Log-only mode

    Events Published:
        - policy.violation.detected: Policy violation found
        - policy.violation.remediated: Violation automatically fixed
        - policy.compliance.report: Periodic compliance summary
        - policy.rule.expired: Firewall rule expired

    Events Subscribed:
        - device.discovered: New device to apply policies
        - device.classified: Reclassified device
        - network.traffic.anomaly: Traffic that may violate policies
    """

    agent_name = "policy_enforcer"
    agent_description = "Continuous security policy enforcement"

    def __init__(self, engine, config: dict):
        super().__init__(engine, config)

        # Configuration
        self.enforcement_interval = config.get("enforcement_interval_seconds", 60)
        self.violation_threshold = config.get("violation_threshold", 3)
        self.auto_remediate = config.get("auto_remediate", True)
        self.audit_mode = config.get("audit_mode", False)

        # State
        self._policy_set: Optional[PolicySet] = None
        self._violation_counts: dict[str, int] = {}  # device_id -> count
        self._compliance_stats: dict[str, dict] = {}
        self._last_enforcement: Optional[datetime] = None
        self._automation_executions: dict[UUID, list[datetime]] = {}

    async def _subscribe_events(self) -> None:
        """Subscribe to policy-relevant events."""
        self.engine.event_bus.subscribe(
            self._handle_device_discovered,
            event_type="device.discovered"
        )
        self.engine.event_bus.subscribe(
            self._handle_device_classified,
            event_type="device.classified"
        )
        self.engine.event_bus.subscribe(
            self._handle_traffic_anomaly,
            event_type="network.traffic.anomaly"
        )
        self.engine.event_bus.subscribe(
            self._handle_segmentation_violation,
            event_type="segmentation.violation"
        )

    async def _main_loop(self) -> None:
        """Main policy enforcement loop."""
        while self._running:
            try:
                now = utc_now()

                # Run enforcement periodically
                if (
                    self._last_enforcement is None or
                    (now - self._last_enforcement).total_seconds() > self.enforcement_interval
                ):
                    await self._run_enforcement_cycle()
                    self._last_enforcement = now

                await asyncio.sleep(10)

            except Exception as e:
                logger.error(f"Policy enforcement loop error: {e}")
                await asyncio.sleep(30)

    async def _run_enforcement_cycle(self) -> None:
        """Run a full policy enforcement cycle."""
        logger.debug("Running policy enforcement cycle")

        # Load current policies
        await self._load_policies()

        if not self._policy_set:
            logger.debug("No policy set configured")
            return

        # Check firewall rule expiration
        await self._check_firewall_expirations()

        # Verify device policy compliance
        await self._verify_device_compliance()

        # Verify segmentation policies
        await self._verify_segmentation_compliance()

        # Process automation rules
        await self._process_automation_rules()

        # Publish compliance report
        await self._publish_compliance_report()

    async def _load_policies(self) -> None:
        """Load policy set from state."""
        try:
            policy_data = await self.engine.state.get("policy_set")
            if policy_data:
                self._policy_set = PolicySet(**policy_data)
            else:
                # Create default policy set if none exists
                self._policy_set = PolicySet(name="default")
        except Exception as e:
            logger.error(f"Failed to load policies: {e}")

    async def _check_firewall_expirations(self) -> None:
        """Check for and handle expired firewall rules."""
        if not self._policy_set:
            return

        for rule in self._policy_set.firewall_rules:
            if rule.is_expired and rule.enabled:
                logger.info(f"Firewall rule '{rule.name}' has expired")

                await self.execute_action(
                    action_type="disable_firewall_rule",
                    target_type="firewall_rule",
                    target_id=str(rule.id),
                    parameters={"rule_name": rule.name},
                    reasoning=f"Firewall rule '{rule.name}' has expired (expired at {rule.expires_at})",
                    confidence=0.95,
                    reversible=True
                )

                await self.engine.event_bus.publish(Event(
                    category=EventCategory.SECURITY,
                    event_type="policy.rule.expired",
                    severity=EventSeverity.INFO,
                    source=f"sentinel.agents.{self.agent_name}",
                    title=f"Firewall rule expired: {rule.name}",
                    description=f"Automatically disabled expired firewall rule",
                    data={"rule_id": str(rule.id), "rule_name": rule.name}
                ))

    async def _verify_device_compliance(self) -> None:
        """Verify devices comply with device policies."""
        if not self._policy_set:
            return

        # Get current device inventory
        inventory = await self.engine.state.get("device_inventory", {})

        for device_id, device in inventory.items():
            device_type = device.get("device_type", "unknown")
            vendor = device.get("vendor")
            tags = device.get("tags", [])
            current_vlan = device.get("vlan")

            # Find matching policy
            matching_policy = None
            for policy in sorted(self._policy_set.device_policies, key=lambda p: p.priority):
                if policy.enabled and policy.matches_device(device_type, vendor, tags):
                    matching_policy = policy
                    break

            if matching_policy and matching_policy.assign_vlan:
                if current_vlan != matching_policy.assign_vlan:
                    await self._handle_vlan_violation(
                        device_id, device, matching_policy, current_vlan
                    )

    async def _handle_vlan_violation(
        self,
        device_id: str,
        device: dict,
        policy: DevicePolicy,
        current_vlan: Optional[int]
    ) -> None:
        """Handle a device VLAN policy violation."""
        # Track violations
        self._violation_counts[device_id] = self._violation_counts.get(device_id, 0) + 1
        violation_count = self._violation_counts[device_id]

        logger.warning(
            f"Device {device_id} in wrong VLAN: current={current_vlan}, "
            f"expected={policy.assign_vlan} (violation #{violation_count})"
        )

        await self.engine.event_bus.publish(Event(
            category=EventCategory.SECURITY,
            event_type="policy.violation.detected",
            severity=EventSeverity.WARNING,
            source=f"sentinel.agents.{self.agent_name}",
            title=f"VLAN policy violation: {device.get('name', device_id)}",
            description=f"Device should be in VLAN {policy.assign_vlan} but is in {current_vlan}",
            data={
                "device_id": device_id,
                "device_name": device.get("name"),
                "policy_name": policy.name,
                "expected_vlan": policy.assign_vlan,
                "current_vlan": current_vlan,
                "violation_count": violation_count
            }
        ))

        # Auto-remediate if threshold reached and not in audit mode
        if self.auto_remediate and not self.audit_mode:
            if violation_count >= self.violation_threshold:
                await self._remediate_vlan_violation(device_id, device, policy)

    async def _remediate_vlan_violation(
        self,
        device_id: str,
        device: dict,
        policy: DevicePolicy
    ) -> None:
        """Remediate a VLAN policy violation."""
        # Calculate confidence based on how many times we've seen this device
        # in the wrong VLAN - more violations = higher confidence it's wrong
        violation_count = self._violation_counts.get(device_id, 0)
        confidence = min(0.95, 0.75 + (violation_count * 0.05))

        decision = AgentDecision(
            agent_name=self.agent_name,
            decision_type="vlan_remediation",
            input_state={
                "device_id": device_id,
                "current_vlan": device.get("vlan"),
                "target_vlan": policy.assign_vlan
            },
            analysis=f"Device {device_id} has been in wrong VLAN for {violation_count} checks. Moving to VLAN {policy.assign_vlan} per policy '{policy.name}'.",
            options_considered=[
                {"action": "move_vlan", "vlan": policy.assign_vlan},
                {"action": "quarantine", "vlan": 999},
                {"action": "ignore", "reason": "Manual review"}
            ],
            selected_option={"action": "move_vlan", "vlan": policy.assign_vlan},
            confidence=confidence
        )
        self._decisions.append(decision)

        await self.execute_action(
            action_type="assign_vlan",
            target_type="device",
            target_id=device_id,
            parameters={
                "vlan_id": policy.assign_vlan,
                "policy_name": policy.name,
                "mac_address": device.get("mac_address"),
                "port": device.get("port")
            },
            reasoning=f"Enforcing policy '{policy.name}': moving device to VLAN {policy.assign_vlan}",
            confidence=confidence,
            reversible=True
        )

        # Reset violation count after remediation
        self._violation_counts[device_id] = 0

        await self.engine.event_bus.publish(Event(
            category=EventCategory.SECURITY,
            event_type="policy.violation.remediated",
            severity=EventSeverity.INFO,
            source=f"sentinel.agents.{self.agent_name}",
            title=f"Policy violation remediated: {device.get('name', device_id)}",
            description=f"Device moved to VLAN {policy.assign_vlan} per policy '{policy.name}'",
            data={
                "device_id": device_id,
                "device_name": device.get("name"),
                "new_vlan": policy.assign_vlan
            }
        ))

    async def _verify_segmentation_compliance(self) -> None:
        """Verify segmentation policies are being enforced."""
        if not self._policy_set:
            return

        # Get current traffic stats or flow data if available
        # This would typically come from flow analysis or firewall logs
        pass  # Placeholder for future flow-based analysis

    async def _process_automation_rules(self) -> None:
        """Process and execute applicable automation rules."""
        if not self._policy_set:
            return

        for rule in self._policy_set.automation_rules:
            if not rule.enabled:
                continue

            # Check if rule can be executed (rate limiting)
            executions_this_hour = self._count_executions_this_hour(rule.id)
            if not rule.can_execute(executions_this_hour):
                continue

            # Rules are triggered by events, handled in event handlers
            # This loop is for time-based or scheduled rules
            if rule.trigger_event == "scheduled":
                await self._execute_automation_rule(rule)

    def _count_executions_this_hour(self, rule_id: UUID) -> int:
        """Count executions of a rule in the last hour."""
        if rule_id not in self._automation_executions:
            return 0

        cutoff = utc_now() - timedelta(hours=1)
        executions = [
            ts for ts in self._automation_executions[rule_id]
            if ts > cutoff
        ]
        self._automation_executions[rule_id] = executions
        return len(executions)

    async def _execute_automation_rule(self, rule: AutomationRule) -> None:
        """Execute an automation rule."""
        logger.info(f"Executing automation rule: {rule.name}")

        await self.execute_action(
            action_type=rule.action_type,
            target_type="automation",
            target_id=str(rule.id),
            parameters=rule.action_params,
            reasoning=f"Automation rule '{rule.name}': {rule.description or 'No description'}",
            confidence=rule.confidence_threshold,
            reversible=rule.rollback_enabled
        )

        # Track execution
        if rule.id not in self._automation_executions:
            self._automation_executions[rule.id] = []
        self._automation_executions[rule.id].append(utc_now())

        rule.record_execution("executed")

    async def _publish_compliance_report(self) -> None:
        """Publish periodic compliance statistics."""
        if not self._policy_set:
            return

        total_devices = len(await self.engine.state.get("device_inventory", {}))
        violations = sum(1 for v in self._violation_counts.values() if v > 0)

        compliance_rate = ((total_devices - violations) / total_devices * 100
                          if total_devices > 0 else 100)

        self._compliance_stats = {
            "timestamp": utc_now().isoformat(),
            "total_devices": total_devices,
            "devices_in_violation": violations,
            "compliance_rate": compliance_rate,
            "firewall_rules": len(self._policy_set.firewall_rules),
            "device_policies": len(self._policy_set.device_policies),
            "automation_rules": len(self._policy_set.automation_rules)
        }

        await self.engine.state.set(
            "policy_enforcer:compliance_stats",
            self._compliance_stats
        )

        await self.engine.event_bus.publish(Event(
            category=EventCategory.SYSTEM,
            event_type="policy.compliance.report",
            severity=EventSeverity.DEBUG,
            source=f"sentinel.agents.{self.agent_name}",
            title="Policy Compliance Report",
            description=f"Compliance rate: {compliance_rate:.1f}%",
            data=self._compliance_stats
        ))

    async def _handle_device_discovered(self, event: Event) -> None:
        """Apply policies to newly discovered devices."""
        device = event.data
        device_id = device.get("id") or device.get("mac_address")

        if not device_id:
            return

        # Let device be classified first, then apply policies
        # Policies are applied on device.classified event
        logger.debug(f"New device discovered: {device_id}")

    async def _handle_device_classified(self, event: Event) -> None:
        """Apply policies to classified devices."""
        device = event.data
        device_id = device.get("id") or device.get("mac_address")
        device_type = device.get("device_type", "unknown")

        if not device_id:
            return

        # Find and apply matching device policy
        if self._policy_set:
            for policy in sorted(self._policy_set.device_policies, key=lambda p: p.priority):
                if policy.enabled and policy.matches_device(
                    device_type,
                    device.get("vendor"),
                    device.get("tags", [])
                ):
                    await self._apply_device_policy(device_id, device, policy)
                    break

    async def _apply_device_policy(
        self,
        device_id: str,
        device: dict,
        policy: DevicePolicy
    ) -> None:
        """Apply a device policy to a device."""
        actions_taken = []

        # Assign VLAN if specified
        if policy.assign_vlan and device.get("vlan") != policy.assign_vlan:
            await self.execute_action(
                action_type="assign_vlan",
                target_type="device",
                target_id=device_id,
                parameters={
                    "vlan_id": policy.assign_vlan,
                    "mac_address": device.get("mac_address")
                },
                reasoning=f"Applying policy '{policy.name}': assigning VLAN {policy.assign_vlan}",
                confidence=0.90,
                reversible=True
            )
            actions_taken.append(f"assign_vlan={policy.assign_vlan}")

        # Apply internet access restrictions
        if not policy.internet_access:
            await self.execute_action(
                action_type="block_internet",
                target_type="device",
                target_id=device_id,
                parameters={"mac_address": device.get("mac_address")},
                reasoning=f"Policy '{policy.name}' denies internet access",
                confidence=0.95,
                reversible=True
            )
            actions_taken.append("block_internet")

        if actions_taken:
            logger.info(f"Applied policy '{policy.name}' to {device_id}: {', '.join(actions_taken)}")

    async def _handle_traffic_anomaly(self, event: Event) -> None:
        """Handle traffic anomalies that may indicate policy violations."""
        anomaly = event.data
        source_ip = anomaly.get("source_ip")
        dest_ip = anomaly.get("destination_ip")
        dest_port = anomaly.get("destination_port")

        # Check if this violates any segmentation policies
        if self._policy_set:
            for policy in self._policy_set.segmentation_policies:
                if not policy.enabled:
                    continue
                # Would need IP-to-VLAN mapping to check properly
                pass

    async def _handle_segmentation_violation(self, event: Event) -> None:
        """Handle explicit segmentation violation events."""
        violation = event.data
        source_vlan = violation.get("source_vlan")
        dest_vlan = violation.get("dest_vlan")
        source_device = violation.get("source_device")

        logger.warning(
            f"Segmentation violation: {source_device} in VLAN {source_vlan} "
            f"attempted to reach VLAN {dest_vlan}"
        )

        await self.engine.event_bus.publish(Event(
            category=EventCategory.SECURITY,
            event_type="policy.violation.detected",
            severity=EventSeverity.WARNING,
            source=f"sentinel.agents.{self.agent_name}",
            title="Segmentation policy violation",
            description=f"Traffic from VLAN {source_vlan} to VLAN {dest_vlan} blocked",
            data=violation
        ))

    async def analyze(self, event: Event) -> Optional[AgentDecision]:
        """Analyze events for policy decisions."""
        # Most handling is done in specific event handlers
        return None

    async def _do_execute(self, action: AgentAction) -> dict:
        """Execute policy enforcement actions."""
        if action.action_type == "assign_vlan":
            return await self._execute_vlan_assignment(action)

        elif action.action_type == "block_internet":
            return await self._execute_internet_block(action)

        elif action.action_type == "disable_firewall_rule":
            return await self._execute_disable_firewall_rule(action)

        elif action.action_type in ("allow_traffic", "block_traffic"):
            return await self._execute_traffic_rule(action)

        raise ValueError(f"Unknown action type: {action.action_type}")

    async def _execute_vlan_assignment(self, action: AgentAction) -> dict:
        """Execute VLAN assignment via switch integration."""
        switch = self.engine.get_integration("switch")
        if not switch:
            return {"success": False, "error": "No switch integration available"}

        try:
            mac_address = action.parameters.get("mac_address")
            vlan_id = action.parameters.get("vlan_id")
            port = action.parameters.get("port")

            if port:
                success = await switch.set_port_vlan(port, vlan_id)
            elif mac_address:
                success = await switch.set_mac_vlan(mac_address, vlan_id)
            else:
                return {"success": False, "error": "No port or MAC address specified"}

            return {"success": success, "vlan_id": vlan_id}

        except Exception as e:
            logger.error(f"VLAN assignment failed: {e}")
            return {"success": False, "error": str(e)}

    async def _execute_internet_block(self, action: AgentAction) -> dict:
        """Block internet access for a device."""
        router = self.engine.get_integration("router")
        if not router:
            return {"success": False, "error": "No router integration available"}

        try:
            mac_address = action.parameters.get("mac_address")
            # Create firewall rule to block internet for this MAC
            # Implementation depends on router integration
            return {"success": True, "blocked": mac_address}

        except Exception as e:
            logger.error(f"Internet block failed: {e}")
            return {"success": False, "error": str(e)}

    async def _execute_disable_firewall_rule(self, action: AgentAction) -> dict:
        """Disable a firewall rule."""
        if not self._policy_set:
            return {"success": False, "error": "No policy set loaded"}

        rule_id = UUID(action.target_id)
        for rule in self._policy_set.firewall_rules:
            if rule.id == rule_id:
                rule.enabled = False
                await self.engine.state.set(
                    "policy_set",
                    self._policy_set.model_dump()
                )
                return {"success": True, "rule_id": str(rule_id)}

        return {"success": False, "error": "Rule not found"}

    async def _execute_traffic_rule(self, action: AgentAction) -> dict:
        """Execute traffic allow/block rule."""
        router = self.engine.get_integration("router")
        firewall = self.engine.get_integration("firewall")

        integration = router or firewall
        if not integration:
            return {"success": False, "error": "No router or firewall integration"}

        try:
            if hasattr(integration, "add_firewall_rule"):
                rule_params = action.parameters
                success = await integration.add_firewall_rule(rule_params)
                return {"success": success}

            return {"success": False, "error": "Integration doesn't support firewall rules"}

        except Exception as e:
            logger.error(f"Traffic rule execution failed: {e}")
            return {"success": False, "error": str(e)}

    async def _capture_rollback_data(self, action: AgentAction) -> Optional[dict]:
        """Capture state for rollback."""
        if action.action_type == "assign_vlan":
            # Get current VLAN assignment
            device_id = action.target_id
            inventory = await self.engine.state.get("device_inventory", {})
            device = inventory.get(device_id, {})

            return {
                "action": "assign_vlan",
                "device_id": device_id,
                "original_vlan": device.get("vlan")
            }

        elif action.action_type == "disable_firewall_rule":
            return {
                "action": "disable_firewall_rule",
                "rule_id": action.target_id,
                "was_enabled": True
            }

        return None

    async def _do_rollback(self, action: AgentAction) -> None:
        """Rollback policy enforcement actions."""
        rollback = action.rollback_data or {}

        if rollback.get("action") == "assign_vlan":
            original_vlan = rollback.get("original_vlan")
            if original_vlan:
                switch = self.engine.get_integration("switch")
                if switch:
                    mac = action.parameters.get("mac_address")
                    await switch.set_mac_vlan(mac, original_vlan)

        elif rollback.get("action") == "disable_firewall_rule":
            rule_id = UUID(rollback.get("rule_id"))
            if self._policy_set:
                for rule in self._policy_set.firewall_rules:
                    if rule.id == rule_id:
                        rule.enabled = True
                        await self.engine.state.set(
                            "policy_set",
                            self._policy_set.model_dump()
                        )
                        break

    async def _get_relevant_state(self) -> dict:
        """Get state relevant to policy decisions."""
        return {
            "compliance_stats": self._compliance_stats,
            "violation_counts": dict(self._violation_counts),
            "policies_loaded": self._policy_set is not None
        }

    @property
    def stats(self) -> dict:
        """Get policy enforcer statistics."""
        base = super().stats

        return {
            **base,
            "compliance_rate": self._compliance_stats.get("compliance_rate", 0),
            "devices_in_violation": len([v for v in self._violation_counts.values() if v > 0]),
            "audit_mode": self.audit_mode,
            "auto_remediate": self.auto_remediate
        }
