"""
Planner Agent - Network segmentation and VLAN automation.

This agent manages:
- VLAN lifecycle
- Segmentation policies
- Firewall rule automation
- Network topology optimization
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


class PlannerAgent(BaseAgent):
    """
    Network segmentation and policy planning agent.

    Manages VLAN assignments, segmentation policies, and firewall
    rules to enforce network security boundaries.

    Configuration:
        planner:
            enabled: true
            auto_execute_threshold: 0.95
            require_confirmation_for:
              - "create_vlan"
              - "delete_vlan"
              - "modify_firewall"

    Events Published:
        - network.vlan.created: VLAN created
        - network.vlan.changed: Device VLAN assignment changed
        - security.policy.applied: Policy applied

    Events Subscribed:
        - device.classified: Device classification results
        - network.segmentation.request: Segmentation requests
        - security.policy.violation: Policy violations
    """

    agent_name = "planner"
    agent_description = "Network segmentation and VLAN automation"

    def __init__(self, engine, config: dict):
        super().__init__(engine, config)

        # Actions that always require confirmation
        self.require_confirmation = config.get("require_confirmation_for", [
            "create_vlan",
            "delete_vlan",
            "modify_firewall"
        ])

        # State
        self._vlans: dict[int, dict] = {}
        self._segmentation_policies: dict[str, dict] = {}
        self._firewall_rules: dict[str, dict] = {}
        self._security_zones: dict[str, dict] = {}

        # Service to port mapping
        self._service_ports = {
            "http": (80, "tcp"),
            "https": (443, "tcp"),
            "ssh": (22, "tcp"),
            "rdp": (3389, "tcp"),
            "smb": (445, "tcp"),
            "nfs": (2049, "tcp"),
            "iscsi": (3260, "tcp"),
            "dns": (53, "udp"),
            "dhcp": (67, "udp"),
            "ldap": (389, "tcp"),
            "ldaps": (636, "tcp"),
            "kerberos": (88, "tcp"),
            "mysql": (3306, "tcp"),
            "postgres": (5432, "tcp"),
            "redis": (6379, "tcp"),
        }

        # Default security zones
        self._default_zones = {
            "trusted": {
                "id": "zone_trusted",
                "name": "Trusted",
                "description": "Internal trusted networks",
                "trust_level": 0.9,
                "vlans": [1, 10, 20, 30]
            },
            "restricted": {
                "id": "zone_restricted",
                "name": "Restricted",
                "description": "Limited access networks",
                "trust_level": 0.5,
                "vlans": [50, 100]
            },
            "untrusted": {
                "id": "zone_untrusted",
                "name": "Untrusted",
                "description": "Guest and quarantine networks",
                "trust_level": 0.1,
                "vlans": [200, 666]
            }
        }

    async def _subscribe_events(self) -> None:
        """Subscribe to segmentation-related events."""
        self.engine.event_bus.subscribe(
            self._handle_device_classified,
            event_type="device.classified"
        )
        self.engine.event_bus.subscribe(
            self._handle_segmentation_request,
            event_type="network.segmentation.request"
        )
        self.engine.event_bus.subscribe(
            self._handle_policy_violation,
            event_type="security.policy.violation"
        )

    async def _main_loop(self) -> None:
        """Main planner loop."""
        # Load VLANs from config
        vlan_config = self.engine.config.get("vlans", [])
        for vlan_data in vlan_config:
            self._vlans[vlan_data["id"]] = {
                "id": vlan_data["id"],
                "name": vlan_data["name"],
                "purpose": vlan_data.get("purpose"),
                "subnet": vlan_data.get("subnet"),
                "gateway": vlan_data.get("gateway"),
                "dns_zone": vlan_data.get("dns_zone"),
                "dhcp_enabled": vlan_data.get("dhcp_enabled", False),
                "dhcp_range_start": vlan_data.get("dhcp_range_start"),
                "dhcp_range_end": vlan_data.get("dhcp_range_end"),
                "isolated": vlan_data.get("isolated", False),
                "allowed_destinations": vlan_data.get("allowed_destinations", [])
            }

        # Load segmentation policies from config
        seg_config = self.engine.config.get("segmentation_policies", [])
        for policy_data in seg_config:
            policy_id = f"seg_{policy_data['name']}"
            self._segmentation_policies[policy_id] = {
                "id": policy_id,
                "name": policy_data["name"],
                "source_vlan": policy_data["source_vlan"],
                "destination_vlan": policy_data["destination_vlan"],
                "allowed_services": policy_data.get("allowed_services", []),
                "denied_services": policy_data.get("denied_services", []),
                "default_action": policy_data.get("default_action", "deny")
            }

        # Initialize security zones
        self._security_zones = self._default_zones.copy()

        # Generate initial firewall rules
        await self._generate_firewall_rules()

        logger.info(f"Planner initialized with {len(self._vlans)} VLANs, {len(self._segmentation_policies)} policies")

        while self._running:
            try:
                await self._validate_policies()
                await asyncio.sleep(60)
            except Exception as e:
                logger.error(f"Planner loop error: {e}")
                await asyncio.sleep(30)

    async def _handle_device_classified(self, event: Event) -> None:
        """Handle device classification events."""
        device_data = event.data
        current_vlan = device_data.get("current_vlan")
        recommended_vlan = device_data.get("recommended_vlan")

        if current_vlan != recommended_vlan and recommended_vlan is not None:
            await self._evaluate_vlan_change(device_data, recommended_vlan)

    async def _handle_segmentation_request(self, event: Event) -> None:
        """Handle segmentation requests."""
        request = event.data
        source_vlan = request.get("source_vlan")
        dest_vlan = request.get("destination_vlan")
        service = request.get("service")

        allowed = self._check_segmentation(source_vlan, dest_vlan, service)
        if not allowed:
            await self._evaluate_segmentation_exception(request)

    async def _handle_policy_violation(self, event: Event) -> None:
        """Handle policy violation events."""
        violation = event.data
        severity = violation.get("severity", "low")

        logger.warning(f"Policy violation: {violation}")

        if severity == "critical":
            await self._propose_quarantine(violation)
        elif severity == "high":
            await self._propose_access_restriction(violation)

    async def _evaluate_vlan_change(self, device_data: dict, target_vlan: int) -> None:
        """Evaluate and propose VLAN change for a device."""
        device_id = device_data.get("device_id")
        mac = device_data.get("mac")
        current_vlan = device_data.get("current_vlan")
        device_type = device_data.get("device_type")
        confidence = device_data.get("confidence", 0.5)

        target_vlan_info = self._vlans.get(target_vlan)
        if not target_vlan_info:
            logger.warning(f"Unknown target VLAN: {target_vlan}")
            return

        action_confidence = confidence * 0.9

        decision = AgentDecision(
            agent_name=self.agent_name,
            decision_type="vlan_change",
            input_state={"device": device_data, "target_vlan": target_vlan},
            analysis=f"Device {mac} classified as {device_type}, should be in VLAN {target_vlan}",
            options_considered=[
                {"action": "change_vlan", "target": target_vlan},
                {"action": "keep_current", "target": current_vlan}
            ],
            selected_option={"action": "change_vlan", "target": target_vlan},
            confidence=action_confidence
        )
        self._decisions.append(decision)

        await self.execute_action(
            action_type="vlan_change",
            target_type="device",
            target_id=device_id or mac,
            parameters={
                "mac": mac,
                "current_vlan": current_vlan,
                "target_vlan": target_vlan,
                "target_vlan_name": target_vlan_info.get("name"),
                "device_type": device_type
            },
            reasoning=f"Device classified as {device_type}, moving from VLAN {current_vlan} to {target_vlan}",
            confidence=action_confidence,
            reversible=True
        )

    def _check_segmentation(self, source_vlan: int, dest_vlan: int, service: str) -> bool:
        """Check if communication is allowed by segmentation policy."""
        for policy in self._segmentation_policies.values():
            if policy["source_vlan"] == source_vlan and policy["destination_vlan"] == dest_vlan:
                if service in policy.get("allowed_services", []):
                    return True
                if service in policy.get("denied_services", []):
                    return False
                return policy.get("default_action") == "allow"

        source_vlan_info = self._vlans.get(source_vlan)
        if source_vlan_info:
            if source_vlan_info.get("isolated"):
                return False
            if dest_vlan not in source_vlan_info.get("allowed_destinations", []):
                return False

        return True

    async def _evaluate_segmentation_exception(self, request: dict) -> None:
        """Evaluate if a segmentation exception should be created."""
        source_vlan = request.get("source_vlan")
        dest_vlan = request.get("destination_vlan")
        service = request.get("service")

        decision = AgentDecision(
            agent_name=self.agent_name,
            decision_type="segmentation_exception",
            input_state=request,
            analysis=f"Exception requested: {source_vlan} -> {dest_vlan} for {service}",
            options_considered=[{"action": "create_exception"}, {"action": "deny"}],
            selected_option={"action": "create_exception"},
            confidence=0.5
        )
        self._decisions.append(decision)

        await self.execute_action(
            action_type="create_segmentation_exception",
            target_type="segmentation_policy",
            target_id=f"{source_vlan}_to_{dest_vlan}",
            parameters={
                "source_vlan": source_vlan,
                "destination_vlan": dest_vlan,
                "service": service,
                "reason": request.get("reason", "Unknown")
            },
            reasoning=f"Segmentation exception requested: {source_vlan} -> {dest_vlan} for {service}",
            confidence=0.5,
            reversible=True
        )

    async def _propose_quarantine(self, violation: dict) -> None:
        """Propose quarantining a device."""
        mac = violation.get("mac")
        current_vlan = violation.get("vlan")

        await self.execute_action(
            action_type="quarantine_device",
            target_type="device",
            target_id=mac,
            parameters={
                "mac": mac,
                "current_vlan": current_vlan,
                "target_vlan": 666,
                "violation": violation
            },
            reasoning=f"Critical policy violation - quarantining device {mac}",
            confidence=0.95,
            reversible=True
        )

    async def _propose_access_restriction(self, violation: dict) -> None:
        """Propose restricting device access."""
        mac = violation.get("mac")
        rule_id = f"restrict_{mac.replace(':', '')}"

        await self.execute_action(
            action_type="add_firewall_rule",
            target_type="firewall_rule",
            target_id=rule_id,
            parameters={
                "rule": {
                    "id": rule_id,
                    "name": rule_id,
                    "description": "Restriction due to policy violation",
                    "action": "drop",
                    "source_mac": mac,
                    "auto_generated": True,
                    "expires_at": (utc_now() + timedelta(hours=24)).isoformat()
                },
                "violation": violation
            },
            reasoning=f"High severity violation - restricting access for {mac}",
            confidence=0.85,
            reversible=True
        )

    async def _generate_firewall_rules(self) -> None:
        """Generate firewall rules from segmentation policies."""
        for policy in self._segmentation_policies.values():
            source_vlan = self._vlans.get(policy["source_vlan"])
            dest_vlan = self._vlans.get(policy["destination_vlan"])

            if not source_vlan or not dest_vlan:
                continue

            for service in policy.get("allowed_services", []):
                port_info = self._service_ports.get(service)
                if port_info:
                    port, proto = port_info
                    rule_id = f"seg_{policy['name']}_{service}"
                    self._firewall_rules[rule_id] = {
                        "id": rule_id,
                        "name": rule_id,
                        "description": f"Allow {service} from {source_vlan['name']} to {dest_vlan['name']}",
                        "action": "allow",
                        "source_zone": f"vlan{source_vlan['id']}",
                        "destination_zone": f"vlan{dest_vlan['id']}",
                        "destination_port": port,
                        "protocol": proto,
                        "auto_generated": True
                    }

            if policy.get("default_action") == "deny":
                rule_id = f"seg_{policy['name']}_default_deny"
                self._firewall_rules[rule_id] = {
                    "id": rule_id,
                    "name": rule_id,
                    "description": f"Default deny from {source_vlan['name']} to {dest_vlan['name']}",
                    "action": "drop",
                    "source_zone": f"vlan{source_vlan['id']}",
                    "destination_zone": f"vlan{dest_vlan['id']}",
                    "auto_generated": True,
                    "priority": 1000
                }

        logger.info(f"Generated {len(self._firewall_rules)} firewall rules")

    async def _validate_policies(self) -> None:
        """Validate and clean up policies."""
        now = utc_now()
        expired = [
            rule_id for rule_id, rule in self._firewall_rules.items()
            if rule.get("expires_at") and datetime.fromisoformat(rule["expires_at"]) < now
        ]

        for rule_id in expired:
            logger.info(f"Removing expired firewall rule: {rule_id}")
            del self._firewall_rules[rule_id]

    async def analyze(self, event: Event) -> Optional[AgentDecision]:
        """Analyze events for segmentation decisions."""
        return None

    async def _do_execute(self, action: AgentAction) -> dict:
        """Execute planner actions."""
        if action.action_type == "vlan_change":
            mac = action.parameters.get("mac")
            target_vlan = action.parameters.get("target_vlan")
            port = action.parameters.get("port")

            switch = self.engine.get_integration("switch")
            router = self.engine.get_integration("router")

            # Try switch first
            if switch:
                try:
                    if port:
                        success = await switch.set_port_vlan(port=port, vlan_id=target_vlan)
                    else:
                        success = await switch.set_port_vlan(mac=mac, vlan_id=target_vlan)

                    if success:
                        logger.info(f"VLAN changed: {mac} -> VLAN {target_vlan}")
                        return {"changed": True, "mac": mac, "vlan": target_vlan, "method": "switch"}
                except Exception as e:
                    logger.warning(f"Switch VLAN change failed: {e}")

            # Try router if switch failed or unavailable
            if router and hasattr(router, "set_port_vlan"):
                try:
                    if port:
                        success = await router.set_port_vlan(port=port, pvid=target_vlan)
                        if success:
                            logger.info(f"VLAN changed via router: {mac} -> VLAN {target_vlan}")
                            return {"changed": True, "mac": mac, "vlan": target_vlan, "method": "router"}
                except Exception as e:
                    logger.warning(f"Router VLAN change failed: {e}")

            # No suitable integration or all attempts failed
            logger.error(f"Failed to change VLAN for {mac} - no integration succeeded")
            return {"changed": False, "mac": mac, "vlan": target_vlan, "error": "No integration available or all attempts failed"}

        elif action.action_type == "create_vlan":
            vlan_data = action.parameters.get("vlan", {})
            self._vlans[vlan_data.get("id")] = vlan_data
            return {"created": True}

        elif action.action_type == "delete_vlan":
            vlan_id = action.parameters.get("vlan_id")
            if vlan_id in self._vlans:
                del self._vlans[vlan_id]
                return {"deleted": True}
            return {"deleted": False}

        elif action.action_type == "add_firewall_rule":
            rule = action.parameters.get("rule", {})
            self._firewall_rules[rule.get("id")] = rule

            router = self.engine.get_integration("router")
            if router:
                await router.add_firewall_rule(rule)

            return {"added": True}

        elif action.action_type == "remove_firewall_rule":
            rule_id = action.parameters.get("rule_id")
            if rule_id in self._firewall_rules:
                del self._firewall_rules[rule_id]
                return {"removed": True}
            return {"removed": False}

        elif action.action_type == "quarantine_device":
            mac = action.parameters.get("mac")
            switch = self.engine.get_integration("switch")
            if switch:
                await switch.set_port_vlan(mac=mac, vlan_id=666)
            return {"quarantined": True, "mac": mac}

        elif action.action_type == "create_segmentation_exception":
            source = action.parameters.get("source_vlan")
            dest = action.parameters.get("destination_vlan")
            service = action.parameters.get("service")

            policy_id = f"exception_{source}_to_{dest}"

            for p in self._segmentation_policies.values():
                if p["source_vlan"] == source and p["destination_vlan"] == dest:
                    p.setdefault("allowed_services", []).append(service)
                    await self._generate_firewall_rules()
                    return {"created": True, "existing_policy": True}

            self._segmentation_policies[policy_id] = {
                "id": policy_id,
                "name": policy_id,
                "source_vlan": source,
                "destination_vlan": dest,
                "allowed_services": [service],
                "default_action": "deny"
            }
            await self._generate_firewall_rules()
            return {"created": True}

        raise ValueError(f"Unknown action type: {action.action_type}")

    async def _capture_rollback_data(self, action: AgentAction) -> Optional[dict]:
        """Capture state for rollback."""
        if action.action_type == "vlan_change":
            return {
                "action": "vlan_change",
                "mac": action.parameters.get("mac"),
                "target_vlan": action.parameters.get("current_vlan")
            }
        elif action.action_type == "add_firewall_rule":
            return {
                "action": "remove_firewall_rule",
                "rule_id": action.parameters.get("rule", {}).get("id")
            }
        elif action.action_type == "quarantine_device":
            return {
                "action": "vlan_change",
                "mac": action.parameters.get("mac"),
                "target_vlan": action.parameters.get("current_vlan")
            }
        return None

    async def _do_rollback(self, action: AgentAction) -> None:
        """Rollback planner actions."""
        rollback = action.rollback_data or {}

        if rollback.get("action") == "vlan_change":
            mac = rollback.get("mac")
            target_vlan = rollback.get("target_vlan")
            switch = self.engine.get_integration("switch")
            if switch and target_vlan:
                await switch.set_port_vlan(mac=mac, vlan_id=target_vlan)

        elif rollback.get("action") == "remove_firewall_rule":
            rule_id = rollback.get("rule_id")
            if rule_id in self._firewall_rules:
                del self._firewall_rules[rule_id]

    async def _get_relevant_state(self) -> dict:
        """Get state relevant to planner decisions."""
        return {
            "vlans": len(self._vlans),
            "segmentation_policies": len(self._segmentation_policies),
            "firewall_rules": len(self._firewall_rules)
        }

    @property
    def stats(self) -> dict:
        """Get planner statistics."""
        base = super().stats
        return {
            **base,
            "vlans": len(self._vlans),
            "segmentation_policies": len(self._segmentation_policies),
            "firewall_rules": len(self._firewall_rules),
            "security_zones": len(self._security_zones)
        }
