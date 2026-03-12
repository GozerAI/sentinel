"""
Guardian Agent - Security policy enforcement and threat response.

This agent monitors for security threats and enforces:
- Anomaly detection (port scans, brute force, etc.)
- Automatic threat response
- Device quarantine
- IP blocking
- Compliance monitoring
"""

import asyncio
import logging
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Optional

from sentinel.core.utils import utc_now
from sentinel.agents.base import BaseAgent
from sentinel.core.models.event import (
    Event,
    EventCategory,
    EventSeverity,
    AgentAction,
    AgentDecision,
    SecurityAlert,
)
from sentinel.core.models.policy import FirewallRule, PolicyAction

logger = logging.getLogger(__name__)


class GuardianAgent(BaseAgent):
    """
    Security enforcement and threat response agent.

    Monitors network traffic for threats and automatically responds
    by blocking malicious IPs, quarantining compromised devices,
    and alerting administrators.

    Configuration:
        guardian:
            enabled: true
            auto_quarantine: true
            quarantine_vlan: 666
            threat_thresholds:
                port_scan: 100  # connections/minute
                failed_auth: 10  # failures/5min
                bandwidth_spike: 500  # percent of baseline

    Events Published:
        - security.alert: Threat detected
        - security.blocked: IP blocked
        - security.quarantined: Device quarantined

    Events Subscribed:
        - network.connection: Connection events for analysis
        - auth.attempt: Authentication attempts
        - network.traffic: Traffic volume events
        - ids.alert: External IDS alerts
    """

    agent_name = "guardian"
    agent_description = "Security enforcement and threat response"

    def __init__(self, engine, config: dict):
        super().__init__(engine, config)

        # Configuration
        self.auto_quarantine = config.get("auto_quarantine", True)
        self.quarantine_vlan = config.get("quarantine_vlan", 666)

        thresholds = config.get("threat_thresholds", {})
        self.port_scan_threshold = thresholds.get("port_scan", 100)
        self.failed_auth_threshold = thresholds.get("failed_auth", 10)
        self.bandwidth_spike_threshold = thresholds.get("bandwidth_spike", 500)

        # State - tracking for anomaly detection
        self._connection_counts: dict[str, list[datetime]] = defaultdict(list)
        self._port_access: dict[str, set[int]] = defaultdict(set)
        self._failed_auths: dict[str, list[datetime]] = defaultdict(list)
        self._bandwidth_baseline: dict[str, float] = {}
        self._blocked_ips: set[str] = set()
        self._quarantined_devices: set[str] = set()
        self._alerts: list[SecurityAlert] = []

        # Known threat signatures
        self._threat_signatures = {
            "malware_c2_ports": {4444, 5555, 6666, 7777, 8888, 31337},
            "crypto_mining_ports": {3333, 4444, 8080, 8888, 9999, 14444, 14433},
            "common_scan_ports": {21, 22, 23, 25, 80, 443, 445, 3389},
        }

        # MITRE ATT&CK mapping
        self._mitre_mapping = {
            "port_scan": ("T1046", "Network Service Discovery"),
            "brute_force": ("T1110", "Brute Force"),
            "lateral_movement": ("T1021", "Remote Services"),
            "data_exfil": ("T1048", "Exfiltration Over Alternative Protocol"),
            "c2_communication": ("T1071", "Application Layer Protocol"),
            "crypto_mining": ("T1496", "Resource Hijacking"),
        }

        # Track analysis interval
        self._last_analysis: Optional[datetime] = None
        self._last_cleanup: Optional[datetime] = None

    async def _subscribe_events(self) -> None:
        """Subscribe to security-related events."""
        self.engine.event_bus.subscribe(
            self._handle_connection_event, event_type="network.connection"
        )
        self.engine.event_bus.subscribe(self._handle_auth_event, event_type="auth.attempt")
        self.engine.event_bus.subscribe(self._handle_traffic_event, event_type="network.traffic")
        self.engine.event_bus.subscribe(self._handle_ids_alert, event_type="ids.alert")

    async def _main_loop(self) -> None:
        """Main security monitoring loop."""
        # Load persisted state
        blocked = await self.engine.state.get("guardian:blocked_ips")
        if blocked:
            self._blocked_ips = set(blocked)

        quarantined = await self.engine.state.get("guardian:quarantined")
        if quarantined:
            self._quarantined_devices = set(quarantined)

        while self._running:
            try:
                now = utc_now()

                # Periodic threat analysis (every minute)
                if self._last_analysis is None or (now - self._last_analysis).total_seconds() > 60:
                    await self._analyze_threats()
                    self._last_analysis = now

                # Cleanup old tracking data (every 5 minutes)
                if self._last_cleanup is None or (now - self._last_cleanup).total_seconds() > 300:
                    await self._cleanup_old_data()
                    self._last_cleanup = now

                await asyncio.sleep(10)

            except Exception as e:
                logger.error(f"Guardian loop error: {e}")
                await asyncio.sleep(30)

    async def _handle_connection_event(self, event: Event) -> None:
        """Handle connection events for anomaly detection."""
        source_ip = event.data.get("source_ip")
        dest_ip = event.data.get("destination_ip")
        dest_port = event.data.get("destination_port")

        if not source_ip:
            return

        now = utc_now()

        # Track connection timing
        self._connection_counts[source_ip].append(now)

        # Track unique ports accessed
        if dest_port:
            self._port_access[source_ip].add(dest_port)

        # Check for port scan
        await self._check_port_scan(source_ip)

        # Check for suspicious ports
        await self._check_suspicious_port(source_ip, dest_port, event.data)

    async def _handle_auth_event(self, event: Event) -> None:
        """Handle authentication events."""
        source_ip = event.data.get("source_ip")
        success = event.data.get("success", False)
        service = event.data.get("service")
        username = event.data.get("username")

        if not success and source_ip:
            self._failed_auths[source_ip].append(utc_now())
            await self._check_brute_force(source_ip, service, username)

    async def _handle_traffic_event(self, event: Event) -> None:
        """Handle traffic events for bandwidth anomaly detection."""
        source_ip = event.data.get("source_ip")
        bytes_transferred = event.data.get("bytes", 0)

        if not source_ip:
            return

        # Update baseline using exponential moving average
        if source_ip not in self._bandwidth_baseline:
            self._bandwidth_baseline[source_ip] = bytes_transferred
        else:
            alpha = 0.1  # Smoothing factor
            self._bandwidth_baseline[source_ip] = (
                self._bandwidth_baseline[source_ip] * (1 - alpha) + bytes_transferred * alpha
            )

        # Check for bandwidth spike
        baseline = self._bandwidth_baseline[source_ip]
        if baseline > 0:
            spike_ratio = bytes_transferred / baseline * 100
            if spike_ratio > self.bandwidth_spike_threshold:
                await self._create_alert(
                    title=f"Bandwidth spike from {source_ip}",
                    description=f"Traffic {bytes_transferred:,} bytes, baseline {baseline:,.0f} bytes ({spike_ratio:.0f}% of baseline)",
                    severity=EventSeverity.WARNING,
                    threat_type="data_exfil",
                    source_ip=source_ip,
                    confidence=0.7,
                )

    async def _handle_ids_alert(self, event: Event) -> None:
        """Handle alerts from external IDS systems."""
        alert_data = event.data
        source_ip = alert_data.get("source_ip")
        signature = alert_data.get("signature")
        severity_str = alert_data.get("severity", "medium")

        severity_map = {
            "critical": EventSeverity.CRITICAL,
            "high": EventSeverity.ERROR,
            "medium": EventSeverity.WARNING,
            "low": EventSeverity.INFO,
        }

        await self._create_alert(
            title=f"IDS Alert: {signature}",
            description=alert_data.get("description", "External IDS alert"),
            severity=severity_map.get(severity_str, EventSeverity.WARNING),
            threat_type="ids_alert",
            source_ip=source_ip,
            confidence=0.85,
            data=alert_data,
        )

        # Auto-respond to critical alerts
        if severity_str == "critical" and self.auto_quarantine and source_ip:
            await self._quarantine_device(source_ip, f"IDS critical alert: {signature}")

    async def _check_port_scan(self, source_ip: str) -> None:
        """Detect port scanning behavior."""
        now = utc_now()
        cutoff = now - timedelta(minutes=1)

        # Count recent connections
        recent_connections = [t for t in self._connection_counts[source_ip] if t > cutoff]
        self._connection_counts[source_ip] = recent_connections

        # Count unique ports
        unique_ports = len(self._port_access[source_ip])

        # Port scan detection: many connections OR many unique ports
        if len(recent_connections) > self.port_scan_threshold or unique_ports > 50:
            if source_ip not in self._blocked_ips:
                await self._create_alert(
                    title=f"Port scan detected from {source_ip}",
                    description=f"{len(recent_connections)} connections to {unique_ports} unique ports in last minute",
                    severity=EventSeverity.WARNING,
                    threat_type="port_scan",
                    source_ip=source_ip,
                    confidence=0.80,
                )

                if self.auto_quarantine:
                    await self._block_ip(source_ip, "Port scan detected")

    async def _check_suspicious_port(
        self, source_ip: str, dest_port: int, connection_data: dict
    ) -> None:
        """Check for connections to suspicious ports."""
        if not dest_port:
            return

        # Check malware C2 ports
        if dest_port in self._threat_signatures["malware_c2_ports"]:
            await self._create_alert(
                title=f"Suspicious C2 port {dest_port} accessed",
                description=f"Source {source_ip} connected to known malware C2 port",
                severity=EventSeverity.ERROR,
                threat_type="c2_communication",
                source_ip=source_ip,
                confidence=0.75,
                data=connection_data,
            )

        # Check crypto mining ports
        if dest_port in self._threat_signatures["crypto_mining_ports"]:
            await self._create_alert(
                title=f"Possible crypto mining activity",
                description=f"Source {source_ip} connected to port {dest_port} (common mining pool port)",
                severity=EventSeverity.WARNING,
                threat_type="crypto_mining",
                source_ip=source_ip,
                confidence=0.65,
                data=connection_data,
            )

    async def _check_brute_force(self, source_ip: str, service: str, username: str) -> None:
        """Detect brute force authentication attempts."""
        now = utc_now()
        cutoff = now - timedelta(minutes=5)

        # Count recent failures
        recent_failures = [t for t in self._failed_auths[source_ip] if t > cutoff]
        self._failed_auths[source_ip] = recent_failures

        if len(recent_failures) >= self.failed_auth_threshold:
            await self._create_alert(
                title=f"Brute force attempt detected",
                description=f"Source {source_ip} had {len(recent_failures)} failed auth attempts to {service} in 5 minutes",
                severity=EventSeverity.ERROR,
                threat_type="brute_force",
                source_ip=source_ip,
                confidence=0.90,
                data={"service": service, "username": username, "attempts": len(recent_failures)},
            )

            if self.auto_quarantine:
                await self._block_ip(source_ip, f"Brute force on {service}")

    async def _create_alert(
        self,
        title: str,
        description: str,
        severity: EventSeverity,
        threat_type: str,
        source_ip: Optional[str] = None,
        confidence: float = 0.5,
        data: Optional[dict] = None,
    ) -> SecurityAlert:
        """Create and publish a security alert."""
        mitre_info = self._mitre_mapping.get(threat_type, (None, None))

        alert = SecurityAlert(
            category=EventCategory.SECURITY,
            event_type=f"security.{threat_type}",
            severity=severity,
            source=f"sentinel.agents.{self.agent_name}",
            title=title,
            description=description,
            data=data or {},
            threat_type=threat_type,
            mitre_technique=mitre_info[0],
            risk_score=self._calculate_risk_score(severity, confidence),
            confidence=confidence,
        )

        self._alerts.append(alert)

        # Keep only recent alerts (max 1000)
        if len(self._alerts) > 1000:
            self._alerts = self._alerts[-500:]

        await self.engine.event_bus.publish(alert)

        return alert

    def _calculate_risk_score(self, severity: EventSeverity, confidence: float) -> float:
        """Calculate risk score from severity and confidence."""
        severity_scores = {
            EventSeverity.CRITICAL: 10.0,
            EventSeverity.ERROR: 8.0,
            EventSeverity.WARNING: 5.0,
            EventSeverity.INFO: 2.0,
            EventSeverity.DEBUG: 1.0,
        }

        base_score = severity_scores.get(severity, 5.0)
        return base_score * confidence

    async def _block_ip(self, ip: str, reason: str) -> None:
        """Block an IP address via firewall."""
        if ip in self._blocked_ips:
            return

        decision = AgentDecision(
            agent_name=self.agent_name,
            decision_type="block_ip",
            input_state={"ip": ip, "reason": reason},
            analysis=f"Blocking IP {ip} due to: {reason}",
            options_considered=[
                {"action": "block", "duration": "24h"},
                {"action": "monitor", "duration": "none"},
            ],
            selected_option={"action": "block", "duration": "24h"},
            confidence=0.85,
        )
        self._decisions.append(decision)

        await self.execute_action(
            action_type="block_ip",
            target_type="ip_address",
            target_id=ip,
            parameters={"ip": ip, "reason": reason, "duration_hours": 24},
            reasoning=f"Blocking IP {ip}: {reason}",
            confidence=0.85,
            reversible=True,
        )

    async def _quarantine_device(self, identifier: str, reason: str) -> None:
        """Quarantine a device by moving to quarantine VLAN."""
        if identifier in self._quarantined_devices:
            return

        decision = AgentDecision(
            agent_name=self.agent_name,
            decision_type="quarantine_device",
            input_state={"identifier": identifier, "reason": reason},
            analysis=f"Quarantining device {identifier} due to: {reason}",
            options_considered=[
                {"action": "quarantine", "vlan": self.quarantine_vlan},
                {"action": "monitor"},
            ],
            selected_option={"action": "quarantine", "vlan": self.quarantine_vlan},
            confidence=0.90,
        )
        self._decisions.append(decision)

        await self.execute_action(
            action_type="quarantine_device",
            target_type="device",
            target_id=identifier,
            parameters={
                "identifier": identifier,
                "quarantine_vlan": self.quarantine_vlan,
                "reason": reason,
            },
            reasoning=f"Quarantining device {identifier}: {reason}",
            confidence=0.90,
            reversible=True,
        )

    async def _analyze_threats(self) -> None:
        """Periodic comprehensive threat analysis."""
        logger.debug("Running threat analysis")

        now = utc_now()

        # Analyze recent alerts for patterns
        recent_alerts = [
            a for a in self._alerts if a.timestamp and (now - a.timestamp).seconds < 300
        ]

        # Group by source IP
        by_source: dict[str, list[SecurityAlert]] = defaultdict(list)
        for alert in recent_alerts:
            source_ip = alert.data.get("source_ip") if hasattr(alert, "data") else None
            if source_ip:
                by_source[source_ip].append(alert)

        # Check for multi-vector attacks
        for source_ip, alerts in by_source.items():
            if len(alerts) >= 3:
                threat_types = set(a.threat_type for a in alerts if a.threat_type)
                if len(threat_types) >= 2:
                    # Multiple threat types from same source = coordinated attack
                    await self._create_alert(
                        title=f"Multi-vector attack detected",
                        description=f"Source {source_ip} showing {len(threat_types)} threat indicators: {', '.join(threat_types)}",
                        severity=EventSeverity.CRITICAL,
                        threat_type="multi_vector",
                        source_ip=source_ip,
                        confidence=0.95,
                    )

                    if self.auto_quarantine:
                        await self._quarantine_device(source_ip, "Multi-vector attack")

    async def _cleanup_old_data(self) -> None:
        """Clean up old tracking data to prevent memory bloat."""
        now = utc_now()
        one_hour_ago = now - timedelta(hours=1)
        one_minute_ago = now - timedelta(minutes=1)

        # Clean connection counts (keep last minute)
        for ip in list(self._connection_counts.keys()):
            self._connection_counts[ip] = [
                t for t in self._connection_counts[ip] if t > one_minute_ago
            ]
            if not self._connection_counts[ip]:
                del self._connection_counts[ip]
                self._port_access.pop(ip, None)

        # Clean failed auths (keep last hour)
        for ip in list(self._failed_auths.keys()):
            self._failed_auths[ip] = [t for t in self._failed_auths[ip] if t > one_hour_ago]
            if not self._failed_auths[ip]:
                del self._failed_auths[ip]

    async def unblock_ip(self, ip: str) -> bool:
        """Manually unblock an IP address."""
        if ip not in self._blocked_ips:
            return False

        action = await self.execute_action(
            action_type="unblock_ip",
            target_type="ip_address",
            target_id=ip,
            parameters={"ip": ip},
            reasoning=f"Manual unblock of IP {ip}",
            confidence=1.0,
            reversible=True,
        )

        return action.status == "executed"

    async def unquarantine_device(self, identifier: str, restore_vlan: int) -> bool:
        """Manually remove a device from quarantine."""
        if identifier not in self._quarantined_devices:
            return False

        action = await self.execute_action(
            action_type="unquarantine_device",
            target_type="device",
            target_id=identifier,
            parameters={"identifier": identifier, "restore_vlan": restore_vlan},
            reasoning=f"Manual unquarantine of device {identifier}",
            confidence=1.0,
            reversible=True,
        )

        return action.status == "executed"

    async def analyze(self, event: Event) -> Optional[AgentDecision]:
        """Analyze events for security decisions."""
        # Most handling is done in specific event handlers
        return None

    async def _do_execute(self, action: AgentAction) -> dict:
        """Execute guardian security actions."""
        if action.action_type == "block_ip":
            ip = action.parameters.get("ip")
            reason = action.parameters.get("reason")
            duration_hours = action.parameters.get("duration_hours", 24)

            # Create firewall rule
            rule = FirewallRule(
                name=f"guardian_block_{ip.replace('.', '_')}",
                description=f"Auto-block: {reason}",
                source_addresses=[ip],
                action=PolicyAction.DENY,
                auto_generated=True,
                generated_by_agent=self.agent_name,
                expires_at=utc_now() + timedelta(hours=duration_hours),
            )

            router = self.engine.get_integration("router")
            router_rule_id = None
            if router:
                try:
                    router_rule_id = await router.add_firewall_rule(rule.model_dump())
                    if router_rule_id:
                        logger.info(f"Blocked IP {ip} with router rule {router_rule_id}")
                    self._blocked_ips.add(ip)
                    # Store the mapping of IP to router rule ID for rollback
                    blocked_ip_rules = (
                        await self.engine.state.get("guardian:blocked_ip_rules") or {}
                    )
                    blocked_ip_rules[ip] = router_rule_id
                    await self.engine.state.set("guardian:blocked_ip_rules", blocked_ip_rules)
                    await self.engine.state.set("guardian:blocked_ips", list(self._blocked_ips))
                    return {"blocked": True, "ip": ip, "rule_id": router_rule_id}
                except Exception as e:
                    logger.error(f"Failed to add firewall rule: {e}")
                    return {"blocked": False, "error": str(e)}

            # No router integration - just track locally
            self._blocked_ips.add(ip)
            await self.engine.state.set("guardian:blocked_ips", list(self._blocked_ips))
            return {"blocked": True, "ip": ip, "rule_id": None}

        elif action.action_type == "unblock_ip":
            ip = action.parameters.get("ip")
            router_rule_id = action.parameters.get("router_rule_id")

            # Try to get the router rule ID if not provided
            if not router_rule_id:
                blocked_ip_rules = await self.engine.state.get("guardian:blocked_ip_rules") or {}
                router_rule_id = blocked_ip_rules.get(ip)

            # Remove from router first
            if router_rule_id:
                router = self.engine.get_integration("router")
                if router:
                    try:
                        await router.delete_firewall_rule(router_rule_id)
                        logger.info(f"Removed block rule {router_rule_id} for IP {ip}")
                    except Exception as e:
                        logger.error(f"Failed to remove firewall rule for {ip}: {e}")

                # Remove from IP->rule mapping
                blocked_ip_rules = await self.engine.state.get("guardian:blocked_ip_rules") or {}
                blocked_ip_rules.pop(ip, None)
                await self.engine.state.set("guardian:blocked_ip_rules", blocked_ip_rules)

            self._blocked_ips.discard(ip)
            await self.engine.state.set("guardian:blocked_ips", list(self._blocked_ips))

            return {"unblocked": True, "ip": ip}

        elif action.action_type == "quarantine_device":
            identifier = action.parameters.get("identifier")
            quarantine_vlan = action.parameters.get("quarantine_vlan")

            switch = self.engine.get_integration("switch")
            if switch:
                try:
                    # Determine if identifier is MAC or IP
                    if ":" in identifier:
                        await switch.set_port_vlan(mac=identifier, vlan_id=quarantine_vlan)
                    else:
                        # Would need to look up MAC from IP via discovery agent
                        discovery = self.engine.get_agent("discovery")
                        if discovery:
                            device = discovery.inventory.get_by_ip(identifier)
                            if device and device.primary_mac:
                                await switch.set_port_vlan(
                                    mac=device.primary_mac, vlan_id=quarantine_vlan
                                )

                    self._quarantined_devices.add(identifier)
                    await self.engine.state.set(
                        "guardian:quarantined", list(self._quarantined_devices)
                    )
                    return {"quarantined": True, "identifier": identifier}

                except Exception as e:
                    logger.error(f"Failed to quarantine device: {e}")
                    return {"quarantined": False, "error": str(e)}

            # No switch integration - just track locally
            self._quarantined_devices.add(identifier)
            await self.engine.state.set("guardian:quarantined", list(self._quarantined_devices))
            return {"quarantined": True, "identifier": identifier}

        elif action.action_type == "unquarantine_device":
            identifier = action.parameters.get("identifier")
            restore_vlan = action.parameters.get("restore_vlan")

            self._quarantined_devices.discard(identifier)
            await self.engine.state.set("guardian:quarantined", list(self._quarantined_devices))

            if restore_vlan:
                switch = self.engine.get_integration("switch")
                if switch:
                    if ":" in identifier:
                        await switch.set_port_vlan(mac=identifier, vlan_id=restore_vlan)

            return {"unquarantined": True, "identifier": identifier}

        raise ValueError(f"Unknown action type: {action.action_type}")

    async def _capture_rollback_data(self, action: AgentAction) -> Optional[dict]:
        """Capture state for rollback."""
        if action.action_type == "block_ip":
            ip = action.parameters.get("ip")
            # Get the router rule ID from stored mapping
            blocked_ip_rules = await self.engine.state.get("guardian:blocked_ip_rules") or {}
            router_rule_id = blocked_ip_rules.get(ip)
            return {"action": "unblock_ip", "ip": ip, "router_rule_id": router_rule_id}

        elif action.action_type == "quarantine_device":
            identifier = action.parameters.get("identifier")
            # Try to get current VLAN for rollback
            discovery = self.engine.get_agent("discovery")
            if discovery:
                device = None
                if ":" in identifier:
                    device = discovery.inventory.get_by_mac(identifier)
                else:
                    device = discovery.inventory.get_by_ip(identifier)

                if device:
                    return {
                        "action": "unquarantine_device",
                        "identifier": identifier,
                        "original_vlan": device.assigned_vlan,
                    }

            return {"action": "unquarantine_device", "identifier": identifier}

        return None

    async def _do_rollback(self, action: AgentAction) -> None:
        """Rollback guardian actions."""
        rollback = action.rollback_data or {}

        if rollback.get("action") == "unblock_ip":
            ip = rollback.get("ip")
            router_rule_id = rollback.get("router_rule_id")

            # Remove from router first
            if router_rule_id:
                router = self.engine.get_integration("router")
                if router:
                    try:
                        await router.delete_firewall_rule(router_rule_id)
                        logger.info(f"Rolled back block rule {router_rule_id} for IP {ip}")
                    except Exception as e:
                        logger.error(f"Failed to rollback firewall rule for {ip}: {e}")

                # Remove from IP->rule mapping
                blocked_ip_rules = await self.engine.state.get("guardian:blocked_ip_rules") or {}
                blocked_ip_rules.pop(ip, None)
                await self.engine.state.set("guardian:blocked_ip_rules", blocked_ip_rules)

            self._blocked_ips.discard(ip)
            await self.engine.state.set("guardian:blocked_ips", list(self._blocked_ips))

        elif rollback.get("action") == "unquarantine_device":
            identifier = rollback.get("identifier")
            original_vlan = rollback.get("original_vlan")

            self._quarantined_devices.discard(identifier)
            await self.engine.state.set("guardian:quarantined", list(self._quarantined_devices))

            if original_vlan:
                switch = self.engine.get_integration("switch")
                if switch and ":" in identifier:
                    try:
                        await switch.set_port_vlan(mac=identifier, vlan_id=original_vlan)
                        logger.info(
                            f"Rolled back quarantine for {identifier} to VLAN {original_vlan}"
                        )
                    except Exception as e:
                        logger.error(f"Failed to rollback quarantine for {identifier}: {e}")

    async def _get_relevant_state(self) -> dict:
        """Get state relevant to guardian decisions."""
        return {
            "blocked_ips": list(self._blocked_ips),
            "quarantined_devices": list(self._quarantined_devices),
            "active_threats": len(self._alerts),
        }

    @property
    def blocked_ips(self) -> set[str]:
        """Get currently blocked IPs."""
        return self._blocked_ips.copy()

    @property
    def quarantined_devices(self) -> set[str]:
        """Get currently quarantined devices."""
        return self._quarantined_devices.copy()

    @property
    def stats(self) -> dict:
        """Get guardian statistics."""
        base = super().stats

        now = utc_now()
        alerts_today = [a for a in self._alerts if a.timestamp and (now - a.timestamp).days == 0]

        return {
            **base,
            "blocked_ips": len(self._blocked_ips),
            "quarantined_devices": len(self._quarantined_devices),
            "alerts_today": len(alerts_today),
            "total_alerts": len(self._alerts),
            "connection_tracking": len(self._connection_counts),
            "failed_auth_tracking": len(self._failed_auths),
        }
