"""
Optimizer Agent - Traffic engineering and QoS management.

This agent analyzes network traffic patterns and optimizes:
- Bandwidth allocation
- QoS policies
- Traffic shaping
- Load balancing
"""
import asyncio
import logging
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Optional

from sentinel.core.utils import utc_now
from sentinel.agents.base import BaseAgent
from sentinel.core.models.event import (
    Event, EventCategory, EventSeverity,
    AgentAction, AgentDecision
)
from sentinel.core.models.network import TrafficFlow, QoSPolicy

logger = logging.getLogger(__name__)


class OptimizerAgent(BaseAgent):
    """
    Traffic optimization and QoS management agent.

    Monitors network traffic patterns and automatically applies
    QoS policies to ensure optimal bandwidth allocation for
    different application types.

    Configuration:
        optimizer:
            enabled: true
            analysis_interval_seconds: 60
            netflow_enabled: true
            netflow_port: 2055
            bandwidth_threshold_percent: 80
            auto_execute_threshold: 0.90

    Events Published:
        - network.bandwidth.high: High utilization detected
        - network.qos.applied: QoS policy applied
        - network.congestion.critical: Critical congestion

    Events Subscribed:
        - network.flow.detected: New traffic flow
        - network.congestion.detected: Congestion events
    """

    agent_name = "optimizer"
    agent_description = "Traffic engineering and QoS management"

    def __init__(self, engine, config: dict):
        super().__init__(engine, config)

        # Configuration
        self.analysis_interval = config.get("analysis_interval_seconds", 60)
        self.netflow_enabled = config.get("netflow_enabled", True)
        self.netflow_port = config.get("netflow_port", 2055)
        self.bandwidth_threshold = config.get("bandwidth_threshold_percent", 80)

        # State
        self._flows: dict[str, TrafficFlow] = {}
        self._link_utilization: dict[str, float] = {}
        self._qos_policies: dict[str, dict] = {}
        self._congestion_events: list[dict] = []

        # Timing
        self._last_analysis: Optional[datetime] = None

        # Application signatures for classification
        self._app_signatures = {
            # Streaming
            (443, "netflix.com"): "streaming",
            (443, "youtube.com"): "streaming",
            (443, "twitch.tv"): "streaming",
            # Gaming
            (3074, None): "gaming",  # Xbox Live
            (3478, None): "gaming",  # PlayStation
            (27015, None): "gaming",  # Steam
            # VoIP
            (5060, None): "voip",
            (5061, None): "voip",
            (10000, None): "voip",  # Webex
            # Backup/Sync
            (443, "backblaze.com"): "backup",
            (443, "dropbox.com"): "sync",
            (443, "drive.google.com"): "sync",
            # Work
            (443, "zoom.us"): "conferencing",
            (443, "teams.microsoft.com"): "conferencing",
        }

        # QoS priority mapping (lower = higher priority)
        self._priority_map = {
            "voip": 1,        # Highest - real-time
            "gaming": 2,      # High - latency sensitive
            "conferencing": 2,
            "streaming": 3,   # Medium - bandwidth heavy
            "sync": 4,        # Lower - bulk transfer
            "backup": 5,      # Lowest - background
            "default": 3,
        }

        # DSCP markings
        self._dscp_map = {
            1: 46,  # EF - Expedited Forwarding
            2: 34,  # AF41 - Assured Forwarding
            3: 0,   # Best effort
            4: 10,  # AF11
            5: 8,   # CS1 - Scavenger
        }

    async def _subscribe_events(self) -> None:
        """Subscribe to traffic-related events."""
        self.engine.event_bus.subscribe(
            self._handle_flow_event,
            event_type="network.flow.detected"
        )
        self.engine.event_bus.subscribe(
            self._handle_congestion_event,
            event_type="network.congestion.detected"
        )

    async def _main_loop(self) -> None:
        """Main traffic analysis loop."""
        # Load existing QoS policies
        stored_policies = await self.engine.state.get("optimizer:qos_policies")
        if stored_policies:
            self._qos_policies = {p["id"]: p for p in stored_policies}

        while self._running:
            try:
                now = utc_now()

                # Run analysis periodically
                if (
                    self._last_analysis is None or
                    (now - self._last_analysis).total_seconds() > self.analysis_interval
                ):
                    await self._analyze_traffic()
                    self._last_analysis = now

                await asyncio.sleep(10)

            except Exception as e:
                logger.error(f"Optimizer loop error: {e}")
                await asyncio.sleep(30)

    async def _handle_flow_event(self, event: Event) -> None:
        """Handle new flow detection."""
        flow_data = event.data

        # Create flow record
        flow_id = flow_data.get("id", f"{flow_data.get('source_ip')}:{flow_data.get('source_port')}")

        flow = {
            "id": flow_id,
            "source_ip": flow_data.get("source_ip"),
            "source_port": flow_data.get("source_port"),
            "destination_ip": flow_data.get("destination_ip"),
            "destination_port": flow_data.get("destination_port"),
            "protocol": flow_data.get("protocol", "tcp"),
            "bytes_sent": flow_data.get("bytes_sent", 0),
            "bytes_received": flow_data.get("bytes_received", 0),
            "start_time": flow_data.get("start_time", utc_now().isoformat()),
            "last_seen": utc_now(),
            "application": self._classify_application(flow_data)
        }

        self._flows[flow_id] = flow

        # Check if flow needs QoS
        await self._evaluate_flow_qos(flow)

    async def _handle_congestion_event(self, event: Event) -> None:
        """Handle congestion detection."""
        congestion_data = event.data

        self._congestion_events.append({
            "timestamp": utc_now(),
            "link_id": congestion_data.get("link_id"),
            "utilization": congestion_data.get("utilization"),
            "queue_depth": congestion_data.get("queue_depth")
        })

        # Trigger immediate analysis for severe congestion
        utilization = congestion_data.get("utilization", 0)
        if utilization > 95:
            await self._handle_critical_congestion(congestion_data)

    def _classify_application(self, flow_data: dict) -> str:
        """Classify application from flow data."""
        dst_port = flow_data.get("destination_port")
        dst_host = flow_data.get("destination_host", "")

        # Check signatures
        for (port, host), app in self._app_signatures.items():
            if dst_port == port:
                if host is None or (dst_host and host in dst_host):
                    return app

        # Heuristics based on port
        if dst_port in (80, 443, 8080):
            return "web"
        elif dst_port in (22, 3389, 5900):
            return "remote_access"
        elif dst_port in (445, 139, 2049):
            return "file_transfer"
        elif dst_port in (25, 587, 993, 143):
            return "email"

        return "default"

    async def _evaluate_flow_qos(self, flow: dict) -> None:
        """Evaluate if flow needs QoS policy."""
        app = flow.get("application", "default")
        priority = self._priority_map.get(app, 3)

        # High priority apps get automatic QoS
        if priority <= 2:
            # Check if policy already exists
            existing = self._find_matching_policy(flow)
            if not existing:
                await self._propose_qos_policy(flow, priority)

    def _find_matching_policy(self, flow: dict) -> Optional[dict]:
        """Find existing QoS policy matching flow."""
        dst_port = flow.get("destination_port")

        for policy in self._qos_policies.values():
            if policy.get("destination_port") == dst_port:
                return policy
        return None

    async def _propose_qos_policy(self, flow: dict, priority: int) -> None:
        """Propose a new QoS policy for a flow."""
        policy_id = f"auto_{flow.get('application')}_{flow.get('destination_port')}"

        policy = {
            "id": policy_id,
            "name": policy_id,
            "description": f"Auto-generated QoS for {flow.get('application')}",
            "priority_queue": priority,
            "bandwidth_limit_mbps": None,  # No limit for high priority
            "bandwidth_guarantee_mbps": 10 if priority <= 2 else None,
            "dscp_marking": self._dscp_map.get(priority, 0),
            "destination_port": flow.get("destination_port"),
            "protocol": flow.get("protocol"),
            "auto_generated": True,
            "created_at": utc_now().isoformat()
        }

        # Calculate confidence
        confidence = 0.85
        if flow.get("application") in ("voip", "gaming", "conferencing"):
            confidence = 0.92  # Higher for known apps

        decision = AgentDecision(
            agent_name=self.agent_name,
            decision_type="apply_qos",
            input_state={"flow": flow},
            analysis=f"High-priority {flow.get('application')} traffic detected",
            options_considered=[
                {"action": "apply_qos", "priority": priority},
                {"action": "monitor_only"}
            ],
            selected_option={"action": "apply_qos", "priority": priority},
            confidence=confidence
        )
        self._decisions.append(decision)

        await self.execute_action(
            action_type="apply_qos_policy",
            target_type="qos_policy",
            target_id=policy_id,
            parameters={
                "policy": policy,
                "flow_id": flow.get("id"),
                "application": flow.get("application")
            },
            reasoning=f"High-priority {flow.get('application')} traffic detected, applying QoS priority {priority}",
            confidence=confidence,
            reversible=True
        )

    async def _analyze_traffic(self) -> None:
        """Periodic traffic analysis."""
        logger.debug("Running traffic analysis")

        # Clean old flows (older than 5 minutes)
        cutoff = utc_now() - timedelta(minutes=5)
        self._flows = {
            k: v for k, v in self._flows.items()
            if isinstance(v.get("last_seen"), datetime) and v["last_seen"] > cutoff
        }

        # Calculate bandwidth utilization per link
        await self._calculate_link_utilization()

        # Check for optimization opportunities
        await self._check_optimization_opportunities()

        # Persist state
        await self.engine.state.set("optimizer:flow_count", len(self._flows))

    async def _calculate_link_utilization(self) -> None:
        """Calculate bandwidth utilization for each link."""
        link_traffic: dict[str, int] = defaultdict(int)

        for flow in self._flows.values():
            src_net = flow.get("source_ip", "0.0.0.0").rsplit(".", 1)[0]
            dst_net = flow.get("destination_ip", "0.0.0.0").rsplit(".", 1)[0]
            link_key = f"{src_net}_to_{dst_net}"

            traffic = flow.get("bytes_sent", 0) + flow.get("bytes_received", 0)
            link_traffic[link_key] += traffic

        # Calculate utilization (assuming 1Gbps links)
        link_capacity_bytes = 125_000_000  # 1Gbps in bytes/sec

        for link_id, traffic in link_traffic.items():
            rate = traffic / max(self.analysis_interval, 1)
            utilization = (rate / link_capacity_bytes) * 100
            self._link_utilization[link_id] = min(utilization, 100)

            if utilization > self.bandwidth_threshold:
                await self._handle_high_utilization(link_id, utilization)

    async def _handle_high_utilization(self, link_id: str, utilization: float) -> None:
        """Handle high bandwidth utilization on a link."""
        logger.warning(f"High utilization on {link_id}: {utilization:.1f}%")

        # Find low-priority flows on this link
        low_priority_flows = []
        for flow in self._flows.values():
            src_net = flow.get("source_ip", "0.0.0.0").rsplit(".", 1)[0]
            dst_net = flow.get("destination_ip", "0.0.0.0").rsplit(".", 1)[0]
            flow_link = f"{src_net}_to_{dst_net}"

            if flow_link == link_id:
                priority = self._priority_map.get(flow.get("application", "default"), 3)
                if priority >= 4:  # Low priority
                    low_priority_flows.append(flow)

        if low_priority_flows:
            await self._propose_rate_limit(link_id, low_priority_flows)

        # Emit event
        await self.engine.event_bus.publish(Event(
            category=EventCategory.NETWORK,
            event_type="network.bandwidth.high",
            severity=EventSeverity.WARNING,
            source=f"sentinel.agents.{self.agent_name}",
            title=f"High bandwidth utilization on {link_id}",
            description=f"Link utilization at {utilization:.1f}%, threshold is {self.bandwidth_threshold}%",
            data={
                "link_id": link_id,
                "utilization": utilization,
                "low_priority_flows": len(low_priority_flows)
            }
        ))

    async def _propose_rate_limit(self, link_id: str, flows: list[dict]) -> None:
        """Propose rate limiting for flows."""
        # Group by application
        by_app: dict[str, list[dict]] = defaultdict(list)
        for flow in flows:
            app = flow.get("application", "default")
            by_app[app].append(flow)

        for app, app_flows in by_app.items():
            total_bytes = sum(
                f.get("bytes_sent", 0) + f.get("bytes_received", 0)
                for f in app_flows
            )

            # Calculate rate limit (50% of current usage, minimum 10 Mbps)
            current_rate_mbps = (total_bytes / max(self.analysis_interval, 1)) * 8 / 1_000_000
            limit_mbps = max(10, current_rate_mbps * 0.5)

            policy_id = f"ratelimit_{app}_{link_id.replace('.', '_')}"

            decision = AgentDecision(
                agent_name=self.agent_name,
                decision_type="rate_limit",
                input_state={"link_id": link_id, "app": app, "flows": len(app_flows)},
                analysis=f"Congestion on {link_id}, proposing rate limit for {app}",
                options_considered=[
                    {"action": "rate_limit", "limit_mbps": limit_mbps},
                    {"action": "monitor_only"}
                ],
                selected_option={"action": "rate_limit", "limit_mbps": limit_mbps},
                confidence=0.78
            )
            self._decisions.append(decision)

            await self.execute_action(
                action_type="apply_rate_limit",
                target_type="qos_policy",
                target_id=policy_id,
                parameters={
                    "policy": {
                        "id": policy_id,
                        "name": policy_id,
                        "description": f"Rate limit for {app} during congestion",
                        "priority_queue": 5,
                        "bandwidth_limit_mbps": limit_mbps,
                        "auto_generated": True
                    },
                    "link_id": link_id,
                    "application": app,
                    "flow_count": len(app_flows)
                },
                reasoning=f"Congestion on {link_id}, limiting {app} traffic to {limit_mbps:.1f} Mbps",
                confidence=0.78,
                reversible=True
            )

    async def _handle_critical_congestion(self, congestion_data: dict) -> None:
        """Handle critical congestion events."""
        link_id = congestion_data.get("link_id")
        utilization = congestion_data.get("utilization", 0)

        logger.error(f"Critical congestion on {link_id}: {utilization}%")

        await self.engine.event_bus.publish(Event(
            category=EventCategory.NETWORK,
            event_type="network.congestion.critical",
            severity=EventSeverity.CRITICAL,
            source=f"sentinel.agents.{self.agent_name}",
            title=f"Critical congestion on {link_id}",
            description=f"Link at {utilization}% capacity, intervention required",
            data=congestion_data
        ))

    async def _check_optimization_opportunities(self) -> None:
        """Check for traffic optimization opportunities."""
        # Remove stale auto-generated QoS policies
        stale_policies = []

        for policy_id, policy in self._qos_policies.items():
            if not policy.get("auto_generated"):
                continue

            dst_port = policy.get("destination_port")
            has_matching_flow = any(
                f.get("destination_port") == dst_port
                for f in self._flows.values()
            )

            if not has_matching_flow:
                stale_policies.append(policy_id)

        for policy_id in stale_policies:
            logger.info(f"Removing stale QoS policy: {policy_id}")
            del self._qos_policies[policy_id]

        # Persist if changes made
        if stale_policies:
            await self.engine.state.set(
                "optimizer:qos_policies",
                list(self._qos_policies.values())
            )

    async def analyze(self, event: Event) -> Optional[AgentDecision]:
        """Analyze events for optimization decisions."""
        # Most handling done in event handlers
        return None

    async def _do_execute(self, action: AgentAction) -> dict:
        """Execute optimizer actions."""
        if action.action_type == "apply_qos_policy":
            policy = action.parameters.get("policy", {})
            policy_id = policy.get("id")

            # Store policy
            self._qos_policies[policy_id] = policy

            # Apply to router if available
            router = self.engine.get_integration("router")
            if router:
                # Would call router API to apply QoS
                pass

            # Persist
            await self.engine.state.set(
                "optimizer:qos_policies",
                list(self._qos_policies.values())
            )

            return {"applied": True, "policy_id": policy_id}

        elif action.action_type == "apply_rate_limit":
            policy = action.parameters.get("policy", {})
            policy_id = policy.get("id")

            self._qos_policies[policy_id] = policy

            await self.engine.state.set(
                "optimizer:qos_policies",
                list(self._qos_policies.values())
            )

            return {"applied": True, "policy_id": policy_id}

        elif action.action_type == "remove_policy":
            policy_id = action.parameters.get("policy_id")

            if policy_id in self._qos_policies:
                del self._qos_policies[policy_id]

                await self.engine.state.set(
                    "optimizer:qos_policies",
                    list(self._qos_policies.values())
                )
                return {"removed": True, "policy_id": policy_id}

            return {"removed": False, "error": "Policy not found"}

        raise ValueError(f"Unknown action type: {action.action_type}")

    async def _capture_rollback_data(self, action: AgentAction) -> Optional[dict]:
        """Capture state for rollback."""
        if action.action_type in ("apply_qos_policy", "apply_rate_limit"):
            policy = action.parameters.get("policy", {})
            return {
                "action": "remove_policy",
                "policy_id": policy.get("id")
            }
        return None

    async def _do_rollback(self, action: AgentAction) -> None:
        """Rollback optimizer actions."""
        rollback = action.rollback_data or {}

        if rollback.get("action") == "remove_policy":
            policy_id = rollback.get("policy_id")

            if policy_id in self._qos_policies:
                del self._qos_policies[policy_id]

                await self.engine.state.set(
                    "optimizer:qos_policies",
                    list(self._qos_policies.values())
                )

    async def _get_relevant_state(self) -> dict:
        """Get state relevant to optimizer decisions."""
        return {
            "active_flows": len(self._flows),
            "qos_policies": len(self._qos_policies),
            "link_utilization": self._link_utilization
        }

    @property
    def stats(self) -> dict:
        """Get optimizer statistics."""
        base = super().stats

        return {
            **base,
            "active_flows": len(self._flows),
            "qos_policies": len(self._qos_policies),
            "congestion_events": len(self._congestion_events),
            "link_utilization": dict(self._link_utilization)
        }
