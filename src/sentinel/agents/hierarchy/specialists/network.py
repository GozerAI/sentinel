"""
Network Specialists - Real implementations for network operations.

These specialists perform actual network operations with:
- Traffic analysis and flow monitoring
- QoS policy management
- Bandwidth monitoring and shaping
- Network path optimization
"""

import asyncio
import json
import logging
import re
import socket
from datetime import datetime
from typing import Dict, List, Any, Optional, TYPE_CHECKING

import ipaddress as _ipaddress

from sentinel.core.hierarchy.base import (
    Specialist,
    Task,
    TaskResult,
    SpecialistCapability,
)

if TYPE_CHECKING:
    from nexus.core.llm import LLMRouter

logger = logging.getLogger(__name__)

_IFACE_RE = re.compile(r'^[a-zA-Z0-9._-]+$')


def _validate_ip(ip_str: str) -> str:
    """Validate and return a safe IP address string."""
    addr = _ipaddress.ip_address(ip_str)  # Raises ValueError if invalid
    return str(addr)


def _validate_interface(name: str) -> str:
    """Validate a network interface name to prevent command injection."""
    if not _IFACE_RE.match(name):
        raise ValueError(f"Invalid interface name: {name}")
    return name


# ============================================================================
# TRAFFIC ANALYSIS SPECIALIST
# ============================================================================


class TrafficAnalysisSpecialist(Specialist):
    """
    Traffic analysis specialist with LLM-powered insights.

    Capabilities:
    - Analyzes network traffic patterns
    - Identifies top talkers and protocols
    - Detects anomalous traffic
    - Provides bandwidth utilization insights
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
            name="Traffic Analysis Specialist",
            task_types=[
                "network.analyze_traffic",
                "traffic.analysis",
                "traffic.flow_analysis",
                "optimizer.traffic",
            ],
            confidence=0.85,
            max_concurrent=5,
            description="Analyzes network traffic patterns and flows",
        )

    async def _do_execute(self, task: Task) -> TaskResult:
        """Analyze network traffic."""
        interface = task.parameters.get("interface", "eth0")
        duration = task.parameters.get("duration_seconds", 10)
        analysis_type = task.parameters.get("analysis_type", "summary")

        # Collect traffic data
        traffic_data = await self._collect_traffic_data(interface, duration)

        # Quick analysis
        quick_analysis = self._quick_analyze(traffic_data)

        # LLM deep analysis if available
        llm_analysis = None
        if self._llm_router:
            llm_analysis = await self._llm_analyze(traffic_data, analysis_type)

        return TaskResult(
            success=True,
            output={
                "interface": interface,
                "duration_seconds": duration,
                "analysis_type": analysis_type,
                "traffic_summary": quick_analysis,
                "llm_insights": llm_analysis,
                "top_protocols": quick_analysis.get("top_protocols", []),
                "top_talkers": quick_analysis.get("top_talkers", []),
                "bandwidth_utilization": quick_analysis.get("bandwidth", {}),
                "anomalies": llm_analysis.get("anomalies", []) if llm_analysis else [],
            },
            confidence=0.85 if llm_analysis else 0.7,
            metadata={"analysis_type": analysis_type},
        )

    async def _collect_traffic_data(self, interface: str, duration: int) -> Dict[str, Any]:
        """Collect traffic data from interface."""
        try:
            interface = _validate_interface(interface)
            # Try to use system tools for traffic capture
            # This is a simplified version - production would use proper tools

            # Get interface stats
            proc = await asyncio.create_subprocess_exec(
                "cat",
                f"/sys/class/net/{interface}/statistics/rx_bytes",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await proc.communicate()
            rx_start = int(stdout.decode().strip()) if proc.returncode == 0 else 0

            proc = await asyncio.create_subprocess_exec(
                "cat",
                f"/sys/class/net/{interface}/statistics/tx_bytes",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await proc.communicate()
            tx_start = int(stdout.decode().strip()) if proc.returncode == 0 else 0

            # Wait for duration
            await asyncio.sleep(min(duration, 5))  # Cap at 5 seconds for responsiveness

            # Get end stats
            proc = await asyncio.create_subprocess_exec(
                "cat",
                f"/sys/class/net/{interface}/statistics/rx_bytes",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await proc.communicate()
            rx_end = int(stdout.decode().strip()) if proc.returncode == 0 else 0

            proc = await asyncio.create_subprocess_exec(
                "cat",
                f"/sys/class/net/{interface}/statistics/tx_bytes",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await proc.communicate()
            tx_end = int(stdout.decode().strip()) if proc.returncode == 0 else 0

            return {
                "interface": interface,
                "rx_bytes": rx_end - rx_start,
                "tx_bytes": tx_end - tx_start,
                "duration": duration,
                "timestamp": datetime.now().isoformat(),
            }

        except Exception as e:
            logger.warning(f"Failed to collect traffic data: {e}")
            return {
                "interface": interface,
                "rx_bytes": 0,
                "tx_bytes": 0,
                "duration": duration,
                "error": str(e),
            }

    def _quick_analyze(self, traffic_data: Dict[str, Any]) -> Dict[str, Any]:
        """Quick traffic analysis."""
        rx_bytes = traffic_data.get("rx_bytes", 0)
        tx_bytes = traffic_data.get("tx_bytes", 0)
        duration = traffic_data.get("duration", 1)

        rx_rate = rx_bytes / duration if duration > 0 else 0
        tx_rate = tx_bytes / duration if duration > 0 else 0

        return {
            "total_rx_bytes": rx_bytes,
            "total_tx_bytes": tx_bytes,
            "rx_rate_bps": rx_rate * 8,
            "tx_rate_bps": tx_rate * 8,
            "rx_rate_mbps": (rx_rate * 8) / 1_000_000,
            "tx_rate_mbps": (tx_rate * 8) / 1_000_000,
            "bandwidth": {
                "rx_utilization_percent": 0,  # Would need link speed to calculate
                "tx_utilization_percent": 0,
            },
            "top_protocols": [],  # Would need deep packet inspection
            "top_talkers": [],  # Would need netflow data
        }

    async def _llm_analyze(
        self, traffic_data: Dict[str, Any], analysis_type: str
    ) -> Optional[Dict[str, Any]]:
        """LLM-powered traffic analysis."""
        system_prompt = """You are a network engineer analyzing traffic patterns.
Analyze the traffic data and provide insights.
Respond with JSON:
{
    "summary": "brief traffic analysis summary",
    "patterns": [{"pattern": "...", "significance": "..."}],
    "anomalies": [{"description": "...", "severity": "..."}],
    "recommendations": ["actionable recommendations"],
    "bandwidth_assessment": "assessment of bandwidth usage",
    "potential_issues": ["potential network issues detected"]
}"""

        prompt = f"""Analyze this network traffic data:

Interface: {traffic_data.get('interface')}
RX Bytes: {traffic_data.get('rx_bytes')}
TX Bytes: {traffic_data.get('tx_bytes')}
Duration: {traffic_data.get('duration')} seconds
Analysis Type: {analysis_type}

Provide network traffic insights as JSON:"""

        try:
            response = await self.llm_complete(
                prompt=prompt,
                task_category="traffic_analysis",
                system_prompt=system_prompt,
            )

            if response:
                json_match = re.search(r"\{[\s\S]*\}", response)
                if json_match:
                    return json.loads(json_match.group())
        except Exception as e:
            logger.warning(f"LLM traffic analysis failed: {e}")

        return None


# ============================================================================
# QOS POLICY SPECIALIST
# ============================================================================


class QoSPolicySpecialist(Specialist):
    """
    QoS policy management specialist with LLM-powered configuration.

    Capabilities:
    - Generates QoS policies for various platforms
    - Validates QoS configurations
    - Recommends traffic classification rules
    - Analyzes policy effectiveness
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
            name="QoS Policy Specialist",
            task_types=[
                "network.qos_policy",
                "qos.configure",
                "qos.generate",
                "optimizer.qos",
            ],
            confidence=0.9,
            max_concurrent=3,
            description="Manages QoS policies and traffic classification",
        )

    async def _do_execute(self, task: Task) -> TaskResult:
        """Execute QoS policy task."""
        action = task.parameters.get("action", "generate")
        platform = task.parameters.get("platform", "generic")
        requirements = task.parameters.get("requirements", {})

        if action == "generate":
            return await self._generate_policy(platform, requirements)
        elif action == "validate":
            config = task.parameters.get("config", "")
            return await self._validate_policy(platform, config)
        elif action == "recommend":
            traffic_profile = task.parameters.get("traffic_profile", {})
            return await self._recommend_policy(traffic_profile)
        else:
            return TaskResult(
                success=False,
                error=f"Unknown action: {action}",
            )

    async def _generate_policy(self, platform: str, requirements: Dict[str, Any]) -> TaskResult:
        """Generate QoS policy configuration."""
        # Generate platform-specific config
        if platform == "mikrotik":
            config = self._generate_mikrotik_qos(requirements)
        elif platform == "cisco":
            config = self._generate_cisco_qos(requirements)
        elif platform == "linux":
            config = self._generate_linux_tc(requirements)
        else:
            config = self._generate_generic_qos(requirements)

        # LLM validation if available
        llm_review = None
        if self._llm_router:
            llm_review = await self._llm_review_policy(config, platform, requirements)

        return TaskResult(
            success=True,
            output={
                "platform": platform,
                "config": config,
                "requirements": requirements,
                "llm_review": llm_review,
                "warnings": llm_review.get("warnings", []) if llm_review else [],
            },
            confidence=0.9 if llm_review else 0.75,
            metadata={"platform": platform},
        )

    def _generate_mikrotik_qos(self, req: Dict[str, Any]) -> str:
        """Generate MikroTik QoS configuration."""
        lines = [
            "# MikroTik QoS Configuration",
            "# Generated by Sentinel Network Optimizer",
            "",
        ]

        # Traffic classes
        classes = req.get("traffic_classes", [])
        for i, tc in enumerate(classes):
            name = tc.get("name", f"class_{i}")
            priority = tc.get("priority", 5)
            rate = tc.get("rate", "10M")

            lines.append(f"/queue simple")
            lines.append(
                f'add name="{name}" target=0.0.0.0/0 priority={priority}/8 max-limit={rate}/{rate}'
            )

        # Mangle rules for classification
        rules = req.get("classification_rules", [])
        for i, rule in enumerate(rules):
            src = rule.get("src", "0.0.0.0/0")
            dst_port = rule.get("dst_port", "")
            mark = rule.get("mark", f"mark_{i}")

            if dst_port:
                lines.append(
                    f"/ip firewall mangle add chain=forward src-address={src} dst-port={dst_port} action=mark-packet new-packet-mark={mark}"
                )

        return "\n".join(lines)

    def _generate_cisco_qos(self, req: Dict[str, Any]) -> str:
        """Generate Cisco IOS QoS configuration."""
        lines = [
            "! Cisco QoS Configuration",
            "! Generated by Sentinel Network Optimizer",
            "",
        ]

        # Class maps
        classes = req.get("traffic_classes", [])
        for tc in classes:
            name = tc.get("name", "default")
            match = tc.get("match", {})

            lines.append(f"class-map match-any {name}")
            if match.get("dscp"):
                lines.append(f"  match dscp {match['dscp']}")
            if match.get("protocol"):
                lines.append(f"  match protocol {match['protocol']}")

        # Policy map
        lines.append("")
        lines.append("policy-map QOS_POLICY")
        for tc in classes:
            name = tc.get("name", "default")
            bandwidth = tc.get("bandwidth_percent", 10)
            lines.append(f"  class {name}")
            lines.append(f"    bandwidth percent {bandwidth}")

        return "\n".join(lines)

    def _generate_linux_tc(self, req: Dict[str, Any]) -> str:
        """Generate Linux tc configuration."""
        interface = req.get("interface", "eth0")
        bandwidth = req.get("total_bandwidth", "100mbit")

        lines = [
            "#!/bin/bash",
            "# Linux tc QoS Configuration",
            "# Generated by Sentinel Network Optimizer",
            "",
            f"# Clear existing rules",
            f"tc qdisc del dev {interface} root 2>/dev/null",
            "",
            f"# Create root qdisc",
            f"tc qdisc add dev {interface} root handle 1: htb default 30",
            f"tc class add dev {interface} parent 1: classid 1:1 htb rate {bandwidth}",
            "",
        ]

        # Traffic classes
        classes = req.get("traffic_classes", [])
        for i, tc in enumerate(classes):
            classid = 10 + i
            rate = tc.get("rate", "10mbit")
            ceil = tc.get("ceil", bandwidth)
            priority = tc.get("priority", 5)

            lines.append(f"# Class: {tc.get('name', f'class_{i}')}")
            lines.append(
                f"tc class add dev {interface} parent 1:1 classid 1:{classid} htb rate {rate} ceil {ceil} prio {priority}"
            )

        return "\n".join(lines)

    def _generate_generic_qos(self, req: Dict[str, Any]) -> Dict[str, Any]:
        """Generate generic QoS policy description."""
        return {
            "policy_type": "generic",
            "traffic_classes": req.get("traffic_classes", []),
            "classification_rules": req.get("classification_rules", []),
            "bandwidth_allocation": req.get("bandwidth_allocation", {}),
        }

    async def _validate_policy(self, platform: str, config: str) -> TaskResult:
        """Validate QoS policy configuration."""
        issues = []
        warnings = []

        # Basic syntax checks
        if platform == "mikrotik":
            if "/queue" not in config and "/ip firewall mangle" not in config:
                issues.append("No QoS rules found in configuration")

        elif platform == "cisco":
            if "policy-map" not in config:
                issues.append("No policy-map found in configuration")

        elif platform == "linux":
            if "tc qdisc" not in config:
                issues.append("No tc qdisc commands found")

        # LLM validation if available
        if self._llm_router:
            llm_validation = await self._llm_validate_policy(config, platform)
            if llm_validation:
                issues.extend(llm_validation.get("issues", []))
                warnings.extend(llm_validation.get("warnings", []))

        return TaskResult(
            success=len(issues) == 0,
            output={
                "valid": len(issues) == 0,
                "issues": issues,
                "warnings": warnings,
                "platform": platform,
            },
            confidence=0.85,
            metadata={"platform": platform},
        )

    async def _recommend_policy(self, traffic_profile: Dict[str, Any]) -> TaskResult:
        """Recommend QoS policy based on traffic profile."""
        if not self._llm_router:
            # Return basic recommendations without LLM
            return TaskResult(
                success=True,
                output={
                    "recommendations": [
                        "Enable traffic classification for voice traffic",
                        "Implement rate limiting for bulk transfers",
                        "Configure priority queuing for interactive traffic",
                    ],
                    "suggested_classes": [
                        {"name": "voice", "priority": 1, "bandwidth_percent": 20},
                        {"name": "interactive", "priority": 2, "bandwidth_percent": 30},
                        {"name": "bulk", "priority": 5, "bandwidth_percent": 50},
                    ],
                },
                confidence=0.7,
            )

        # LLM-powered recommendations
        system_prompt = """You are a network QoS expert.
Analyze the traffic profile and recommend QoS policies.
Respond with JSON:
{
    "recommendations": ["detailed recommendations"],
    "suggested_classes": [{"name": "...", "priority": 1-8, "bandwidth_percent": 0-100, "description": "..."}],
    "classification_rules": [{"name": "...", "match": {...}, "action": "..."}],
    "rationale": "explanation of recommendations"
}"""

        prompt = f"""Recommend QoS policy for this traffic profile:

{json.dumps(traffic_profile, indent=2)}

Provide QoS recommendations as JSON:"""

        try:
            response = await self.llm_complete(
                prompt=prompt,
                task_category="config_generation",
                system_prompt=system_prompt,
            )

            if response:
                json_match = re.search(r"\{[\s\S]*\}", response)
                if json_match:
                    recommendations = json.loads(json_match.group())
                    return TaskResult(
                        success=True,
                        output=recommendations,
                        confidence=0.85,
                    )
        except Exception as e:
            logger.warning(f"LLM QoS recommendation failed: {e}")

        return TaskResult(
            success=False,
            error="Failed to generate recommendations",
        )

    async def _llm_review_policy(
        self, config: str, platform: str, requirements: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        """LLM review of generated policy."""
        system_prompt = """You are a network QoS expert reviewing configurations.
Analyze the QoS configuration and provide feedback.
Respond with JSON:
{
    "valid": true/false,
    "quality_score": 0.0-1.0,
    "issues": ["critical issues"],
    "warnings": ["non-critical warnings"],
    "suggestions": ["improvement suggestions"],
    "meets_requirements": true/false
}"""

        prompt = f"""Review this {platform} QoS configuration:

```
{config}
```

Requirements:
{json.dumps(requirements, indent=2)}

Provide review as JSON:"""

        try:
            response = await self.llm_complete(
                prompt=prompt,
                task_category="config_generation",
                system_prompt=system_prompt,
            )

            if response:
                json_match = re.search(r"\{[\s\S]*\}", response)
                if json_match:
                    return json.loads(json_match.group())
        except Exception as e:
            logger.warning(f"LLM policy review failed: {e}")

        return None

    async def _llm_validate_policy(self, config: str, platform: str) -> Optional[Dict[str, Any]]:
        """LLM validation of policy syntax and semantics."""
        system_prompt = f"""You are a {platform} network configuration expert.
Validate this QoS configuration for syntax and semantic errors.
Respond with JSON:
{{
    "valid": true/false,
    "issues": ["syntax or semantic errors"],
    "warnings": ["potential issues or best practice violations"]
}}"""

        prompt = f"""Validate this {platform} QoS configuration:

```
{config}
```

Provide validation result as JSON:"""

        try:
            response = await self.llm_complete(
                prompt=prompt,
                task_category="config_generation",
                system_prompt=system_prompt,
            )

            if response:
                json_match = re.search(r"\{[\s\S]*\}", response)
                if json_match:
                    return json.loads(json_match.group())
        except Exception as e:
            logger.warning(f"LLM policy validation failed: {e}")

        return None


# ============================================================================
# BANDWIDTH MONITOR SPECIALIST
# ============================================================================


class BandwidthMonitorSpecialist(Specialist):
    """
    Bandwidth monitoring specialist with real-time metrics.

    Capabilities:
    - Monitors interface bandwidth utilization
    - Tracks throughput over time
    - Identifies bandwidth hogs
    - Detects congestion
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
            name="Bandwidth Monitor Specialist",
            task_types=[
                "network.bandwidth_monitor",
                "bandwidth.monitor",
                "bandwidth.utilization",
                "optimizer.bandwidth",
            ],
            confidence=0.9,
            max_concurrent=10,
            description="Monitors network bandwidth utilization",
        )

    async def _do_execute(self, task: Task) -> TaskResult:
        """Monitor bandwidth."""
        interface = task.parameters.get("interface", "eth0")
        samples = task.parameters.get("samples", 5)
        interval = task.parameters.get("interval_seconds", 1)

        # Collect bandwidth samples
        metrics = await self._collect_bandwidth_metrics(interface, samples, interval)

        # Calculate statistics
        stats = self._calculate_stats(metrics)

        # LLM analysis if available
        llm_analysis = None
        if self._llm_router and len(metrics) > 0:
            llm_analysis = await self._llm_analyze_bandwidth(stats)

        return TaskResult(
            success=True,
            output={
                "interface": interface,
                "samples": len(metrics),
                "metrics": metrics,
                "statistics": stats,
                "llm_analysis": llm_analysis,
                "congestion_detected": stats.get("congestion_risk", False),
            },
            confidence=0.9,
            metadata={"interface": interface},
        )

    async def _collect_bandwidth_metrics(
        self, interface: str, samples: int, interval: float
    ) -> List[Dict[str, Any]]:
        """Collect bandwidth metrics over time."""
        metrics = []

        try:
            prev_rx = 0
            prev_tx = 0

            for i in range(samples + 1):
                # Read interface stats
                proc = await asyncio.create_subprocess_exec(
                    "cat",
                    f"/sys/class/net/{interface}/statistics/rx_bytes",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, _ = await proc.communicate()
                rx_bytes = int(stdout.decode().strip()) if proc.returncode == 0 else 0

                proc = await asyncio.create_subprocess_exec(
                    "cat",
                    f"/sys/class/net/{interface}/statistics/tx_bytes",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, _ = await proc.communicate()
                tx_bytes = int(stdout.decode().strip()) if proc.returncode == 0 else 0

                if i > 0:
                    rx_delta = rx_bytes - prev_rx
                    tx_delta = tx_bytes - prev_tx

                    metrics.append(
                        {
                            "timestamp": datetime.now().isoformat(),
                            "rx_bytes_per_sec": rx_delta / interval,
                            "tx_bytes_per_sec": tx_delta / interval,
                            "rx_mbps": (rx_delta * 8) / (interval * 1_000_000),
                            "tx_mbps": (tx_delta * 8) / (interval * 1_000_000),
                        }
                    )

                prev_rx = rx_bytes
                prev_tx = tx_bytes

                if i < samples:
                    await asyncio.sleep(interval)

        except Exception as e:
            logger.warning(f"Failed to collect bandwidth metrics: {e}")

        return metrics

    def _calculate_stats(self, metrics: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Calculate bandwidth statistics."""
        if not metrics:
            return {"error": "No metrics collected"}

        rx_values = [m["rx_mbps"] for m in metrics]
        tx_values = [m["tx_mbps"] for m in metrics]

        return {
            "rx_avg_mbps": sum(rx_values) / len(rx_values),
            "rx_max_mbps": max(rx_values),
            "rx_min_mbps": min(rx_values),
            "tx_avg_mbps": sum(tx_values) / len(tx_values),
            "tx_max_mbps": max(tx_values),
            "tx_min_mbps": min(tx_values),
            "total_avg_mbps": (sum(rx_values) + sum(tx_values)) / len(rx_values),
            "sample_count": len(metrics),
            "congestion_risk": max(rx_values) > 80 or max(tx_values) > 80,  # Assuming 100 Mbps link
        }

    async def _llm_analyze_bandwidth(self, stats: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """LLM analysis of bandwidth usage."""
        system_prompt = """You are a network engineer analyzing bandwidth metrics.
Provide insights about bandwidth utilization.
Respond with JSON:
{
    "assessment": "overall assessment",
    "utilization_level": "low/moderate/high/critical",
    "concerns": ["any concerns"],
    "recommendations": ["optimization recommendations"],
    "trend": "stable/increasing/decreasing/variable"
}"""

        prompt = f"""Analyze these bandwidth statistics:

{json.dumps(stats, indent=2)}

Provide bandwidth analysis as JSON:"""

        try:
            response = await self.llm_complete(
                prompt=prompt,
                task_category="traffic_analysis",
                system_prompt=system_prompt,
            )

            if response:
                json_match = re.search(r"\{[\s\S]*\}", response)
                if json_match:
                    return json.loads(json_match.group())
        except Exception as e:
            logger.warning(f"LLM bandwidth analysis failed: {e}")

        return None


# ============================================================================
# PATH OPTIMIZATION SPECIALIST
# ============================================================================


class PathOptimizationSpecialist(Specialist):
    """
    Network path optimization specialist with LLM-powered routing decisions.

    Capabilities:
    - Analyzes network paths and latency
    - Recommends optimal routes
    - Identifies path redundancy
    - Suggests load balancing configurations
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
            name="Path Optimization Specialist",
            task_types=[
                "network.optimize_path",
                "path.optimization",
                "routing.optimize",
                "optimizer.path",
            ],
            confidence=0.85,
            max_concurrent=3,
            description="Optimizes network paths and routing",
        )

    async def _do_execute(self, task: Task) -> TaskResult:
        """Execute path optimization task."""
        action = task.parameters.get("action", "analyze")
        targets = task.parameters.get("targets", [])

        if action == "analyze":
            return await self._analyze_paths(targets)
        elif action == "recommend":
            current_topology = task.parameters.get("topology", {})
            return await self._recommend_optimization(current_topology, targets)
        else:
            return TaskResult(
                success=False,
                error=f"Unknown action: {action}",
            )

    async def _analyze_paths(self, targets: List[str]) -> TaskResult:
        """Analyze paths to multiple targets."""
        path_results = []

        for target in targets:
            try:
                target = _validate_ip(target)
                # Run traceroute
                proc = await asyncio.create_subprocess_exec(
                    "traceroute",
                    "-n",
                    "-w",
                    "2",
                    "-q",
                    "1",
                    target,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=30)

                hops = self._parse_traceroute(stdout.decode())

                # Calculate path metrics
                total_latency = sum(h.get("latency_ms", 0) for h in hops if h.get("latency_ms"))

                path_results.append(
                    {
                        "target": target,
                        "reachable": len(hops) > 0 and hops[-1].get("ip") is not None,
                        "hop_count": len(hops),
                        "total_latency_ms": total_latency,
                        "hops": hops,
                    }
                )

            except asyncio.TimeoutError:
                path_results.append(
                    {
                        "target": target,
                        "reachable": False,
                        "error": "timeout",
                    }
                )
            except Exception as e:
                path_results.append(
                    {
                        "target": target,
                        "reachable": False,
                        "error": str(e),
                    }
                )

        # LLM analysis if available
        llm_analysis = None
        if self._llm_router and path_results:
            llm_analysis = await self._llm_analyze_paths(path_results)

        return TaskResult(
            success=True,
            output={
                "targets_analyzed": len(targets),
                "paths": path_results,
                "llm_analysis": llm_analysis,
                "optimization_opportunities": (
                    llm_analysis.get("opportunities", []) if llm_analysis else []
                ),
            },
            confidence=0.85 if llm_analysis else 0.7,
        )

    def _parse_traceroute(self, output: str) -> List[Dict[str, Any]]:
        """Parse traceroute output."""
        hops = []
        lines = output.strip().split("\n")

        for line in lines[1:]:  # Skip header
            match = re.search(r"^\s*(\d+)\s+(\S+)\s+([\d.]+)\s*ms", line)
            if match:
                hops.append(
                    {
                        "hop": int(match.group(1)),
                        "ip": match.group(2) if match.group(2) != "*" else None,
                        "latency_ms": float(match.group(3)),
                    }
                )
            elif re.search(r"^\s*(\d+)\s+\*", line):
                hop_num = int(re.search(r"^\s*(\d+)", line).group(1))
                hops.append(
                    {
                        "hop": hop_num,
                        "ip": None,
                        "latency_ms": None,
                        "timeout": True,
                    }
                )

        return hops

    async def _recommend_optimization(
        self, topology: Dict[str, Any], targets: List[str]
    ) -> TaskResult:
        """Recommend path optimizations."""
        if not self._llm_router:
            return TaskResult(
                success=True,
                output={
                    "recommendations": [
                        "Enable ECMP for load balancing",
                        "Configure backup paths for redundancy",
                        "Implement policy-based routing for critical traffic",
                    ],
                },
                confidence=0.6,
            )

        system_prompt = """You are a network routing expert.
Analyze the topology and recommend path optimizations.
Respond with JSON:
{
    "recommendations": [{"action": "...", "reason": "...", "priority": "high/medium/low"}],
    "load_balancing": {"enabled": true/false, "method": "...", "targets": []},
    "redundancy": {"current_level": "...", "recommended_level": "...", "actions": []},
    "estimated_improvement": "description of expected improvement"
}"""

        prompt = f"""Recommend path optimizations for this network:

Topology: {json.dumps(topology, indent=2)}
Critical Targets: {targets}

Provide optimization recommendations as JSON:"""

        try:
            response = await self.llm_complete(
                prompt=prompt,
                task_category="config_generation",
                system_prompt=system_prompt,
            )

            if response:
                json_match = re.search(r"\{[\s\S]*\}", response)
                if json_match:
                    recommendations = json.loads(json_match.group())
                    return TaskResult(
                        success=True,
                        output=recommendations,
                        confidence=0.85,
                    )
        except Exception as e:
            logger.warning(f"LLM path optimization failed: {e}")

        return TaskResult(
            success=False,
            error="Failed to generate recommendations",
        )

    async def _llm_analyze_paths(
        self, path_results: List[Dict[str, Any]]
    ) -> Optional[Dict[str, Any]]:
        """LLM analysis of path data."""
        system_prompt = """You are a network engineer analyzing network paths.
Provide insights about path quality and optimization opportunities.
Respond with JSON:
{
    "overall_health": "good/fair/poor",
    "issues": ["identified issues"],
    "opportunities": ["optimization opportunities"],
    "recommendations": ["specific recommendations"],
    "critical_paths": ["paths that need attention"]
}"""

        prompt = f"""Analyze these network paths:

{json.dumps(path_results, indent=2)}

Provide path analysis as JSON:"""

        try:
            response = await self.llm_complete(
                prompt=prompt,
                task_category="traffic_analysis",
                system_prompt=system_prompt,
            )

            if response:
                json_match = re.search(r"\{[\s\S]*\}", response)
                if json_match:
                    return json.loads(json_match.group())
        except Exception as e:
            logger.warning(f"LLM path analysis failed: {e}")

        return None
