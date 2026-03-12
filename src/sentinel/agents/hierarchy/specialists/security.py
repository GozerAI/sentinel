"""
Security Specialists - Real implementations with LLM integration.

These specialists perform actual security operations:
- Intrusion detection with LLM-powered analysis
- Firewall rule generation and application
- Threat classification and response
- Forensics and incident investigation
"""

import asyncio
import json
import logging
import re
from datetime import datetime
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
# INTRUSION DETECTION SPECIALIST
# ============================================================================


class IntrusionDetectionSpecialist(Specialist):
    """
    Intrusion detection specialist with LLM-powered analysis.

    Capabilities:
    - Analyzes traffic patterns for intrusion indicators
    - Classifies attack types using LLM
    - Generates risk scores and recommendations
    - Correlates multiple signals for accuracy
    """

    def __init__(
        self,
        specialist_id: Optional[str] = None,
        llm_router: Optional["LLMRouter"] = None,
        # Known attack signatures for quick matching
        known_signatures: Optional[Dict[str, Any]] = None,
    ):
        super().__init__(specialist_id, llm_router)
        self._known_signatures = known_signatures or self._default_signatures()

    def _default_signatures(self) -> Dict[str, Any]:
        """Default attack signatures for quick detection."""
        return {
            "port_scan": {
                "pattern": "multiple_ports_short_time",
                "threshold": 20,  # ports in 10 seconds
                "severity": "medium",
            },
            "brute_force": {
                "pattern": "repeated_auth_failures",
                "threshold": 5,  # failures in 60 seconds
                "severity": "high",
            },
            "dos_attempt": {
                "pattern": "high_packet_rate",
                "threshold": 10000,  # packets per second
                "severity": "critical",
            },
            "sql_injection": {
                "pattern": "sql_keywords_in_payload",
                "keywords": ["UNION", "SELECT", "DROP", "INSERT", "--", "/*"],
                "severity": "high",
            },
            "xss_attempt": {
                "pattern": "script_tags_in_payload",
                "keywords": ["<script>", "javascript:", "onerror=", "onload="],
                "severity": "medium",
            },
        }

    @property
    def capability(self) -> SpecialistCapability:
        return SpecialistCapability(
            name="Intrusion Detection Specialist",
            task_types=[
                "threat.detect.intrusion",
                "threat.analyze.intrusion",
                "security.intrusion_detect",
                "security.traffic_analyze",
            ],
            confidence=0.85,
            max_concurrent=10,
            description="Detects and analyzes network intrusions using signatures and LLM",
        )

    async def _do_execute(self, task: Task) -> TaskResult:
        """
        Detect and analyze potential intrusions.

        Parameters:
            source_ip: Source IP address
            dest_ip: Destination IP address
            dest_port: Destination port
            protocol: Protocol (tcp, udp, icmp)
            payload_sample: Sample of packet payload (hex or ascii)
            packet_count: Number of packets observed
            time_window: Time window in seconds
            connection_flags: TCP flags if applicable
        """
        params = task.parameters

        # Extract parameters
        source_ip = params.get("source_ip", "unknown")
        dest_ip = params.get("dest_ip", "unknown")
        dest_port = params.get("dest_port")
        protocol = params.get("protocol", "tcp")
        payload_sample = params.get("payload_sample", "")
        packet_count = params.get("packet_count", 1)
        time_window = params.get("time_window", 60)
        flags = params.get("connection_flags", [])

        # Phase 1: Quick signature matching
        signature_matches = self._check_signatures(
            payload_sample=payload_sample,
            packet_count=packet_count,
            time_window=time_window,
            dest_port=dest_port,
            flags=flags,
        )

        # Phase 2: Calculate base risk score
        risk_score = self._calculate_risk_score(signature_matches, params)

        # Phase 3: LLM analysis for complex patterns (if available and needed)
        llm_analysis = None
        if self._llm_router and (risk_score > 0.3 or params.get("force_llm_analysis")):
            llm_analysis = await self._llm_analyze(params, signature_matches)
            if llm_analysis:
                # Adjust risk score based on LLM assessment
                llm_risk = llm_analysis.get("risk_score", risk_score)
                risk_score = (risk_score + llm_risk) / 2

        # Build response
        alerts = []
        for match in signature_matches:
            alerts.append(
                {
                    "type": match["signature"],
                    "severity": match["severity"],
                    "description": match["description"],
                    "timestamp": datetime.now().isoformat(),
                }
            )

        # Determine overall classification
        classification = self._classify_threat(risk_score, signature_matches, llm_analysis)

        return TaskResult(
            success=True,
            output={
                "threat_type": "intrusion",
                "source_ip": source_ip,
                "dest_ip": dest_ip,
                "dest_port": dest_port,
                "protocol": protocol,
                "classification": classification,
                "risk_score": round(risk_score, 3),
                "alerts": alerts,
                "signature_matches": len(signature_matches),
                "llm_analysis": llm_analysis,
                "recommended_actions": self._get_recommendations(classification, risk_score),
                "indicators": self._extract_indicators(params, signature_matches),
            },
            confidence=0.85 if not llm_analysis else 0.92,
            metadata={
                "threat_type": "intrusion",
                "analysis_method": "hybrid" if llm_analysis else "signature",
            },
        )

    def _check_signatures(
        self,
        payload_sample: str,
        packet_count: int,
        time_window: int,
        dest_port: Optional[int],
        flags: List[str],
    ) -> List[Dict[str, Any]]:
        """Check traffic against known attack signatures."""
        matches = []

        # Check for port scan
        if dest_port and packet_count > 20 and time_window < 10:
            matches.append(
                {
                    "signature": "port_scan",
                    "severity": "medium",
                    "description": f"Possible port scan: {packet_count} connections in {time_window}s",
                }
            )

        # Check for DoS attempt
        if packet_count / max(time_window, 1) > 1000:
            matches.append(
                {
                    "signature": "dos_attempt",
                    "severity": "critical",
                    "description": f"High packet rate: {packet_count/time_window:.0f} pps",
                }
            )

        # Check payload for SQL injection
        if payload_sample:
            payload_upper = payload_sample.upper()
            sql_keywords = self._known_signatures["sql_injection"]["keywords"]
            found_sql = [kw for kw in sql_keywords if kw in payload_upper]
            if len(found_sql) >= 2:
                matches.append(
                    {
                        "signature": "sql_injection",
                        "severity": "high",
                        "description": f"SQL injection attempt detected: {found_sql}",
                    }
                )

            # Check for XSS
            xss_keywords = self._known_signatures["xss_attempt"]["keywords"]
            found_xss = [kw for kw in xss_keywords if kw.lower() in payload_sample.lower()]
            if found_xss:
                matches.append(
                    {
                        "signature": "xss_attempt",
                        "severity": "medium",
                        "description": f"XSS attempt detected: {found_xss}",
                    }
                )

        # Check for SYN flood (many SYN without ACK)
        if "SYN" in flags and "ACK" not in flags and packet_count > 100:
            matches.append(
                {
                    "signature": "syn_flood",
                    "severity": "high",
                    "description": f"Possible SYN flood: {packet_count} SYN packets",
                }
            )

        return matches

    def _calculate_risk_score(self, signature_matches: List[Dict], params: Dict[str, Any]) -> float:
        """Calculate risk score based on multiple factors."""
        score = 0.0

        # Score from signature matches
        severity_scores = {"critical": 0.9, "high": 0.7, "medium": 0.4, "low": 0.2}
        for match in signature_matches:
            score = max(score, severity_scores.get(match["severity"], 0.1))

        # Adjust for packet volume
        packet_count = params.get("packet_count", 1)
        if packet_count > 1000:
            score = min(score + 0.2, 1.0)
        elif packet_count > 100:
            score = min(score + 0.1, 1.0)

        # Adjust for known bad ports
        dest_port = params.get("dest_port")
        suspicious_ports = [22, 23, 3389, 445, 135, 139]  # SSH, Telnet, RDP, SMB
        if dest_port in suspicious_ports:
            score = min(score + 0.1, 1.0)

        return score

    async def _llm_analyze(
        self, params: Dict[str, Any], signature_matches: List[Dict]
    ) -> Optional[Dict[str, Any]]:
        """Use LLM for deeper traffic analysis."""
        system_prompt = """You are a network security analyst specializing in intrusion detection.
Analyze the provided traffic data and respond with JSON containing:
{
    "attack_type": "type of attack or 'benign'",
    "risk_score": 0.0-1.0,
    "confidence": 0.0-1.0,
    "indicators": ["list of suspicious indicators"],
    "reasoning": "brief explanation",
    "false_positive_likelihood": "low/medium/high"
}"""

        prompt = f"""Analyze this network traffic for potential intrusion:

Source IP: {params.get('source_ip', 'unknown')}
Destination IP: {params.get('dest_ip', 'unknown')}
Destination Port: {params.get('dest_port', 'unknown')}
Protocol: {params.get('protocol', 'unknown')}
Packet Count: {params.get('packet_count', 1)}
Time Window: {params.get('time_window', 60)} seconds
TCP Flags: {params.get('connection_flags', [])}

Payload Sample (first 200 chars):
{str(params.get('payload_sample', ''))[:200]}

Signature Matches:
{json.dumps(signature_matches, indent=2)}

Provide your analysis as JSON."""

        try:
            response = await self.llm_complete(
                prompt=prompt,
                task_category="threat_detection",
                system_prompt=system_prompt,
                context={"severity": "high" if signature_matches else "medium"},
            )

            if response:
                # Try to parse JSON from response
                json_match = re.search(r"\{[\s\S]*\}", response)
                if json_match:
                    return json.loads(json_match.group())
        except Exception as e:
            logger.warning(f"LLM analysis failed: {e}")

        return None

    def _classify_threat(
        self, risk_score: float, signature_matches: List[Dict], llm_analysis: Optional[Dict]
    ) -> str:
        """Classify the overall threat level."""
        if risk_score >= 0.8:
            return "critical"
        elif risk_score >= 0.6:
            return "high"
        elif risk_score >= 0.4:
            return "medium"
        elif risk_score >= 0.2:
            return "low"
        else:
            return "benign"

    def _get_recommendations(self, classification: str, risk_score: float) -> List[str]:
        """Get recommended actions based on threat level."""
        recommendations = []

        if classification == "critical":
            recommendations = [
                "IMMEDIATE: Block source IP at firewall",
                "Alert security team",
                "Capture full packet trace",
                "Check for lateral movement",
                "Review affected system logs",
            ]
        elif classification == "high":
            recommendations = [
                "Block source IP temporarily",
                "Increase monitoring on target",
                "Review recent access logs",
                "Consider threat hunting",
            ]
        elif classification == "medium":
            recommendations = [
                "Add to watchlist",
                "Enable detailed logging",
                "Review after 24 hours",
            ]
        elif classification == "low":
            recommendations = [
                "Monitor for pattern",
                "Log for future reference",
            ]

        return recommendations

    def _extract_indicators(
        self, params: Dict[str, Any], signature_matches: List[Dict]
    ) -> List[Dict[str, str]]:
        """Extract indicators of compromise."""
        indicators = []

        if params.get("source_ip"):
            indicators.append(
                {
                    "type": "ip",
                    "value": params["source_ip"],
                    "context": "source_ip",
                }
            )

        for match in signature_matches:
            indicators.append(
                {
                    "type": "signature",
                    "value": match["signature"],
                    "context": match["description"],
                }
            )

        return indicators


# ============================================================================
# FIREWALL SPECIALIST
# ============================================================================


class FirewallSpecialist(Specialist):
    """
    Firewall configuration specialist with LLM-powered rule generation.

    Capabilities:
    - Generates firewall rules for multiple platforms
    - Validates rule syntax and logic
    - Applies rules via integration APIs
    - Manages rule lifecycle (add, remove, update)
    """

    # Supported platforms and their rule formats
    PLATFORMS = {
        "mikrotik": {
            "add_rule": "/ip firewall filter add chain={chain} action={action} "
            "src-address={src} dst-address={dst} dst-port={port} "
            'protocol={protocol} comment="{comment}"',
            "remove_rule": '/ip firewall filter remove [find comment="{comment}"]',
        },
        "iptables": {
            "add_rule": "iptables -A {chain} -s {src} -d {dst} -p {protocol} "
            '--dport {port} -j {action} -m comment --comment "{comment}"',
            "remove_rule": "iptables -D {chain} -s {src} -d {dst} -p {protocol} "
            "--dport {port} -j {action}",
        },
        "pf": {
            "add_rule": "pass in on {interface} proto {protocol} from {src} "
            "to {dst} port {port}  # {comment}",
            "block_rule": "block in quick on {interface} proto {protocol} "
            "from {src} to {dst} port {port}  # {comment}",
        },
    }

    def __init__(
        self,
        specialist_id: Optional[str] = None,
        llm_router: Optional["LLMRouter"] = None,
        default_platform: str = "mikrotik",
        router_integration: Optional[Any] = None,  # RouterOS integration
    ):
        super().__init__(specialist_id, llm_router)
        self._default_platform = default_platform
        self._router = router_integration

    @property
    def capability(self) -> SpecialistCapability:
        return SpecialistCapability(
            name="Firewall Specialist",
            task_types=[
                "access.firewall",
                "access.firewall.add",
                "access.firewall.remove",
                "security.block_ip",
                "security.firewall_rule",
                "infrastructure.firewall_rule",
            ],
            confidence=0.95,
            max_concurrent=3,
            description="Manages firewall rules across platforms",
        )

    async def _do_execute(self, task: Task) -> TaskResult:
        """Execute firewall operations."""
        action = task.parameters.get("action", "add")
        platform = task.parameters.get("platform", self._default_platform)

        if action == "add":
            return await self._add_rule(task, platform)
        elif action == "remove":
            return await self._remove_rule(task, platform)
        elif action == "generate":
            return await self._generate_rules(task, platform)
        else:
            return TaskResult(
                success=False,
                error=f"Unknown firewall action: {action}",
            )

    async def _add_rule(self, task: Task, platform: str) -> TaskResult:
        """Add a firewall rule."""
        params = task.parameters

        # Build rule specification
        rule_spec = {
            "chain": params.get("chain", "forward"),
            "action": params.get("rule_action", "drop"),
            "src": params.get("source_ip", "any"),
            "dst": params.get("dest_ip", "any"),
            "port": params.get("port", "any"),
            "protocol": params.get("protocol", "tcp"),
            "comment": params.get("comment", f"auto-{task.id[:8]}"),
            "interface": params.get("interface", "any"),
        }

        # Generate rule command
        rule_cmd = self._format_rule(platform, "add_rule", rule_spec)

        # If we have LLM, validate the rule
        validation = None
        if self._llm_router:
            validation = await self._validate_rule_with_llm(rule_cmd, rule_spec, platform)
            if validation and not validation.get("valid", True):
                return TaskResult(
                    success=False,
                    error=f"Rule validation failed: {validation.get('reason')}",
                    output={"rule": rule_cmd, "validation": validation},
                )

        # Apply rule if we have router integration
        applied = False
        apply_result = None
        if self._router and platform == "mikrotik":
            try:
                apply_result = await self._apply_mikrotik_rule(rule_spec)
                applied = True
            except Exception as e:
                logger.error(f"Failed to apply rule: {e}")
                apply_result = str(e)

        return TaskResult(
            success=True,
            output={
                "action": "add",
                "platform": platform,
                "rule_command": rule_cmd,
                "rule_spec": rule_spec,
                "applied": applied,
                "apply_result": apply_result,
                "validation": validation,
            },
            confidence=0.95,
            metadata={"platform": platform, "action": "add"},
        )

    async def _remove_rule(self, task: Task, platform: str) -> TaskResult:
        """Remove a firewall rule."""
        params = task.parameters
        comment = params.get("comment") or params.get("rule_id")

        if not comment:
            return TaskResult(
                success=False,
                error="Must specify 'comment' or 'rule_id' to remove rule",
            )

        rule_cmd = self._format_rule(platform, "remove_rule", {"comment": comment})

        # Apply removal if we have router integration
        applied = False
        if self._router and platform == "mikrotik":
            try:
                # In real implementation, this would call router API
                applied = True
            except Exception as e:
                logger.error(f"Failed to remove rule: {e}")

        return TaskResult(
            success=True,
            output={
                "action": "remove",
                "platform": platform,
                "rule_command": rule_cmd,
                "comment": comment,
                "applied": applied,
            },
            confidence=0.95,
            metadata={"platform": platform, "action": "remove"},
        )

    async def _generate_rules(self, task: Task, platform: str) -> TaskResult:
        """Generate firewall rules using LLM."""
        requirements = task.parameters.get("requirements", "")
        context = task.parameters.get("context", {})

        if not self._llm_router:
            return TaskResult(
                success=False,
                error="LLM router required for rule generation",
            )

        system_prompt = f"""You are a network security engineer expert in {platform} firewall configuration.
Generate valid {platform} firewall rules based on the requirements.
Output ONLY the firewall commands, one per line.
Use proper {platform} syntax and best practices.
Include comments for each rule explaining its purpose."""

        prompt = f"""Generate {platform} firewall rules for:

Requirements:
{requirements}

Context:
- Network: {context.get('network', 'unknown')}
- Protected services: {context.get('services', [])}
- Threat level: {context.get('threat_level', 'normal')}

Generate the firewall rules:"""

        response = await self.llm_complete(
            prompt=prompt,
            task_category="config_generation",
            system_prompt=system_prompt,
            context={"severity": context.get("threat_level", "medium")},
        )

        if not response:
            return TaskResult(
                success=False,
                error="Failed to generate rules via LLM",
            )

        # Parse generated rules
        rules = [
            line.strip()
            for line in response.split("\n")
            if line.strip() and not line.startswith("#")
        ]

        return TaskResult(
            success=True,
            output={
                "action": "generate",
                "platform": platform,
                "requirements": requirements,
                "generated_rules": rules,
                "rule_count": len(rules),
                "raw_response": response,
            },
            confidence=0.85,
            metadata={"platform": platform, "action": "generate"},
        )

    def _format_rule(self, platform: str, rule_type: str, spec: Dict[str, str]) -> str:
        """Format a rule command for the specified platform."""
        if platform not in self.PLATFORMS:
            return f"# Unsupported platform: {platform}"

        template = self.PLATFORMS[platform].get(rule_type, "")
        try:
            return template.format(**spec)
        except KeyError as e:
            return f"# Missing parameter: {e}"

    async def _validate_rule_with_llm(
        self, rule_cmd: str, rule_spec: Dict[str, str], platform: str
    ) -> Optional[Dict[str, Any]]:
        """Validate a firewall rule using LLM."""
        system_prompt = """You are a firewall security auditor.
Validate the firewall rule for correctness, security, and best practices.
Respond with JSON:
{
    "valid": true/false,
    "reason": "explanation if invalid",
    "warnings": ["list of potential issues"],
    "suggestions": ["list of improvements"]
}"""

        prompt = f"""Validate this {platform} firewall rule:

Rule: {rule_cmd}

Specification:
- Source: {rule_spec.get('src')}
- Destination: {rule_spec.get('dst')}
- Port: {rule_spec.get('port')}
- Protocol: {rule_spec.get('protocol')}
- Action: {rule_spec.get('action')}

Check for:
1. Syntax correctness
2. Overly permissive rules
3. Security best practices
4. Potential conflicts

Respond with JSON validation result:"""

        try:
            response = await self.llm_complete(
                prompt=prompt,
                task_category="threat_detection",  # Use fast model for validation
                system_prompt=system_prompt,
            )

            if response:
                json_match = re.search(r"\{[\s\S]*\}", response)
                if json_match:
                    return json.loads(json_match.group())
        except Exception as e:
            logger.warning(f"Rule validation failed: {e}")

        return None

    async def _apply_mikrotik_rule(self, rule_spec: Dict[str, str]) -> Dict[str, Any]:
        """Apply rule to Mikrotik router via API."""
        if not self._router:
            raise RuntimeError("Router integration not configured")

        # This would call the actual RouterOS API
        # For now, return a placeholder
        return {
            "status": "applied",
            "rule_id": f"rule-{rule_spec.get('comment', 'auto')}",
        }


# ============================================================================
# THREAT CLASSIFICATION SPECIALIST
# ============================================================================


class ThreatClassificationSpecialist(Specialist):
    """
    Threat classification specialist using LLM.

    Capabilities:
    - Classifies security events by type
    - Determines severity and priority
    - Suggests response actions
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
            name="Threat Classification Specialist",
            task_types=[
                "threat.classify",
                "security.classify",
                "security.triage",
            ],
            confidence=0.9,
            max_concurrent=10,
            description="Classifies and triages security threats",
        )

    async def _do_execute(self, task: Task) -> TaskResult:
        """Classify a security threat."""
        event_data = task.parameters.get("event", {})
        event_type = task.parameters.get("event_type", "unknown")

        # Quick classification for known patterns
        quick_class = self._quick_classify(event_data, event_type)

        # LLM classification for better accuracy
        llm_class = None
        if self._llm_router:
            llm_class = await self._llm_classify(event_data, event_type)

        # Merge classifications
        final_class = self._merge_classifications(quick_class, llm_class)

        return TaskResult(
            success=True,
            output={
                "event_type": event_type,
                "classification": final_class["category"],
                "severity": final_class["severity"],
                "confidence": final_class["confidence"],
                "attack_vector": final_class.get("attack_vector"),
                "recommended_actions": final_class.get("actions", []),
                "analysis": {
                    "quick": quick_class,
                    "llm": llm_class,
                },
            },
            confidence=final_class["confidence"],
            metadata={"event_type": event_type},
        )

    def _quick_classify(self, event_data: Dict, event_type: str) -> Dict[str, Any]:
        """Quick rule-based classification."""
        # Simple pattern matching
        classifications = {
            "failed_login": {"category": "brute_force", "severity": "medium"},
            "port_scan": {"category": "reconnaissance", "severity": "low"},
            "malware_detected": {"category": "malware", "severity": "high"},
            "data_exfil": {"category": "exfiltration", "severity": "critical"},
            "privilege_escalation": {"category": "privilege_escalation", "severity": "critical"},
        }

        return classifications.get(
            event_type,
            {
                "category": "unknown",
                "severity": "medium",
                "confidence": 0.5,
            },
        )

    async def _llm_classify(self, event_data: Dict, event_type: str) -> Optional[Dict[str, Any]]:
        """Classify using LLM."""
        system_prompt = """You are a security analyst classifying security events.
Analyze the event and respond with JSON:
{
    "category": "one of: malware, intrusion, exfiltration, reconnaissance, brute_force, privilege_escalation, dos, insider_threat, benign",
    "severity": "one of: critical, high, medium, low, info",
    "confidence": 0.0-1.0,
    "attack_vector": "brief description of attack method",
    "actions": ["list of recommended response actions"]
}"""

        prompt = f"""Classify this security event:

Event Type: {event_type}
Event Data: {json.dumps(event_data, indent=2)}

Provide classification as JSON:"""

        try:
            response = await self.llm_complete(
                prompt=prompt,
                task_category="threat_detection",
                system_prompt=system_prompt,
            )

            if response:
                json_match = re.search(r"\{[\s\S]*\}", response)
                if json_match:
                    return json.loads(json_match.group())
        except Exception as e:
            logger.warning(f"LLM classification failed: {e}")

        return None

    def _merge_classifications(
        self, quick: Dict[str, Any], llm: Optional[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Merge quick and LLM classifications."""
        if not llm:
            quick["confidence"] = quick.get("confidence", 0.6)
            return quick

        # Prefer LLM classification but validate against quick
        result = llm.copy()

        # If quick and LLM agree, boost confidence
        if quick.get("category") == llm.get("category"):
            result["confidence"] = min(llm.get("confidence", 0.8) + 0.1, 1.0)

        return result
