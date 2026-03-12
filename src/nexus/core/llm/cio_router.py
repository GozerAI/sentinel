"""
CIO LLM Router - Infrastructure-optimized model routing for Sentinel.

The CIO router manages a model pool optimized for infrastructure operations:
- Real-time threat detection (fast models)
- Log analysis and forensics (balanced models)
- Complex incident investigation (quality models)
- Network configuration generation (specialized models)

Task Categories:
    threat_detection    → FAST tier (low latency critical)
    anomaly_detection   → FAST tier
    log_analysis        → BALANCED tier
    forensics           → BALANCED/QUALITY tier
    incident_response   → QUALITY tier
    config_generation   → SPECIALIZED tier
    compliance_audit    → BALANCED tier
    health_assessment   → FAST tier
"""

import logging
from typing import Dict, List, Any

from nexus.core.llm.router import (
    LLMRouter,
    ModelConfig,
    ModelTier,
    ModelProvider,
)

logger = logging.getLogger(__name__)


class CIORouter(LLMRouter):
    """
    CIO-specific LLM router for infrastructure operations.

    Optimized for:
    - Low-latency threat detection
    - Pattern recognition in logs/traffic
    - Network configuration synthesis
    - Compliance and audit analysis

    Model Pool Strategy:
    - FAST: Mistral 7B, Llama 3.1 8B for real-time decisions
    - BALANCED: Mixtral 8x7B, Llama 3.1 70B for analysis
    - QUALITY: Claude Haiku/Sonnet for complex reasoning
    - SPECIALIZED: Codestral for config generation
    """

    @property
    def domain(self) -> str:
        return "cio"

    @property
    def default_model_pool(self) -> List[ModelConfig]:
        """Default infrastructure-optimized model pool."""
        return [
            # FAST tier - Real-time operations
            ModelConfig(
                name="mistral:7b-instruct",
                provider=ModelProvider.OLLAMA,
                tier=ModelTier.FAST,
                max_tokens=2048,
                temperature=0.3,  # Lower temp for consistent decisions
                timeout=30.0,
                specializations=["threat", "anomaly", "quick"],
                max_concurrent=10,
                priority=10,
            ),
            ModelConfig(
                name="llama3.1:8b",
                provider=ModelProvider.OLLAMA,
                tier=ModelTier.FAST,
                max_tokens=2048,
                temperature=0.3,
                timeout=30.0,
                specializations=["health", "status", "quick"],
                max_concurrent=10,
                priority=5,
            ),
            # BALANCED tier - Analysis tasks
            ModelConfig(
                name="mixtral:8x7b",
                provider=ModelProvider.OLLAMA,
                tier=ModelTier.BALANCED,
                max_tokens=4096,
                temperature=0.5,
                timeout=90.0,
                specializations=["log", "forensics", "pattern"],
                max_concurrent=3,
                priority=10,
            ),
            ModelConfig(
                name="llama3.1:70b",
                provider=ModelProvider.OLLAMA,
                tier=ModelTier.BALANCED,
                max_tokens=4096,
                temperature=0.5,
                timeout=120.0,
                specializations=["analysis", "reasoning"],
                max_concurrent=2,
                priority=5,
            ),
            # QUALITY tier - Complex reasoning (cloud fallback)
            ModelConfig(
                name="claude-3-5-haiku-20241022",
                provider=ModelProvider.ANTHROPIC,
                tier=ModelTier.QUALITY,
                max_tokens=4096,
                temperature=0.7,
                timeout=120.0,
                specializations=["incident", "investigation", "decision"],
                max_concurrent=5,
                priority=10,
            ),
            ModelConfig(
                name="claude-3-5-sonnet-20241022",
                provider=ModelProvider.ANTHROPIC,
                tier=ModelTier.QUALITY,
                max_tokens=8192,
                temperature=0.7,
                timeout=180.0,
                specializations=["complex", "strategy"],
                max_concurrent=3,
                priority=5,
            ),
            # SPECIALIZED tier - Config/code generation
            ModelConfig(
                name="codestral:22b",
                provider=ModelProvider.OLLAMA,
                tier=ModelTier.SPECIALIZED,
                max_tokens=4096,
                temperature=0.2,  # Low temp for deterministic config
                timeout=90.0,
                specializations=["config", "firewall", "routing", "script"],
                max_concurrent=3,
                priority=10,
            ),
        ]

    def get_task_tier(self, task_category: str, context: Dict[str, Any]) -> ModelTier:
        """
        Map infrastructure task categories to model tiers.

        Routing Logic:
        - Real-time security → FAST (latency critical)
        - Analysis/forensics → BALANCED (quality matters)
        - Complex decisions → QUALITY (reasoning critical)
        - Config generation → SPECIALIZED (syntax critical)
        """
        category = task_category.lower()

        # Check severity override in context
        severity = context.get("severity", "").lower()
        if severity == "critical":
            # Critical tasks might need faster or better models
            if "incident" in category or "response" in category:
                return ModelTier.QUALITY  # Need best reasoning
            return ModelTier.FAST  # Need fastest response

        # FAST tier mappings - Real-time operations
        fast_tasks = [
            "threat_detection",
            "threat_classify",
            "anomaly_detection",
            "anomaly_score",
            "health_check",
            "health_assess",
            "status_check",
            "quick_scan",
            "alert_triage",
            "traffic_classify",
        ]
        if any(task in category for task in fast_tasks):
            return ModelTier.FAST

        # SPECIALIZED tier mappings - Config/code generation
        specialized_tasks = [
            "config_generation",
            "config_gen",
            "firewall_rule",
            "acl_generate",
            "routing_config",
            "script_generate",
            "automation_script",
            "vlan_config",
            "qos_config",
        ]
        if any(task in category for task in specialized_tasks):
            return ModelTier.SPECIALIZED

        # QUALITY tier mappings - Complex reasoning
        quality_tasks = [
            "incident_response",
            "incident_investigate",
            "root_cause",
            "impact_analysis",
            "security_strategy",
            "remediation_plan",
            "risk_assessment",
            "threat_hunt",
            "complex_decision",
        ]
        if any(task in category for task in quality_tasks):
            return ModelTier.QUALITY

        # BALANCED tier - Default for analysis tasks
        balanced_tasks = [
            "log_analysis",
            "forensics",
            "pattern_detection",
            "compliance_audit",
            "compliance_check",
            "vulnerability_scan",
            "traffic_analysis",
            "baseline_compare",
            "report_generate",
        ]
        if any(task in category for task in balanced_tasks):
            return ModelTier.BALANCED

        # Default to BALANCED for unknown tasks
        return ModelTier.BALANCED

    # =========================================================================
    # CIO-SPECIFIC HELPER METHODS
    # =========================================================================

    async def analyze_threat(
        self, threat_data: Dict[str, Any], context: Dict[str, Any] = None
    ) -> Dict[str, Any]:
        """
        Analyze a potential threat with appropriate model.

        Args:
            threat_data: Threat indicators and data
            context: Additional context

        Returns:
            Analysis result with classification and recommendations
        """
        system_prompt = """You are a network security analyst specializing in threat detection.
Analyze the provided threat data and respond with JSON containing:
- classification: threat type (malware, intrusion, ddos, exfiltration, reconnaissance, benign)
- confidence: 0.0-1.0
- severity: critical, high, medium, low, info
- indicators: list of suspicious indicators found
- recommendations: list of recommended actions
- reasoning: brief explanation"""

        prompt = f"""Analyze this potential security threat:

Source IP: {threat_data.get('source_ip', 'unknown')}
Destination IP: {threat_data.get('dest_ip', 'unknown')}
Protocol: {threat_data.get('protocol', 'unknown')}
Port: {threat_data.get('port', 'unknown')}
Payload Sample: {threat_data.get('payload_sample', 'N/A')[:500]}
Traffic Pattern: {threat_data.get('pattern', 'unknown')}
Timestamp: {threat_data.get('timestamp', 'unknown')}

Additional Context:
{context or {}}"""

        result = await self.complete(
            prompt=prompt,
            task_category="threat_detection",
            system_prompt=system_prompt,
            context={"severity": threat_data.get("severity", "medium")},
        )

        return {
            "analysis": result.text,
            "model_used": result.model_used,
            "latency_ms": result.latency_ms,
        }

    async def generate_firewall_config(
        self,
        rules: List[Dict[str, Any]],
        platform: str = "mikrotik",
        context: Dict[str, Any] = None,
    ) -> Dict[str, Any]:
        """
        Generate firewall configuration for specified platform.

        Args:
            rules: List of rule specifications
            platform: Target platform (mikrotik, iptables, pf, etc.)
            context: Additional context

        Returns:
            Generated configuration
        """
        system_prompt = f"""You are a network engineer expert in {platform} firewall configuration.
Generate valid {platform} firewall rules based on the specifications.
Output ONLY the configuration commands, no explanations.
Follow {platform} syntax exactly."""

        rules_text = "\n".join(
            [
                f"- {r.get('action', 'drop')} traffic from {r.get('source', 'any')} "
                f"to {r.get('dest', 'any')} port {r.get('port', 'any')} "
                f"protocol {r.get('protocol', 'tcp')} "
                f"comment: {r.get('comment', 'auto-generated')}"
                for r in rules
            ]
        )

        prompt = f"""Generate {platform} firewall rules for:

{rules_text}

Requirements:
- Rules should be in correct order (most specific first)
- Include appropriate logging
- Use standard {platform} naming conventions"""

        result = await self.complete(
            prompt=prompt,
            task_category="config_generation",
            system_prompt=system_prompt,
            context=context,
            temperature=0.1,  # Very low for deterministic output
        )

        return {
            "config": result.text,
            "platform": platform,
            "model_used": result.model_used,
        }

    async def analyze_logs(
        self, logs: str, analysis_type: str = "security", context: Dict[str, Any] = None
    ) -> Dict[str, Any]:
        """
        Analyze log data for patterns and anomalies.

        Args:
            logs: Log text to analyze
            analysis_type: Type of analysis (security, performance, error)
            context: Additional context

        Returns:
            Analysis results
        """
        system_prompts = {
            "security": """You are a security analyst examining logs for threats.
Identify suspicious patterns, potential attacks, and security concerns.
Output JSON with: findings (list), risk_level, recommendations.""",
            "performance": """You are a performance engineer analyzing system logs.
Identify bottlenecks, resource issues, and optimization opportunities.
Output JSON with: findings (list), severity, recommendations.""",
            "error": """You are a systems engineer debugging from logs.
Identify error patterns, root causes, and resolution steps.
Output JSON with: errors (list), root_cause, resolution_steps.""",
        }

        system_prompt = system_prompts.get(analysis_type, system_prompts["security"])

        # Truncate logs if too long
        max_log_length = 8000
        if len(logs) > max_log_length:
            logs = logs[:max_log_length] + "\n... [truncated]"

        prompt = f"""Analyze these {analysis_type} logs:

```
{logs}
```

Provide detailed analysis."""

        result = await self.complete(
            prompt=prompt,
            task_category="log_analysis",
            system_prompt=system_prompt,
            context=context,
        )

        return {
            "analysis": result.text,
            "analysis_type": analysis_type,
            "model_used": result.model_used,
            "latency_ms": result.latency_ms,
        }

    async def investigate_incident(
        self,
        incident: Dict[str, Any],
        evidence: List[Dict[str, Any]] = None,
        context: Dict[str, Any] = None,
    ) -> Dict[str, Any]:
        """
        Conduct deep investigation of a security incident.

        Uses QUALITY tier for complex reasoning.

        Args:
            incident: Incident details
            evidence: Supporting evidence
            context: Additional context

        Returns:
            Investigation findings and recommendations
        """
        system_prompt = """You are a senior incident response analyst conducting a thorough investigation.
Analyze all evidence and provide a comprehensive incident report.

Output JSON with:
- summary: brief incident summary
- timeline: reconstructed event timeline
- indicators_of_compromise: list of IOCs found
- attack_vector: how the attack occurred
- impact_assessment: what was affected
- attribution: threat actor assessment (if possible)
- containment_steps: immediate actions needed
- remediation_plan: long-term fixes
- lessons_learned: preventive measures"""

        evidence_text = ""
        if evidence:
            evidence_text = "\n\nEvidence:\n" + "\n".join(
                [
                    f"- [{e.get('type', 'unknown')}] {e.get('description', '')}: {e.get('data', '')[:200]}"
                    for e in evidence
                ]
            )

        prompt = f"""Investigate this security incident:

Incident ID: {incident.get('id', 'unknown')}
Type: {incident.get('type', 'unknown')}
Severity: {incident.get('severity', 'unknown')}
First Detected: {incident.get('detected_at', 'unknown')}
Affected Systems: {incident.get('affected_systems', [])}
Initial Alert: {incident.get('alert', 'N/A')}

Description:
{incident.get('description', 'No description provided')}
{evidence_text}

Provide comprehensive investigation findings."""

        result = await self.complete(
            prompt=prompt,
            task_category="incident_investigate",
            system_prompt=system_prompt,
            context={"severity": incident.get("severity", "high")},
            max_tokens=4096,  # Need longer output for detailed report
        )

        return {
            "investigation": result.text,
            "incident_id": incident.get("id"),
            "model_used": result.model_used,
            "latency_ms": result.latency_ms,
        }
