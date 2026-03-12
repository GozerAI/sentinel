"""
Compliance Specialists - Real implementations for compliance management.

These specialists perform actual compliance operations:
- Policy enforcement and auditing
- Regulatory compliance checking (PCI-DSS, HIPAA, SOC2, etc.)
- Audit trail analysis and reporting
- Configuration compliance verification
"""

import asyncio
import json
import logging
import re
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, TYPE_CHECKING
from pathlib import Path

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
# POLICY AUDIT SPECIALIST
# ============================================================================


class PolicyAuditSpecialist(Specialist):
    """
    Policy audit specialist for configuration compliance.

    Capabilities:
    - Audits system configurations against defined policies
    - Checks firewall rules compliance
    - Validates access control policies
    - Verifies encryption standards
    - Reports policy violations
    """

    def __init__(
        self,
        specialist_id: Optional[str] = None,
        llm_router: Optional["LLMRouter"] = None,
        policy_definitions: Optional[Dict[str, Any]] = None,
    ):
        super().__init__(specialist_id, llm_router)
        self._policy_definitions = policy_definitions or self._default_policies()

    def _default_policies(self) -> Dict[str, Any]:
        """Default security policies."""
        return {
            "password": {
                "min_length": 12,
                "require_uppercase": True,
                "require_lowercase": True,
                "require_numbers": True,
                "require_special": True,
                "max_age_days": 90,
            },
            "firewall": {
                "deny_by_default": True,
                "require_logging": True,
                "max_open_ports": 10,
                "banned_ports": [23, 21, 20, 137, 138, 139, 445],  # Telnet, FTP, NetBIOS, SMB
            },
            "encryption": {
                "min_tls_version": "1.2",
                "required_algorithms": ["AES-256", "RSA-2048"],
                "banned_algorithms": ["DES", "3DES", "RC4", "MD5"],
            },
            "access_control": {
                "max_session_hours": 8,
                "require_mfa": True,
                "max_failed_logins": 5,
                "lockout_minutes": 30,
            },
        }

    @property
    def capability(self) -> SpecialistCapability:
        return SpecialistCapability(
            name="Policy Audit Specialist",
            task_types=[
                "compliance.policy_audit",
                "compliance.check_policy",
                "audit.policy",
                "compliance.policy.check",
            ],
            confidence=0.9,
            max_concurrent=5,
            description="Audits configurations against security policies",
        )

    async def _do_execute(self, task: Task) -> TaskResult:
        """Execute policy audit."""
        audit_type = task.parameters.get("audit_type", "full")
        target = task.parameters.get("target")
        config_data = task.parameters.get("config_data", {})
        policies_to_check = task.parameters.get("policies", list(self._policy_definitions.keys()))

        # Quick rule-based audit
        violations = []
        compliant_items = []

        for policy_name in policies_to_check:
            if policy_name in self._policy_definitions:
                policy = self._policy_definitions[policy_name]
                result = await self._check_policy(policy_name, policy, config_data)
                violations.extend(result.get("violations", []))
                compliant_items.extend(result.get("compliant", []))

        # LLM deep analysis if available
        llm_analysis = None
        if self._llm_router and config_data:
            llm_analysis = await self._llm_policy_analysis(
                config_data, violations, policies_to_check
            )

        # Calculate compliance score
        total_checks = len(violations) + len(compliant_items)
        compliance_score = (len(compliant_items) / total_checks * 100) if total_checks > 0 else 100

        return TaskResult(
            success=True,
            output={
                "audit_type": audit_type,
                "target": target,
                "compliance_score": round(compliance_score, 2),
                "is_compliant": len(violations) == 0,
                "violations": violations,
                "compliant_items": compliant_items,
                "total_checks": total_checks,
                "policies_checked": policies_to_check,
                "llm_analysis": llm_analysis,
                "recommendations": llm_analysis.get("recommendations", []) if llm_analysis else [],
                "audit_timestamp": datetime.now().isoformat(),
            },
            confidence=0.9 if llm_analysis else 0.85,
            metadata={"audit_type": audit_type},
        )

    async def _check_policy(
        self, policy_name: str, policy: Dict[str, Any], config_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Check configuration against a specific policy."""
        violations = []
        compliant = []

        if policy_name == "firewall":
            fw_config = config_data.get("firewall", {})

            # Check deny by default
            if policy.get("deny_by_default"):
                if fw_config.get("default_action") != "deny":
                    violations.append(
                        {
                            "policy": "firewall",
                            "rule": "deny_by_default",
                            "severity": "high",
                            "description": "Firewall does not deny by default",
                            "current_value": fw_config.get("default_action"),
                            "expected_value": "deny",
                        }
                    )
                else:
                    compliant.append({"policy": "firewall", "rule": "deny_by_default"})

            # Check banned ports
            open_ports = fw_config.get("open_ports", [])
            banned = policy.get("banned_ports", [])
            for port in open_ports:
                if port in banned:
                    violations.append(
                        {
                            "policy": "firewall",
                            "rule": "banned_ports",
                            "severity": "critical",
                            "description": f"Banned port {port} is open",
                            "port": port,
                        }
                    )

            # Check max open ports
            if len(open_ports) > policy.get("max_open_ports", 10):
                violations.append(
                    {
                        "policy": "firewall",
                        "rule": "max_open_ports",
                        "severity": "medium",
                        "description": f"Too many open ports ({len(open_ports)})",
                        "current_value": len(open_ports),
                        "expected_value": f"<= {policy.get('max_open_ports')}",
                    }
                )

        elif policy_name == "encryption":
            enc_config = config_data.get("encryption", {})

            # Check TLS version
            tls_version = enc_config.get("tls_version", "1.0")
            min_tls = policy.get("min_tls_version", "1.2")
            if float(tls_version) < float(min_tls):
                violations.append(
                    {
                        "policy": "encryption",
                        "rule": "min_tls_version",
                        "severity": "critical",
                        "description": f"TLS version {tls_version} below minimum {min_tls}",
                        "current_value": tls_version,
                        "expected_value": f">= {min_tls}",
                    }
                )
            else:
                compliant.append({"policy": "encryption", "rule": "min_tls_version"})

            # Check for banned algorithms
            algorithms = enc_config.get("algorithms", [])
            banned = policy.get("banned_algorithms", [])
            for algo in algorithms:
                if algo.upper() in [b.upper() for b in banned]:
                    violations.append(
                        {
                            "policy": "encryption",
                            "rule": "banned_algorithms",
                            "severity": "critical",
                            "description": f"Banned algorithm {algo} in use",
                            "algorithm": algo,
                        }
                    )

        elif policy_name == "access_control":
            ac_config = config_data.get("access_control", {})

            # Check MFA requirement
            if policy.get("require_mfa") and not ac_config.get("mfa_enabled"):
                violations.append(
                    {
                        "policy": "access_control",
                        "rule": "require_mfa",
                        "severity": "high",
                        "description": "MFA not enabled",
                    }
                )
            elif policy.get("require_mfa"):
                compliant.append({"policy": "access_control", "rule": "require_mfa"})

            # Check lockout settings
            max_failed = policy.get("max_failed_logins", 5)
            if ac_config.get("max_failed_attempts", 999) > max_failed:
                violations.append(
                    {
                        "policy": "access_control",
                        "rule": "max_failed_logins",
                        "severity": "medium",
                        "description": f"Failed login threshold too high",
                        "current_value": ac_config.get("max_failed_attempts"),
                        "expected_value": f"<= {max_failed}",
                    }
                )

        elif policy_name == "password":
            pw_config = config_data.get("password_policy", {})

            # Check minimum length
            min_len = policy.get("min_length", 12)
            if pw_config.get("min_length", 0) < min_len:
                violations.append(
                    {
                        "policy": "password",
                        "rule": "min_length",
                        "severity": "high",
                        "description": f"Password minimum length too short",
                        "current_value": pw_config.get("min_length"),
                        "expected_value": f">= {min_len}",
                    }
                )
            else:
                compliant.append({"policy": "password", "rule": "min_length"})

        return {"violations": violations, "compliant": compliant}

    async def _llm_policy_analysis(
        self, config_data: Dict[str, Any], violations: List[Dict], policies_checked: List[str]
    ) -> Optional[Dict[str, Any]]:
        """Deep policy analysis using LLM."""
        system_prompt = """You are a security compliance expert analyzing configurations.
Review the configuration and violations, then provide additional insights.
Respond with JSON:
{
    "risk_assessment": "overall risk level and context",
    "hidden_issues": [{"issue": "...", "severity": "...", "explanation": "..."}],
    "recommendations": [
        {"priority": "high/medium/low", "action": "...", "rationale": "..."}
    ],
    "compliance_gaps": ["gaps not caught by automated checks"],
    "remediation_steps": [{"violation": "...", "steps": [...]}]
}"""

        config_summary = json.dumps(config_data, indent=2)[:3000]
        violations_summary = json.dumps(violations[:10], indent=2)

        prompt = f"""Analyze this security configuration for compliance issues:

Configuration:
```json
{config_summary}
```

Automated Violations Found:
```json
{violations_summary}
```

Policies Checked: {', '.join(policies_checked)}

Provide deep compliance analysis:"""

        try:
            response = await self.llm_complete(
                prompt=prompt,
                task_category="security_analysis",
                system_prompt=system_prompt,
            )

            if response:
                json_match = re.search(r"\{[\s\S]*\}", response)
                if json_match:
                    return json.loads(json_match.group())
        except Exception as e:
            logger.warning(f"LLM policy analysis failed: {e}")

        return None


# ============================================================================
# REGULATORY COMPLIANCE SPECIALIST
# ============================================================================


class RegulatoryComplianceSpecialist(Specialist):
    """
    Regulatory compliance specialist for framework compliance.

    Capabilities:
    - PCI-DSS compliance checking
    - HIPAA compliance verification
    - SOC2 control assessment
    - GDPR data handling compliance
    - NIST framework alignment
    """

    # Compliance framework requirements
    FRAMEWORKS = {
        "pci-dss": {
            "name": "PCI-DSS",
            "version": "4.0",
            "requirements": {
                "1.1": "Install and maintain network security controls",
                "1.2": "Restrict connections between untrusted networks",
                "2.1": "Change vendor defaults before installation",
                "3.1": "Keep cardholder data storage to minimum",
                "4.1": "Protect cardholder data with strong cryptography",
                "5.1": "Deploy anti-malware mechanisms",
                "6.1": "Develop secure systems and software",
                "7.1": "Restrict access to system components",
                "8.1": "Identify users and authenticate access",
                "9.1": "Restrict physical access to cardholder data",
                "10.1": "Log and monitor all access",
                "11.1": "Test security of systems regularly",
                "12.1": "Support information security with policies",
            },
        },
        "hipaa": {
            "name": "HIPAA",
            "version": "2013",
            "requirements": {
                "164.308": "Administrative safeguards",
                "164.310": "Physical safeguards",
                "164.312": "Technical safeguards",
                "164.314": "Organizational requirements",
                "164.316": "Policies and documentation",
            },
        },
        "soc2": {
            "name": "SOC2",
            "version": "Type II",
            "requirements": {
                "CC1": "Control environment",
                "CC2": "Communication and information",
                "CC3": "Risk assessment",
                "CC4": "Monitoring activities",
                "CC5": "Control activities",
                "CC6": "Logical and physical access",
                "CC7": "System operations",
                "CC8": "Change management",
                "CC9": "Risk mitigation",
            },
        },
        "nist": {
            "name": "NIST CSF",
            "version": "2.0",
            "requirements": {
                "ID": "Identify - Asset management, risk assessment",
                "PR": "Protect - Access control, awareness training",
                "DE": "Detect - Anomalies, continuous monitoring",
                "RS": "Respond - Response planning, communications",
                "RC": "Recover - Recovery planning, improvements",
            },
        },
    }

    def __init__(
        self,
        specialist_id: Optional[str] = None,
        llm_router: Optional["LLMRouter"] = None,
    ):
        super().__init__(specialist_id, llm_router)

    @property
    def capability(self) -> SpecialistCapability:
        return SpecialistCapability(
            name="Regulatory Compliance Specialist",
            task_types=[
                "compliance.regulatory",
                "compliance.framework",
                "compliance.pci",
                "compliance.hipaa",
                "compliance.soc2",
                "compliance.nist",
                "audit.regulatory",
            ],
            confidence=0.85,
            max_concurrent=3,
            description="Checks compliance against regulatory frameworks",
        )

    async def _do_execute(self, task: Task) -> TaskResult:
        """Execute regulatory compliance check."""
        framework = task.parameters.get("framework", "pci-dss").lower()
        evidence = task.parameters.get("evidence", {})
        controls = task.parameters.get("controls", {})
        scope = task.parameters.get("scope", "full")

        if framework not in self.FRAMEWORKS:
            return TaskResult(
                success=False,
                error=f"Unknown framework: {framework}. Supported: {list(self.FRAMEWORKS.keys())}",
            )

        framework_info = self.FRAMEWORKS[framework]

        # Quick automated compliance check
        quick_results = await self._quick_compliance_check(
            framework, framework_info, evidence, controls
        )

        # LLM deep compliance analysis
        llm_analysis = None
        if self._llm_router:
            llm_analysis = await self._llm_compliance_analysis(
                framework, framework_info, evidence, controls, quick_results
            )

        # Calculate overall compliance
        total_requirements = len(framework_info["requirements"])
        met_requirements = len(quick_results.get("met", []))
        compliance_percentage = (
            (met_requirements / total_requirements * 100) if total_requirements > 0 else 0
        )

        return TaskResult(
            success=True,
            output={
                "framework": framework_info["name"],
                "framework_version": framework_info["version"],
                "scope": scope,
                "compliance_percentage": round(compliance_percentage, 2),
                "is_compliant": compliance_percentage >= 100,
                "requirements_met": quick_results.get("met", []),
                "requirements_not_met": quick_results.get("not_met", []),
                "requirements_partial": quick_results.get("partial", []),
                "gaps": quick_results.get("gaps", []),
                "llm_analysis": llm_analysis,
                "remediation_plan": (
                    llm_analysis.get("remediation_plan", []) if llm_analysis else []
                ),
                "audit_timestamp": datetime.now().isoformat(),
            },
            confidence=0.85 if llm_analysis else 0.75,
            metadata={"framework": framework},
        )

    async def _quick_compliance_check(
        self,
        framework: str,
        framework_info: Dict[str, Any],
        evidence: Dict[str, Any],
        controls: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Quick automated compliance check."""
        met = []
        not_met = []
        partial = []
        gaps = []

        for req_id, req_desc in framework_info["requirements"].items():
            # Check if control exists for this requirement
            control = controls.get(req_id, {})
            evidence_for_req = evidence.get(req_id, {})

            if control.get("implemented") and evidence_for_req.get("verified"):
                met.append(
                    {
                        "requirement_id": req_id,
                        "description": req_desc,
                        "status": "met",
                        "evidence": evidence_for_req.get("summary", "Evidence provided"),
                    }
                )
            elif control.get("implemented"):
                partial.append(
                    {
                        "requirement_id": req_id,
                        "description": req_desc,
                        "status": "partial",
                        "issue": "Implemented but evidence not verified",
                    }
                )
            else:
                not_met.append(
                    {
                        "requirement_id": req_id,
                        "description": req_desc,
                        "status": "not_met",
                    }
                )
                gaps.append(
                    {
                        "requirement_id": req_id,
                        "description": req_desc,
                        "gap_type": "missing_control",
                    }
                )

        return {
            "met": met,
            "not_met": not_met,
            "partial": partial,
            "gaps": gaps,
        }

    async def _llm_compliance_analysis(
        self,
        framework: str,
        framework_info: Dict[str, Any],
        evidence: Dict[str, Any],
        controls: Dict[str, Any],
        quick_results: Dict[str, Any],
    ) -> Optional[Dict[str, Any]]:
        """Deep compliance analysis using LLM."""
        system_prompt = f"""You are a {framework_info['name']} compliance expert.
Analyze the compliance evidence and controls, then provide detailed assessment.
Respond with JSON:
{{
    "overall_assessment": "summary of compliance posture",
    "risk_level": "critical/high/medium/low",
    "key_findings": [
        {{"finding": "...", "severity": "...", "requirement": "..."}}
    ],
    "remediation_plan": [
        {{"priority": 1-5, "requirement": "...", "actions": [...], "timeline": "..."}}
    ],
    "audit_readiness": "assessment of audit readiness",
    "recommendations": ["strategic recommendations"]
}}"""

        evidence_summary = json.dumps(evidence, indent=2)[:2000]
        gaps_summary = json.dumps(quick_results.get("gaps", [])[:5], indent=2)

        prompt = f"""Analyze {framework_info['name']} {framework_info['version']} compliance:

Framework Requirements: {len(framework_info['requirements'])} total
Met: {len(quick_results['met'])}
Not Met: {len(quick_results['not_met'])}
Partial: {len(quick_results['partial'])}

Evidence Summary:
```json
{evidence_summary}
```

Key Gaps:
```json
{gaps_summary}
```

Provide detailed compliance analysis and remediation plan:"""

        try:
            response = await self.llm_complete(
                prompt=prompt,
                task_category="compliance_analysis",
                system_prompt=system_prompt,
            )

            if response:
                json_match = re.search(r"\{[\s\S]*\}", response)
                if json_match:
                    return json.loads(json_match.group())
        except Exception as e:
            logger.warning(f"LLM compliance analysis failed: {e}")

        return None


# ============================================================================
# AUDIT LOG SPECIALIST
# ============================================================================


class AuditLogSpecialist(Specialist):
    """
    Audit log specialist for compliance auditing.

    Capabilities:
    - Analyzes audit logs for compliance events
    - Tracks access patterns and anomalies
    - Generates audit reports
    - Identifies compliance violations from logs
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
            name="Audit Log Specialist",
            task_types=[
                "compliance.audit_logs",
                "audit.logs",
                "audit.trail",
                "compliance.log_review",
            ],
            confidence=0.9,
            max_concurrent=5,
            description="Analyzes audit logs for compliance",
        )

    async def _do_execute(self, task: Task) -> TaskResult:
        """Analyze audit logs."""
        logs = task.parameters.get("logs", "")
        log_entries = task.parameters.get("log_entries", [])
        time_range = task.parameters.get("time_range", "24h")
        compliance_focus = task.parameters.get("focus", ["access", "changes", "failures"])

        if not logs and not log_entries:
            return TaskResult(
                success=False,
                error="Audit logs required for analysis",
            )

        # Parse logs if string
        if logs and not log_entries:
            log_entries = self._parse_audit_logs(logs)

        # Quick pattern analysis
        quick_analysis = self._quick_audit_analysis(log_entries, compliance_focus)

        # LLM deep analysis
        llm_analysis = None
        if self._llm_router:
            llm_analysis = await self._llm_audit_analysis(
                log_entries[:100], compliance_focus, quick_analysis
            )

        return TaskResult(
            success=True,
            output={
                "time_range": time_range,
                "total_events": len(log_entries),
                "events_analyzed": min(len(log_entries), 1000),
                "summary": quick_analysis.get("summary", {}),
                "access_events": quick_analysis.get("access_events", []),
                "change_events": quick_analysis.get("change_events", []),
                "failure_events": quick_analysis.get("failure_events", []),
                "anomalies": quick_analysis.get("anomalies", []),
                "compliance_issues": quick_analysis.get("compliance_issues", []),
                "llm_analysis": llm_analysis,
                "risk_indicators": llm_analysis.get("risk_indicators", []) if llm_analysis else [],
                "audit_timestamp": datetime.now().isoformat(),
            },
            confidence=0.9 if llm_analysis else 0.8,
            metadata={"time_range": time_range},
        )

    def _parse_audit_logs(self, logs: str) -> List[Dict[str, Any]]:
        """Parse raw audit log text into structured entries."""
        entries = []
        lines = logs.strip().split("\n")

        for line in lines:
            if not line.strip():
                continue

            entry = {"raw": line}

            # Try to extract timestamp
            ts_match = re.search(r"(\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2})", line)
            if ts_match:
                entry["timestamp"] = ts_match.group(1)

            # Try to extract user
            user_match = re.search(r'user[=:]\s*["\']?(\w+)["\']?', line, re.IGNORECASE)
            if user_match:
                entry["user"] = user_match.group(1)

            # Try to extract action
            action_patterns = [
                (r"(login|logout|authentication)", "access"),
                (r"(create|update|delete|modify|change)", "change"),
                (r"(fail|error|denied|rejected)", "failure"),
                (r"(read|view|access)", "access"),
            ]
            for pattern, action_type in action_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    entry["action_type"] = action_type
                    break

            # Try to extract IP
            ip_match = re.search(r"(\d+\.\d+\.\d+\.\d+)", line)
            if ip_match:
                entry["ip_address"] = ip_match.group(1)

            entries.append(entry)

        return entries

    def _quick_audit_analysis(
        self, entries: List[Dict[str, Any]], focus: List[str]
    ) -> Dict[str, Any]:
        """Quick pattern-based audit analysis."""
        access_events = []
        change_events = []
        failure_events = []
        anomalies = []
        compliance_issues = []

        # Track patterns for anomaly detection
        user_activity = {}
        ip_activity = {}
        hourly_activity = {}

        for entry in entries[:1000]:  # Limit for quick analysis
            action_type = entry.get("action_type", "unknown")
            user = entry.get("user", "unknown")
            ip = entry.get("ip_address")

            # Categorize events
            if action_type == "access" and "access" in focus:
                access_events.append(entry)
            elif action_type == "change" and "changes" in focus:
                change_events.append(entry)
            elif action_type == "failure" and "failures" in focus:
                failure_events.append(entry)

            # Track activity patterns
            user_activity[user] = user_activity.get(user, 0) + 1
            if ip:
                ip_activity[ip] = ip_activity.get(ip, 0) + 1

        # Detect anomalies
        avg_user_activity = sum(user_activity.values()) / len(user_activity) if user_activity else 0
        for user, count in user_activity.items():
            if count > avg_user_activity * 5:  # 5x average is anomalous
                anomalies.append(
                    {
                        "type": "high_activity_user",
                        "user": user,
                        "event_count": count,
                        "average": avg_user_activity,
                    }
                )

        # Check for compliance issues
        if len(failure_events) > len(entries) * 0.1:  # >10% failures
            compliance_issues.append(
                {
                    "issue": "high_failure_rate",
                    "description": f"Failure rate above 10% ({len(failure_events)}/{len(entries)})",
                    "severity": "medium",
                }
            )

        # Summary
        summary = {
            "total_events": len(entries),
            "access_count": len(access_events),
            "change_count": len(change_events),
            "failure_count": len(failure_events),
            "unique_users": len(user_activity),
            "unique_ips": len(ip_activity),
            "anomaly_count": len(anomalies),
        }

        return {
            "summary": summary,
            "access_events": access_events[:50],
            "change_events": change_events[:50],
            "failure_events": failure_events[:50],
            "anomalies": anomalies,
            "compliance_issues": compliance_issues,
        }

    async def _llm_audit_analysis(
        self, entries: List[Dict[str, Any]], focus: List[str], quick_results: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        """Deep audit analysis using LLM."""
        system_prompt = """You are a security auditor analyzing audit logs.
Identify compliance issues, security concerns, and anomalies.
Respond with JSON:
{
    "executive_summary": "brief summary for leadership",
    "risk_indicators": [
        {"indicator": "...", "severity": "critical/high/medium/low", "evidence": "..."}
    ],
    "compliance_concerns": [
        {"concern": "...", "regulation": "...", "recommended_action": "..."}
    ],
    "behavioral_anomalies": [
        {"anomaly": "...", "users_affected": [...], "investigation_needed": true/false}
    ],
    "recommendations": ["prioritized list of actions"],
    "audit_opinion": "qualified/unqualified opinion on controls"
}"""

        entries_sample = json.dumps(entries[:20], indent=2)
        summary = json.dumps(quick_results.get("summary", {}), indent=2)

        prompt = f"""Analyze these audit log entries for compliance and security:

Focus Areas: {', '.join(focus)}

Summary Statistics:
{summary}

Sample Log Entries:
```json
{entries_sample}
```

Anomalies Detected: {len(quick_results.get('anomalies', []))}
Compliance Issues: {len(quick_results.get('compliance_issues', []))}

Provide detailed audit analysis:"""

        try:
            response = await self.llm_complete(
                prompt=prompt,
                task_category="audit_analysis",
                system_prompt=system_prompt,
            )

            if response:
                json_match = re.search(r"\{[\s\S]*\}", response)
                if json_match:
                    return json.loads(json_match.group())
        except Exception as e:
            logger.warning(f"LLM audit analysis failed: {e}")

        return None


# ============================================================================
# COMPLIANCE REPORT SPECIALIST
# ============================================================================


class ComplianceReportSpecialist(Specialist):
    """
    Compliance report specialist for generating compliance documentation.

    Capabilities:
    - Generates compliance reports for various frameworks
    - Creates executive summaries
    - Produces audit-ready documentation
    - Tracks compliance trends over time
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
            name="Compliance Report Specialist",
            task_types=[
                "compliance.report",
                "compliance.generate_report",
                "audit.report",
                "compliance.documentation",
            ],
            confidence=0.9,
            max_concurrent=3,
            description="Generates compliance reports and documentation",
        )

    async def _do_execute(self, task: Task) -> TaskResult:
        """Generate compliance report."""
        report_type = task.parameters.get("report_type", "summary")
        framework = task.parameters.get("framework")
        compliance_data = task.parameters.get("compliance_data", {})
        period = task.parameters.get("period", "monthly")
        include_recommendations = task.parameters.get("include_recommendations", True)

        # Generate report sections
        sections = await self._generate_report_sections(
            report_type, framework, compliance_data, period
        )

        # LLM enhancement if available
        if self._llm_router and include_recommendations:
            enhanced_sections = await self._llm_enhance_report(sections, compliance_data, framework)
            sections.update(enhanced_sections)

        report = {
            "report_type": report_type,
            "framework": framework,
            "period": period,
            "generated_at": datetime.now().isoformat(),
            "sections": sections,
            "summary": sections.get("executive_summary", ""),
            "compliance_score": compliance_data.get("compliance_score", 0),
            "recommendations": sections.get("recommendations", []),
            "action_items": sections.get("action_items", []),
        }

        return TaskResult(
            success=True,
            output=report,
            confidence=0.9,
            metadata={"report_type": report_type, "framework": framework},
        )

    async def _generate_report_sections(
        self, report_type: str, framework: Optional[str], data: Dict[str, Any], period: str
    ) -> Dict[str, Any]:
        """Generate standard report sections."""
        sections = {}

        # Executive summary
        score = data.get("compliance_score", 0)
        violations = data.get("violations", [])
        sections["executive_summary"] = {
            "compliance_score": score,
            "status": "Compliant" if score >= 100 else "Non-Compliant",
            "critical_issues": len([v for v in violations if v.get("severity") == "critical"]),
            "high_issues": len([v for v in violations if v.get("severity") == "high"]),
            "period": period,
            "framework": framework or "General",
        }

        # Detailed findings
        sections["findings"] = {
            "total_checks": data.get("total_checks", 0),
            "passed": data.get("passed", 0),
            "failed": data.get("failed", 0),
            "violations": violations[:20],  # Top 20 violations
        }

        # Trend data if available
        if "historical" in data:
            sections["trends"] = {
                "score_trend": data["historical"].get("scores", []),
                "violation_trend": data["historical"].get("violations", []),
                "improvement_areas": data["historical"].get("improvements", []),
            }

        # Remediation status
        if "remediation" in data:
            sections["remediation"] = {
                "in_progress": data["remediation"].get("in_progress", []),
                "completed": data["remediation"].get("completed", []),
                "planned": data["remediation"].get("planned", []),
            }

        return sections

    async def _llm_enhance_report(
        self, sections: Dict[str, Any], data: Dict[str, Any], framework: Optional[str]
    ) -> Dict[str, Any]:
        """Enhance report with LLM-generated content."""
        system_prompt = """You are a compliance officer writing a report.
Create professional, audit-ready content based on the data provided.
Respond with JSON:
{
    "narrative_summary": "professional executive summary paragraph",
    "key_risks": ["top risks requiring attention"],
    "recommendations": [
        {"priority": "high/medium/low", "recommendation": "...", "timeline": "..."}
    ],
    "action_items": [
        {"item": "...", "owner": "suggested owner", "deadline": "..."}
    ],
    "next_steps": ["immediate next steps"]
}"""

        sections_summary = json.dumps(sections, indent=2)[:3000]

        prompt = f"""Generate enhanced compliance report content:

Framework: {framework or 'General Security'}
Current Compliance Score: {data.get('compliance_score', 0)}%

Report Sections:
```json
{sections_summary}
```

Create professional report enhancements:"""

        try:
            response = await self.llm_complete(
                prompt=prompt,
                task_category="report_generation",
                system_prompt=system_prompt,
            )

            if response:
                json_match = re.search(r"\{[\s\S]*\}", response)
                if json_match:
                    return json.loads(json_match.group())
        except Exception as e:
            logger.warning(f"LLM report enhancement failed: {e}")

        return {}


# ============================================================================
# CONFIGURATION DRIFT SPECIALIST
# ============================================================================


class ConfigurationDriftSpecialist(Specialist):
    """
    Configuration drift specialist for detecting unauthorized changes.

    Capabilities:
    - Compares current configs against baselines
    - Detects unauthorized modifications
    - Tracks configuration versions
    - Reports drift from compliance standards
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
            name="Configuration Drift Specialist",
            task_types=[
                "compliance.drift",
                "compliance.config_drift",
                "audit.drift",
                "compliance.baseline",
            ],
            confidence=0.9,
            max_concurrent=5,
            description="Detects configuration drift from baselines",
        )

    async def _do_execute(self, task: Task) -> TaskResult:
        """Detect configuration drift."""
        baseline = task.parameters.get("baseline", {})
        current = task.parameters.get("current", {})
        config_type = task.parameters.get("config_type", "general")
        tolerance = task.parameters.get("tolerance", "strict")

        if not baseline or not current:
            return TaskResult(
                success=False,
                error="Both baseline and current configurations required",
            )

        # Detect drift
        drift_results = self._detect_drift(baseline, current, tolerance)

        # LLM analysis if available
        llm_analysis = None
        if self._llm_router and drift_results["total_drifts"] > 0:
            llm_analysis = await self._llm_drift_analysis(
                baseline, current, drift_results, config_type
            )

        return TaskResult(
            success=True,
            output={
                "config_type": config_type,
                "tolerance": tolerance,
                "has_drift": drift_results["total_drifts"] > 0,
                "total_drifts": drift_results["total_drifts"],
                "additions": drift_results["additions"],
                "removals": drift_results["removals"],
                "modifications": drift_results["modifications"],
                "compliance_impact": drift_results["compliance_impact"],
                "llm_analysis": llm_analysis,
                "risk_assessment": llm_analysis.get("risk_assessment") if llm_analysis else None,
                "remediation": llm_analysis.get("remediation") if llm_analysis else [],
                "check_timestamp": datetime.now().isoformat(),
            },
            confidence=0.9,
            metadata={"config_type": config_type},
        )

    def _detect_drift(
        self, baseline: Dict[str, Any], current: Dict[str, Any], tolerance: str
    ) -> Dict[str, Any]:
        """Detect configuration drift between baseline and current."""
        additions = []
        removals = []
        modifications = []
        compliance_impact = []

        # Flatten configs for comparison
        baseline_flat = self._flatten_dict(baseline)
        current_flat = self._flatten_dict(current)

        baseline_keys = set(baseline_flat.keys())
        current_keys = set(current_flat.keys())

        # Find additions
        for key in current_keys - baseline_keys:
            additions.append(
                {
                    "key": key,
                    "value": current_flat[key],
                    "severity": self._assess_severity(key, "addition"),
                }
            )

        # Find removals
        for key in baseline_keys - current_keys:
            removals.append(
                {
                    "key": key,
                    "value": baseline_flat[key],
                    "severity": self._assess_severity(key, "removal"),
                }
            )

        # Find modifications
        for key in baseline_keys & current_keys:
            if baseline_flat[key] != current_flat[key]:
                severity = self._assess_severity(key, "modification")
                modifications.append(
                    {
                        "key": key,
                        "baseline_value": baseline_flat[key],
                        "current_value": current_flat[key],
                        "severity": severity,
                    }
                )

                # Check compliance impact
                if severity in ["critical", "high"]:
                    compliance_impact.append(
                        {
                            "key": key,
                            "impact": f"Configuration change may affect compliance",
                            "severity": severity,
                        }
                    )

        return {
            "total_drifts": len(additions) + len(removals) + len(modifications),
            "additions": additions,
            "removals": removals,
            "modifications": modifications,
            "compliance_impact": compliance_impact,
        }

    def _flatten_dict(
        self, d: Dict[str, Any], parent_key: str = "", sep: str = "."
    ) -> Dict[str, Any]:
        """Flatten nested dictionary."""
        items = []
        for k, v in d.items():
            new_key = f"{parent_key}{sep}{k}" if parent_key else k
            if isinstance(v, dict):
                items.extend(self._flatten_dict(v, new_key, sep).items())
            else:
                items.append((new_key, v))
        return dict(items)

    def _assess_severity(self, key: str, change_type: str) -> str:
        """Assess severity of configuration change."""
        critical_patterns = [
            "password",
            "secret",
            "key",
            "credential",
            "auth",
            "encryption",
            "firewall",
            "ssl",
            "tls",
        ]
        high_patterns = [
            "access",
            "permission",
            "role",
            "admin",
            "port",
            "network",
            "security",
        ]

        key_lower = key.lower()

        for pattern in critical_patterns:
            if pattern in key_lower:
                return "critical"

        for pattern in high_patterns:
            if pattern in key_lower:
                return "high"

        if change_type == "removal":
            return "medium"

        return "low"

    async def _llm_drift_analysis(
        self,
        baseline: Dict[str, Any],
        current: Dict[str, Any],
        drift_results: Dict[str, Any],
        config_type: str,
    ) -> Optional[Dict[str, Any]]:
        """Analyze configuration drift using LLM."""
        system_prompt = """You are a configuration management expert.
Analyze configuration drift and its security/compliance implications.
Respond with JSON:
{
    "risk_assessment": "overall risk from drift",
    "authorized_changes": ["changes that appear intentional"],
    "suspicious_changes": [
        {"change": "...", "concern": "...", "investigation_needed": true/false}
    ],
    "compliance_implications": ["how drift affects compliance"],
    "remediation": [
        {"priority": "high/medium/low", "action": "...", "rationale": "..."}
    ],
    "recommendations": ["general recommendations"]
}"""

        drift_summary = {
            "additions": len(drift_results["additions"]),
            "removals": len(drift_results["removals"]),
            "modifications": len(drift_results["modifications"]),
            "critical_changes": [
                d for d in drift_results["modifications"] if d.get("severity") == "critical"
            ][:5],
        }

        prompt = f"""Analyze this configuration drift:

Config Type: {config_type}
Total Drifts: {drift_results['total_drifts']}

Drift Summary:
```json
{json.dumps(drift_summary, indent=2)}
```

Compliance Impact Items: {len(drift_results['compliance_impact'])}

Provide security and compliance analysis:"""

        try:
            response = await self.llm_complete(
                prompt=prompt,
                task_category="security_analysis",
                system_prompt=system_prompt,
            )

            if response:
                json_match = re.search(r"\{[\s\S]*\}", response)
                if json_match:
                    return json.loads(json_match.group())
        except Exception as e:
            logger.warning(f"LLM drift analysis failed: {e}")

        return None
