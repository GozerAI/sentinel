"""
Guardian Hierarchical Agent - Security Operations Domain Executive.

The Guardian Agent owns the security operations domain.
It orchestrates managers for threat detection, access control,
incident response, and compliance monitoring.

Hierarchy:
    GuardianHierarchyAgent (Domain Executive)
        ├── ThreatManager (Coordinates threat detection)
        │   ├── IntrusionDetectionSpecialist
        │   ├── MalwareAnalysisSpecialist
        │   ├── AnomalyDetectionSpecialist
        │   └── ThreatIntelSpecialist
        ├── AccessManager (Coordinates access control)
        │   ├── FirewallSpecialist
        │   ├── ACLSpecialist
        │   ├── IPBlockSpecialist
        │   └── AuthenticationSpecialist
        ├── IncidentManager (Coordinates incident response)
        │   ├── QuarantineSpecialist
        │   ├── ForensicsSpecialist
        │   ├── ContainmentSpecialist
        │   └── NotificationSpecialist
        └── ComplianceManager (Coordinates compliance)
            ├── PolicyAuditSpecialist
            ├── VulnerabilitySpecialist
            └── ReportingSpecialist
"""

import asyncio
import logging
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field

from sentinel.core.hierarchy.base import (
    SentinelAgentBase,
    Manager,
    Specialist,
    Task,
    TaskResult,
    TaskStatus,
    TaskPriority,
    TaskSeverity,
    SpecialistCapability,
)

# Import real specialists with LLM integration
from sentinel.agents.hierarchy.specialists.security import (
    IntrusionDetectionSpecialist as RealIntrusionDetectionSpecialist,
    FirewallSpecialist as RealFirewallSpecialist,
    ThreatClassificationSpecialist,
)

logger = logging.getLogger(__name__)


# ============================================================================
# THREAT DETECTION SPECIALISTS
# ============================================================================


class ThreatSpecialist(Specialist):
    """Base class for threat detection specialists."""

    def __init__(
        self,
        threat_type: str,
        specialist_id: Optional[str] = None,
    ):
        super().__init__(specialist_id)
        self._threat_type = threat_type

    @property
    def capability(self) -> SpecialistCapability:
        return SpecialistCapability(
            name=f"{self._threat_type.title()} Threat Specialist",
            task_types=[
                f"threat.detect.{self._threat_type}",
                f"threat.analyze.{self._threat_type}",
            ],
            confidence=0.85,
            max_concurrent=5,
            description=f"Detects and analyzes {self._threat_type} threats",
        )


class IntrusionDetectionSpecialist(ThreatSpecialist):
    """Intrusion detection specialist."""

    def __init__(self, specialist_id: Optional[str] = None):
        super().__init__("intrusion", specialist_id)

    async def _do_execute(self, task: Task) -> TaskResult:
        """Detect intrusions."""
        source_ip = task.parameters.get("source_ip")
        dest_ip = task.parameters.get("dest_ip")
        traffic_data = task.parameters.get("traffic_data", {})

        # Placeholder for actual intrusion detection
        return TaskResult(
            success=True,
            output={
                "threat_type": "intrusion",
                "source_ip": source_ip,
                "dest_ip": dest_ip,
                "alerts": [],
                "risk_score": 0.0,
                "indicators": [],
            },
            confidence=0.85,
            metadata={"threat_type": "intrusion"},
        )


class MalwareAnalysisSpecialist(ThreatSpecialist):
    """Malware analysis specialist."""

    def __init__(self, specialist_id: Optional[str] = None):
        super().__init__("malware", specialist_id)

    async def _do_execute(self, task: Task) -> TaskResult:
        """Analyze for malware indicators."""
        target = task.parameters.get("target")
        hash_value = task.parameters.get("hash")

        return TaskResult(
            success=True,
            output={
                "threat_type": "malware",
                "target": target,
                "hash": hash_value,
                "detected": False,
                "signatures_matched": [],
                "c2_indicators": [],
            },
            confidence=0.9,
            metadata={"threat_type": "malware"},
        )


class AnomalyDetectionSpecialist(ThreatSpecialist):
    """Behavioral anomaly detection specialist."""

    def __init__(self, specialist_id: Optional[str] = None):
        super().__init__("anomaly", specialist_id)

    async def _do_execute(self, task: Task) -> TaskResult:
        """Detect behavioral anomalies."""
        entity = task.parameters.get("entity")
        baseline = task.parameters.get("baseline", {})
        current = task.parameters.get("current", {})

        return TaskResult(
            success=True,
            output={
                "threat_type": "anomaly",
                "entity": entity,
                "anomalies_detected": [],
                "deviation_score": 0.0,
                "baseline_comparison": {},
            },
            confidence=0.75,
            metadata={"threat_type": "anomaly"},
        )


class ThreatIntelSpecialist(ThreatSpecialist):
    """Threat intelligence specialist."""

    def __init__(self, specialist_id: Optional[str] = None):
        super().__init__("intel", specialist_id)

    async def _do_execute(self, task: Task) -> TaskResult:
        """Query threat intelligence feeds."""
        ioc = task.parameters.get("ioc")  # Indicator of Compromise
        ioc_type = task.parameters.get("ioc_type", "ip")

        return TaskResult(
            success=True,
            output={
                "threat_type": "intel",
                "ioc": ioc,
                "ioc_type": ioc_type,
                "found_in_feeds": [],
                "threat_score": 0.0,
                "related_iocs": [],
            },
            confidence=0.9,
            metadata={"threat_type": "intel"},
        )


# ============================================================================
# ACCESS CONTROL SPECIALISTS
# ============================================================================


class AccessSpecialist(Specialist):
    """Base class for access control specialists."""

    def __init__(
        self,
        access_type: str,
        specialist_id: Optional[str] = None,
    ):
        super().__init__(specialist_id)
        self._access_type = access_type

    @property
    def capability(self) -> SpecialistCapability:
        return SpecialistCapability(
            name=f"{self._access_type.title()} Access Specialist",
            task_types=[
                f"access.{self._access_type}",
                f"access.manage.{self._access_type}",
            ],
            confidence=0.95,
            max_concurrent=3,
            description=f"Manages {self._access_type} access control",
        )


class FirewallSpecialist(AccessSpecialist):
    """Firewall rule management specialist."""

    def __init__(self, specialist_id: Optional[str] = None):
        super().__init__("firewall", specialist_id)

    async def _do_execute(self, task: Task) -> TaskResult:
        """Manage firewall rules."""
        action = task.parameters.get("action", "add")
        rule = task.parameters.get("rule", {})

        return TaskResult(
            success=True,
            output={
                "access_type": "firewall",
                "action": action,
                "rule": rule,
                "rule_id": None,
                "applied": True,
            },
            confidence=0.95,
            metadata={"access_type": "firewall"},
        )


class ACLSpecialist(AccessSpecialist):
    """ACL management specialist."""

    def __init__(self, specialist_id: Optional[str] = None):
        super().__init__("acl", specialist_id)

    async def _do_execute(self, task: Task) -> TaskResult:
        """Manage ACLs."""
        acl_name = task.parameters.get("acl_name")
        entries = task.parameters.get("entries", [])

        return TaskResult(
            success=True,
            output={
                "access_type": "acl",
                "acl_name": acl_name,
                "entries_count": len(entries),
                "applied": True,
            },
            confidence=0.95,
            metadata={"access_type": "acl"},
        )


class IPBlockSpecialist(AccessSpecialist):
    """IP blocking specialist."""

    def __init__(self, specialist_id: Optional[str] = None):
        super().__init__("ip_block", specialist_id)

    async def _do_execute(self, task: Task) -> TaskResult:
        """Block/unblock IP addresses."""
        action = task.parameters.get("action", "block")
        ip = task.parameters.get("ip")
        duration_hours = task.parameters.get("duration_hours", 24)
        reason = task.parameters.get("reason", "")

        return TaskResult(
            success=True,
            output={
                "access_type": "ip_block",
                "action": action,
                "ip": ip,
                "duration_hours": duration_hours,
                "reason": reason,
                "success": True,
            },
            confidence=0.95,
            metadata={"access_type": "ip_block"},
        )


class AuthenticationSpecialist(AccessSpecialist):
    """Authentication monitoring specialist."""

    def __init__(self, specialist_id: Optional[str] = None):
        super().__init__("authentication", specialist_id)

    async def _do_execute(self, task: Task) -> TaskResult:
        """Monitor and manage authentication."""
        action = task.parameters.get("action")
        user = task.parameters.get("user")

        return TaskResult(
            success=True,
            output={
                "access_type": "authentication",
                "action": action,
                "user": user,
                "status": "completed",
            },
            confidence=0.9,
            metadata={"access_type": "authentication"},
        )


# ============================================================================
# INCIDENT RESPONSE SPECIALISTS
# ============================================================================


class IncidentSpecialist(Specialist):
    """Base class for incident response specialists."""

    def __init__(
        self,
        incident_type: str,
        specialist_id: Optional[str] = None,
    ):
        super().__init__(specialist_id)
        self._incident_type = incident_type

    @property
    def capability(self) -> SpecialistCapability:
        return SpecialistCapability(
            name=f"{self._incident_type.title()} Incident Specialist",
            task_types=[
                f"incident.{self._incident_type}",
                f"response.{self._incident_type}",
            ],
            confidence=0.9,
            max_concurrent=2,
            description=f"Handles {self._incident_type} incident response",
        )


class QuarantineSpecialist(IncidentSpecialist):
    """Device quarantine specialist."""

    def __init__(self, specialist_id: Optional[str] = None):
        super().__init__("quarantine", specialist_id)

    async def _do_execute(self, task: Task) -> TaskResult:
        """Quarantine/unquarantine devices."""
        action = task.parameters.get("action", "quarantine")
        identifier = task.parameters.get("identifier")  # MAC or IP
        quarantine_vlan = task.parameters.get("quarantine_vlan", 666)
        reason = task.parameters.get("reason", "")

        return TaskResult(
            success=True,
            output={
                "incident_type": "quarantine",
                "action": action,
                "identifier": identifier,
                "quarantine_vlan": quarantine_vlan,
                "reason": reason,
                "success": True,
            },
            confidence=0.9,
            metadata={"incident_type": "quarantine"},
        )


class ForensicsSpecialist(IncidentSpecialist):
    """Digital forensics specialist."""

    def __init__(self, specialist_id: Optional[str] = None):
        super().__init__("forensics", specialist_id)

    async def _do_execute(self, task: Task) -> TaskResult:
        """Perform forensic analysis."""
        target = task.parameters.get("target")
        analysis_type = task.parameters.get("analysis_type", "full")

        return TaskResult(
            success=True,
            output={
                "incident_type": "forensics",
                "target": target,
                "analysis_type": analysis_type,
                "artifacts_collected": [],
                "timeline": [],
                "indicators": [],
            },
            confidence=0.8,
            metadata={"incident_type": "forensics"},
        )


class ContainmentSpecialist(IncidentSpecialist):
    """Threat containment specialist."""

    def __init__(self, specialist_id: Optional[str] = None):
        super().__init__("containment", specialist_id)

    async def _do_execute(self, task: Task) -> TaskResult:
        """Contain security threats."""
        threat_id = task.parameters.get("threat_id")
        containment_strategy = task.parameters.get("strategy", "isolate")

        return TaskResult(
            success=True,
            output={
                "incident_type": "containment",
                "threat_id": threat_id,
                "strategy": containment_strategy,
                "actions_taken": [],
                "contained": True,
            },
            confidence=0.85,
            metadata={"incident_type": "containment"},
        )


class NotificationSpecialist(IncidentSpecialist):
    """Security notification specialist."""

    def __init__(self, specialist_id: Optional[str] = None):
        super().__init__("notification", specialist_id)

    async def _do_execute(self, task: Task) -> TaskResult:
        """Send security notifications."""
        alert = task.parameters.get("alert", {})
        recipients = task.parameters.get("recipients", [])
        channels = task.parameters.get("channels", ["email"])

        return TaskResult(
            success=True,
            output={
                "incident_type": "notification",
                "alert": alert,
                "recipients_count": len(recipients),
                "channels": channels,
                "sent": True,
            },
            confidence=0.95,
            metadata={"incident_type": "notification"},
        )


# ============================================================================
# COMPLIANCE SPECIALISTS
# ============================================================================


class ComplianceSpecialist(Specialist):
    """Base class for compliance specialists."""

    def __init__(
        self,
        compliance_type: str,
        specialist_id: Optional[str] = None,
    ):
        super().__init__(specialist_id)
        self._compliance_type = compliance_type

    @property
    def capability(self) -> SpecialistCapability:
        return SpecialistCapability(
            name=f"{self._compliance_type.title()} Compliance Specialist",
            task_types=[
                f"compliance.{self._compliance_type}",
                f"audit.{self._compliance_type}",
            ],
            confidence=0.9,
            max_concurrent=3,
            description=f"Handles {self._compliance_type} compliance",
        )


class PolicyAuditSpecialist(ComplianceSpecialist):
    """Policy audit specialist."""

    def __init__(self, specialist_id: Optional[str] = None):
        super().__init__("policy", specialist_id)

    async def _do_execute(self, task: Task) -> TaskResult:
        """Audit policy compliance."""
        policy_type = task.parameters.get("policy_type")
        scope = task.parameters.get("scope", "all")

        return TaskResult(
            success=True,
            output={
                "compliance_type": "policy",
                "policy_type": policy_type,
                "scope": scope,
                "compliant": True,
                "violations": [],
                "recommendations": [],
            },
            confidence=0.9,
            metadata={"compliance_type": "policy"},
        )


class VulnerabilitySpecialist(ComplianceSpecialist):
    """Vulnerability assessment specialist."""

    def __init__(self, specialist_id: Optional[str] = None):
        super().__init__("vulnerability", specialist_id)

    async def _do_execute(self, task: Task) -> TaskResult:
        """Assess vulnerabilities."""
        target = task.parameters.get("target")
        scan_type = task.parameters.get("scan_type", "quick")

        return TaskResult(
            success=True,
            output={
                "compliance_type": "vulnerability",
                "target": target,
                "scan_type": scan_type,
                "vulnerabilities": [],
                "severity_summary": {
                    "critical": 0,
                    "high": 0,
                    "medium": 0,
                    "low": 0,
                },
            },
            confidence=0.85,
            metadata={"compliance_type": "vulnerability"},
        )


class ReportingSpecialist(ComplianceSpecialist):
    """Security reporting specialist."""

    def __init__(self, specialist_id: Optional[str] = None):
        super().__init__("reporting", specialist_id)

    async def _do_execute(self, task: Task) -> TaskResult:
        """Generate security reports."""
        report_type = task.parameters.get("report_type", "summary")
        time_range = task.parameters.get("time_range", "24h")

        return TaskResult(
            success=True,
            output={
                "compliance_type": "reporting",
                "report_type": report_type,
                "time_range": time_range,
                "report": {},
                "generated_at": None,
            },
            confidence=0.95,
            metadata={"compliance_type": "reporting"},
        )


# ============================================================================
# MANAGERS
# ============================================================================


class ThreatManager(Manager):
    """Threat Manager - Coordinates threat detection specialists."""

    @property
    def name(self) -> str:
        return "Threat Manager"

    @property
    def domain(self) -> str:
        return "threat"

    @property
    def handled_task_types(self) -> List[str]:
        return [
            "threat.detect",
            "threat.analyze",
            "threat.detect.intrusion",
            "threat.detect.malware",
            "threat.detect.anomaly",
            "threat.detect.intel",
            "threat.analyze.intrusion",
            "threat.analyze.malware",
            "threat.analyze.anomaly",
            "threat.analyze.intel",
        ]

    async def _decompose_task(self, task: Task) -> List[Task]:
        """Decompose full threat analysis."""
        if task.task_type in ["threat.detect", "threat.analyze"]:
            threat_types = task.parameters.get("threat_types", ["intrusion", "anomaly", "intel"])
            subtasks = []

            for threat_type in threat_types:
                subtask = Task(
                    task_type=f"threat.detect.{threat_type}",
                    description=f"Detect {threat_type} threats",
                    parameters=task.parameters.copy(),
                    priority=task.priority,
                    severity=task.severity,
                    context=task.context,
                )
                subtasks.append(subtask)

            return subtasks

        return []


class AccessManager(Manager):
    """Access Manager - Coordinates access control specialists."""

    @property
    def name(self) -> str:
        return "Access Manager"

    @property
    def domain(self) -> str:
        return "access"

    @property
    def handled_task_types(self) -> List[str]:
        return [
            "access",
            "access.firewall",
            "access.acl",
            "access.ip_block",
            "access.authentication",
            "access.manage.firewall",
            "access.manage.acl",
            "access.manage.ip_block",
            "access.manage.authentication",
            "security.block_ip",
            "security.unblock_ip",
        ]


class IncidentManager(Manager):
    """Incident Manager - Coordinates incident response specialists."""

    @property
    def name(self) -> str:
        return "Incident Manager"

    @property
    def domain(self) -> str:
        return "incident"

    @property
    def handled_task_types(self) -> List[str]:
        return [
            "incident",
            "incident.quarantine",
            "incident.forensics",
            "incident.containment",
            "incident.notification",
            "response.quarantine",
            "response.forensics",
            "response.containment",
            "response.notification",
            "security.quarantine",
            "security.unquarantine",
        ]


class ComplianceManager(Manager):
    """Compliance Manager - Coordinates compliance specialists."""

    @property
    def name(self) -> str:
        return "Compliance Manager"

    @property
    def domain(self) -> str:
        return "compliance"

    @property
    def handled_task_types(self) -> List[str]:
        return [
            "compliance",
            "compliance.policy",
            "compliance.vulnerability",
            "compliance.reporting",
            "audit.policy",
            "audit.vulnerability",
            "audit.reporting",
            "security.scan",
        ]


# ============================================================================
# GUARDIAN HIERARCHY AGENT
# ============================================================================


class GuardianHierarchyAgent(SentinelAgentBase):
    """
    Guardian Hierarchical Agent - Security Operations Domain Executive.

    The Guardian Agent owns the entire security operations domain.
    It coordinates managers for threat detection, access control,
    incident response, and compliance monitoring.

    Capabilities:
    - Threat detection (intrusion, malware, anomaly, intel)
    - Access control (firewall, ACL, IP blocking, authentication)
    - Incident response (quarantine, forensics, containment, notification)
    - Compliance (policy audit, vulnerability assessment, reporting)

    Architecture:
    - 4 Managers coordinate different security aspects
    - 15 Specialists handle individual security tasks
    """

    def __init__(self, agent_id: Optional[str] = None):
        super().__init__(agent_id)
        self._manager_count = 0
        self._specialist_count = 0

    @property
    def name(self) -> str:
        return "Guardian Agent"

    @property
    def domain(self) -> str:
        return "security"

    @property
    def handled_task_types(self) -> List[str]:
        return [
            # High-level security tasks
            "security",
            "security.full",
            "security.block_ip",
            "security.unblock_ip",
            "security.quarantine",
            "security.unquarantine",
            "security.scan",
            # Threat tasks
            "threat",
            "threat.detect",
            "threat.analyze",
            # Access tasks
            "access",
            # Incident tasks
            "incident",
            "response",
            # Compliance tasks
            "compliance",
            "audit",
        ]

    async def _setup_managers(self) -> None:
        """Set up all managers and their specialists."""
        # Threat Manager - Use real LLM-powered specialists where available
        threat_manager = ThreatManager()
        # Real implementation with LLM-powered analysis
        threat_manager.register_specialist(RealIntrusionDetectionSpecialist())
        threat_manager.register_specialist(ThreatClassificationSpecialist())
        # Stub implementations (to be upgraded)
        threat_manager.register_specialist(MalwareAnalysisSpecialist())
        threat_manager.register_specialist(AnomalyDetectionSpecialist())
        threat_manager.register_specialist(ThreatIntelSpecialist())
        self.register_manager(threat_manager)

        # Access Manager - Use real LLM-powered firewall specialist
        access_manager = AccessManager()
        # Real implementation with LLM-powered config generation
        access_manager.register_specialist(RealFirewallSpecialist())
        # Stub implementations (to be upgraded)
        access_manager.register_specialist(ACLSpecialist())
        access_manager.register_specialist(IPBlockSpecialist())
        access_manager.register_specialist(AuthenticationSpecialist())
        self.register_manager(access_manager)

        # Incident Manager
        incident_manager = IncidentManager()
        incident_manager.register_specialist(QuarantineSpecialist())
        incident_manager.register_specialist(ForensicsSpecialist())
        incident_manager.register_specialist(ContainmentSpecialist())
        incident_manager.register_specialist(NotificationSpecialist())
        self.register_manager(incident_manager)

        # Compliance Manager
        compliance_manager = ComplianceManager()
        compliance_manager.register_specialist(PolicyAuditSpecialist())
        compliance_manager.register_specialist(VulnerabilitySpecialist())
        compliance_manager.register_specialist(ReportingSpecialist())
        self.register_manager(compliance_manager)

        self._manager_count = len(self._managers)
        self._specialist_count = sum(len(m.specialists) for m in self._managers.values())

        logger.info(
            f"GuardianHierarchyAgent initialized with {self._manager_count} managers "
            f"and {self._specialist_count} specialists (including LLM-powered)"
        )

    async def _plan_execution(self, task: Task) -> Dict[str, Any]:
        """Plan security task execution."""
        if task.task_type in ["security", "security.full"]:
            return await self._plan_full_security(task)

        return await super()._plan_execution(task)

    async def _plan_full_security(self, task: Task) -> Dict[str, Any]:
        """Plan full security assessment."""
        steps = []
        security_aspects = task.parameters.get("aspects", ["threat", "compliance"])

        task_type_map = {
            "threat": "threat.detect",
            "access": "access",
            "incident": "incident",
            "compliance": "compliance",
        }

        for aspect in security_aspects:
            manager = self._find_manager_by_domain(aspect)
            if manager:
                steps.append(
                    {
                        "manager_id": manager.id,
                        "task": Task(
                            task_type=task_type_map.get(aspect, f"{aspect}.execute"),
                            description=f"Execute {aspect} security assessment",
                            parameters=task.parameters,
                            priority=task.priority,
                            severity=task.severity,
                            context=task.context,
                        ),
                    }
                )

        return {
            "parallel": True,  # Security aspects can run in parallel
            "steps": steps,
        }

    def _find_manager_by_domain(self, domain: str) -> Optional[Manager]:
        """Find manager by domain."""
        for manager in self._managers.values():
            if manager.domain == domain:
                return manager
        return None

    @property
    def stats(self) -> Dict[str, Any]:
        """Get extended agent statistics."""
        base_stats = super().stats
        base_stats.update(
            {
                "total_specialists": self._specialist_count,
                "capabilities": {
                    "threat_types": ["intrusion", "malware", "anomaly", "intel"],
                    "access_types": ["firewall", "acl", "ip_block", "authentication"],
                    "incident_types": ["quarantine", "forensics", "containment", "notification"],
                    "compliance_types": ["policy", "vulnerability", "reporting"],
                },
            }
        )
        return base_stats
