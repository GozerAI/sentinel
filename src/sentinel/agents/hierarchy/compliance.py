"""
Compliance Hierarchical Agent - Compliance Operations Domain Executive.

The Compliance Agent owns the compliance operations domain.
It orchestrates managers for policy enforcement, regulatory compliance,
audit trail management, and compliance reporting.

Hierarchy:
    ComplianceHierarchyAgent (Domain Executive)
        ├── PolicyManager (Coordinates policy enforcement)
        │   ├── PolicyAuditSpecialist
        │   ├── PolicyEnforcementSpecialist
        │   └── ConfigurationDriftSpecialist
        ├── RegulatoryManager (Coordinates regulatory compliance)
        │   ├── RegulatoryComplianceSpecialist
        │   ├── FrameworkMappingSpecialist
        │   └── CertificationSpecialist
        └── AuditManager (Coordinates audit operations)
            ├── AuditLogSpecialist
            ├── ComplianceReportSpecialist
            └── EvidenceCollectionSpecialist
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

# Import real LLM-powered specialists
from sentinel.agents.hierarchy.specialists.compliance import (
    PolicyAuditSpecialist as RealPolicyAuditSpecialist,
    RegulatoryComplianceSpecialist as RealRegulatoryComplianceSpecialist,
    AuditLogSpecialist as RealAuditLogSpecialist,
    ComplianceReportSpecialist as RealComplianceReportSpecialist,
    ConfigurationDriftSpecialist as RealConfigurationDriftSpecialist,
)

logger = logging.getLogger(__name__)


# ============================================================================
# STUB SPECIALISTS (To be upgraded to real implementations)
# ============================================================================


class PolicyEnforcementSpecialist(Specialist):
    """Policy enforcement specialist - enforces security policies."""

    def __init__(self, specialist_id: Optional[str] = None):
        super().__init__(specialist_id)

    @property
    def capability(self) -> SpecialistCapability:
        return SpecialistCapability(
            name="Policy Enforcement Specialist",
            task_types=[
                "compliance.enforce_policy",
                "policy.enforce",
                "policy.apply",
            ],
            confidence=0.85,
            max_concurrent=3,
            description="Enforces security policies on systems",
        )

    async def _do_execute(self, task: Task) -> TaskResult:
        """Enforce policy."""
        policy_id = task.parameters.get("policy_id")
        target = task.parameters.get("target")
        action = task.parameters.get("action", "apply")

        return TaskResult(
            success=True,
            output={
                "policy_id": policy_id,
                "target": target,
                "action": action,
                "status": "enforced",
                "changes_applied": [],
            },
            confidence=0.85,
            metadata={"policy_id": policy_id},
        )


class FrameworkMappingSpecialist(Specialist):
    """Framework mapping specialist - maps controls across frameworks."""

    def __init__(self, specialist_id: Optional[str] = None):
        super().__init__(specialist_id)

    @property
    def capability(self) -> SpecialistCapability:
        return SpecialistCapability(
            name="Framework Mapping Specialist",
            task_types=[
                "compliance.map_frameworks",
                "regulatory.mapping",
                "framework.crosswalk",
            ],
            confidence=0.8,
            max_concurrent=2,
            description="Maps controls across compliance frameworks",
        )

    async def _do_execute(self, task: Task) -> TaskResult:
        """Map frameworks."""
        source_framework = task.parameters.get("source_framework")
        target_framework = task.parameters.get("target_framework")
        controls = task.parameters.get("controls", [])

        return TaskResult(
            success=True,
            output={
                "source_framework": source_framework,
                "target_framework": target_framework,
                "mappings": [],
                "unmapped_controls": [],
                "coverage_percentage": 0.0,
            },
            confidence=0.8,
            metadata={"source": source_framework, "target": target_framework},
        )


class CertificationSpecialist(Specialist):
    """Certification specialist - tracks compliance certifications."""

    def __init__(self, specialist_id: Optional[str] = None):
        super().__init__(specialist_id)

    @property
    def capability(self) -> SpecialistCapability:
        return SpecialistCapability(
            name="Certification Specialist",
            task_types=[
                "compliance.certification",
                "regulatory.certification",
                "audit.certification",
            ],
            confidence=0.9,
            max_concurrent=2,
            description="Tracks and manages compliance certifications",
        )

    async def _do_execute(self, task: Task) -> TaskResult:
        """Track certification."""
        certification = task.parameters.get("certification")
        action = task.parameters.get("action", "status")

        return TaskResult(
            success=True,
            output={
                "certification": certification,
                "action": action,
                "status": "active",
                "expiry_date": None,
                "renewal_requirements": [],
            },
            confidence=0.9,
            metadata={"certification": certification},
        )


class EvidenceCollectionSpecialist(Specialist):
    """Evidence collection specialist - gathers audit evidence."""

    def __init__(self, specialist_id: Optional[str] = None):
        super().__init__(specialist_id)

    @property
    def capability(self) -> SpecialistCapability:
        return SpecialistCapability(
            name="Evidence Collection Specialist",
            task_types=[
                "audit.collect_evidence",
                "compliance.evidence",
                "audit.gather",
            ],
            confidence=0.9,
            max_concurrent=5,
            description="Collects evidence for compliance audits",
        )

    async def _do_execute(self, task: Task) -> TaskResult:
        """Collect evidence."""
        evidence_type = task.parameters.get("evidence_type")
        requirement_id = task.parameters.get("requirement_id")
        sources = task.parameters.get("sources", [])

        return TaskResult(
            success=True,
            output={
                "evidence_type": evidence_type,
                "requirement_id": requirement_id,
                "sources_checked": sources,
                "evidence_collected": [],
                "gaps": [],
            },
            confidence=0.9,
            metadata={"evidence_type": evidence_type},
        )


# ============================================================================
# MANAGERS
# ============================================================================


class PolicyManager(Manager):
    """Policy Manager - Coordinates policy enforcement specialists."""

    @property
    def name(self) -> str:
        return "Policy Manager"

    @property
    def domain(self) -> str:
        return "policy"

    @property
    def handled_task_types(self) -> List[str]:
        return [
            "compliance.policy",
            "compliance.policy_audit",
            "compliance.check_policy",
            "compliance.enforce_policy",
            "compliance.drift",
            "compliance.config_drift",
            "compliance.baseline",
            "policy.audit",
            "policy.enforce",
            "policy.apply",
            "policy.check",
            "audit.policy",
        ]

    async def _decompose_task(self, task: Task) -> List[Task]:
        """Decompose policy tasks."""
        if task.task_type == "compliance.policy":
            # Full policy compliance includes audit and enforcement
            return [
                Task(
                    task_type="compliance.policy_audit",
                    description="Audit policy compliance",
                    parameters=task.parameters.copy(),
                    priority=task.priority,
                    severity=task.severity,
                    context=task.context,
                ),
                Task(
                    task_type="compliance.drift",
                    description="Check configuration drift",
                    parameters=task.parameters.copy(),
                    priority=task.priority,
                    severity=task.severity,
                    context=task.context,
                ),
            ]
        return []


class RegulatoryManager(Manager):
    """Regulatory Manager - Coordinates regulatory compliance specialists."""

    @property
    def name(self) -> str:
        return "Regulatory Manager"

    @property
    def domain(self) -> str:
        return "regulatory"

    @property
    def handled_task_types(self) -> List[str]:
        return [
            "compliance.regulatory",
            "compliance.framework",
            "compliance.pci",
            "compliance.hipaa",
            "compliance.soc2",
            "compliance.nist",
            "compliance.map_frameworks",
            "compliance.certification",
            "regulatory.check",
            "regulatory.mapping",
            "regulatory.certification",
            "framework.crosswalk",
            "audit.regulatory",
        ]

    async def _decompose_task(self, task: Task) -> List[Task]:
        """Decompose regulatory tasks."""
        if task.task_type == "compliance.regulatory":
            frameworks = task.parameters.get("frameworks", ["pci-dss"])
            return [
                Task(
                    task_type=f"compliance.{fw.replace('-', '')}",
                    description=f"Check {fw} compliance",
                    parameters={**task.parameters, "framework": fw},
                    priority=task.priority,
                    severity=task.severity,
                    context=task.context,
                )
                for fw in frameworks
            ]
        return []


class AuditManager(Manager):
    """Audit Manager - Coordinates audit operations specialists."""

    @property
    def name(self) -> str:
        return "Audit Manager"

    @property
    def domain(self) -> str:
        return "audit"

    @property
    def handled_task_types(self) -> List[str]:
        return [
            "compliance.audit",
            "compliance.audit_logs",
            "compliance.report",
            "compliance.generate_report",
            "compliance.evidence",
            "compliance.log_review",
            "compliance.documentation",
            "audit.logs",
            "audit.trail",
            "audit.report",
            "audit.collect_evidence",
            "audit.gather",
        ]

    async def _decompose_task(self, task: Task) -> List[Task]:
        """Decompose audit tasks."""
        if task.task_type == "compliance.audit":
            # Full audit includes log review, evidence collection, and report
            return [
                Task(
                    task_type="compliance.audit_logs",
                    description="Analyze audit logs",
                    parameters=task.parameters.copy(),
                    priority=task.priority,
                    severity=task.severity,
                    context=task.context,
                ),
                Task(
                    task_type="audit.collect_evidence",
                    description="Collect audit evidence",
                    parameters=task.parameters.copy(),
                    priority=task.priority,
                    severity=task.severity,
                    context=task.context,
                ),
                Task(
                    task_type="compliance.report",
                    description="Generate compliance report",
                    parameters=task.parameters.copy(),
                    priority=task.priority,
                    severity=task.severity,
                    context=task.context,
                ),
            ]
        return []


# ============================================================================
# COMPLIANCE HIERARCHY AGENT
# ============================================================================


class ComplianceHierarchyAgent(SentinelAgentBase):
    """
    Compliance Hierarchical Agent - Compliance Operations Domain Executive.

    The Compliance Agent owns the entire compliance operations domain.
    It coordinates managers for policy enforcement, regulatory compliance,
    audit trail management, and compliance reporting.

    Capabilities:
    - Policy audit and enforcement (security policies, baselines)
    - Regulatory compliance (PCI-DSS, HIPAA, SOC2, NIST)
    - Audit operations (log analysis, evidence collection, reporting)
    - Configuration drift detection

    Architecture:
    - 3 Managers coordinate different compliance aspects
    - 9 Specialists handle individual compliance tasks
    """

    def __init__(self, agent_id: Optional[str] = None):
        super().__init__(agent_id)
        self._manager_count = 0
        self._specialist_count = 0

    @property
    def name(self) -> str:
        return "Compliance Agent"

    @property
    def domain(self) -> str:
        return "compliance"

    @property
    def handled_task_types(self) -> List[str]:
        return [
            # High-level compliance tasks
            "compliance",
            "compliance.full",
            "compliance.check",
            # Policy tasks
            "compliance.policy",
            "compliance.policy_audit",
            "compliance.enforce_policy",
            "compliance.drift",
            # Regulatory tasks
            "compliance.regulatory",
            "compliance.framework",
            "compliance.pci",
            "compliance.hipaa",
            "compliance.soc2",
            "compliance.nist",
            # Audit tasks
            "compliance.audit",
            "compliance.audit_logs",
            "compliance.report",
            "compliance.evidence",
            # Generic
            "policy",
            "regulatory",
            "audit",
        ]

    async def _setup_managers(self) -> None:
        """Set up all managers and their specialists."""
        # Policy Manager - Use real LLM-powered specialists
        policy_manager = PolicyManager()
        # Real implementations with LLM
        policy_manager.register_specialist(RealPolicyAuditSpecialist())
        policy_manager.register_specialist(RealConfigurationDriftSpecialist())
        # Stub implementation (to be upgraded)
        policy_manager.register_specialist(PolicyEnforcementSpecialist())
        self.register_manager(policy_manager)

        # Regulatory Manager - Use real LLM-powered specialists
        regulatory_manager = RegulatoryManager()
        # Real implementation with LLM
        regulatory_manager.register_specialist(RealRegulatoryComplianceSpecialist())
        # Stub implementations (to be upgraded)
        regulatory_manager.register_specialist(FrameworkMappingSpecialist())
        regulatory_manager.register_specialist(CertificationSpecialist())
        self.register_manager(regulatory_manager)

        # Audit Manager - Use real LLM-powered specialists
        audit_manager = AuditManager()
        # Real implementations with LLM
        audit_manager.register_specialist(RealAuditLogSpecialist())
        audit_manager.register_specialist(RealComplianceReportSpecialist())
        # Stub implementation (to be upgraded)
        audit_manager.register_specialist(EvidenceCollectionSpecialist())
        self.register_manager(audit_manager)

        self._manager_count = len(self._managers)
        self._specialist_count = sum(len(m.specialists) for m in self._managers.values())

        logger.info(
            f"ComplianceHierarchyAgent initialized with {self._manager_count} managers "
            f"and {self._specialist_count} specialists (including LLM-powered)"
        )

    async def _plan_execution(self, task: Task) -> Dict[str, Any]:
        """Plan compliance task execution."""
        if task.task_type in ["compliance", "compliance.full"]:
            return await self._plan_full_compliance(task)

        return await super()._plan_execution(task)

    async def _plan_full_compliance(self, task: Task) -> Dict[str, Any]:
        """Plan full compliance assessment."""
        steps = []
        compliance_aspects = task.parameters.get("aspects", ["policy", "regulatory", "audit"])

        task_type_map = {
            "policy": "compliance.policy",
            "regulatory": "compliance.regulatory",
            "audit": "compliance.audit",
        }

        for aspect in compliance_aspects:
            manager = self._find_manager_by_domain(aspect)
            if manager:
                aspect_params = task.parameters.copy()
                if aspect == "regulatory":
                    aspect_params.setdefault("frameworks", ["pci-dss", "nist"])

                steps.append(
                    {
                        "manager_id": manager.id,
                        "task": Task(
                            task_type=task_type_map.get(aspect, f"compliance.{aspect}"),
                            description=f"Execute {aspect} compliance assessment",
                            parameters=aspect_params,
                            priority=task.priority,
                            severity=task.severity,
                            context=task.context,
                        ),
                    }
                )

        return {
            "parallel": True,  # Compliance aspects can run in parallel
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
                    "policy_types": ["audit", "enforcement", "drift_detection"],
                    "regulatory_frameworks": ["pci-dss", "hipaa", "soc2", "nist"],
                    "audit_types": ["logs", "evidence", "reporting"],
                },
            }
        )
        return base_stats
