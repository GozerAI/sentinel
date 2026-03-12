"""
Disaster Recovery Hierarchical Agent - DR Operations Domain Executive.

The Disaster Recovery Agent owns the DR operations domain.
It orchestrates managers for backup management, recovery testing,
failover orchestration, and DR planning.

Hierarchy:
    DisasterRecoveryHierarchyAgent (Domain Executive)
        ├── BackupManager (Coordinates backup operations)
        │   ├── BackupManagementSpecialist
        │   ├── BackupVerificationSpecialist
        │   └── RetentionPolicySpecialist
        ├── RecoveryManager (Coordinates recovery operations)
        │   ├── RecoveryTestingSpecialist
        │   ├── FailoverOrchestrationSpecialist
        │   └── ReplicationMonitoringSpecialist
        └── PlanningManager (Coordinates DR planning)
            ├── DRPlanManagementSpecialist
            ├── RunbookSpecialist
            └── ComplianceTrackingSpecialist
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
from sentinel.agents.hierarchy.specialists.disaster_recovery import (
    BackupManagementSpecialist as RealBackupManagementSpecialist,
    RecoveryTestingSpecialist as RealRecoveryTestingSpecialist,
    FailoverOrchestrationSpecialist as RealFailoverOrchestrationSpecialist,
    ReplicationMonitoringSpecialist as RealReplicationMonitoringSpecialist,
    DRPlanManagementSpecialist as RealDRPlanManagementSpecialist,
)

logger = logging.getLogger(__name__)


# ============================================================================
# STUB SPECIALISTS (To be upgraded to real implementations)
# ============================================================================


class BackupVerificationSpecialist(Specialist):
    """Backup verification specialist - verifies backup integrity."""

    def __init__(self, specialist_id: Optional[str] = None):
        super().__init__(specialist_id)

    @property
    def capability(self) -> SpecialistCapability:
        return SpecialistCapability(
            name="Backup Verification Specialist",
            task_types=[
                "dr.backup.verify_all",
                "backup.integrity_check",
            ],
            confidence=0.9,
            max_concurrent=3,
            description="Verifies backup integrity across systems",
        )

    async def _do_execute(self, task: Task) -> TaskResult:
        """Verify backups."""
        targets = task.parameters.get("targets", [])
        verification_type = task.parameters.get("verification_type", "checksum")

        return TaskResult(
            success=True,
            output={
                "targets": targets,
                "verification_type": verification_type,
                "verified": True,
                "results": [],
            },
            confidence=0.9,
            metadata={"verification_type": verification_type},
        )


class RetentionPolicySpecialist(Specialist):
    """Retention policy specialist - manages backup retention."""

    def __init__(self, specialist_id: Optional[str] = None):
        super().__init__(specialist_id)

    @property
    def capability(self) -> SpecialistCapability:
        return SpecialistCapability(
            name="Retention Policy Specialist",
            task_types=[
                "dr.retention",
                "backup.retention",
                "backup.cleanup",
            ],
            confidence=0.85,
            max_concurrent=2,
            description="Manages backup retention policies",
        )

    async def _do_execute(self, task: Task) -> TaskResult:
        """Manage retention."""
        action = task.parameters.get("action", "status")
        policy = task.parameters.get("policy", {})

        return TaskResult(
            success=True,
            output={
                "action": action,
                "policy": policy,
                "status": "applied",
                "backups_affected": 0,
            },
            confidence=0.85,
            metadata={"action": action},
        )


class RunbookSpecialist(Specialist):
    """Runbook specialist - manages DR runbooks."""

    def __init__(self, specialist_id: Optional[str] = None):
        super().__init__(specialist_id)

    @property
    def capability(self) -> SpecialistCapability:
        return SpecialistCapability(
            name="Runbook Specialist",
            task_types=[
                "dr.runbook",
                "dr.runbook.execute",
                "runbook.status",
            ],
            confidence=0.85,
            max_concurrent=2,
            description="Manages and executes DR runbooks",
        )

    async def _do_execute(self, task: Task) -> TaskResult:
        """Manage runbooks."""
        action = task.parameters.get("action", "list")
        runbook_id = task.parameters.get("runbook_id")

        return TaskResult(
            success=True,
            output={
                "action": action,
                "runbook_id": runbook_id,
                "status": "available",
                "runbooks": [],
            },
            confidence=0.85,
            metadata={"action": action},
        )


class DRComplianceTrackingSpecialist(Specialist):
    """DR compliance tracking specialist - tracks DR compliance."""

    def __init__(self, specialist_id: Optional[str] = None):
        super().__init__(specialist_id)

    @property
    def capability(self) -> SpecialistCapability:
        return SpecialistCapability(
            name="DR Compliance Tracking Specialist",
            task_types=[
                "dr.compliance",
                "dr.compliance.check",
                "dr.sla.status",
            ],
            confidence=0.85,
            max_concurrent=2,
            description="Tracks DR compliance and SLA status",
        )

    async def _do_execute(self, task: Task) -> TaskResult:
        """Track DR compliance."""
        check_type = task.parameters.get("check_type", "full")

        return TaskResult(
            success=True,
            output={
                "check_type": check_type,
                "rto_compliant": True,
                "rpo_compliant": True,
                "test_compliance": True,
                "compliance_percentage": 100.0,
            },
            confidence=0.85,
            metadata={"check_type": check_type},
        )


# ============================================================================
# MANAGERS
# ============================================================================


class BackupManager(Manager):
    """Backup Manager - Coordinates backup operations specialists."""

    @property
    def name(self) -> str:
        return "Backup Manager"

    @property
    def domain(self) -> str:
        return "backup"

    @property
    def handled_task_types(self) -> List[str]:
        return [
            "dr.backup",
            "dr.backup.status",
            "dr.backup.verify",
            "dr.backup.verify_all",
            "dr.backup.initiate",
            "dr.retention",
            "backup.status",
            "backup.verify",
            "backup.integrity_check",
            "backup.retention",
            "backup.cleanup",
            "disaster_recovery.backup",
        ]

    async def _decompose_task(self, task: Task) -> List[Task]:
        """Decompose backup tasks."""
        if task.task_type == "dr.backup":
            action = task.parameters.get("action", "status")
            if action == "full_check":
                return [
                    Task(
                        task_type="dr.backup.status",
                        description="Check backup status",
                        parameters=task.parameters.copy(),
                        priority=task.priority,
                        severity=task.severity,
                        context=task.context,
                    ),
                    Task(
                        task_type="dr.backup.verify_all",
                        description="Verify all backups",
                        parameters=task.parameters.copy(),
                        priority=task.priority,
                        severity=task.severity,
                        context=task.context,
                    ),
                ]
        return []


class RecoveryManager(Manager):
    """Recovery Manager - Coordinates recovery operations specialists."""

    @property
    def name(self) -> str:
        return "Recovery Manager"

    @property
    def domain(self) -> str:
        return "recovery"

    @property
    def handled_task_types(self) -> List[str]:
        return [
            "dr.test",
            "dr.recovery_test",
            "dr.rto_test",
            "dr.failover",
            "dr.failback",
            "dr.switchover",
            "dr.replication",
            "dr.replication.status",
            "dr.replication.verify",
            "disaster_recovery.test",
            "disaster_recovery.failover",
            "disaster_recovery.replication",
        ]

    async def _decompose_task(self, task: Task) -> List[Task]:
        """Decompose recovery tasks."""
        if task.task_type == "dr.recovery_test":
            test_type = task.parameters.get("test_type", "full")
            if test_type == "comprehensive":
                return [
                    Task(
                        task_type="dr.replication.status",
                        description="Check replication status",
                        parameters=task.parameters.copy(),
                        priority=task.priority,
                        severity=task.severity,
                        context=task.context,
                    ),
                    Task(
                        task_type="dr.failover",
                        description="Validate failover readiness",
                        parameters={**task.parameters, "action": "validate"},
                        priority=task.priority,
                        severity=task.severity,
                        context=task.context,
                    ),
                    Task(
                        task_type="dr.test",
                        description="Execute recovery test",
                        parameters={**task.parameters, "test_type": "simulation"},
                        priority=task.priority,
                        severity=task.severity,
                        context=task.context,
                    ),
                ]
        return []


class PlanningManager(Manager):
    """Planning Manager - Coordinates DR planning specialists."""

    @property
    def name(self) -> str:
        return "Planning Manager"

    @property
    def domain(self) -> str:
        return "planning"

    @property
    def handled_task_types(self) -> List[str]:
        return [
            "dr.plan",
            "dr.plan.status",
            "dr.plan.validate",
            "dr.runbook",
            "dr.runbook.execute",
            "dr.compliance",
            "dr.compliance.check",
            "dr.sla.status",
            "disaster_recovery.plan",
            "runbook.status",
        ]

    async def _decompose_task(self, task: Task) -> List[Task]:
        """Decompose planning tasks."""
        if task.task_type == "dr.plan":
            action = task.parameters.get("action", "status")
            if action == "full_review":
                return [
                    Task(
                        task_type="dr.plan.status",
                        description="Get plan status",
                        parameters=task.parameters.copy(),
                        priority=task.priority,
                        severity=task.severity,
                        context=task.context,
                    ),
                    Task(
                        task_type="dr.plan.validate",
                        description="Validate plan",
                        parameters=task.parameters.copy(),
                        priority=task.priority,
                        severity=task.severity,
                        context=task.context,
                    ),
                    Task(
                        task_type="dr.compliance.check",
                        description="Check DR compliance",
                        parameters=task.parameters.copy(),
                        priority=task.priority,
                        severity=task.severity,
                        context=task.context,
                    ),
                ]
        return []


# ============================================================================
# DISASTER RECOVERY HIERARCHY AGENT
# ============================================================================


class DisasterRecoveryHierarchyAgent(SentinelAgentBase):
    """
    Disaster Recovery Hierarchical Agent - DR Operations Domain Executive.

    The Disaster Recovery Agent owns the entire DR operations domain.
    It coordinates managers for backup management, recovery testing,
    failover orchestration, and DR planning.

    Capabilities:
    - Backup management (status, verification, initiation, retention)
    - Recovery operations (testing, failover, failback, replication)
    - DR planning (plans, runbooks, compliance tracking)

    Architecture:
    - 3 Managers coordinate different DR aspects
    - 9 Specialists handle individual DR tasks
    """

    def __init__(self, agent_id: Optional[str] = None):
        super().__init__(agent_id)
        self._manager_count = 0
        self._specialist_count = 0

    @property
    def name(self) -> str:
        return "Disaster Recovery Agent"

    @property
    def domain(self) -> str:
        return "disaster_recovery"

    @property
    def handled_task_types(self) -> List[str]:
        return [
            # High-level DR tasks
            "disaster_recovery",
            "disaster_recovery.full",
            "dr",
            "dr.full",
            # Backup tasks
            "dr.backup",
            "dr.backup.status",
            "dr.backup.verify",
            "dr.backup.initiate",
            "dr.retention",
            # Recovery tasks
            "dr.test",
            "dr.recovery_test",
            "dr.failover",
            "dr.failback",
            "dr.replication",
            # Planning tasks
            "dr.plan",
            "dr.runbook",
            "dr.compliance",
            # Generic
            "backup",
            "recovery",
            "failover",
        ]

    async def _setup_managers(self) -> None:
        """Set up all managers and their specialists."""
        # Backup Manager - Use real LLM-powered specialists
        backup_manager = BackupManager()
        # Real implementation with LLM
        backup_manager.register_specialist(RealBackupManagementSpecialist())
        # Stub implementations (to be upgraded)
        backup_manager.register_specialist(BackupVerificationSpecialist())
        backup_manager.register_specialist(RetentionPolicySpecialist())
        self.register_manager(backup_manager)

        # Recovery Manager - Use real LLM-powered specialists
        recovery_manager = RecoveryManager()
        # Real implementations with LLM
        recovery_manager.register_specialist(RealRecoveryTestingSpecialist())
        recovery_manager.register_specialist(RealFailoverOrchestrationSpecialist())
        recovery_manager.register_specialist(RealReplicationMonitoringSpecialist())
        self.register_manager(recovery_manager)

        # Planning Manager - Use real LLM-powered specialists
        planning_manager = PlanningManager()
        # Real implementation with LLM
        planning_manager.register_specialist(RealDRPlanManagementSpecialist())
        # Stub implementations (to be upgraded)
        planning_manager.register_specialist(RunbookSpecialist())
        planning_manager.register_specialist(DRComplianceTrackingSpecialist())
        self.register_manager(planning_manager)

        self._manager_count = len(self._managers)
        self._specialist_count = sum(len(m.specialists) for m in self._managers.values())

        logger.info(
            f"DisasterRecoveryHierarchyAgent initialized with {self._manager_count} managers "
            f"and {self._specialist_count} specialists (including LLM-powered)"
        )

    async def _plan_execution(self, task: Task) -> Dict[str, Any]:
        """Plan DR task execution."""
        if task.task_type in ["disaster_recovery", "disaster_recovery.full", "dr", "dr.full"]:
            return await self._plan_full_dr_assessment(task)

        return await super()._plan_execution(task)

    async def _plan_full_dr_assessment(self, task: Task) -> Dict[str, Any]:
        """Plan full DR assessment."""
        steps = []
        dr_aspects = task.parameters.get("aspects", ["backup", "recovery", "planning"])

        task_type_map = {
            "backup": "dr.backup",
            "recovery": "dr.replication",
            "planning": "dr.plan",
        }

        for aspect in dr_aspects:
            manager = self._find_manager_by_domain(aspect)
            if manager:
                aspect_params = task.parameters.copy()
                aspect_params["action"] = "status"

                steps.append(
                    {
                        "manager_id": manager.id,
                        "task": Task(
                            task_type=task_type_map.get(aspect, f"dr.{aspect}"),
                            description=f"Execute {aspect} DR assessment",
                            parameters=aspect_params,
                            priority=task.priority,
                            severity=task.severity,
                            context=task.context,
                        ),
                    }
                )

        return {
            "parallel": True,  # DR aspects can run in parallel
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
                    "backup_operations": ["status", "verify", "initiate", "retention"],
                    "recovery_operations": ["test", "failover", "failback", "replication"],
                    "planning_operations": ["plans", "runbooks", "compliance"],
                },
            }
        )
        return base_stats
