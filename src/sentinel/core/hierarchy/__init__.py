"""
Sentinel Hierarchical Agent Architecture.

This module provides the base classes for the three-tier agent architecture:
- SentinelAgentBase: Domain executives (e.g., GuardianAgent, HealerAgent)
- Manager: Specialist coordinators (e.g., ThreatManager, HealthManager)
- Specialist: Atomic task executors (e.g., FirewallSpecialist, SNMPSpecialist)
"""

from sentinel.core.hierarchy.base import (
    # Enums
    TaskStatus,
    TaskPriority,
    TaskSeverity,
    # Data classes
    Task,
    TaskResult,
    SpecialistCapability,
    # Base classes
    Specialist,
    Manager,
    SentinelAgentBase,
)

__all__ = [
    # Enums
    "TaskStatus",
    "TaskPriority",
    "TaskSeverity",
    # Data classes
    "Task",
    "TaskResult",
    "SpecialistCapability",
    # Base classes
    "Specialist",
    "Manager",
    "SentinelAgentBase",
]
