"""
Sentinel Hierarchical Agents.

These agents follow the Agent → Manager → Specialist pattern for
integration with the Nexus COO orchestrator.

Each hierarchical agent wraps and coordinates the existing Sentinel agents
to provide a scalable, parallel execution architecture.
"""

from sentinel.agents.hierarchy.guardian import GuardianHierarchyAgent
from sentinel.agents.hierarchy.healer import HealerHierarchyAgent
from sentinel.agents.hierarchy.discovery import DiscoveryHierarchyAgent
from sentinel.agents.hierarchy.optimizer import OptimizerHierarchyAgent
from sentinel.agents.hierarchy.compliance import ComplianceHierarchyAgent
from sentinel.agents.hierarchy.disaster_recovery import DisasterRecoveryHierarchyAgent
from sentinel.agents.hierarchy.cost_manager import CostManagerHierarchyAgent

__all__ = [
    "GuardianHierarchyAgent",
    "HealerHierarchyAgent",
    "DiscoveryHierarchyAgent",
    "OptimizerHierarchyAgent",
    "ComplianceHierarchyAgent",
    "DisasterRecoveryHierarchyAgent",
    "CostManagerHierarchyAgent",
]
