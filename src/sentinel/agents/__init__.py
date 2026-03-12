"""
Sentinel AI Agents Package.

This package contains the AI agents that power the Sentinel platform:
- Discovery: Network scanning and device classification
- Optimizer: Traffic engineering and QoS management
- Planner: Segmentation and VLAN automation
- Healer: Self-repair and automated failover
- Guardian: Security policy enforcement
- PolicyEnforcer: Continuous policy compliance monitoring
- Testing: Automated system health and issue detection
- Strategy: High-level strategic oversight (CTO brain)

CTO Architecture components:
- AgentFactory: Dynamic agent creation and management
- AgentRegistry: Inter-agent communication and discovery
"""

from sentinel.agents.base import BaseAgent
from sentinel.agents.discovery import DiscoveryAgent
from sentinel.agents.optimizer import OptimizerAgent
from sentinel.agents.planner import PlannerAgent
from sentinel.agents.healer import HealerAgent
from sentinel.agents.guardian import GuardianAgent
from sentinel.agents.policy import PolicyEnforcerAgent
from sentinel.agents.testing import TestingAgent
from sentinel.agents.strategy import StrategyAgent
from sentinel.agents.factory import AgentFactory, AgentTemplate, AgentInstance
from sentinel.agents.registry import AgentRegistry, AgentCapability, AgentMessage

__all__ = [
    # Core agents
    "BaseAgent",
    "DiscoveryAgent",
    "OptimizerAgent",
    "PlannerAgent",
    "HealerAgent",
    "GuardianAgent",
    "PolicyEnforcerAgent",
    "TestingAgent",
    "StrategyAgent",
    # CTO architecture
    "AgentFactory",
    "AgentTemplate",
    "AgentInstance",
    "AgentRegistry",
    "AgentCapability",
    "AgentMessage",
]
