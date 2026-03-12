"""
Sentinel - AI-Native Chief Information Officer (CIO)

An autonomous infrastructure management platform that uses AI agents
to manage, monitor, secure, and optimize internal IT operations.

Sentinel serves as the CIO function for the organization:
- Guardian Agent: Security Operations (SOC)
- Healer Agent: Infrastructure Reliability (SRE/Ops)
- Discovery Agent: Asset Management (IT Inventory)
- Optimizer Agent: Network Performance (Network Ops)
- Planner Agent: Infrastructure Architecture
- Strategy Agent: IT Strategic Oversight

Sentinel works alongside the CTO system (product/external focus)
to provide complete technology leadership automation.

Part of the GozerAI ecosystem.
"""

__version__ = "0.2.0"
__author__ = "GozerAI"

from sentinel.core.engine import SentinelEngine
from sentinel.core.event_bus import EventBus
from sentinel.core.state import StateManager
from sentinel.core.scheduler import Scheduler
from sentinel.core.config import load_config, SentinelConfig

# Nexus integration
from sentinel.nexus_agent import SentinelAgent, CIOCapability

__all__ = [
    "__version__",
    "SentinelEngine",
    "EventBus",
    "StateManager",
    "Scheduler",
    "load_config",
    "SentinelConfig",
    # Nexus integration
    "SentinelAgent",
    "CIOCapability",
]
