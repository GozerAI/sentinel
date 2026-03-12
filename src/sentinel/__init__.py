"""
Sentinel - AI Security Monitoring and Threat Detection

An autonomous infrastructure management platform that uses AI agents
to manage, monitor, secure, and optimize IT operations.

Part of the GozerAI ecosystem.
"""

__version__ = "0.2.0"
__author__ = "GozerAI"

from sentinel.core.engine import SentinelEngine
from sentinel.core.event_bus import EventBus
from sentinel.core.state import StateManager
from sentinel.core.scheduler import Scheduler
from sentinel.core.config import load_config, SentinelConfig

__all__ = [
    "__version__",
    "SentinelEngine",
    "EventBus",
    "StateManager",
    "Scheduler",
    "load_config",
    "SentinelConfig",
]
