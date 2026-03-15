"""
Sentinel - AI-Native Security Platform

An autonomous network security and automation platform that uses
AI agents to manage, monitor, and protect homelab infrastructure.

Part of the GozerAI ecosystem by 1450 Enterprises.
"""
__version__ = "0.1.0"
__author__ = "1450 Enterprises"

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
