"""
Sentinel Core Package.

This package contains the core components of the Sentinel platform:
- SentinelEngine: Main orchestration engine
- EventBus: Inter-component communication
- StateManager: Persistent state storage
- Scheduler: Periodic task scheduling
- Config: Configuration management
- MetricsCollector: Prometheus metrics
"""

from sentinel.core.engine import SentinelEngine
from sentinel.core.event_bus import EventBus
from sentinel.core.state import StateManager
from sentinel.core.scheduler import Scheduler
from sentinel.core.config import load_config, SentinelConfig
from sentinel.core.metrics import MetricsCollector, get_metrics_collector, configure_metrics

__all__ = [
    "SentinelEngine",
    "EventBus",
    "StateManager",
    "Scheduler",
    "load_config",
    "SentinelConfig",
    "MetricsCollector",
    "get_metrics_collector",
    "configure_metrics",
]
