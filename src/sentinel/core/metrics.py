"""
Prometheus metrics collection for Sentinel platform.

This module provides metrics for monitoring the Sentinel engine,
agents, integrations, and overall platform health.
"""
import logging
from typing import Optional

from prometheus_client import (
    Counter,
    Gauge,
    Histogram,
    Info,
    CollectorRegistry,
    REGISTRY,
    generate_latest,
    CONTENT_TYPE_LATEST,
)

logger = logging.getLogger(__name__)


# =============================================================================
# Engine Metrics
# =============================================================================

ENGINE_INFO = Info(
    "sentinel_engine",
    "Sentinel engine information"
)

ENGINE_UPTIME = Gauge(
    "sentinel_engine_uptime_seconds",
    "Engine uptime in seconds"
)

ENGINE_RUNNING = Gauge(
    "sentinel_engine_running",
    "Whether the engine is running (1=running, 0=stopped)"
)


# =============================================================================
# Agent Metrics
# =============================================================================

AGENT_RUNNING = Gauge(
    "sentinel_agent_running",
    "Whether the agent is running",
    ["agent_name"]
)

AGENT_EVENTS_PROCESSED = Counter(
    "sentinel_agent_events_processed_total",
    "Total events processed by agent",
    ["agent_name", "event_type"]
)

AGENT_ACTIONS_TAKEN = Counter(
    "sentinel_agent_actions_total",
    "Total actions taken by agent",
    ["agent_name", "action_type", "status"]
)

AGENT_DECISIONS_MADE = Counter(
    "sentinel_agent_decisions_total",
    "Total decisions made by agent",
    ["agent_name"]
)

AGENT_ANALYSIS_DURATION = Histogram(
    "sentinel_agent_analysis_duration_seconds",
    "Time spent analyzing events",
    ["agent_name"],
    buckets=(0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0, 5.0, 10.0)
)


# =============================================================================
# Device Metrics
# =============================================================================

DEVICES_TOTAL = Gauge(
    "sentinel_devices_total",
    "Total number of discovered devices",
    ["device_type", "status"]
)

DEVICES_BY_VLAN = Gauge(
    "sentinel_devices_by_vlan",
    "Number of devices per VLAN",
    ["vlan_id", "vlan_name"]
)

DEVICES_BY_TRUST_LEVEL = Gauge(
    "sentinel_devices_by_trust_level",
    "Number of devices by trust level",
    ["trust_level"]
)


# =============================================================================
# Network Metrics
# =============================================================================

VLANS_TOTAL = Gauge(
    "sentinel_vlans_total",
    "Total number of configured VLANs"
)

TRAFFIC_FLOWS_ACTIVE = Gauge(
    "sentinel_traffic_flows_active",
    "Number of active traffic flows"
)

BANDWIDTH_USAGE_BYTES = Counter(
    "sentinel_bandwidth_bytes_total",
    "Total bandwidth usage in bytes",
    ["direction", "vlan_id"]
)


# =============================================================================
# Security Metrics
# =============================================================================

BLOCKED_IPS_TOTAL = Gauge(
    "sentinel_blocked_ips_total",
    "Number of currently blocked IPs"
)

QUARANTINED_DEVICES_TOTAL = Gauge(
    "sentinel_quarantined_devices_total",
    "Number of quarantined devices"
)

SECURITY_EVENTS = Counter(
    "sentinel_security_events_total",
    "Total security events",
    ["event_type", "severity"]
)

THREAT_DETECTIONS = Counter(
    "sentinel_threat_detections_total",
    "Total threat detections",
    ["threat_type"]
)


# =============================================================================
# Event Bus Metrics
# =============================================================================

EVENTS_PUBLISHED = Counter(
    "sentinel_events_published_total",
    "Total events published to event bus",
    ["category", "event_type"]
)

EVENTS_QUEUE_SIZE = Gauge(
    "sentinel_events_queue_size",
    "Current event queue size"
)

EVENT_HANDLERS_TOTAL = Gauge(
    "sentinel_event_handlers_total",
    "Number of registered event handlers"
)


# =============================================================================
# Integration Metrics
# =============================================================================

INTEGRATION_STATUS = Gauge(
    "sentinel_integration_connected",
    "Whether integration is connected",
    ["integration_name", "integration_type"]
)

INTEGRATION_REQUESTS = Counter(
    "sentinel_integration_requests_total",
    "Total requests to integrations",
    ["integration_name", "operation", "status"]
)

INTEGRATION_LATENCY = Histogram(
    "sentinel_integration_latency_seconds",
    "Integration request latency",
    ["integration_name", "operation"],
    buckets=(0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0)
)


# =============================================================================
# API Metrics
# =============================================================================

API_REQUESTS = Counter(
    "sentinel_api_requests_total",
    "Total API requests",
    ["method", "endpoint", "status_code"]
)

API_LATENCY = Histogram(
    "sentinel_api_latency_seconds",
    "API request latency",
    ["method", "endpoint"],
    buckets=(0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0)
)


# =============================================================================
# Scheduler Metrics
# =============================================================================

SCHEDULED_TASKS_TOTAL = Gauge(
    "sentinel_scheduled_tasks_total",
    "Number of scheduled tasks"
)

SCHEDULED_TASK_EXECUTIONS = Counter(
    "sentinel_scheduled_task_executions_total",
    "Total scheduled task executions",
    ["task_name", "status"]
)


# =============================================================================
# Metrics Collector Class
# =============================================================================

class MetricsCollector:
    """
    Centralized metrics collector for the Sentinel platform.

    This class provides methods for updating metrics and integrates
    with the engine to collect system-wide statistics.

    Example:
        ```python
        collector = MetricsCollector()
        collector.set_engine(engine)

        # Update metrics
        collector.record_agent_event("discovery", "device.discovered")
        collector.record_agent_action("guardian", "block_ip", "success")
        ```
    """

    def __init__(self, registry: CollectorRegistry = REGISTRY):
        """Initialize the metrics collector."""
        self.registry = registry
        self._engine = None

        # Set initial engine info
        ENGINE_INFO.info({
            "version": "0.1.0",
            "platform": "sentinel"
        })

    def set_engine(self, engine) -> None:
        """
        Set the engine reference for metrics collection.

        Args:
            engine: The SentinelEngine instance
        """
        self._engine = engine

    def update_engine_metrics(self) -> None:
        """Update engine-level metrics."""
        if not self._engine:
            return

        ENGINE_RUNNING.set(1 if self._engine.is_running else 0)
        ENGINE_UPTIME.set(self._engine.uptime_seconds)

    def update_agent_metrics(self) -> None:
        """Update agent-level metrics."""
        if not self._engine:
            return

        for name, agent in self._engine._agents.items():
            AGENT_RUNNING.labels(agent_name=name).set(
                1 if getattr(agent, '_running', False) else 0
            )

    def update_device_metrics(self) -> None:
        """Update device inventory metrics."""
        if not self._engine:
            return

        discovery = self._engine.get_agent("discovery")
        if not discovery or not hasattr(discovery, '_inventory'):
            return

        # Count devices by type and status
        from collections import defaultdict
        type_status_counts = defaultdict(int)
        vlan_counts = defaultdict(int)
        trust_counts = defaultdict(int)

        for device in discovery._inventory.devices.values():
            type_key = (device.device_type.value, device.status.value)
            type_status_counts[type_key] += 1

            if device.assigned_vlan is not None:
                vlan_counts[device.assigned_vlan] += 1

            trust_counts[device.trust_level.value] += 1

        # Update gauges
        for (dtype, status), count in type_status_counts.items():
            DEVICES_TOTAL.labels(device_type=dtype, status=status).set(count)

        for trust_level, count in trust_counts.items():
            DEVICES_BY_TRUST_LEVEL.labels(trust_level=trust_level).set(count)

    def update_security_metrics(self) -> None:
        """Update security metrics."""
        if not self._engine:
            return

        guardian = self._engine.get_agent("guardian")
        if guardian:
            BLOCKED_IPS_TOTAL.set(len(getattr(guardian, '_blocked_ips', set())))
            QUARANTINED_DEVICES_TOTAL.set(
                len(getattr(guardian, '_quarantined_devices', set()))
            )

    def update_event_bus_metrics(self) -> None:
        """Update event bus metrics."""
        if not self._engine:
            return

        event_bus = self._engine.event_bus
        EVENTS_QUEUE_SIZE.set(event_bus._queue.qsize())
        EVENT_HANDLERS_TOTAL.set(len(event_bus._global_handlers))

    def update_all_metrics(self) -> None:
        """Update all metrics at once."""
        try:
            self.update_engine_metrics()
            self.update_agent_metrics()
            self.update_device_metrics()
            self.update_security_metrics()
            self.update_event_bus_metrics()
        except Exception as e:
            logger.error(f"Error updating metrics: {e}")

    # ==========================================================================
    # Recording methods for specific events
    # ==========================================================================

    def record_agent_event(
        self,
        agent_name: str,
        event_type: str
    ) -> None:
        """Record an event processed by an agent."""
        AGENT_EVENTS_PROCESSED.labels(
            agent_name=agent_name,
            event_type=event_type
        ).inc()

    def record_agent_action(
        self,
        agent_name: str,
        action_type: str,
        status: str = "success"
    ) -> None:
        """Record an action taken by an agent."""
        AGENT_ACTIONS_TAKEN.labels(
            agent_name=agent_name,
            action_type=action_type,
            status=status
        ).inc()

    def record_agent_decision(self, agent_name: str) -> None:
        """Record a decision made by an agent."""
        AGENT_DECISIONS_MADE.labels(agent_name=agent_name).inc()

    def record_agent_analysis_time(
        self,
        agent_name: str,
        duration: float
    ) -> None:
        """Record time spent analyzing an event."""
        AGENT_ANALYSIS_DURATION.labels(agent_name=agent_name).observe(duration)

    def record_event_published(
        self,
        category: str,
        event_type: str
    ) -> None:
        """Record an event published to the event bus."""
        EVENTS_PUBLISHED.labels(
            category=category,
            event_type=event_type
        ).inc()

    def record_security_event(
        self,
        event_type: str,
        severity: str
    ) -> None:
        """Record a security event."""
        SECURITY_EVENTS.labels(
            event_type=event_type,
            severity=severity
        ).inc()

    def record_threat_detection(self, threat_type: str) -> None:
        """Record a threat detection."""
        THREAT_DETECTIONS.labels(threat_type=threat_type).inc()

    def record_integration_request(
        self,
        integration_name: str,
        operation: str,
        status: str = "success",
        latency: Optional[float] = None
    ) -> None:
        """Record an integration request."""
        INTEGRATION_REQUESTS.labels(
            integration_name=integration_name,
            operation=operation,
            status=status
        ).inc()

        if latency is not None:
            INTEGRATION_LATENCY.labels(
                integration_name=integration_name,
                operation=operation
            ).observe(latency)

    def record_api_request(
        self,
        method: str,
        endpoint: str,
        status_code: int,
        latency: float
    ) -> None:
        """Record an API request."""
        API_REQUESTS.labels(
            method=method,
            endpoint=endpoint,
            status_code=str(status_code)
        ).inc()

        API_LATENCY.labels(
            method=method,
            endpoint=endpoint
        ).observe(latency)

    def set_integration_status(
        self,
        integration_name: str,
        integration_type: str,
        connected: bool
    ) -> None:
        """Set integration connection status."""
        INTEGRATION_STATUS.labels(
            integration_name=integration_name,
            integration_type=integration_type
        ).set(1 if connected else 0)

    def generate_metrics(self) -> bytes:
        """Generate Prometheus metrics output."""
        self.update_all_metrics()
        return generate_latest(self.registry)

    def get_content_type(self) -> str:
        """Get the content type for metrics response."""
        return CONTENT_TYPE_LATEST


# Global metrics collector instance
_metrics_collector: Optional[MetricsCollector] = None


def get_metrics_collector() -> MetricsCollector:
    """Get the global metrics collector instance."""
    global _metrics_collector
    if _metrics_collector is None:
        _metrics_collector = MetricsCollector()
    return _metrics_collector


def configure_metrics(engine) -> MetricsCollector:
    """
    Configure metrics collection with the engine.

    Args:
        engine: The SentinelEngine instance

    Returns:
        Configured MetricsCollector instance
    """
    collector = get_metrics_collector()
    collector.set_engine(engine)
    return collector
