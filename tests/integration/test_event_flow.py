"""
Integration tests for Event Flow across the Sentinel platform.

Tests the complete lifecycle of events from creation, through the event bus,
to handlers, and storage.
"""
import asyncio
import pytest
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4
from datetime import datetime, timezone

from sentinel.core.engine import SentinelEngine
from sentinel.core.event_bus import EventBus
from sentinel.core.models.event import Event, EventCategory, EventSeverity, AgentAction


class TestEventBusFlow:
    """Tests for event bus flow mechanics."""

    @pytest.mark.asyncio
    async def test_event_flows_through_bus(self):
        """Test that events flow from publisher to subscriber."""
        bus = EventBus()
        received = []

        async def handler(event):
            received.append(event)

        bus.subscribe(handler)
        await bus.start()

        try:
            event = Event(
                category=EventCategory.SYSTEM,
                event_type="test.flow",
                severity=EventSeverity.INFO,
                source="test",
                title="Flow test",
            )

            await bus.publish(event)
            await asyncio.sleep(0.2)

            assert len(received) == 1
            assert received[0].event_type == "test.flow"

        finally:
            await bus.stop()

    @pytest.mark.asyncio
    async def test_filtered_subscription(self):
        """Test that filtered subscriptions only receive matching events."""
        bus = EventBus()
        security_events = []
        network_events = []

        async def security_handler(event):
            security_events.append(event)

        async def network_handler(event):
            network_events.append(event)

        bus.subscribe(security_handler, category=EventCategory.SECURITY)
        bus.subscribe(network_handler, category=EventCategory.NETWORK)
        await bus.start()

        try:
            # Publish different category events
            await bus.publish(Event(
                category=EventCategory.SECURITY,
                event_type="security.alert",
                severity=EventSeverity.WARNING,
                source="test",
                title="Security alert",
            ))

            await bus.publish(Event(
                category=EventCategory.NETWORK,
                event_type="network.change",
                severity=EventSeverity.INFO,
                source="test",
                title="Network change",
            ))

            await bus.publish(Event(
                category=EventCategory.SYSTEM,
                event_type="system.update",
                severity=EventSeverity.INFO,
                source="test",
                title="System update",
            ))

            await asyncio.sleep(0.3)

            # Each handler should only receive their category
            assert len(security_events) == 1
            assert security_events[0].category == EventCategory.SECURITY

            assert len(network_events) == 1
            assert network_events[0].category == EventCategory.NETWORK

        finally:
            await bus.stop()

    @pytest.mark.asyncio
    async def test_event_type_filter(self):
        """Test filtering by specific event type."""
        bus = EventBus()
        discovery_events = []

        async def handler(event):
            discovery_events.append(event)

        bus.subscribe(handler, event_type="device.discovered")
        await bus.start()

        try:
            # Publish different event types
            await bus.publish(Event(
                category=EventCategory.DEVICE,
                event_type="device.discovered",
                severity=EventSeverity.INFO,
                source="discovery",
                title="Device discovered",
            ))

            await bus.publish(Event(
                category=EventCategory.DEVICE,
                event_type="device.updated",
                severity=EventSeverity.INFO,
                source="discovery",
                title="Device updated",
            ))

            await asyncio.sleep(0.2)

            # Should only receive discovery events
            assert len(discovery_events) == 1
            assert discovery_events[0].event_type == "device.discovered"

        finally:
            await bus.stop()

    @pytest.mark.asyncio
    async def test_event_ordering(self):
        """Test that events are processed in order."""
        bus = EventBus()
        received_order = []

        async def handler(event):
            received_order.append(int(event.data.get("order", -1)))

        bus.subscribe(handler)
        await bus.start()

        try:
            # Publish events in order
            for i in range(10):
                await bus.publish(Event(
                    category=EventCategory.SYSTEM,
                    event_type="test.ordered",
                    severity=EventSeverity.INFO,
                    source="test",
                    title=f"Event {i}",
                    data={"order": i},
                ))

            await asyncio.sleep(0.3)

            # Verify order is preserved
            assert received_order == list(range(10))

        finally:
            await bus.stop()

    @pytest.mark.asyncio
    async def test_event_with_correlation(self):
        """Test events with correlation IDs."""
        bus = EventBus()
        received = []

        async def handler(event):
            received.append(event)

        bus.subscribe(handler)
        await bus.start()

        try:
            # Create parent event
            correlation_id = uuid4()
            parent = Event(
                id=correlation_id,
                category=EventCategory.SYSTEM,
                event_type="workflow.started",
                severity=EventSeverity.INFO,
                source="test",
                title="Workflow started",
            )
            await bus.publish(parent)

            # Create child events with same correlation
            for i in range(3):
                child = Event(
                    category=EventCategory.SYSTEM,
                    event_type=f"workflow.step.{i}",
                    severity=EventSeverity.INFO,
                    source="test",
                    title=f"Workflow step {i}",
                    correlation_id=correlation_id,
                )
                await bus.publish(child)

            await asyncio.sleep(0.3)

            # Verify correlation
            correlated = [e for e in received if e.correlation_id == correlation_id]
            assert len(correlated) == 3

        finally:
            await bus.stop()

    @pytest.mark.asyncio
    async def test_event_history_maintained(self):
        """Test that event history is maintained."""
        bus = EventBus()
        await bus.start()

        try:
            # Publish several events
            for i in range(5):
                await bus.publish(Event(
                    category=EventCategory.SYSTEM,
                    event_type=f"test.history.{i}",
                    severity=EventSeverity.INFO,
                    source="test",
                    title=f"History event {i}",
                ))

            await asyncio.sleep(0.2)

            # Check history
            recent = bus.get_recent_events(10)
            assert len(recent) >= 5

        finally:
            await bus.stop()


class TestEventFlowWithEngine:
    """Tests for event flow through the full engine."""

    @pytest.fixture
    def engine_config(self):
        return {
            "agents": {
                "discovery": {"enabled": True},
                "guardian": {"enabled": True},
            },
            "state": {"backend": "memory"},
        }

    @pytest.mark.asyncio
    async def test_engine_startup_event_flow(self, engine_config):
        """Test that engine startup generates proper event flow."""
        engine = SentinelEngine(engine_config)
        startup_events = []

        async def handler(event):
            if event.event_type == "engine.started":
                startup_events.append(event)

        engine.event_bus.subscribe(handler, event_type="engine.started")

        await engine.start()
        await asyncio.sleep(0.2)
        await engine.stop()

        assert len(startup_events) >= 1
        assert startup_events[0].source == "sentinel.engine"

    @pytest.mark.asyncio
    async def test_cross_agent_event_flow(self, engine_config):
        """Test that events flow between agents."""
        engine = SentinelEngine(engine_config)

        # Track events received by guardian
        guardian_received = []

        await engine.start()

        try:
            async def track_events(event):
                if event.category == EventCategory.DEVICE:
                    guardian_received.append(event)

            engine.event_bus.subscribe(track_events, category=EventCategory.DEVICE)

            # Simulate discovery finding a device
            device_event = Event(
                category=EventCategory.DEVICE,
                event_type="device.discovered",
                severity=EventSeverity.INFO,
                source="discovery",
                title="New device found",
                data={
                    "mac": "AA:BB:CC:DD:EE:FF",
                    "ip": "192.168.1.100",
                },
            )
            await engine.event_bus.publish(device_event)
            await asyncio.sleep(0.2)

            # Guardian should have received the device event
            assert len(guardian_received) >= 1

        finally:
            await engine.stop()

    @pytest.mark.asyncio
    async def test_security_event_escalation(self, engine_config):
        """Test security event escalation flow."""
        engine = SentinelEngine(engine_config)
        escalated = []

        await engine.start()

        try:
            async def track_security(event):
                if event.severity in [EventSeverity.WARNING, EventSeverity.ERROR, EventSeverity.CRITICAL]:
                    escalated.append(event)

            engine.event_bus.subscribe(track_security, category=EventCategory.SECURITY)

            # Publish escalating security events
            await engine.event_bus.publish(Event(
                category=EventCategory.SECURITY,
                event_type="security.scan_detected",
                severity=EventSeverity.WARNING,
                source="guardian",
                title="Port scan detected",
            ))

            await engine.event_bus.publish(Event(
                category=EventCategory.SECURITY,
                event_type="security.threat",
                severity=EventSeverity.ERROR,
                source="guardian",
                title="Active threat detected",
            ))

            await asyncio.sleep(0.2)

            assert len(escalated) == 2

        finally:
            await engine.stop()

    @pytest.mark.asyncio
    async def test_event_triggers_state_update(self, engine_config):
        """Test that events can trigger state updates."""
        engine = SentinelEngine(engine_config)

        await engine.start()

        try:
            async def update_state_on_event(event):
                if event.event_type == "device.discovered":
                    await engine.state.increment("devices:discovered_count")

            engine.event_bus.subscribe(update_state_on_event, event_type="device.discovered")

            # Initialize counter
            await engine.state.set("devices:discovered_count", 0)

            # Publish discovery events
            for i in range(5):
                await engine.event_bus.publish(Event(
                    category=EventCategory.DEVICE,
                    event_type="device.discovered",
                    severity=EventSeverity.INFO,
                    source="discovery",
                    title=f"Device {i} found",
                ))

            await asyncio.sleep(0.3)

            # Verify state was updated
            count = await engine.state.get("devices:discovered_count")
            assert count == 5

        finally:
            await engine.stop()


class TestAgentActionFlow:
    """Tests for agent action event flow."""

    @pytest.fixture
    def engine_config(self):
        return {
            "agents": {
                "guardian": {"enabled": True},
                "planner": {"enabled": True},
            },
            "state": {"backend": "memory"},
        }

    @pytest.mark.asyncio
    async def test_action_creates_event(self, engine_config):
        """Test that agent actions create events."""
        engine = SentinelEngine(engine_config)
        action_events = []

        await engine.start()

        try:
            async def track_actions(event):
                # Only track action.executed events, not agent.started events
                if event.category == EventCategory.AGENT and event.event_type == "agent.action.executed":
                    action_events.append(event)

            engine.event_bus.subscribe(track_actions, category=EventCategory.AGENT)

            # Create an action event
            action = AgentAction(
                agent_name="guardian",
                action_type="block_ip",
                target_type="ip",
                target_id="192.168.1.200",
                parameters={"reason": "port scan"},
                reasoning="Detected port scan from this IP",
                confidence=0.95,
            )

            # Publish action event
            await engine.event_bus.publish(Event(
                category=EventCategory.AGENT,
                event_type="agent.action.executed",
                severity=EventSeverity.INFO,
                source="guardian",
                title="IP Blocked",
                data={
                    "action_type": action.action_type,
                    "target": action.target_id,
                },
            ))

            await asyncio.sleep(0.2)

            assert len(action_events) >= 1
            assert action_events[0].data["action_type"] == "block_ip"

        finally:
            await engine.stop()

    @pytest.mark.asyncio
    async def test_action_chain_events(self, engine_config):
        """Test chain of events from a single action."""
        engine = SentinelEngine(engine_config)
        event_chain = []

        await engine.start()

        try:
            async def track_all(event):
                event_chain.append(event)

            engine.event_bus.subscribe(track_all)

            # Simulate a threat detection triggering multiple actions
            correlation_id = uuid4()

            # Detection event
            await engine.event_bus.publish(Event(
                id=correlation_id,
                category=EventCategory.SECURITY,
                event_type="threat.detected",
                severity=EventSeverity.WARNING,
                source="guardian",
                title="Threat detected",
            ))

            # Analysis event
            await engine.event_bus.publish(Event(
                category=EventCategory.AGENT,
                event_type="agent.analyzing",
                severity=EventSeverity.INFO,
                source="guardian",
                title="Analyzing threat",
                correlation_id=correlation_id,
            ))

            # Action event
            await engine.event_bus.publish(Event(
                category=EventCategory.AGENT,
                event_type="agent.action.executed",
                severity=EventSeverity.INFO,
                source="guardian",
                title="Mitigation applied",
                correlation_id=correlation_id,
            ))

            await asyncio.sleep(0.3)

            # Verify chain
            assert len(event_chain) >= 3
            correlated = [e for e in event_chain if e.correlation_id == correlation_id]
            assert len(correlated) >= 2

        finally:
            await engine.stop()


class TestEventErrorHandling:
    """Tests for error handling in event flow."""

    @pytest.mark.asyncio
    async def test_handler_error_doesnt_stop_bus(self):
        """Test that handler errors don't stop event processing."""
        bus = EventBus()
        successful_receives = []

        async def failing_handler(event):
            raise Exception("Handler failed")

        async def successful_handler(event):
            successful_receives.append(event)

        bus.subscribe(failing_handler)
        bus.subscribe(successful_handler)
        await bus.start()

        try:
            # Publish event - failing handler shouldn't stop successful one
            await bus.publish(Event(
                category=EventCategory.SYSTEM,
                event_type="test.error",
                severity=EventSeverity.INFO,
                source="test",
                title="Error test",
            ))

            await asyncio.sleep(0.2)

            # Successful handler should still receive
            assert len(successful_receives) >= 1

        finally:
            await bus.stop()

    @pytest.mark.asyncio
    async def test_slow_handler_doesnt_block(self):
        """Test that slow handlers don't block other handlers."""
        bus = EventBus()
        fast_receives = []
        slow_receives = []

        async def slow_handler(event):
            await asyncio.sleep(0.5)
            slow_receives.append(event)

        async def fast_handler(event):
            fast_receives.append(event)

        bus.subscribe(slow_handler)
        bus.subscribe(fast_handler)
        await bus.start()

        try:
            await bus.publish(Event(
                category=EventCategory.SYSTEM,
                event_type="test.slow",
                severity=EventSeverity.INFO,
                source="test",
                title="Slow test",
            ))

            # Fast handler should receive quickly
            await asyncio.sleep(0.1)
            assert len(fast_receives) >= 1

            # Wait for slow handler
            await asyncio.sleep(0.5)
            assert len(slow_receives) >= 1

        finally:
            await bus.stop()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
