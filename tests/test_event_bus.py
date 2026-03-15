"""
Tests for the EventBus module.

Tests cover subscription, publishing, filtering, history, and error handling.
"""
import asyncio
import pytest
from unittest.mock import AsyncMock, patch
from datetime import datetime, timedelta
from uuid import uuid4

from sentinel.core.event_bus import EventBus
from sentinel.core.models.event import Event, EventCategory, EventSeverity
from sentinel.core.utils import utc_now


def create_test_event(
    category: EventCategory = EventCategory.SYSTEM,
    event_type: str = "test.event",
    severity: EventSeverity = EventSeverity.INFO,
    source: str = "test",
    title: str = "Test Event",
    **kwargs
) -> Event:
    """Helper to create test events."""
    return Event(
        category=category,
        event_type=event_type,
        severity=severity,
        source=source,
        title=title,
        **kwargs
    )


class TestEventBusInit:
    """Tests for EventBus initialization."""

    def test_default_init(self):
        """Test default initialization."""
        bus = EventBus()

        assert bus._persist_events is True
        assert bus._running is False
        assert bus._processor_task is None
        assert bus._events_processed == 0
        assert bus._events_dropped == 0
        assert len(bus._global_handlers) == 0

    def test_custom_init(self):
        """Test initialization with custom parameters."""
        bus = EventBus(persist_events=False, max_queue_size=100)

        assert bus._persist_events is False
        assert bus._queue.maxsize == 100


class TestEventBusLifecycle:
    """Tests for EventBus start/stop lifecycle."""

    @pytest.mark.asyncio
    async def test_start(self):
        """Test starting the event bus."""
        bus = EventBus()
        await bus.start()

        try:
            assert bus._running is True
            assert bus._processor_task is not None
        finally:
            await bus.stop()

    @pytest.mark.asyncio
    async def test_stop(self):
        """Test stopping the event bus."""
        bus = EventBus()
        await bus.start()
        await bus.stop()

        assert bus._running is False

    @pytest.mark.asyncio
    async def test_stop_without_start(self):
        """Test stopping without starting."""
        bus = EventBus()
        # Should not raise
        await bus.stop()

        assert bus._running is False


class TestEventBusSubscription:
    """Tests for handler subscription."""

    def test_subscribe_global(self):
        """Test subscribing a global handler."""
        bus = EventBus()

        async def handler(event):
            pass

        bus.subscribe(handler)

        assert handler in bus._global_handlers

    def test_subscribe_by_event_type(self):
        """Test subscribing to specific event type."""
        bus = EventBus()

        async def handler(event):
            pass

        bus.subscribe(handler, event_type="device.discovered")

        assert handler in bus._handlers["device.discovered"]

    def test_subscribe_by_category(self):
        """Test subscribing to event category."""
        bus = EventBus()

        async def handler(event):
            pass

        bus.subscribe(handler, category=EventCategory.SECURITY)

        assert handler in bus._category_handlers[EventCategory.SECURITY]

    def test_multiple_subscriptions(self):
        """Test multiple handlers for same event type."""
        bus = EventBus()

        async def handler1(event):
            pass

        async def handler2(event):
            pass

        bus.subscribe(handler1, event_type="test.event")
        bus.subscribe(handler2, event_type="test.event")

        assert len(bus._handlers["test.event"]) == 2

    def test_unsubscribe_global(self):
        """Test unsubscribing global handler."""
        bus = EventBus()

        async def handler(event):
            pass

        bus.subscribe(handler)
        bus.unsubscribe(handler)

        assert handler not in bus._global_handlers

    def test_unsubscribe_by_event_type(self):
        """Test unsubscribing from event type."""
        bus = EventBus()

        async def handler(event):
            pass

        bus.subscribe(handler, event_type="test.event")
        bus.unsubscribe(handler, event_type="test.event")

        assert handler not in bus._handlers["test.event"]

    def test_unsubscribe_by_category(self):
        """Test unsubscribing from category."""
        bus = EventBus()

        async def handler(event):
            pass

        bus.subscribe(handler, category=EventCategory.DEVICE)
        bus.unsubscribe(handler, category=EventCategory.DEVICE)

        assert handler not in bus._category_handlers[EventCategory.DEVICE]

    def test_unsubscribe_non_existent(self):
        """Test unsubscribing handler that isn't subscribed."""
        bus = EventBus()

        async def handler(event):
            pass

        # Should not raise
        bus.unsubscribe(handler)
        bus.unsubscribe(handler, event_type="test.event")
        bus.unsubscribe(handler, category=EventCategory.DEVICE)


class TestEventBusPublish:
    """Tests for event publishing."""

    @pytest.mark.asyncio
    async def test_publish_delivers_to_global_handler(self):
        """Test publishing delivers event to global handler."""
        bus = EventBus()
        received = []

        async def handler(event):
            received.append(event)

        bus.subscribe(handler)
        await bus.start()

        try:
            event = create_test_event()
            await bus.publish(event)
            await asyncio.sleep(0.1)

            assert len(received) == 1
            assert received[0].event_type == "test.event"
        finally:
            await bus.stop()

    @pytest.mark.asyncio
    async def test_publish_delivers_to_category_handler(self):
        """Test publishing delivers event to category handler."""
        bus = EventBus()
        received = []

        async def handler(event):
            received.append(event)

        bus.subscribe(handler, category=EventCategory.SECURITY)
        await bus.start()

        try:
            # Matching category
            await bus.publish(create_test_event(category=EventCategory.SECURITY))
            # Non-matching category
            await bus.publish(create_test_event(category=EventCategory.NETWORK))
            await asyncio.sleep(0.1)

            assert len(received) == 1
            assert received[0].category == EventCategory.SECURITY
        finally:
            await bus.stop()

    @pytest.mark.asyncio
    async def test_publish_delivers_to_event_type_handler(self):
        """Test publishing delivers event to event type handler."""
        bus = EventBus()
        received = []

        async def handler(event):
            received.append(event)

        bus.subscribe(handler, event_type="device.discovered")
        await bus.start()

        try:
            # Matching type
            await bus.publish(create_test_event(event_type="device.discovered"))
            # Non-matching type
            await bus.publish(create_test_event(event_type="device.updated"))
            await asyncio.sleep(0.1)

            assert len(received) == 1
            assert received[0].event_type == "device.discovered"
        finally:
            await bus.stop()

    @pytest.mark.asyncio
    async def test_publish_sync(self):
        """Test synchronous publishing."""
        bus = EventBus()
        received = []

        async def handler(event):
            received.append(event)

        bus.subscribe(handler)
        await bus.start()

        try:
            event = create_test_event()
            bus.publish_sync(event)
            await asyncio.sleep(0.1)

            assert len(received) == 1
        finally:
            await bus.stop()

    @pytest.mark.asyncio
    async def test_publish_sync_queue_full(self):
        """Test sync publish when queue is full."""
        bus = EventBus(max_queue_size=1)

        # Fill the queue without processing
        event1 = create_test_event()
        event2 = create_test_event()

        bus.publish_sync(event1)
        bus.publish_sync(event2)  # Should be dropped

        assert bus._events_dropped == 1


class TestEventBusEventPersistence:
    """Tests for event history persistence."""

    @pytest.mark.asyncio
    async def test_events_persisted(self):
        """Test that events are persisted when enabled."""
        bus = EventBus(persist_events=True)
        await bus.start()

        try:
            await bus.publish(create_test_event())
            await asyncio.sleep(0.1)

            assert len(bus._event_history) == 1
        finally:
            await bus.stop()

    @pytest.mark.asyncio
    async def test_events_not_persisted_when_disabled(self):
        """Test that events are not persisted when disabled."""
        bus = EventBus(persist_events=False)
        await bus.start()

        try:
            await bus.publish(create_test_event())
            await asyncio.sleep(0.1)

            assert len(bus._event_history) == 0
        finally:
            await bus.stop()

    @pytest.mark.asyncio
    async def test_history_trimmed(self):
        """Test that history is trimmed when too large."""
        bus = EventBus(persist_events=True)
        bus._max_history = 5
        await bus.start()

        try:
            for i in range(10):
                await bus.publish(create_test_event(title=f"Event {i}"))
            await asyncio.sleep(0.2)

            # Should only have last 5 events
            assert len(bus._event_history) == 5
            # Most recent events should be kept
            assert bus._event_history[-1].title == "Event 9"
        finally:
            await bus.stop()


class TestEventBusGetRecentEvents:
    """Tests for getting recent events."""

    @pytest.mark.asyncio
    async def test_get_recent_events(self):
        """Test getting recent events."""
        bus = EventBus()
        await bus.start()

        try:
            for i in range(5):
                await bus.publish(create_test_event(title=f"Event {i}"))
            await asyncio.sleep(0.2)

            recent = bus.get_recent_events(10)
            assert len(recent) == 5
        finally:
            await bus.stop()

    @pytest.mark.asyncio
    async def test_get_recent_events_with_limit(self):
        """Test getting limited recent events."""
        bus = EventBus()
        await bus.start()

        try:
            for i in range(10):
                await bus.publish(create_test_event(title=f"Event {i}"))
            await asyncio.sleep(0.2)

            recent = bus.get_recent_events(3)
            assert len(recent) == 3
        finally:
            await bus.stop()

    @pytest.mark.asyncio
    async def test_get_recent_events_filter_by_category(self):
        """Test filtering events by category."""
        bus = EventBus()
        await bus.start()

        try:
            await bus.publish(create_test_event(category=EventCategory.SECURITY))
            await bus.publish(create_test_event(category=EventCategory.NETWORK))
            await bus.publish(create_test_event(category=EventCategory.SECURITY))
            await asyncio.sleep(0.2)

            security_events = bus.get_recent_events(10, category=EventCategory.SECURITY)
            assert len(security_events) == 2
            for e in security_events:
                assert e.category == EventCategory.SECURITY
        finally:
            await bus.stop()

    @pytest.mark.asyncio
    async def test_get_recent_events_filter_by_type(self):
        """Test filtering events by event type."""
        bus = EventBus()
        await bus.start()

        try:
            await bus.publish(create_test_event(event_type="device.discovered"))
            await bus.publish(create_test_event(event_type="device.updated"))
            await bus.publish(create_test_event(event_type="device.discovered"))
            await asyncio.sleep(0.2)

            discovered = bus.get_recent_events(10, event_type="device.discovered")
            assert len(discovered) == 2
        finally:
            await bus.stop()

    @pytest.mark.asyncio
    async def test_get_recent_events_filter_by_since(self):
        """Test filtering events by timestamp."""
        bus = EventBus()
        await bus.start()

        try:
            # Add older event
            old_event = create_test_event(title="Old")
            old_event.timestamp = utc_now() - timedelta(hours=1)
            bus._event_history.append(old_event)

            # Add new event
            await bus.publish(create_test_event(title="New"))
            await asyncio.sleep(0.1)

            since = utc_now() - timedelta(minutes=5)
            recent = bus.get_recent_events(10, since=since)

            assert len(recent) == 1
            assert recent[0].title == "New"
        finally:
            await bus.stop()


class TestEventBusGetEventById:
    """Tests for getting event by ID."""

    @pytest.mark.asyncio
    async def test_get_event_by_id_found(self):
        """Test getting event by ID when found."""
        bus = EventBus()
        await bus.start()

        try:
            event = create_test_event()
            await bus.publish(event)
            await asyncio.sleep(0.1)

            found = bus.get_event_by_id(event.id)
            assert found is not None
            assert found.id == event.id
        finally:
            await bus.stop()

    @pytest.mark.asyncio
    async def test_get_event_by_id_not_found(self):
        """Test getting event by ID when not found."""
        bus = EventBus()
        await bus.start()

        try:
            found = bus.get_event_by_id(uuid4())
            assert found is None
        finally:
            await bus.stop()


class TestEventBusErrorHandling:
    """Tests for error handling in event processing."""

    @pytest.mark.asyncio
    async def test_handler_error_doesnt_stop_processing(self):
        """Test that handler errors don't stop event processing."""
        bus = EventBus()
        successful_receives = []

        async def failing_handler(event):
            raise ValueError("Handler failed!")

        async def successful_handler(event):
            successful_receives.append(event)

        bus.subscribe(failing_handler)
        bus.subscribe(successful_handler)
        await bus.start()

        try:
            await bus.publish(create_test_event())
            await asyncio.sleep(0.1)

            # Should still process despite error
            assert len(successful_receives) == 1
        finally:
            await bus.stop()

    @pytest.mark.asyncio
    async def test_multiple_events_after_error(self):
        """Test that events continue to process after an error."""
        bus = EventBus()
        received = []
        call_count = [0]

        async def sometimes_failing_handler(event):
            call_count[0] += 1
            if call_count[0] == 1:
                raise Exception("First call fails")
            received.append(event)

        bus.subscribe(sometimes_failing_handler)
        await bus.start()

        try:
            await bus.publish(create_test_event(title="First"))
            await bus.publish(create_test_event(title="Second"))
            await asyncio.sleep(0.2)

            # Second event should still be processed
            assert len(received) >= 1
        finally:
            await bus.stop()


class TestEventBusProperties:
    """Tests for EventBus properties."""

    def test_queue_size(self):
        """Test queue_size property."""
        bus = EventBus()

        assert bus.queue_size == 0

        bus.publish_sync(create_test_event())
        assert bus.queue_size == 1

    def test_history_size(self):
        """Test history_size property."""
        bus = EventBus()

        assert bus.history_size == 0

        bus._event_history.append(create_test_event())
        assert bus.history_size == 1

    def test_stats(self):
        """Test stats property."""
        bus = EventBus()

        async def handler1(event):
            pass

        async def handler2(event):
            pass

        bus.subscribe(handler1)
        bus.subscribe(handler2, event_type="test.event")
        bus.subscribe(handler1, category=EventCategory.SECURITY)

        stats = bus.stats

        assert stats["events_processed"] == 0
        assert stats["events_dropped"] == 0
        assert stats["queue_size"] == 0
        assert stats["history_size"] == 0
        assert stats["handlers"]["global"] == 1
        assert "security" in stats["handlers"]["by_category"]
        assert "test.event" in stats["handlers"]["by_type"]

    @pytest.mark.asyncio
    async def test_stats_after_processing(self):
        """Test stats after processing events."""
        bus = EventBus()
        await bus.start()

        try:
            for i in range(5):
                await bus.publish(create_test_event())
            await asyncio.sleep(0.2)

            stats = bus.stats
            assert stats["events_processed"] == 5
            assert stats["history_size"] == 5
        finally:
            await bus.stop()


class TestEventBusConcurrentHandlers:
    """Tests for concurrent handler execution."""

    @pytest.mark.asyncio
    async def test_handlers_run_concurrently(self):
        """Test that handlers for same event run concurrently."""
        bus = EventBus()
        execution_times = []

        async def slow_handler(event):
            execution_times.append(("slow_start", utc_now()))
            await asyncio.sleep(0.1)
            execution_times.append(("slow_end", utc_now()))

        async def fast_handler(event):
            execution_times.append(("fast_start", utc_now()))
            execution_times.append(("fast_end", utc_now()))

        bus.subscribe(slow_handler)
        bus.subscribe(fast_handler)
        await bus.start()

        try:
            await bus.publish(create_test_event())
            await asyncio.sleep(0.2)

            # Fast handler should complete while slow handler is still running
            slow_start_idx = next(i for i, (name, _) in enumerate(execution_times) if name == "slow_start")
            slow_end_idx = next(i for i, (name, _) in enumerate(execution_times) if name == "slow_end")
            fast_end_idx = next(i for i, (name, _) in enumerate(execution_times) if name == "fast_end")

            # Fast should finish before slow
            assert fast_end_idx < slow_end_idx
        finally:
            await bus.stop()


class TestEventBusDispatch:
    """Tests for event dispatch to different handler types."""

    @pytest.mark.asyncio
    async def test_event_dispatched_to_all_matching_handlers(self):
        """Test event is dispatched to global, category, and type handlers."""
        bus = EventBus()
        global_received = []
        category_received = []
        type_received = []

        async def global_handler(event):
            global_received.append(event)

        async def category_handler(event):
            category_received.append(event)

        async def type_handler(event):
            type_received.append(event)

        bus.subscribe(global_handler)
        bus.subscribe(category_handler, category=EventCategory.SECURITY)
        bus.subscribe(type_handler, event_type="security.alert")

        await bus.start()

        try:
            event = create_test_event(
                category=EventCategory.SECURITY,
                event_type="security.alert"
            )
            await bus.publish(event)
            await asyncio.sleep(0.1)

            # All handlers should receive the event
            assert len(global_received) == 1
            assert len(category_received) == 1
            assert len(type_received) == 1
        finally:
            await bus.stop()

    @pytest.mark.asyncio
    async def test_no_handlers_no_error(self):
        """Test publishing event with no handlers doesn't error."""
        bus = EventBus()
        await bus.start()

        try:
            # Should not raise
            await bus.publish(create_test_event())
            await asyncio.sleep(0.1)

            assert bus._events_processed == 1
        finally:
            await bus.stop()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
