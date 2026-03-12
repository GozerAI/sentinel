"""
Event bus for internal message passing.

This module provides an asynchronous event bus for decoupled communication
between components in the Sentinel platform.
"""

import asyncio
import logging
from collections import defaultdict
from datetime import datetime
from typing import Callable, Awaitable, Optional

from sentinel.core.models.event import Event, EventCategory

logger = logging.getLogger(__name__)

# Type alias for event handlers
EventHandler = Callable[[Event], Awaitable[None]]


class EventBus:
    """
    Async event bus for decoupled communication between components.

    The EventBus is the central nervous system of the Sentinel platform.
    It enables pub/sub communication between components without tight coupling.

    Features:
    - Pub/sub pattern with async handlers
    - Event filtering by category and type
    - Event persistence for replay
    - Concurrent handler execution

    Attributes:
        persist_events: Whether to store events for later retrieval
        max_queue_size: Maximum events in the processing queue

    Example:
        ```python
        bus = EventBus()
        await bus.start()

        # Subscribe to events
        async def handle_device(event: Event):
            print(f"Device event: {event.title}")

        bus.subscribe(handle_device, category=EventCategory.DEVICE)

        # Publish events
        await bus.publish(Event(
            category=EventCategory.DEVICE,
            event_type="device.discovered",
            source="discovery",
            title="New device found"
        ))

        await bus.stop()
        ```
    """

    def __init__(self, persist_events: bool = True, max_queue_size: int = 10000):
        """
        Initialize the event bus.

        Args:
            persist_events: Whether to store events in history
            max_queue_size: Maximum queue size before blocking
        """
        # Handler registries
        self._handlers: dict[str, list[EventHandler]] = defaultdict(list)
        self._category_handlers: dict[EventCategory, list[EventHandler]] = defaultdict(list)
        self._global_handlers: list[EventHandler] = []

        # Event processing
        self._queue: asyncio.Queue[Event] = asyncio.Queue(maxsize=max_queue_size)
        self._persist_events = persist_events
        self._event_history: list[Event] = []
        self._max_history = 10000

        # State
        self._running = False
        self._processor_task: Optional[asyncio.Task] = None

        # Metrics
        self._events_processed = 0
        self._events_dropped = 0

    async def start(self) -> None:
        """Start the event processor task."""
        self._running = True
        self._processor_task = asyncio.create_task(self._process_events())
        logger.info("Event bus started")

    async def stop(self) -> None:
        """Stop the event processor task."""
        self._running = False

        if self._processor_task:
            self._processor_task.cancel()
            try:
                await self._processor_task
            except asyncio.CancelledError:
                pass

        logger.info(
            f"Event bus stopped - processed {self._events_processed} events, "
            f"dropped {self._events_dropped}"
        )

    def subscribe(
        self,
        handler: EventHandler,
        event_type: Optional[str] = None,
        category: Optional[EventCategory] = None,
    ) -> None:
        """
        Subscribe a handler to events.

        Handlers can be subscribed to:
        - Specific event types (e.g., "device.discovered")
        - Event categories (e.g., EventCategory.DEVICE)
        - All events (global handler)

        Args:
            handler: Async function to handle events
            event_type: Specific event type to subscribe to
            category: Event category to subscribe to

        Example:
            ```python
            # Subscribe to specific event type
            bus.subscribe(handler, event_type="device.discovered")

            # Subscribe to category
            bus.subscribe(handler, category=EventCategory.SECURITY)

            # Subscribe to all events
            bus.subscribe(handler)
            ```
        """
        if event_type:
            self._handlers[event_type].append(handler)
            logger.debug(f"Handler subscribed to event type: {event_type}")
        elif category:
            self._category_handlers[category].append(handler)
            logger.debug(f"Handler subscribed to category: {category}")
        else:
            self._global_handlers.append(handler)
            logger.debug("Global handler subscribed")

    def unsubscribe(
        self,
        handler: EventHandler,
        event_type: Optional[str] = None,
        category: Optional[EventCategory] = None,
    ) -> None:
        """
        Unsubscribe a handler from events.

        Args:
            handler: Handler to unsubscribe
            event_type: Event type to unsubscribe from
            category: Category to unsubscribe from
        """
        if event_type and handler in self._handlers[event_type]:
            self._handlers[event_type].remove(handler)
        elif category and handler in self._category_handlers[category]:
            self._category_handlers[category].remove(handler)
        elif handler in self._global_handlers:
            self._global_handlers.remove(handler)

    async def publish(self, event: Event) -> None:
        """
        Publish an event to the bus.

        Events are queued for async processing. If the queue is full,
        this method will block until space is available.

        Args:
            event: Event to publish
        """
        try:
            await asyncio.wait_for(self._queue.put(event), timeout=5.0)
        except asyncio.TimeoutError:
            self._events_dropped += 1
            logger.warning(f"Event dropped due to full queue: {event.event_type}")

    def publish_sync(self, event: Event) -> None:
        """
        Synchronously queue an event (non-blocking).

        Use this when you need to publish from a sync context.
        Event will be dropped if queue is full.

        Args:
            event: Event to publish
        """
        try:
            self._queue.put_nowait(event)
        except asyncio.QueueFull:
            self._events_dropped += 1
            logger.warning(f"Event dropped (queue full): {event.event_type}")

    async def _process_events(self) -> None:
        """Main event processing loop."""
        while self._running:
            try:
                # Wait for event with timeout to allow checking _running
                event = await asyncio.wait_for(self._queue.get(), timeout=1.0)

                # Persist event if enabled
                if self._persist_events:
                    self._event_history.append(event)
                    # Trim history if too large
                    if len(self._event_history) > self._max_history:
                        self._event_history = self._event_history[-self._max_history :]

                # Dispatch to handlers
                await self._dispatch(event)

                self._events_processed += 1

            except asyncio.TimeoutError:
                # Normal timeout, continue loop
                continue
            except Exception as e:
                logger.error(f"Error processing event: {e}")

    async def _dispatch(self, event: Event) -> None:
        """Dispatch event to all matching handlers."""
        handlers: list[EventHandler] = []

        # Collect matching handlers
        handlers.extend(self._global_handlers)
        handlers.extend(self._category_handlers.get(event.category, []))
        handlers.extend(self._handlers.get(event.event_type, []))

        if not handlers:
            return

        # Execute handlers concurrently
        results = await asyncio.gather(
            *[self._safe_handle(h, event) for h in handlers], return_exceptions=True
        )

        # Log any exceptions
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                logger.error(f"Handler exception for {event.event_type}: {result}")

    async def _safe_handle(self, handler: EventHandler, event: Event) -> None:
        """Safely execute a handler with error handling."""
        try:
            await handler(event)
        except Exception as e:
            logger.error(
                f"Handler error for event {event.id} ({event.event_type}): {e}", exc_info=True
            )

    def get_recent_events(
        self,
        count: int = 100,
        category: Optional[EventCategory] = None,
        event_type: Optional[str] = None,
        since: Optional[datetime] = None,
    ) -> list[Event]:
        """
        Get recent events from history.

        Args:
            count: Maximum number of events to return
            category: Filter by category
            event_type: Filter by event type
            since: Only events after this timestamp

        Returns:
            List of matching events, most recent first
        """
        events = self._event_history

        if category:
            events = [e for e in events if e.category == category]
        if event_type:
            events = [e for e in events if e.event_type == event_type]
        if since:
            events = [e for e in events if e.timestamp > since]

        return events[-count:]

    def get_event_by_id(self, event_id) -> Optional[Event]:
        """
        Get a specific event by ID.

        Args:
            event_id: Event UUID

        Returns:
            Event if found, None otherwise
        """
        for event in self._event_history:
            if event.id == event_id:
                return event
        return None

    @property
    def queue_size(self) -> int:
        """Current number of events in the queue."""
        return self._queue.qsize()

    @property
    def history_size(self) -> int:
        """Current number of events in history."""
        return len(self._event_history)

    @property
    def stats(self) -> dict:
        """Get event bus statistics."""
        return {
            "events_processed": self._events_processed,
            "events_dropped": self._events_dropped,
            "queue_size": self.queue_size,
            "history_size": self.history_size,
            "handlers": {
                "global": len(self._global_handlers),
                "by_category": {
                    cat.value: len(handlers) for cat, handlers in self._category_handlers.items()
                },
                "by_type": {etype: len(handlers) for etype, handlers in self._handlers.items()},
            },
        }
