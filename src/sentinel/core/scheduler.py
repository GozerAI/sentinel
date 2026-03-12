"""
Task scheduler for periodic operations.

This module provides a simple async task scheduler for running
periodic operations in the Sentinel platform.
"""

import asyncio
import logging
from datetime import datetime, timedelta
from typing import Callable, Awaitable, Optional
from dataclasses import dataclass, field
from uuid import UUID, uuid4

from sentinel.core.utils import utc_now

logger = logging.getLogger(__name__)

# Type alias for scheduled tasks
ScheduledTask = Callable[[], Awaitable[None]]


@dataclass
class Task:
    """Represents a scheduled task."""

    id: UUID = field(default_factory=uuid4)
    name: str = ""
    callback: ScheduledTask = None
    interval_seconds: float = 0
    run_immediately: bool = False
    enabled: bool = True

    # State
    last_run: Optional[datetime] = None
    next_run: Optional[datetime] = None
    run_count: int = 0
    error_count: int = 0
    last_error: Optional[str] = None

    def __post_init__(self):
        if self.run_immediately:
            self.next_run = utc_now()
        else:
            self.next_run = utc_now() + timedelta(seconds=self.interval_seconds)


class Scheduler:
    """
    Async task scheduler for periodic operations.

    Provides a simple way to schedule recurring tasks with configurable
    intervals. Tasks are executed concurrently and errors are logged
    but don't stop other tasks.

    Example:
        ```python
        scheduler = Scheduler()

        async def scan_network():
            print("Scanning network...")

        scheduler.add_task(
            "network_scan",
            scan_network,
            interval_seconds=300,  # Every 5 minutes
            run_immediately=True
        )

        await scheduler.start()
        # ... tasks run in background ...
        await scheduler.stop()
        ```
    """

    def __init__(self, tick_interval: float = 1.0):
        """
        Initialize the scheduler.

        Args:
            tick_interval: How often to check for due tasks (seconds)
        """
        self._tasks: dict[str, Task] = {}
        self._tick_interval = tick_interval
        self._running = False
        self._task: Optional[asyncio.Task] = None

    async def start(self) -> None:
        """Start the scheduler loop."""
        self._running = True
        self._task = asyncio.create_task(self._scheduler_loop())
        logger.info(f"Scheduler started with {len(self._tasks)} tasks")

    async def stop(self) -> None:
        """Stop the scheduler loop."""
        self._running = False

        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass

        logger.info("Scheduler stopped")

    def add_task(
        self,
        name: str,
        callback: ScheduledTask,
        interval_seconds: float,
        run_immediately: bool = False,
        enabled: bool = True,
    ) -> Task:
        """
        Add a task to the scheduler.

        Args:
            name: Unique task name
            callback: Async function to call
            interval_seconds: Time between runs
            run_immediately: Whether to run on first tick
            enabled: Whether task is active

        Returns:
            Created Task object
        """
        task = Task(
            name=name,
            callback=callback,
            interval_seconds=interval_seconds,
            run_immediately=run_immediately,
            enabled=enabled,
        )
        self._tasks[name] = task
        logger.debug(f"Task '{name}' added with {interval_seconds}s interval")
        return task

    def remove_task(self, name: str) -> bool:
        """
        Remove a task from the scheduler.

        Args:
            name: Task name to remove

        Returns:
            True if task was removed, False if not found
        """
        if name in self._tasks:
            del self._tasks[name]
            logger.debug(f"Task '{name}' removed")
            return True
        return False

    def enable_task(self, name: str) -> bool:
        """Enable a task."""
        if name in self._tasks:
            self._tasks[name].enabled = True
            return True
        return False

    def disable_task(self, name: str) -> bool:
        """Disable a task."""
        if name in self._tasks:
            self._tasks[name].enabled = False
            return True
        return False

    def get_task(self, name: str) -> Optional[Task]:
        """Get a task by name."""
        return self._tasks.get(name)

    async def run_task_now(self, name: str) -> bool:
        """
        Immediately run a task.

        Args:
            name: Task name to run

        Returns:
            True if task was found and executed
        """
        task = self._tasks.get(name)
        if not task:
            return False

        await self._execute_task(task)
        return True

    async def _scheduler_loop(self) -> None:
        """Main scheduler loop."""
        while self._running:
            now = utc_now()

            # Find due tasks
            due_tasks = [
                task
                for task in self._tasks.values()
                if task.enabled and task.next_run and task.next_run <= now
            ]

            # Execute due tasks concurrently
            if due_tasks:
                await asyncio.gather(
                    *[self._execute_task(task) for task in due_tasks], return_exceptions=True
                )

            # Wait for next tick
            await asyncio.sleep(self._tick_interval)

    async def _execute_task(self, task: Task) -> None:
        """Execute a single task."""
        try:
            logger.debug(f"Executing task '{task.name}'")
            await task.callback()

            task.last_run = utc_now()
            task.next_run = task.last_run + timedelta(seconds=task.interval_seconds)
            task.run_count += 1

        except Exception as e:
            task.error_count += 1
            task.last_error = str(e)
            logger.error(f"Task '{task.name}' failed: {e}", exc_info=True)

            # Still schedule next run
            task.next_run = utc_now() + timedelta(seconds=task.interval_seconds)

    @property
    def task_names(self) -> list[str]:
        """Get list of all task names."""
        return list(self._tasks.keys())

    @property
    def stats(self) -> dict:
        """Get scheduler statistics."""
        return {
            "running": self._running,
            "task_count": len(self._tasks),
            "tasks": {
                name: {
                    "enabled": task.enabled,
                    "interval_seconds": task.interval_seconds,
                    "run_count": task.run_count,
                    "error_count": task.error_count,
                    "last_run": task.last_run.isoformat() if task.last_run else None,
                    "next_run": task.next_run.isoformat() if task.next_run else None,
                    "last_error": task.last_error,
                }
                for name, task in self._tasks.items()
            },
        }
