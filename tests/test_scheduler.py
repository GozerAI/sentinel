"""
Tests for the Scheduler module.

Tests cover task scheduling, execution, state management, and error handling.
"""

import asyncio
import pytest
from unittest.mock import AsyncMock, patch
from datetime import datetime, timedelta

from sentinel.core.scheduler import Scheduler, Task
from sentinel.core.utils import utc_now


class TestTask:
    """Tests for Task dataclass."""

    def test_task_default_values(self):
        """Test task has correct default values."""
        task = Task()

        assert task.id is not None
        assert task.name == ""
        assert task.callback is None
        assert task.interval_seconds == 0
        assert task.run_immediately is False
        assert task.enabled is True
        assert task.last_run is None
        assert task.run_count == 0
        assert task.error_count == 0
        assert task.last_error is None

    def test_task_run_immediately_sets_next_run(self):
        """Test that run_immediately sets next_run to now."""
        before = utc_now()
        task = Task(run_immediately=True, interval_seconds=60)
        after = utc_now()

        assert task.next_run is not None
        assert before <= task.next_run <= after

    def test_task_delayed_sets_next_run_in_future(self):
        """Test that delayed task sets next_run to future."""
        before = utc_now()
        interval = 60
        task = Task(run_immediately=False, interval_seconds=interval)

        expected_min = before + timedelta(seconds=interval)
        expected_max = utc_now() + timedelta(seconds=interval)

        assert task.next_run is not None
        assert expected_min <= task.next_run <= expected_max

    def test_task_custom_values(self):
        """Test task with custom values."""

        async def my_callback():
            pass

        task = Task(
            name="custom_task",
            callback=my_callback,
            interval_seconds=30,
            run_immediately=True,
            enabled=False,
        )

        assert task.name == "custom_task"
        assert task.callback is my_callback
        assert task.interval_seconds == 30
        assert task.run_immediately is True
        assert task.enabled is False


class TestSchedulerBasic:
    """Basic scheduler tests."""

    def test_scheduler_init_default(self):
        """Test scheduler initializes with defaults."""
        scheduler = Scheduler()

        assert scheduler._tick_interval == 1.0
        assert scheduler._running is False
        assert scheduler._task is None
        assert len(scheduler._tasks) == 0

    def test_scheduler_init_custom_tick(self):
        """Test scheduler with custom tick interval."""
        scheduler = Scheduler(tick_interval=0.5)

        assert scheduler._tick_interval == 0.5

    def test_add_task(self):
        """Test adding a task."""
        scheduler = Scheduler()

        async def my_task():
            pass

        task = scheduler.add_task(name="test_task", callback=my_task, interval_seconds=60)

        assert task.name == "test_task"
        assert task.callback is my_task
        assert task.interval_seconds == 60
        assert "test_task" in scheduler._tasks

    def test_add_task_with_all_options(self):
        """Test adding task with all options."""
        scheduler = Scheduler()

        async def my_task():
            pass

        task = scheduler.add_task(
            name="full_task",
            callback=my_task,
            interval_seconds=120,
            run_immediately=True,
            enabled=False,
        )

        assert task.run_immediately is True
        assert task.enabled is False

    def test_remove_task_exists(self):
        """Test removing an existing task."""
        scheduler = Scheduler()

        async def my_task():
            pass

        scheduler.add_task("task1", my_task, 60)
        result = scheduler.remove_task("task1")

        assert result is True
        assert "task1" not in scheduler._tasks

    def test_remove_task_not_found(self):
        """Test removing a non-existent task."""
        scheduler = Scheduler()
        result = scheduler.remove_task("nonexistent")

        assert result is False

    def test_enable_task(self):
        """Test enabling a task."""
        scheduler = Scheduler()

        async def my_task():
            pass

        scheduler.add_task("task1", my_task, 60, enabled=False)
        result = scheduler.enable_task("task1")

        assert result is True
        assert scheduler._tasks["task1"].enabled is True

    def test_enable_task_not_found(self):
        """Test enabling non-existent task."""
        scheduler = Scheduler()
        result = scheduler.enable_task("nonexistent")

        assert result is False

    def test_disable_task(self):
        """Test disabling a task."""
        scheduler = Scheduler()

        async def my_task():
            pass

        scheduler.add_task("task1", my_task, 60, enabled=True)
        result = scheduler.disable_task("task1")

        assert result is True
        assert scheduler._tasks["task1"].enabled is False

    def test_disable_task_not_found(self):
        """Test disabling non-existent task."""
        scheduler = Scheduler()
        result = scheduler.disable_task("nonexistent")

        assert result is False

    def test_get_task_exists(self):
        """Test getting an existing task."""
        scheduler = Scheduler()

        async def my_task():
            pass

        scheduler.add_task("task1", my_task, 60)
        task = scheduler.get_task("task1")

        assert task is not None
        assert task.name == "task1"

    def test_get_task_not_found(self):
        """Test getting non-existent task."""
        scheduler = Scheduler()
        task = scheduler.get_task("nonexistent")

        assert task is None

    def test_task_names(self):
        """Test getting task names."""
        scheduler = Scheduler()

        async def my_task():
            pass

        scheduler.add_task("task1", my_task, 60)
        scheduler.add_task("task2", my_task, 30)
        scheduler.add_task("task3", my_task, 120)

        names = scheduler.task_names

        assert len(names) == 3
        assert "task1" in names
        assert "task2" in names
        assert "task3" in names


class TestSchedulerStats:
    """Tests for scheduler stats."""

    def test_stats_empty_scheduler(self):
        """Test stats for empty scheduler."""
        scheduler = Scheduler()
        stats = scheduler.stats

        assert stats["running"] is False
        assert stats["task_count"] == 0
        assert stats["tasks"] == {}

    def test_stats_with_tasks(self):
        """Test stats with tasks."""
        scheduler = Scheduler()

        async def my_task():
            pass

        scheduler.add_task("task1", my_task, 60)
        scheduler.add_task("task2", my_task, 30, enabled=False)

        stats = scheduler.stats

        assert stats["task_count"] == 2
        assert "task1" in stats["tasks"]
        assert "task2" in stats["tasks"]
        assert stats["tasks"]["task1"]["enabled"] is True
        assert stats["tasks"]["task2"]["enabled"] is False
        assert stats["tasks"]["task1"]["interval_seconds"] == 60
        assert stats["tasks"]["task2"]["interval_seconds"] == 30

    def test_stats_includes_run_info(self):
        """Test stats includes run information."""
        scheduler = Scheduler()

        async def my_task():
            pass

        task = scheduler.add_task("task1", my_task, 60)
        task.run_count = 5
        task.error_count = 1
        task.last_run = utc_now()
        task.last_error = "Test error"

        stats = scheduler.stats

        assert stats["tasks"]["task1"]["run_count"] == 5
        assert stats["tasks"]["task1"]["error_count"] == 1
        assert stats["tasks"]["task1"]["last_run"] is not None
        assert stats["tasks"]["task1"]["last_error"] == "Test error"


class TestSchedulerLifecycle:
    """Tests for scheduler start/stop lifecycle."""

    @pytest.mark.asyncio
    async def test_start_scheduler(self):
        """Test starting the scheduler."""
        scheduler = Scheduler(tick_interval=0.1)

        await scheduler.start()

        try:
            assert scheduler._running is True
            assert scheduler._task is not None
        finally:
            await scheduler.stop()

    @pytest.mark.asyncio
    async def test_stop_scheduler(self):
        """Test stopping the scheduler."""
        scheduler = Scheduler(tick_interval=0.1)

        await scheduler.start()
        await scheduler.stop()

        assert scheduler._running is False

    @pytest.mark.asyncio
    async def test_stop_without_start(self):
        """Test stopping scheduler that wasn't started."""
        scheduler = Scheduler()

        # Should not raise
        await scheduler.stop()

        assert scheduler._running is False


class TestSchedulerExecution:
    """Tests for task execution."""

    @pytest.mark.asyncio
    async def test_task_executes_immediately(self):
        """Test task with run_immediately executes."""
        scheduler = Scheduler(tick_interval=0.05)
        executed = []

        async def my_task():
            executed.append(utc_now())

        scheduler.add_task("task1", my_task, 10, run_immediately=True)

        await scheduler.start()
        await asyncio.sleep(0.15)
        await scheduler.stop()

        assert len(executed) >= 1

    @pytest.mark.asyncio
    async def test_task_updates_state_on_success(self):
        """Test task state updates on successful execution."""
        scheduler = Scheduler(tick_interval=0.05)

        async def my_task():
            pass

        task = scheduler.add_task("task1", my_task, 10, run_immediately=True)

        await scheduler.start()
        await asyncio.sleep(0.15)
        await scheduler.stop()

        assert task.run_count >= 1
        assert task.last_run is not None
        assert task.error_count == 0

    @pytest.mark.asyncio
    async def test_task_updates_state_on_error(self):
        """Test task state updates on error."""
        scheduler = Scheduler(tick_interval=0.05)

        async def failing_task():
            raise ValueError("Task failed!")

        task = scheduler.add_task("fail_task", failing_task, 10, run_immediately=True)

        await scheduler.start()
        await asyncio.sleep(0.15)
        await scheduler.stop()

        assert task.error_count >= 1
        assert task.last_error == "Task failed!"

    @pytest.mark.asyncio
    async def test_disabled_task_not_executed(self):
        """Test disabled task is not executed."""
        scheduler = Scheduler(tick_interval=0.05)
        executed = []

        async def my_task():
            executed.append(True)

        scheduler.add_task("task1", my_task, 0.01, run_immediately=True, enabled=False)

        await scheduler.start()
        await asyncio.sleep(0.15)
        await scheduler.stop()

        assert len(executed) == 0

    @pytest.mark.asyncio
    async def test_run_task_now(self):
        """Test running a task immediately on demand."""
        scheduler = Scheduler()
        executed = []

        async def my_task():
            executed.append(True)

        scheduler.add_task("task1", my_task, 3600)  # Long interval

        result = await scheduler.run_task_now("task1")

        assert result is True
        assert len(executed) == 1

    @pytest.mark.asyncio
    async def test_run_task_now_not_found(self):
        """Test running non-existent task."""
        scheduler = Scheduler()

        result = await scheduler.run_task_now("nonexistent")

        assert result is False

    @pytest.mark.asyncio
    async def test_multiple_tasks_execute(self):
        """Test multiple tasks execute."""
        scheduler = Scheduler(tick_interval=0.05)
        task1_executions = []
        task2_executions = []

        async def task1():
            task1_executions.append(True)

        async def task2():
            task2_executions.append(True)

        scheduler.add_task("task1", task1, 10, run_immediately=True)
        scheduler.add_task("task2", task2, 10, run_immediately=True)

        await scheduler.start()
        await asyncio.sleep(0.15)
        await scheduler.stop()

        assert len(task1_executions) >= 1
        assert len(task2_executions) >= 1

    @pytest.mark.asyncio
    async def test_failing_task_doesnt_stop_others(self):
        """Test that a failing task doesn't stop other tasks."""
        scheduler = Scheduler(tick_interval=0.05)
        good_task_executions = []

        async def failing_task():
            raise Exception("I always fail")

        async def good_task():
            good_task_executions.append(True)

        scheduler.add_task("bad", failing_task, 10, run_immediately=True)
        scheduler.add_task("good", good_task, 10, run_immediately=True)

        await scheduler.start()
        await asyncio.sleep(0.15)
        await scheduler.stop()

        # Good task should still execute despite bad task failing
        assert len(good_task_executions) >= 1

    @pytest.mark.asyncio
    async def test_execute_task_updates_next_run(self):
        """Test that executing a task updates next_run."""
        scheduler = Scheduler(tick_interval=0.05)

        async def my_task():
            pass

        task = scheduler.add_task("task1", my_task, 60, run_immediately=True)
        initial_next_run = task.next_run

        await scheduler.start()
        await asyncio.sleep(0.15)
        await scheduler.stop()

        # next_run should be updated to future
        assert task.next_run > initial_next_run

    @pytest.mark.asyncio
    async def test_error_still_schedules_next_run(self):
        """Test that errors still schedule next run."""
        scheduler = Scheduler(tick_interval=0.05)

        async def failing_task():
            raise Exception("Failed!")

        task = scheduler.add_task("fail", failing_task, 60, run_immediately=True)

        await scheduler.start()
        await asyncio.sleep(0.15)
        await scheduler.stop()

        # next_run should still be set for future
        assert task.next_run is not None
        assert task.next_run > utc_now()


class TestSchedulerConcurrency:
    """Tests for concurrent task execution."""

    @pytest.mark.asyncio
    async def test_concurrent_task_execution(self):
        """Test that multiple due tasks execute concurrently."""
        scheduler = Scheduler(tick_interval=0.05)
        execution_order = []

        async def slow_task():
            execution_order.append(("slow_start", utc_now()))
            await asyncio.sleep(0.1)
            execution_order.append(("slow_end", utc_now()))

        async def fast_task():
            execution_order.append(("fast_start", utc_now()))
            execution_order.append(("fast_end", utc_now()))

        scheduler.add_task("slow", slow_task, 10, run_immediately=True)
        scheduler.add_task("fast", fast_task, 10, run_immediately=True)

        await scheduler.start()
        await asyncio.sleep(0.2)
        await scheduler.stop()

        # Fast task should complete before slow task ends
        # (if they run concurrently)
        slow_start_idx = next(
            i for i, (name, _) in enumerate(execution_order) if name == "slow_start"
        )
        slow_end_idx = next(i for i, (name, _) in enumerate(execution_order) if name == "slow_end")
        fast_end_idx = next(i for i, (name, _) in enumerate(execution_order) if name == "fast_end")

        # If concurrent, fast_end should be between slow_start and slow_end
        assert slow_start_idx < fast_end_idx < slow_end_idx


class TestSchedulerEdgeCases:
    """Tests for edge cases."""

    @pytest.mark.asyncio
    async def test_zero_interval_task(self):
        """Test task with zero interval."""
        scheduler = Scheduler(tick_interval=0.05)
        executions = []

        async def my_task():
            executions.append(True)

        scheduler.add_task("zero", my_task, 0, run_immediately=True)

        await scheduler.start()
        await asyncio.sleep(0.2)
        await scheduler.stop()

        # Should execute multiple times due to zero interval
        assert len(executions) >= 2

    @pytest.mark.asyncio
    async def test_very_short_interval(self):
        """Test task with very short interval."""
        scheduler = Scheduler(tick_interval=0.02)
        executions = []

        async def my_task():
            executions.append(True)

        scheduler.add_task("short", my_task, 0.05, run_immediately=True)

        await scheduler.start()
        await asyncio.sleep(0.25)
        await scheduler.stop()

        # Should have multiple executions
        assert len(executions) >= 2

    def test_add_multiple_tasks_same_name_overwrites(self):
        """Test adding tasks with same name overwrites."""
        scheduler = Scheduler()

        async def task1():
            pass

        async def task2():
            pass

        scheduler.add_task("same_name", task1, 60)
        scheduler.add_task("same_name", task2, 30)

        assert len(scheduler._tasks) == 1
        assert scheduler._tasks["same_name"].interval_seconds == 30

    @pytest.mark.asyncio
    async def test_enable_disable_during_execution(self):
        """Test enabling/disabling tasks during execution."""
        scheduler = Scheduler(tick_interval=0.05)
        executions = []

        async def my_task():
            executions.append(True)

        scheduler.add_task("toggle", my_task, 0.05, run_immediately=True)

        await scheduler.start()
        await asyncio.sleep(0.1)

        # Disable task
        scheduler.disable_task("toggle")
        exec_count_after_disable = len(executions)

        await asyncio.sleep(0.1)
        await scheduler.stop()

        # Should not have executed more after disable
        assert len(executions) == exec_count_after_disable

    @pytest.mark.asyncio
    async def test_remove_task_during_execution(self):
        """Test removing task while scheduler is running."""
        scheduler = Scheduler(tick_interval=0.05)
        executions = []

        async def my_task():
            executions.append(True)

        scheduler.add_task("removable", my_task, 0.05, run_immediately=True)

        await scheduler.start()
        await asyncio.sleep(0.1)

        # Remove task
        scheduler.remove_task("removable")
        exec_count_after_remove = len(executions)

        await asyncio.sleep(0.1)
        await scheduler.stop()

        # Should not have executed more after removal
        assert len(executions) == exec_count_after_remove


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
