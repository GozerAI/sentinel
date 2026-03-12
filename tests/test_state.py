"""
Tests for StateManager and backends.
"""

import asyncio
import pytest
import tempfile
from pathlib import Path

from sentinel.core.state import StateManager, MemoryBackend, SQLiteBackend


class TestMemoryBackend:
    """Tests for the in-memory state backend."""

    @pytest.mark.asyncio
    async def test_basic_operations(self):
        """Test basic get/set/delete operations."""
        backend = MemoryBackend()
        await backend.initialize()

        # Test set and get
        await backend.set("key1", "value1")
        value = await backend.get("key1")
        assert value == "value1"

        # Test get nonexistent
        value = await backend.get("nonexistent")
        assert value is None

        # Test delete
        await backend.delete("key1")
        value = await backend.get("key1")
        assert value is None

    @pytest.mark.asyncio
    async def test_complex_values(self):
        """Test storing complex values."""
        backend = MemoryBackend()
        await backend.initialize()

        # Dict
        await backend.set("dict_key", {"name": "test", "value": 123})
        value = await backend.get("dict_key")
        assert value == {"name": "test", "value": 123}

        # List
        await backend.set("list_key", [1, 2, 3, "four"])
        value = await backend.get("list_key")
        assert value == [1, 2, 3, "four"]

    @pytest.mark.asyncio
    async def test_keys_pattern(self):
        """Test keys with glob pattern."""
        backend = MemoryBackend()
        await backend.initialize()

        await backend.set("devices:001", "device1")
        await backend.set("devices:002", "device2")
        await backend.set("vlans:10", "vlan10")

        # All keys
        all_keys = await backend.keys("*")
        assert len(all_keys) == 3

        # Pattern match
        device_keys = await backend.keys("devices:*")
        assert len(device_keys) == 2
        assert "devices:001" in device_keys
        assert "devices:002" in device_keys


class TestSQLiteBackend:
    """Tests for SQLite state backend."""

    @pytest.mark.asyncio
    async def test_basic_operations(self):
        """Test basic operations with SQLite."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "test_state.db"
            backend = SQLiteBackend(str(db_path))
            await backend.initialize()

            # Test set and get
            await backend.set("key1", "value1")
            await backend.persist()

            value = await backend.get("key1")
            assert value == "value1"

            # Test delete
            await backend.delete("key1")
            await backend.persist()

            value = await backend.get("key1")
            assert value is None

            await backend.close()

    @pytest.mark.asyncio
    async def test_persistence(self):
        """Test that data persists across connections."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "test_state.db"

            # First connection - write data
            backend1 = SQLiteBackend(str(db_path))
            await backend1.initialize()
            await backend1.set("persistent_key", {"data": "test"})
            await backend1.persist()
            await backend1.close()

            # Second connection - read data
            backend2 = SQLiteBackend(str(db_path))
            await backend2.initialize()
            value = await backend2.get("persistent_key")
            assert value == {"data": "test"}
            await backend2.close()

    @pytest.mark.asyncio
    async def test_keys_pattern(self):
        """Test keys with pattern matching."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "test_state.db"
            backend = SQLiteBackend(str(db_path))
            await backend.initialize()

            await backend.set("agents:discovery:state", "running")
            await backend.set("agents:optimizer:state", "stopped")
            await backend.set("devices:inventory", "data")
            await backend.persist()

            agent_keys = await backend.keys("agents:*")
            assert len(agent_keys) == 2

            all_keys = await backend.keys("*")
            assert len(all_keys) == 3

            await backend.close()


class TestStateManager:
    """Tests for the StateManager facade."""

    @pytest.mark.asyncio
    async def test_memory_backend_default(self):
        """Test StateManager uses memory backend by default."""
        manager = StateManager({})
        await manager.initialize()

        assert manager._backend is not None

        await manager.set("test", "value")
        value = await manager.get("test")
        assert value == "value"

        await manager.close()

    @pytest.mark.asyncio
    async def test_sqlite_backend(self):
        """Test StateManager with SQLite backend."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "state.db"
            config = {"backend": "sqlite", "path": str(db_path)}

            manager = StateManager(config)
            await manager.initialize()

            await manager.set("key", {"complex": "value"})
            await manager.persist()

            value = await manager.get("key")
            assert value == {"complex": "value"}

            await manager.close()

    @pytest.mark.asyncio
    async def test_default_value(self):
        """Test get with default value."""
        manager = StateManager({"backend": "memory"})
        await manager.initialize()

        value = await manager.get("nonexistent", default="default_value")
        assert value == "default_value"

        await manager.close()

    @pytest.mark.asyncio
    async def test_namespace_operations(self):
        """Test namespace get and delete."""
        manager = StateManager({"backend": "memory"})
        await manager.initialize()

        await manager.set("devices:001", "device1")
        await manager.set("devices:002", "device2")
        await manager.set("devices:003", "device3")
        await manager.set("vlans:10", "vlan10")

        # Get namespace
        devices = await manager.get_namespace("devices")
        assert len(devices) == 3
        assert "001" in devices
        assert devices["001"] == "device1"

        # Delete namespace
        deleted = await manager.delete_namespace("devices")
        assert deleted == 3

        # Verify deleted
        devices = await manager.get_namespace("devices")
        assert len(devices) == 0

        # Other namespace still exists
        vlans = await manager.get_namespace("vlans")
        assert len(vlans) == 1

        await manager.close()

    @pytest.mark.asyncio
    async def test_increment(self):
        """Test atomic increment operation."""
        manager = StateManager({"backend": "memory"})
        await manager.initialize()

        # Increment new counter
        result = await manager.increment("counter")
        assert result == 1

        # Increment existing
        result = await manager.increment("counter")
        assert result == 2

        # Increment by custom amount
        result = await manager.increment("counter", amount=5)
        assert result == 7

        await manager.close()

    @pytest.mark.asyncio
    async def test_atomic_update(self):
        """Test atomic update operation."""
        manager = StateManager({"backend": "memory"})
        await manager.initialize()

        # Set initial value
        await manager.set("list_key", [1, 2, 3])

        # Atomic update to append
        result = await manager.atomic_update("list_key", lambda x: x + [4, 5])
        assert result == [1, 2, 3, 4, 5]

        # Verify persisted
        value = await manager.get("list_key")
        assert value == [1, 2, 3, 4, 5]

        await manager.close()

    @pytest.mark.asyncio
    async def test_concurrent_access(self):
        """Test concurrent access is safe."""
        manager = StateManager({"backend": "memory"})
        await manager.initialize()

        # Concurrent increments
        async def increment_many():
            for _ in range(100):
                await manager.increment("concurrent_counter")

        # Run 5 concurrent incrementers
        await asyncio.gather(*[increment_many() for _ in range(5)])

        # Should have 500 total
        value = await manager.get("concurrent_counter")
        assert value == 500

        await manager.close()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
