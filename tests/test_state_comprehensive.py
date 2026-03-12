"""
Comprehensive tests for State Manager covering all code paths.

These tests achieve full coverage including:
- Memory backend
- SQLite backend
- State manager operations
- Atomic operations
- Namespace operations
"""

import asyncio
import pytest
import tempfile
import os
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

from sentinel.core.state import StateBackend, MemoryBackend, SQLiteBackend, StateManager


class TestMemoryBackend:
    """Tests for MemoryBackend."""

    @pytest.mark.asyncio
    async def test_initialize(self):
        """Test initialize does nothing for memory backend."""
        backend = MemoryBackend()
        await backend.initialize()  # Should not raise

    @pytest.mark.asyncio
    async def test_get_returns_none_for_missing_key(self):
        """Test get returns None for missing key."""
        backend = MemoryBackend()
        result = await backend.get("missing")
        assert result is None

    @pytest.mark.asyncio
    async def test_set_and_get(self):
        """Test set and get operations."""
        backend = MemoryBackend()

        await backend.set("key1", "value1")
        result = await backend.get("key1")

        assert result == "value1"

    @pytest.mark.asyncio
    async def test_set_overwrites_existing(self):
        """Test set overwrites existing value."""
        backend = MemoryBackend()

        await backend.set("key1", "value1")
        await backend.set("key1", "value2")

        result = await backend.get("key1")
        assert result == "value2"

    @pytest.mark.asyncio
    async def test_delete_existing_key(self):
        """Test delete removes existing key."""
        backend = MemoryBackend()

        await backend.set("key1", "value1")
        await backend.delete("key1")

        result = await backend.get("key1")
        assert result is None

    @pytest.mark.asyncio
    async def test_delete_missing_key(self):
        """Test delete of missing key doesn't raise."""
        backend = MemoryBackend()
        await backend.delete("missing")  # Should not raise

    @pytest.mark.asyncio
    async def test_keys_all(self):
        """Test keys returns all keys."""
        backend = MemoryBackend()

        await backend.set("key1", "value1")
        await backend.set("key2", "value2")
        await backend.set("other", "value3")

        keys = await backend.keys()

        assert len(keys) == 3
        assert "key1" in keys
        assert "key2" in keys
        assert "other" in keys

    @pytest.mark.asyncio
    async def test_keys_with_pattern(self):
        """Test keys with glob pattern."""
        backend = MemoryBackend()

        await backend.set("devices:1", "value1")
        await backend.set("devices:2", "value2")
        await backend.set("users:1", "value3")

        keys = await backend.keys("devices:*")

        assert len(keys) == 2
        assert "devices:1" in keys
        assert "devices:2" in keys

    @pytest.mark.asyncio
    async def test_persist_does_nothing(self):
        """Test persist does nothing for memory backend."""
        backend = MemoryBackend()
        await backend.persist()  # Should not raise

    @pytest.mark.asyncio
    async def test_close_does_nothing(self):
        """Test close does nothing for memory backend."""
        backend = MemoryBackend()
        await backend.close()  # Should not raise


class TestSQLiteBackend:
    """Tests for SQLiteBackend."""

    @pytest.fixture
    def temp_db_path(self):
        """Create a temporary database path."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield os.path.join(tmpdir, "test_state.db")

    @pytest.mark.asyncio
    async def test_initialize_creates_table(self, temp_db_path):
        """Test initialize creates database and table."""
        backend = SQLiteBackend(temp_db_path)
        await backend.initialize()

        assert backend._conn is not None

        await backend.close()
        assert Path(temp_db_path).exists()

    @pytest.mark.asyncio
    async def test_initialize_creates_parent_directory(self):
        """Test initialize creates parent directories."""
        with tempfile.TemporaryDirectory() as tmpdir:
            nested_path = os.path.join(tmpdir, "subdir", "deep", "state.db")

            backend = SQLiteBackend(nested_path)
            await backend.initialize()

            assert Path(nested_path).parent.exists()

            await backend.close()

    @pytest.mark.asyncio
    async def test_get_returns_none_for_missing_key(self, temp_db_path):
        """Test get returns None for missing key."""
        backend = SQLiteBackend(temp_db_path)
        await backend.initialize()

        result = await backend.get("missing")

        assert result is None
        await backend.close()

    @pytest.mark.asyncio
    async def test_get_returns_none_when_not_connected(self, temp_db_path):
        """Test get returns None when not connected."""
        backend = SQLiteBackend(temp_db_path)
        # Don't initialize

        result = await backend.get("any_key")

        assert result is None

    @pytest.mark.asyncio
    async def test_set_and_get(self, temp_db_path):
        """Test set and get operations."""
        backend = SQLiteBackend(temp_db_path)
        await backend.initialize()

        await backend.set("key1", {"data": "value"})
        await backend.persist()

        result = await backend.get("key1")

        assert result == {"data": "value"}
        await backend.close()

    @pytest.mark.asyncio
    async def test_set_when_not_connected(self, temp_db_path):
        """Test set does nothing when not connected."""
        backend = SQLiteBackend(temp_db_path)
        # Don't initialize

        await backend.set("key1", "value")  # Should not raise

    @pytest.mark.asyncio
    async def test_set_overwrites_existing(self, temp_db_path):
        """Test set overwrites existing value."""
        backend = SQLiteBackend(temp_db_path)
        await backend.initialize()

        await backend.set("key1", "value1")
        await backend.set("key1", "value2")
        await backend.persist()

        result = await backend.get("key1")

        assert result == "value2"
        await backend.close()

    @pytest.mark.asyncio
    async def test_delete_existing_key(self, temp_db_path):
        """Test delete removes existing key."""
        backend = SQLiteBackend(temp_db_path)
        await backend.initialize()

        await backend.set("key1", "value1")
        await backend.persist()
        await backend.delete("key1")
        await backend.persist()

        result = await backend.get("key1")

        assert result is None
        await backend.close()

    @pytest.mark.asyncio
    async def test_delete_when_not_connected(self, temp_db_path):
        """Test delete does nothing when not connected."""
        backend = SQLiteBackend(temp_db_path)
        # Don't initialize

        await backend.delete("key1")  # Should not raise

    @pytest.mark.asyncio
    async def test_keys_all(self, temp_db_path):
        """Test keys returns all keys."""
        backend = SQLiteBackend(temp_db_path)
        await backend.initialize()

        await backend.set("key1", "value1")
        await backend.set("key2", "value2")
        await backend.persist()

        keys = await backend.keys()

        assert len(keys) == 2
        assert "key1" in keys
        assert "key2" in keys
        await backend.close()

    @pytest.mark.asyncio
    async def test_keys_with_pattern(self, temp_db_path):
        """Test keys with SQL LIKE pattern."""
        backend = SQLiteBackend(temp_db_path)
        await backend.initialize()

        await backend.set("devices:1", "v1")
        await backend.set("devices:2", "v2")
        await backend.set("users:1", "v3")
        await backend.persist()

        keys = await backend.keys("devices:*")

        assert len(keys) == 2
        await backend.close()

    @pytest.mark.asyncio
    async def test_keys_when_not_connected(self, temp_db_path):
        """Test keys returns empty list when not connected."""
        backend = SQLiteBackend(temp_db_path)
        # Don't initialize

        keys = await backend.keys()

        assert keys == []

    @pytest.mark.asyncio
    async def test_persist_commits(self, temp_db_path):
        """Test persist commits changes."""
        backend = SQLiteBackend(temp_db_path)
        await backend.initialize()

        await backend.set("key1", "value1")
        await backend.persist()

        # Close and reopen to verify persistence
        await backend.close()

        backend2 = SQLiteBackend(temp_db_path)
        await backend2.initialize()

        result = await backend2.get("key1")
        assert result == "value1"

        await backend2.close()

    @pytest.mark.asyncio
    async def test_persist_when_not_connected(self, temp_db_path):
        """Test persist does nothing when not connected."""
        backend = SQLiteBackend(temp_db_path)
        # Don't initialize

        await backend.persist()  # Should not raise

    @pytest.mark.asyncio
    async def test_close(self, temp_db_path):
        """Test close closes connection."""
        backend = SQLiteBackend(temp_db_path)
        await backend.initialize()

        assert backend._conn is not None

        await backend.close()

        assert backend._conn is None

    @pytest.mark.asyncio
    async def test_close_when_not_connected(self, temp_db_path):
        """Test close does nothing when not connected."""
        backend = SQLiteBackend(temp_db_path)
        # Don't initialize

        await backend.close()  # Should not raise


class TestStateManager:
    """Tests for StateManager."""

    @pytest.mark.asyncio
    async def test_initialize_memory_backend(self):
        """Test initialize with memory backend."""
        manager = StateManager({"backend": "memory"})
        await manager.initialize()

        assert manager._backend is not None
        assert isinstance(manager._backend, MemoryBackend)

        await manager.close()

    @pytest.mark.asyncio
    async def test_initialize_sqlite_backend(self):
        """Test initialize with SQLite backend."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = os.path.join(tmpdir, "state.db")

            manager = StateManager({"backend": "sqlite", "path": db_path})
            await manager.initialize()

            assert manager._backend is not None
            assert isinstance(manager._backend, SQLiteBackend)

            await manager.close()

    @pytest.mark.asyncio
    async def test_initialize_unknown_backend_defaults_to_memory(self):
        """Test unknown backend defaults to memory."""
        manager = StateManager({"backend": "unknown_backend"})
        await manager.initialize()

        assert isinstance(manager._backend, MemoryBackend)

        await manager.close()

    @pytest.mark.asyncio
    async def test_get_returns_default_when_not_initialized(self):
        """Test get returns default when backend not initialized."""
        manager = StateManager({})

        result = await manager.get("key", "default_value")

        assert result == "default_value"

    @pytest.mark.asyncio
    async def test_get_returns_default_for_missing_key(self):
        """Test get returns default for missing key."""
        manager = StateManager({"backend": "memory"})
        await manager.initialize()

        result = await manager.get("missing", "default")

        assert result == "default"
        await manager.close()

    @pytest.mark.asyncio
    async def test_get_returns_stored_value(self):
        """Test get returns stored value."""
        manager = StateManager({"backend": "memory"})
        await manager.initialize()

        await manager.set("key1", "value1")
        result = await manager.get("key1", "default")

        assert result == "value1"
        await manager.close()

    @pytest.mark.asyncio
    async def test_set_does_nothing_when_not_initialized(self):
        """Test set does nothing when backend not initialized."""
        manager = StateManager({})

        await manager.set("key", "value")  # Should not raise

    @pytest.mark.asyncio
    async def test_set_stores_value(self):
        """Test set stores value."""
        manager = StateManager({"backend": "memory"})
        await manager.initialize()

        await manager.set("key1", {"complex": "data"})
        result = await manager.get("key1")

        assert result == {"complex": "data"}
        await manager.close()

    @pytest.mark.asyncio
    async def test_delete_does_nothing_when_not_initialized(self):
        """Test delete does nothing when backend not initialized."""
        manager = StateManager({})

        await manager.delete("key")  # Should not raise

    @pytest.mark.asyncio
    async def test_delete_removes_key(self):
        """Test delete removes key."""
        manager = StateManager({"backend": "memory"})
        await manager.initialize()

        await manager.set("key1", "value1")
        await manager.delete("key1")

        result = await manager.get("key1")
        assert result is None

        await manager.close()

    @pytest.mark.asyncio
    async def test_keys_returns_empty_when_not_initialized(self):
        """Test keys returns empty list when not initialized."""
        manager = StateManager({})

        keys = await manager.keys()

        assert keys == []

    @pytest.mark.asyncio
    async def test_keys_returns_matching_keys(self):
        """Test keys returns matching keys."""
        manager = StateManager({"backend": "memory"})
        await manager.initialize()

        await manager.set("devices:1", "v1")
        await manager.set("devices:2", "v2")
        await manager.set("users:1", "v3")

        keys = await manager.keys("devices:*")

        assert len(keys) == 2
        await manager.close()

    @pytest.mark.asyncio
    async def test_get_namespace(self):
        """Test get_namespace returns all values in namespace."""
        manager = StateManager({"backend": "memory"})
        await manager.initialize()

        await manager.set("devices:device1", {"name": "Device 1"})
        await manager.set("devices:device2", {"name": "Device 2"})
        await manager.set("users:user1", {"name": "User 1"})

        namespace_data = await manager.get_namespace("devices")

        assert len(namespace_data) == 2
        assert "device1" in namespace_data
        assert "device2" in namespace_data
        assert namespace_data["device1"]["name"] == "Device 1"

        await manager.close()

    @pytest.mark.asyncio
    async def test_get_namespace_returns_empty_when_not_initialized(self):
        """Test get_namespace returns empty dict when not initialized."""
        manager = StateManager({})

        result = await manager.get_namespace("devices")

        assert result == {}

    @pytest.mark.asyncio
    async def test_delete_namespace(self):
        """Test delete_namespace removes all keys in namespace."""
        manager = StateManager({"backend": "memory"})
        await manager.initialize()

        await manager.set("devices:device1", "v1")
        await manager.set("devices:device2", "v2")
        await manager.set("users:user1", "v3")

        count = await manager.delete_namespace("devices")

        assert count == 2

        keys = await manager.keys()
        assert "users:user1" in keys
        assert len(keys) == 1

        await manager.close()

    @pytest.mark.asyncio
    async def test_delete_namespace_returns_zero_when_not_initialized(self):
        """Test delete_namespace returns 0 when not initialized."""
        manager = StateManager({})

        count = await manager.delete_namespace("devices")

        assert count == 0

    @pytest.mark.asyncio
    async def test_persist(self):
        """Test persist calls backend persist."""
        manager = StateManager({"backend": "memory"})
        await manager.initialize()

        manager._backend.persist = AsyncMock()

        await manager.persist()

        manager._backend.persist.assert_called_once()
        await manager.close()

    @pytest.mark.asyncio
    async def test_persist_does_nothing_when_not_initialized(self):
        """Test persist does nothing when not initialized."""
        manager = StateManager({})

        await manager.persist()  # Should not raise

    @pytest.mark.asyncio
    async def test_close(self):
        """Test close closes backend."""
        manager = StateManager({"backend": "memory"})
        await manager.initialize()

        manager._backend.close = AsyncMock()

        await manager.close()

        manager._backend.close.assert_called_once()

    @pytest.mark.asyncio
    async def test_close_does_nothing_when_not_initialized(self):
        """Test close does nothing when not initialized."""
        manager = StateManager({})

        await manager.close()  # Should not raise

    @pytest.mark.asyncio
    async def test_atomic_update(self):
        """Test atomic_update updates value atomically."""
        manager = StateManager({"backend": "memory"})
        await manager.initialize()

        await manager.set("counter", 5)

        result = await manager.atomic_update("counter", lambda x: x + 10, 0)

        assert result == 15

        stored = await manager.get("counter")
        assert stored == 15

        await manager.close()

    @pytest.mark.asyncio
    async def test_atomic_update_with_default(self):
        """Test atomic_update uses default for missing key."""
        manager = StateManager({"backend": "memory"})
        await manager.initialize()

        result = await manager.atomic_update("new_key", lambda x: x + 10, 5)

        assert result == 15
        await manager.close()

    @pytest.mark.asyncio
    async def test_increment(self):
        """Test increment atomically increments counter."""
        manager = StateManager({"backend": "memory"})
        await manager.initialize()

        result = await manager.increment("counter")
        assert result == 1

        result = await manager.increment("counter")
        assert result == 2

        result = await manager.increment("counter", 5)
        assert result == 7

        await manager.close()

    @pytest.mark.asyncio
    async def test_concurrent_set_operations(self):
        """Test concurrent set operations are safe."""
        manager = StateManager({"backend": "memory"})
        await manager.initialize()

        async def set_value(key, value):
            await manager.set(key, value)

        # Run many concurrent sets
        await asyncio.gather(*[set_value(f"key{i}", f"value{i}") for i in range(100)])

        keys = await manager.keys()
        assert len(keys) == 100

        await manager.close()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
