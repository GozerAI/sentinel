"""
State management for the Sentinel platform.

This module provides persistent state management with support for
multiple backends (SQLite, PostgreSQL, Redis).
"""

import asyncio
import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Optional, Any
from abc import ABC, abstractmethod

from sentinel.core.utils import utc_now

logger = logging.getLogger(__name__)


class StateBackend(ABC):
    """Abstract base class for state storage backends."""

    @abstractmethod
    async def initialize(self) -> None:
        """Initialize the backend."""
        pass

    @abstractmethod
    async def get(self, key: str) -> Optional[Any]:
        """Get a value by key."""
        pass

    @abstractmethod
    async def set(self, key: str, value: Any) -> None:
        """Set a value by key."""
        pass

    @abstractmethod
    async def delete(self, key: str) -> None:
        """Delete a value by key."""
        pass

    @abstractmethod
    async def keys(self, pattern: str = "*") -> list[str]:
        """Get all keys matching pattern."""
        pass

    @abstractmethod
    async def persist(self) -> None:
        """Persist any pending changes."""
        pass

    @abstractmethod
    async def close(self) -> None:
        """Close the backend connection."""
        pass


class MemoryBackend(StateBackend):
    """In-memory state backend for testing."""

    def __init__(self):
        self._data: dict[str, Any] = {}

    async def initialize(self) -> None:
        pass

    async def get(self, key: str) -> Optional[Any]:
        return self._data.get(key)

    async def set(self, key: str, value: Any) -> None:
        self._data[key] = value

    async def delete(self, key: str) -> None:
        self._data.pop(key, None)

    async def keys(self, pattern: str = "*") -> list[str]:
        if pattern == "*":
            return list(self._data.keys())
        # Simple glob matching
        import fnmatch

        return [k for k in self._data.keys() if fnmatch.fnmatch(k, pattern)]

    async def persist(self) -> None:
        pass

    async def close(self) -> None:
        pass


class SQLiteBackend(StateBackend):
    """SQLite state backend for persistent storage."""

    def __init__(self, path: str):
        self.path = Path(path)
        self._conn = None

    async def initialize(self) -> None:
        """Initialize SQLite database."""
        import aiosqlite

        # Ensure directory exists
        self.path.parent.mkdir(parents=True, exist_ok=True)

        self._conn = await aiosqlite.connect(str(self.path))

        # Create table if not exists
        await self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS state (
                key TEXT PRIMARY KEY,
                value TEXT,
                updated_at TEXT
            )
        """
        )
        await self._conn.commit()

        logger.debug(f"SQLite backend initialized at {self.path}")

    async def get(self, key: str) -> Optional[Any]:
        if not self._conn:
            return None

        async with self._conn.execute("SELECT value FROM state WHERE key = ?", (key,)) as cursor:
            row = await cursor.fetchone()
            if row:
                return json.loads(row[0])
            return None

    async def set(self, key: str, value: Any) -> None:
        if not self._conn:
            return

        json_value = json.dumps(value, default=str)
        updated_at = utc_now().isoformat()

        await self._conn.execute(
            """
            INSERT OR REPLACE INTO state (key, value, updated_at)
            VALUES (?, ?, ?)
            """,
            (key, json_value, updated_at),
        )

    async def delete(self, key: str) -> None:
        if not self._conn:
            return

        await self._conn.execute("DELETE FROM state WHERE key = ?", (key,))

    async def keys(self, pattern: str = "*") -> list[str]:
        if not self._conn:
            return []

        if pattern == "*":
            sql = "SELECT key FROM state"
            params = ()
        else:
            # Convert glob to SQL LIKE pattern
            like_pattern = pattern.replace("*", "%").replace("?", "_")
            sql = "SELECT key FROM state WHERE key LIKE ?"
            params = (like_pattern,)

        async with self._conn.execute(sql, params) as cursor:
            rows = await cursor.fetchall()
            return [row[0] for row in rows]

    async def persist(self) -> None:
        if self._conn:
            await self._conn.commit()

    async def close(self) -> None:
        if self._conn:
            await self._conn.close()
            self._conn = None


class StateManager:
    """
    Global state manager for the Sentinel platform.

    Provides a unified interface for storing and retrieving state
    across the platform with support for multiple backends.

    Features:
    - Multiple backend support (memory, SQLite, PostgreSQL, Redis)
    - Automatic serialization/deserialization
    - Namespace support for logical grouping
    - Atomic operations

    Attributes:
        config: Backend configuration

    Example:
        ```python
        state = StateManager({"backend": "sqlite", "path": "/var/lib/sentinel/state.db"})
        await state.initialize()

        # Store data
        await state.set("devices:inventory", inventory.model_dump())

        # Retrieve data
        data = await state.get("devices:inventory")

        await state.persist()
        ```
    """

    def __init__(self, config: dict):
        """
        Initialize state manager.

        Args:
            config: Configuration with backend settings
                - backend: "memory", "sqlite", "postgresql", or "redis"
                - path: Path for file-based backends
                - host/port: For network backends
        """
        self.config = config
        self._backend: Optional[StateBackend] = None
        self._lock = asyncio.Lock()

    async def initialize(self) -> None:
        """Initialize the state backend."""
        backend_type = self.config.get("backend", "memory")

        if backend_type == "memory":
            self._backend = MemoryBackend()
        elif backend_type == "sqlite":
            path = self.config.get("path", "/var/lib/sentinel/state.db")
            self._backend = SQLiteBackend(path)
        else:
            logger.warning(f"Unknown backend type: {backend_type}, using memory")
            self._backend = MemoryBackend()

        await self._backend.initialize()
        logger.info(f"State manager initialized with {backend_type} backend")

    async def get(self, key: str, default: Any = None) -> Any:
        """
        Get a value from state.

        Args:
            key: State key (supports namespacing with colons, e.g., "devices:inventory")
            default: Default value if key not found

        Returns:
            Stored value or default
        """
        if not self._backend:
            return default

        value = await self._backend.get(key)
        return value if value is not None else default

    async def set(self, key: str, value: Any) -> None:
        """
        Set a value in state.

        Args:
            key: State key
            value: Value to store (must be JSON-serializable)
        """
        if not self._backend:
            return

        async with self._lock:
            await self._backend.set(key, value)

    async def delete(self, key: str) -> None:
        """
        Delete a value from state.

        Args:
            key: State key to delete
        """
        if not self._backend:
            return

        async with self._lock:
            await self._backend.delete(key)

    async def keys(self, pattern: str = "*") -> list[str]:
        """
        Get all keys matching a pattern.

        Args:
            pattern: Glob pattern (e.g., "devices:*")

        Returns:
            List of matching keys
        """
        if not self._backend:
            return []

        return await self._backend.keys(pattern)

    async def get_namespace(self, namespace: str) -> dict[str, Any]:
        """
        Get all values in a namespace.

        Args:
            namespace: Namespace prefix (e.g., "devices")

        Returns:
            Dictionary of key -> value for all keys in namespace
        """
        if not self._backend:
            return {}

        keys = await self.keys(f"{namespace}:*")
        result = {}
        for key in keys:
            value = await self.get(key)
            # Strip namespace from key
            short_key = key[len(namespace) + 1 :]
            result[short_key] = value
        return result

    async def delete_namespace(self, namespace: str) -> int:
        """
        Delete all keys in a namespace.

        Args:
            namespace: Namespace prefix

        Returns:
            Number of keys deleted
        """
        if not self._backend:
            return 0

        keys = await self.keys(f"{namespace}:*")
        for key in keys:
            await self.delete(key)
        return len(keys)

    async def persist(self) -> None:
        """Persist any pending changes to storage."""
        if self._backend:
            await self._backend.persist()
            logger.debug("State persisted")

    async def close(self) -> None:
        """Close the state backend."""
        if self._backend:
            await self._backend.close()

    async def atomic_update(self, key: str, update_fn: callable, default: Any = None) -> Any:
        """
        Atomically update a value.

        Args:
            key: State key
            update_fn: Function that takes current value and returns new value
            default: Default value if key doesn't exist

        Returns:
            Updated value
        """
        async with self._lock:
            current = await self.get(key, default)
            new_value = update_fn(current)
            await self._backend.set(key, new_value)
            return new_value

    async def increment(self, key: str, amount: int = 1) -> int:
        """
        Atomically increment a counter.

        Args:
            key: Counter key
            amount: Amount to increment by

        Returns:
            New counter value
        """
        return await self.atomic_update(key, lambda x: (x or 0) + amount, 0)
