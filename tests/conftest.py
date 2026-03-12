"""
Pytest configuration and fixtures for Sentinel tests.
"""

import asyncio
import pytest
from typing import AsyncGenerator
from uuid import uuid4


@pytest.fixture(scope="session")
def event_loop():
    """Create an event loop for async tests."""
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


@pytest.fixture
async def event_bus():
    """Create a test event bus."""
    from sentinel.core.event_bus import EventBus

    bus = EventBus()
    yield bus
    # Cleanup


@pytest.fixture
async def state_manager():
    """Create an in-memory state manager for tests."""
    from sentinel.core.state import StateManager

    manager = StateManager({"backend": "memory"})
    await manager.initialize()
    yield manager
    await manager.close()


@pytest.fixture
def sample_device():
    """Create a sample device for testing."""
    from sentinel.core.models.device import Device, DeviceType, NetworkInterface

    return Device(
        id=str(uuid4()),
        device_type=DeviceType.WORKSTATION,
        hostname="test-device",
        interfaces=[
            NetworkInterface(mac="00:11:22:33:44:55", ip_addresses=["192.168.1.100"], vlan=10)
        ],
    )


@pytest.fixture
def sample_vlan():
    """Create a sample VLAN for testing."""
    from sentinel.core.models.network import VLAN

    return VLAN(
        id=10,
        name="Test VLAN",
        purpose="testing",
        subnet="192.168.10.0/24",
        gateway="192.168.10.1",
        dhcp_enabled=True,
    )


@pytest.fixture
def sample_event():
    """Create a sample event for testing."""
    from sentinel.core.models.event import Event, EventCategory, EventSeverity

    return Event(
        id=str(uuid4()),
        category=EventCategory.NETWORK,
        event_type="test.event",
        severity=EventSeverity.INFO,
        source="test",
        title="Test Event",
        description="This is a test event",
    )


@pytest.fixture
def mock_config():
    """Create a mock configuration for testing."""
    return {
        "state": {"backend": "memory"},
        "agents": {
            "discovery": {
                "enabled": True,
                "scan_interval_seconds": 60,
                "networks": ["192.168.1.0/24"],
                "auto_execute_threshold": 0.95,
            }
        },
        "vlans": [
            {
                "id": 10,
                "name": "Workstations",
                "purpose": "workstations",
                "subnet": "192.168.10.0/24",
            },
            {"id": 20, "name": "Servers", "purpose": "servers", "subnet": "192.168.20.0/24"},
        ],
    }


@pytest.fixture
async def mock_engine(mock_config, event_bus, state_manager):
    """Create a mock engine for testing agents."""

    class MockEngine:
        def __init__(self):
            self.config = mock_config
            self.event_bus = event_bus
            self.state = state_manager
            self.integrations = {}
            self.agents = {}
            self.scheduler = MockScheduler()

    class MockScheduler:
        def __init__(self):
            self.tasks = {}

        def add_task(self, name, func, interval_seconds, run_immediately=False):
            self.tasks[name] = {"func": func, "interval": interval_seconds}

        def remove_task(self, name):
            self.tasks.pop(name, None)

    return MockEngine()
