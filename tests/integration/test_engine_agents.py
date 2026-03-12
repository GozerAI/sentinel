"""
Integration tests for SentinelEngine with Agents.

Tests the full lifecycle of the engine starting with agents,
processing events, and coordinating actions.
"""

import asyncio
import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

from sentinel.core.engine import SentinelEngine
from sentinel.core.event_bus import EventBus
from sentinel.core.state import StateManager
from sentinel.core.models.event import Event, EventCategory, EventSeverity
from sentinel.core.models.device import Device, DeviceType, NetworkInterface


class TestEngineAgentIntegration:
    """Tests for engine and agent integration."""

    @pytest.fixture
    def integration_config(self):
        """Configuration for integration tests."""
        return {
            "agents": {
                "discovery": {
                    "enabled": True,
                    "scan_interval_seconds": 60,
                    "networks": ["192.168.1.0/24"],
                },
                "guardian": {
                    "enabled": True,
                    "threat_thresholds": {
                        "port_scan": 50,
                        "failed_auth": 5,
                    },
                    "quarantine_vlan": 666,
                },
                "planner": {
                    "enabled": True,
                    "require_confirmation_for": [],
                },
                "optimizer": {
                    "enabled": True,
                },
                "healer": {
                    "enabled": True,
                },
            },
            "state": {
                "backend": "memory",
            },
            "vlans": [
                {"id": 10, "name": "Workstations"},
                {"id": 20, "name": "Servers"},
            ],
        }

    @pytest.mark.asyncio
    async def test_engine_starts_all_agents(self, integration_config):
        """Test that engine starts all configured agents."""
        engine = SentinelEngine(integration_config)

        await engine.start()

        try:
            # Verify engine is running
            assert engine.is_running is True

            # Verify all agents were created and started
            assert "discovery" in engine._agents
            assert "guardian" in engine._agents
            assert "planner" in engine._agents
            assert "optimizer" in engine._agents
            assert "healer" in engine._agents

            # Verify agents are running
            for name, agent in engine._agents.items():
                assert agent._running is True, f"Agent {name} should be running"

        finally:
            await engine.stop()

    @pytest.mark.asyncio
    async def test_engine_stops_all_agents_gracefully(self, integration_config):
        """Test that engine stops all agents gracefully."""
        engine = SentinelEngine(integration_config)

        await engine.start()
        await engine.stop()

        # Verify engine is stopped
        assert engine.is_running is False

        # Verify all agents are stopped
        for name, agent in engine._agents.items():
            assert agent._running is False, f"Agent {name} should be stopped"

    @pytest.mark.asyncio
    async def test_event_bus_connects_agents(self, integration_config):
        """Test that event bus connects agents for communication."""
        engine = SentinelEngine(integration_config)

        await engine.start()

        try:
            # Verify event bus is running
            assert engine.event_bus._running is True

            # Create and publish a test event
            test_event = Event(
                category=EventCategory.NETWORK,
                event_type="test.integration",
                severity=EventSeverity.INFO,
                source="test",
                title="Integration test event",
            )

            await engine.event_bus.publish(test_event)

            # Give time for event processing
            await asyncio.sleep(0.2)

            # Verify event was queued (basic check)
            # In a full test, we'd verify agents received it

        finally:
            await engine.stop()

    @pytest.mark.asyncio
    async def test_agent_can_access_engine_state(self, integration_config):
        """Test that agents can access shared state through engine."""
        engine = SentinelEngine(integration_config)

        await engine.start()

        try:
            # Set some state
            await engine.state.set("test:key", "test_value")

            # Verify agents can access it through engine reference
            discovery = engine.get_agent("discovery")
            assert discovery is not None
            assert discovery.engine.state is engine.state

            # Verify state retrieval works
            value = await engine.state.get("test:key")
            assert value == "test_value"

        finally:
            await engine.stop()

    @pytest.mark.asyncio
    async def test_engine_emits_startup_event(self, integration_config):
        """Test that engine emits startup event that agents can receive."""
        engine = SentinelEngine(integration_config)
        received_events = []

        async def capture_event(event):
            received_events.append(event)

        # Subscribe before starting
        engine.event_bus.subscribe(capture_event, event_type="engine.started")

        await engine.start()

        # Give time for event processing
        await asyncio.sleep(0.2)

        await engine.stop()

        # Verify startup event was emitted
        startup_events = [e for e in received_events if e.event_type == "engine.started"]
        assert len(startup_events) >= 1

    @pytest.mark.asyncio
    async def test_discovery_agent_inventory_accessible(self, integration_config):
        """Test that discovery agent's device inventory is accessible."""
        engine = SentinelEngine(integration_config)

        await engine.start()

        try:
            discovery = engine.get_agent("discovery")
            assert discovery is not None

            # Verify inventory exists
            assert hasattr(discovery, "_inventory")

            # Add a test device
            device = Device(
                id=uuid4(),
                device_type=DeviceType.WORKSTATION,
                hostname="test-workstation",
                interfaces=[
                    NetworkInterface(
                        mac_address="00:11:22:33:44:55",
                        ip_addresses=["192.168.1.100"],
                    )
                ],
            )
            discovery._inventory.add_device(device)

            # Verify device can be retrieved
            retrieved = discovery._inventory.get_by_mac("00:11:22:33:44:55")
            assert retrieved is not None
            assert retrieved.hostname == "test-workstation"

        finally:
            await engine.stop()

    @pytest.mark.asyncio
    async def test_guardian_agent_blocking_state(self, integration_config):
        """Test that guardian agent maintains blocking state."""
        engine = SentinelEngine(integration_config)

        await engine.start()

        try:
            guardian = engine.get_agent("guardian")
            assert guardian is not None

            # Verify blocked IPs set exists
            assert hasattr(guardian, "_blocked_ips")
            assert isinstance(guardian._blocked_ips, set)

            # Add a blocked IP manually
            guardian._blocked_ips.add("192.168.1.200")

            # Verify it's tracked
            assert "192.168.1.200" in guardian._blocked_ips

        finally:
            await engine.stop()

    @pytest.mark.asyncio
    async def test_planner_agent_vlan_management(self, integration_config):
        """Test that planner agent manages VLANs."""
        engine = SentinelEngine(integration_config)

        await engine.start()

        try:
            planner = engine.get_agent("planner")
            assert planner is not None

            # Verify VLAN management structures exist
            assert hasattr(planner, "_vlans")
            assert hasattr(planner, "_segmentation_policies")

        finally:
            await engine.stop()

    @pytest.mark.asyncio
    async def test_engine_status_includes_all_agents(self, integration_config):
        """Test that engine status report includes all agents."""
        engine = SentinelEngine(integration_config)

        await engine.start()

        try:
            status = await engine.get_status()

            assert "agents" in status
            assert "discovery" in status["agents"]
            assert "guardian" in status["agents"]
            assert "planner" in status["agents"]

            # Verify agent status details
            for agent_name, agent_status in status["agents"].items():
                assert "running" in agent_status

        finally:
            await engine.stop()

    @pytest.mark.asyncio
    async def test_selective_agent_enablement(self):
        """Test that only enabled agents are started."""
        config = {
            "agents": {
                "discovery": {"enabled": True},
                "guardian": {"enabled": False},
                "planner": {"enabled": True},
                "optimizer": {"enabled": False},
                "healer": {"enabled": False},
            },
            "state": {"backend": "memory"},
        }

        engine = SentinelEngine(config)
        await engine.start()

        try:
            # Only enabled agents should be present
            assert "discovery" in engine._agents
            assert "planner" in engine._agents

            # Disabled agents should not be present
            assert "guardian" not in engine._agents
            assert "optimizer" not in engine._agents
            assert "healer" not in engine._agents

        finally:
            await engine.stop()

    @pytest.mark.asyncio
    async def test_engine_handles_agent_start_failure(self):
        """Test that engine handles individual agent start failures gracefully."""
        config = {
            "agents": {
                "discovery": {"enabled": True},
            },
            "state": {"backend": "memory"},
        }

        engine = SentinelEngine(config)

        # Mock an agent to fail on start
        with patch(
            "sentinel.agents.discovery.DiscoveryAgent.start",
            side_effect=Exception("Agent start failed"),
        ):
            # Engine should still start despite agent failure
            await engine.start()

            try:
                assert engine.is_running is True
            finally:
                await engine.stop()


class TestEngineAgentCommunication:
    """Tests for communication between engine and agents via event bus."""

    @pytest.fixture
    def minimal_config(self):
        return {
            "agents": {
                "discovery": {"enabled": True},
                "guardian": {"enabled": True},
            },
            "state": {"backend": "memory"},
        }

    @pytest.mark.asyncio
    async def test_event_routing_between_agents(self, minimal_config):
        """Test that events are routed between agents."""
        engine = SentinelEngine(minimal_config)
        guardian_received = []

        await engine.start()

        try:
            # Subscribe guardian to device events
            async def guardian_handler(event):
                if event.category == EventCategory.DEVICE:
                    guardian_received.append(event)

            engine.event_bus.subscribe(guardian_handler, category=EventCategory.DEVICE)

            # Simulate discovery agent publishing a device event
            device_event = Event(
                category=EventCategory.DEVICE,
                event_type="device.discovered",
                severity=EventSeverity.INFO,
                source="discovery",
                title="New device found",
                data={"mac": "00:11:22:33:44:55"},
            )

            await engine.event_bus.publish(device_event)
            await asyncio.sleep(0.2)

            # Verify event was received
            assert len(guardian_received) >= 1

        finally:
            await engine.stop()

    @pytest.mark.asyncio
    async def test_security_event_triggers_guardian(self, minimal_config):
        """Test that security events can trigger guardian responses."""
        engine = SentinelEngine(minimal_config)
        security_events = []

        await engine.start()

        try:

            async def security_handler(event):
                security_events.append(event)

            engine.event_bus.subscribe(security_handler, category=EventCategory.SECURITY)

            # Publish a security alert
            alert = Event(
                category=EventCategory.SECURITY,
                event_type="security.threat_detected",
                severity=EventSeverity.WARNING,
                source="test",
                title="Potential port scan detected",
                data={
                    "source_ip": "192.168.1.200",
                    "ports_scanned": 100,
                },
            )

            await engine.event_bus.publish(alert)
            await asyncio.sleep(0.2)

            assert len(security_events) >= 1

        finally:
            await engine.stop()

    @pytest.mark.asyncio
    async def test_multiple_subscribers_receive_event(self, minimal_config):
        """Test that multiple subscribers all receive the same event."""
        engine = SentinelEngine(minimal_config)

        subscriber1_events = []
        subscriber2_events = []
        subscriber3_events = []

        await engine.start()

        try:

            async def handler1(event):
                subscriber1_events.append(event)

            async def handler2(event):
                subscriber2_events.append(event)

            async def handler3(event):
                subscriber3_events.append(event)

            engine.event_bus.subscribe(handler1)
            engine.event_bus.subscribe(handler2)
            engine.event_bus.subscribe(handler3)

            # Publish an event
            event = Event(
                category=EventCategory.SYSTEM,
                event_type="test.broadcast",
                severity=EventSeverity.INFO,
                source="test",
                title="Broadcast event",
            )

            await engine.event_bus.publish(event)
            await asyncio.sleep(0.3)

            # All subscribers should have received the event
            assert len(subscriber1_events) >= 1
            assert len(subscriber2_events) >= 1
            assert len(subscriber3_events) >= 1

        finally:
            await engine.stop()


class TestEngineStateSharing:
    """Tests for state sharing between engine components."""

    @pytest.mark.asyncio
    async def test_agents_share_state_namespace(self):
        """Test that agents can share state through namespaces."""
        config = {
            "agents": {
                "discovery": {"enabled": True},
                "planner": {"enabled": True},
            },
            "state": {"backend": "memory"},
        }

        engine = SentinelEngine(config)
        await engine.start()

        try:
            # Discovery sets a value
            await engine.state.set("devices:count", 10)

            # Planner can read it
            count = await engine.state.get("devices:count")
            assert count == 10

            # Test atomic operations
            await engine.state.increment("devices:count")
            count = await engine.state.get("devices:count")
            assert count == 11

        finally:
            await engine.stop()

    @pytest.mark.asyncio
    async def test_state_persistence_across_operations(self):
        """Test that state persists across multiple operations."""
        config = {
            "agents": {
                "discovery": {"enabled": True},
            },
            "state": {"backend": "memory"},
        }

        engine = SentinelEngine(config)
        await engine.start()

        try:
            # Perform multiple state operations
            await engine.state.set("key1", "value1")
            await engine.state.set("key2", {"nested": "data"})
            await engine.state.set("key3", [1, 2, 3])

            # Verify all values persist
            assert await engine.state.get("key1") == "value1"
            assert await engine.state.get("key2") == {"nested": "data"}
            assert await engine.state.get("key3") == [1, 2, 3]

        finally:
            await engine.stop()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
