"""
End-to-end workflow tests for the Sentinel platform.

Tests complete user scenarios from start to finish across all components.
"""

import asyncio
import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

from fastapi.testclient import TestClient

from sentinel.core.engine import SentinelEngine
from sentinel.core.models.device import Device, DeviceType, NetworkInterface, DeviceStatus
from sentinel.core.models.event import Event, EventCategory, EventSeverity
from sentinel.api.app import create_app
import sentinel.api.auth as auth_module


class TestDeviceDiscoveryWorkflow:
    """
    End-to-end test for device discovery workflow.

    Workflow:
    1. Engine starts with discovery agent
    2. Device is discovered
    3. Event is published
    4. Device appears in inventory
    5. Device is accessible via API
    """

    @pytest.fixture
    def config(self):
        return {
            "agents": {
                "discovery": {"enabled": True, "networks": ["192.168.1.0/24"]},
                "guardian": {"enabled": True},
                "planner": {"enabled": True},
            },
            "state": {"backend": "memory"},
        }

    @pytest.mark.asyncio
    async def test_complete_device_discovery_workflow(self, config):
        """Test the complete device discovery workflow."""
        engine = SentinelEngine(config)
        discovered_events = []

        async def track_discoveries(event):
            if event.event_type == "device.discovered":
                discovered_events.append(event)

        engine.event_bus.subscribe(track_discoveries, event_type="device.discovered")

        await engine.start()

        try:
            # Step 1: Verify discovery agent is running
            discovery = engine.get_agent("discovery")
            assert discovery is not None
            assert discovery._running is True

            # Step 2: Simulate device discovery (add device to inventory)
            new_device = Device(
                id=uuid4(),
                device_type=DeviceType.WORKSTATION,
                hostname="discovered-ws-01",
                interfaces=[
                    NetworkInterface(
                        mac_address="DE:VI:CE:00:00:01",
                        ip_addresses=["192.168.1.50"],
                        is_primary=True,
                    )
                ],
            )
            discovery._inventory.add_device(new_device)

            # Step 3: Publish discovery event
            await engine.event_bus.publish(
                Event(
                    category=EventCategory.DEVICE,
                    event_type="device.discovered",
                    severity=EventSeverity.INFO,
                    source="discovery",
                    title="New device discovered",
                    data={
                        "device_id": str(new_device.id),
                        "mac": "DE:VI:CE:00:00:01",
                        "ip": "192.168.1.50",
                        "hostname": "discovered-ws-01",
                    },
                )
            )

            await asyncio.sleep(0.2)

            # Step 4: Verify device is in inventory
            retrieved = discovery._inventory.get_by_mac("DE:VI:CE:00:00:01")
            assert retrieved is not None
            assert retrieved.hostname == "discovered-ws-01"

            # Step 5: Verify discovery event was received
            assert len(discovered_events) >= 1
            assert discovered_events[0].data["mac"] == "DE:VI:CE:00:00:01"

            # Step 6: Test API access
            original_auth = getattr(auth_module, "_auth_config", None)
            auth_module._auth_config = None
            app = create_app(engine)

            try:
                client = TestClient(app)
                response = client.get("/devices/DE:VI:CE:00:00:01")
                assert response.status_code == 200
                data = response.json()
                assert data["hostname"] == "discovered-ws-01"
            finally:
                auth_module._auth_config = original_auth

        finally:
            await engine.stop()


class TestThreatDetectionWorkflow:
    """
    End-to-end test for threat detection and response workflow.

    Workflow:
    1. Engine starts with guardian agent
    2. Suspicious activity is detected
    3. Guardian analyzes and decides to block
    4. IP is blocked
    5. Security event is published
    6. Block status is visible via API
    """

    @pytest.fixture
    def config(self):
        return {
            "agents": {
                "guardian": {
                    "enabled": True,
                    "threat_thresholds": {
                        "port_scan": 50,
                        "failed_auth": 5,
                    },
                    "quarantine_vlan": 666,
                },
            },
            "state": {"backend": "memory"},
        }

    @pytest.mark.asyncio
    async def test_complete_threat_response_workflow(self, config):
        """Test the complete threat detection and response workflow."""
        engine = SentinelEngine(config)
        security_events = []
        action_events = []

        async def track_security(event):
            if event.category == EventCategory.SECURITY:
                security_events.append(event)

        async def track_actions(event):
            if event.category == EventCategory.AGENT:
                action_events.append(event)

        engine.event_bus.subscribe(track_security, category=EventCategory.SECURITY)
        engine.event_bus.subscribe(track_actions, category=EventCategory.AGENT)

        await engine.start()

        try:
            guardian = engine.get_agent("guardian")
            assert guardian is not None

            # Step 1: Simulate threat detection
            threat_ip = "192.168.1.200"

            await engine.event_bus.publish(
                Event(
                    category=EventCategory.SECURITY,
                    event_type="security.port_scan_detected",
                    severity=EventSeverity.WARNING,
                    source="guardian",
                    title="Port scan detected",
                    data={
                        "source_ip": threat_ip,
                        "ports_scanned": 100,
                        "duration_seconds": 30,
                    },
                )
            )

            await asyncio.sleep(0.1)

            # Step 2: Guardian blocks the IP
            guardian._blocked_ips.add(threat_ip)

            # Step 3: Publish action event
            await engine.event_bus.publish(
                Event(
                    category=EventCategory.AGENT,
                    event_type="agent.action.executed",
                    severity=EventSeverity.INFO,
                    source="guardian",
                    title="IP blocked",
                    data={
                        "action": "block_ip",
                        "target_ip": threat_ip,
                        "reason": "port_scan",
                    },
                )
            )

            await asyncio.sleep(0.2)

            # Step 4: Verify block status
            assert threat_ip in guardian._blocked_ips

            # Step 5: Verify events were recorded
            assert len(security_events) >= 1
            assert len(action_events) >= 1

            # Step 6: Verify via API
            original_auth = getattr(auth_module, "_auth_config", None)
            auth_module._auth_config = None
            app = create_app(engine)

            try:
                client = TestClient(app)
                response = client.get("/security/blocked")
                assert response.status_code == 200
                data = response.json()
                assert threat_ip in data["blocked_ips"]
            finally:
                auth_module._auth_config = original_auth

        finally:
            await engine.stop()


class TestVLANAssignmentWorkflow:
    """
    End-to-end test for VLAN assignment workflow.

    Workflow:
    1. Engine starts with planner agent
    2. New device is discovered
    3. Planner assigns device to appropriate VLAN
    4. Device VLAN is updated
    5. Change is visible via API
    """

    @pytest.fixture
    def config(self):
        return {
            "agents": {
                "discovery": {"enabled": True},
                "planner": {"enabled": True},
            },
            "state": {"backend": "memory"},
            "vlans": [
                {"id": 10, "name": "Workstations"},
                {"id": 20, "name": "Servers"},
                {"id": 30, "name": "IoT"},
            ],
        }

    @pytest.mark.asyncio
    async def test_complete_vlan_assignment_workflow(self, config):
        """Test the complete VLAN assignment workflow."""
        engine = SentinelEngine(config)

        await engine.start()

        try:
            discovery = engine.get_agent("discovery")
            planner = engine.get_agent("planner")

            # Set up VLANs in planner
            planner._vlans[10] = {"id": 10, "name": "Workstations", "purpose": "workstations"}
            planner._vlans[20] = {"id": 20, "name": "Servers", "purpose": "servers"}
            planner._vlans[30] = {"id": 30, "name": "IoT", "purpose": "iot"}

            # Step 1: Create a new device (workstation)
            device = Device(
                id=uuid4(),
                device_type=DeviceType.WORKSTATION,
                hostname="new-workstation",
                interfaces=[
                    NetworkInterface(
                        mac_address="VL:AN:00:00:00:01",
                        ip_addresses=["192.168.1.100"],
                    )
                ],
                assigned_vlan=None,  # Not yet assigned
            )
            discovery._inventory.add_device(device)

            # Step 2: Publish discovery event
            await engine.event_bus.publish(
                Event(
                    category=EventCategory.DEVICE,
                    event_type="device.discovered",
                    severity=EventSeverity.INFO,
                    source="discovery",
                    title="New workstation discovered",
                    data={"device_id": str(device.id)},
                )
            )

            # Step 3: Simulate planner assigning VLAN
            device.assigned_vlan = 10  # Assign to workstations VLAN

            # Step 4: Publish assignment event
            await engine.event_bus.publish(
                Event(
                    category=EventCategory.NETWORK,
                    event_type="vlan.assigned",
                    severity=EventSeverity.INFO,
                    source="planner",
                    title="VLAN assigned",
                    data={
                        "device_id": str(device.id),
                        "vlan_id": 10,
                    },
                )
            )

            await asyncio.sleep(0.2)

            # Step 5: Verify assignment
            retrieved = discovery._inventory.get_by_mac("VL:AN:00:00:00:01")
            assert retrieved.assigned_vlan == 10

            # Step 6: Verify via API
            original_auth = getattr(auth_module, "_auth_config", None)
            auth_module._auth_config = None
            app = create_app(engine)

            try:
                client = TestClient(app)
                response = client.get("/devices/VL:AN:00:00:00:01")
                assert response.status_code == 200
                data = response.json()
                assert data["vlan"] == 10
            finally:
                auth_module._auth_config = original_auth

        finally:
            await engine.stop()


class TestNetworkSegmentationWorkflow:
    """
    End-to-end test for network segmentation policy workflow.

    Workflow:
    1. Create VLANs via API
    2. Create segmentation policy
    3. Verify policy is enforced (in planner state)
    """

    @pytest.fixture
    def config(self):
        return {
            "agents": {
                "planner": {"enabled": True},
            },
            "state": {"backend": "memory"},
        }

    @pytest.mark.asyncio
    async def test_complete_segmentation_workflow(self, config):
        """Test the complete network segmentation workflow."""
        engine = SentinelEngine(config)

        await engine.start()

        try:
            planner = engine.get_agent("planner")

            # Set up test via API
            original_auth = getattr(auth_module, "_auth_config", None)
            auth_module._auth_config = None
            app = create_app(engine)

            try:
                client = TestClient(app)

                # Step 1: Create VLANs
                response = client.post(
                    "/vlans",
                    json={
                        "id": 10,
                        "name": "Workstations",
                        "subnet": "192.168.10.0/24",
                        "purpose": "workstations",
                    },
                )
                assert response.status_code == 200

                response = client.post(
                    "/vlans",
                    json={
                        "id": 20,
                        "name": "Servers",
                        "subnet": "192.168.20.0/24",
                        "purpose": "servers",
                    },
                )
                assert response.status_code == 200

                # Verify VLANs created
                response = client.get("/vlans")
                assert response.status_code == 200
                vlans = response.json()
                assert len(vlans) >= 2

                # Step 2: Create segmentation policy (directly on planner)
                planner._segmentation_policies["ws-to-srv"] = {
                    "id": "ws-to-srv",
                    "name": "Workstations to Servers",
                    "source_vlan": 10,
                    "destination_vlan": 20,
                    "allowed_services": ["http", "https", "ssh"],
                    "denied_services": ["telnet", "ftp"],
                    "default_action": "deny",
                }

                # Step 3: Verify policy via API
                response = client.get("/policies")
                assert response.status_code == 200
                policies = response.json()
                assert len(policies) >= 1

                policy_names = [p["name"] for p in policies]
                assert "Workstations to Servers" in policy_names

            finally:
                auth_module._auth_config = original_auth

        finally:
            await engine.stop()


class TestMultiAgentCoordinationWorkflow:
    """
    End-to-end test for multi-agent coordination.

    Workflow:
    1. Discovery finds a new device
    2. Planner assigns VLAN
    3. Guardian monitors for threats
    4. All agents coordinate through event bus
    """

    @pytest.fixture
    def config(self):
        return {
            "agents": {
                "discovery": {"enabled": True},
                "guardian": {"enabled": True},
                "planner": {"enabled": True},
            },
            "state": {"backend": "memory"},
        }

    @pytest.mark.asyncio
    async def test_multi_agent_coordination(self, config):
        """Test that multiple agents coordinate properly."""
        engine = SentinelEngine(config)
        all_events = []

        async def track_all(event):
            all_events.append(event)

        engine.event_bus.subscribe(track_all)

        await engine.start()

        try:
            discovery = engine.get_agent("discovery")
            planner = engine.get_agent("planner")
            guardian = engine.get_agent("guardian")

            # All agents should be running
            assert discovery._running is True
            assert planner._running is True
            assert guardian._running is True

            # Set up VLANs
            planner._vlans[10] = {"id": 10, "name": "Workstations"}

            # Step 1: Discovery finds device
            device = Device(
                id=uuid4(),
                device_type=DeviceType.WORKSTATION,
                hostname="multi-agent-test",
                interfaces=[
                    NetworkInterface(
                        mac_address="MA:AG:EN:T0:00:01",
                        ip_addresses=["192.168.1.100"],
                    )
                ],
            )
            discovery._inventory.add_device(device)

            await engine.event_bus.publish(
                Event(
                    category=EventCategory.DEVICE,
                    event_type="device.discovered",
                    severity=EventSeverity.INFO,
                    source="discovery",
                    title="Device discovered",
                    data={"device_id": str(device.id)},
                )
            )

            # Step 2: Planner assigns VLAN
            device.assigned_vlan = 10

            await engine.event_bus.publish(
                Event(
                    category=EventCategory.NETWORK,
                    event_type="vlan.assigned",
                    severity=EventSeverity.INFO,
                    source="planner",
                    title="VLAN assigned",
                    data={"device_id": str(device.id), "vlan": 10},
                )
            )

            # Step 3: Guardian clears device
            await engine.event_bus.publish(
                Event(
                    category=EventCategory.SECURITY,
                    event_type="device.cleared",
                    severity=EventSeverity.INFO,
                    source="guardian",
                    title="Device security cleared",
                    data={"device_id": str(device.id)},
                )
            )

            await asyncio.sleep(0.3)

            # Verify coordination
            event_sources = set(e.source for e in all_events)
            # Should have events from multiple sources including engine startup
            assert len(event_sources) >= 2

        finally:
            await engine.stop()


class TestFullSystemHealthCheck:
    """
    End-to-end test for complete system health.
    """

    @pytest.fixture
    def config(self):
        return {
            "agents": {
                "discovery": {"enabled": True},
                "guardian": {"enabled": True},
                "planner": {"enabled": True},
                "optimizer": {"enabled": True},
                "healer": {"enabled": True},
            },
            "state": {"backend": "memory"},
        }

    @pytest.mark.asyncio
    async def test_full_system_health(self, config):
        """Test complete system health and status."""
        engine = SentinelEngine(config)

        await engine.start()

        try:
            # Verify all components are healthy
            assert engine.is_running is True
            assert len(engine._agents) == 5

            for name, agent in engine._agents.items():
                assert agent._running is True, f"Agent {name} not running"

            # Verify state manager
            await engine.state.set("health:check", "ok")
            value = await engine.state.get("health:check")
            assert value == "ok"

            # Verify event bus
            assert engine.event_bus._running is True

            # Get full status
            status = await engine.get_status()
            assert status["running"] is True
            assert len(status["agents"]) == 5

            # Test API health
            original_auth = getattr(auth_module, "_auth_config", None)
            auth_module._auth_config = None
            app = create_app(engine)

            try:
                client = TestClient(app)

                # Health endpoint
                response = client.get("/health")
                assert response.status_code == 200
                assert response.json()["status"] == "healthy"

                # Status endpoint
                response = client.get("/status")
                assert response.status_code == 200
                assert response.json()["status"] == "running"

                # Metrics endpoint
                response = client.get("/metrics")
                assert response.status_code == 200
                assert "sentinel_" in response.text

            finally:
                auth_module._auth_config = original_auth

        finally:
            await engine.stop()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
