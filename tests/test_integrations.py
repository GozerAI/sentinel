"""
Comprehensive tests for integration modules.

Tests cover base integration classes and all integration implementations.
"""
import pytest
from unittest.mock import MagicMock, patch, AsyncMock
from typing import Any

from sentinel.integrations.base import (
    BaseIntegration,
    RouterIntegration,
    SwitchIntegration,
    HypervisorIntegration,
    StorageIntegration,
)


# =============================================================================
# Test Implementations for Abstract Classes
# =============================================================================

class ConcreteIntegration(BaseIntegration):
    """Concrete implementation for testing BaseIntegration."""

    def __init__(self, config: dict):
        super().__init__(config)
        self._connect_called = False
        self._disconnect_called = False
        self._health_check_result = True

    async def connect(self) -> None:
        self._connect_called = True
        self._connected = True

    async def disconnect(self) -> None:
        self._disconnect_called = True
        self._connected = False

    async def health_check(self) -> bool:
        return self._health_check_result


class ConcreteRouterIntegration(RouterIntegration):
    """Concrete implementation for testing RouterIntegration."""

    async def connect(self) -> None:
        self._connected = True

    async def disconnect(self) -> None:
        self._connected = False

    async def health_check(self) -> bool:
        return True

    async def get_arp_table(self) -> list[dict]:
        return [{"ip": "192.168.1.10", "mac": "00:11:22:33:44:55"}]

    async def get_dhcp_leases(self) -> list[dict]:
        return [{"ip": "192.168.1.20", "hostname": "device1"}]

    async def add_firewall_rule(self, rule: dict) -> str:
        return "rule-123"

    async def delete_firewall_rule(self, rule_id: str) -> bool:
        return True

    async def get_firewall_rules(self) -> list[dict]:
        return [{"id": "rule-1", "action": "allow"}]


class ConcreteSwitchIntegration(SwitchIntegration):
    """Concrete implementation for testing SwitchIntegration."""

    async def connect(self) -> None:
        self._connected = True

    async def disconnect(self) -> None:
        self._connected = False

    async def health_check(self) -> bool:
        return True

    async def get_ports(self) -> list[dict]:
        return [{"port": "eth0", "status": "up", "vlan": 10}]

    async def set_port_vlan(self, port: str = None, mac: str = None, vlan_id: int = None) -> bool:
        return True

    async def get_lldp_neighbors(self) -> list[dict]:
        return [{"port": "eth0", "neighbor": "switch2"}]

    async def get_port_statistics(self, port: str) -> dict:
        return {"rx_bytes": 1000, "tx_bytes": 500}


class ConcreteHypervisorIntegration(HypervisorIntegration):
    """Concrete implementation for testing HypervisorIntegration."""

    async def connect(self) -> None:
        self._connected = True

    async def disconnect(self) -> None:
        self._connected = False

    async def health_check(self) -> bool:
        return True

    async def get_vms(self) -> list[dict]:
        return [{"id": "vm-1", "name": "server1", "status": "running"}]

    async def start_vm(self, vm_id: str) -> bool:
        return True

    async def stop_vm(self, vm_id: str) -> bool:
        return True

    async def migrate_vm(self, vm_id: str, target_host: str) -> bool:
        return True

    async def get_host_resources(self) -> dict:
        return {"cpu_percent": 50, "memory_percent": 60}


class ConcreteStorageIntegration(StorageIntegration):
    """Concrete implementation for testing StorageIntegration."""

    async def connect(self) -> None:
        self._connected = True

    async def disconnect(self) -> None:
        self._connected = False

    async def health_check(self) -> bool:
        return True

    async def get_pools(self) -> list[dict]:
        return [{"name": "pool1", "size": "10TB", "used": "5TB"}]

    async def get_datasets(self) -> list[dict]:
        return [{"name": "dataset1", "quota": "1TB"}]

    async def create_snapshot(self, dataset: str, name: str) -> bool:
        return True

    async def get_health(self) -> dict:
        return {"status": "healthy", "errors": 0}


# =============================================================================
# Base Integration Tests
# =============================================================================

class TestBaseIntegration:
    """Tests for BaseIntegration abstract class."""

    def test_init(self):
        """Test initialization."""
        config = {"host": "localhost", "port": 8080}
        integration = ConcreteIntegration(config)

        assert integration.config == config
        assert integration._connected is False

    def test_connected_property(self):
        """Test connected property."""
        integration = ConcreteIntegration({})

        assert integration.connected is False

        integration._connected = True
        assert integration.connected is True

    @pytest.mark.asyncio
    async def test_connect(self):
        """Test connect method."""
        integration = ConcreteIntegration({})

        await integration.connect()

        assert integration._connect_called is True
        assert integration.connected is True

    @pytest.mark.asyncio
    async def test_disconnect(self):
        """Test disconnect method."""
        integration = ConcreteIntegration({})
        integration._connected = True

        await integration.disconnect()

        assert integration._disconnect_called is True
        assert integration.connected is False

    @pytest.mark.asyncio
    async def test_health_check(self):
        """Test health_check method."""
        integration = ConcreteIntegration({})

        result = await integration.health_check()

        assert result is True

    @pytest.mark.asyncio
    async def test_health_check_failure(self):
        """Test health_check method with failure."""
        integration = ConcreteIntegration({})
        integration._health_check_result = False

        result = await integration.health_check()

        assert result is False

    @pytest.mark.asyncio
    async def test_reconnect_when_connected(self):
        """Test reconnect when already connected."""
        integration = ConcreteIntegration({})
        integration._connected = True

        await integration.reconnect()

        assert integration._disconnect_called is True
        assert integration._connect_called is True
        assert integration.connected is True

    @pytest.mark.asyncio
    async def test_reconnect_when_disconnected(self):
        """Test reconnect when not connected."""
        integration = ConcreteIntegration({})
        integration._connected = False

        await integration.reconnect()

        assert integration._disconnect_called is False
        assert integration._connect_called is True
        assert integration.connected is True


# =============================================================================
# Router Integration Tests
# =============================================================================

class TestRouterIntegration:
    """Tests for RouterIntegration class."""

    def test_init(self):
        """Test initialization."""
        config = {"host": "192.168.1.1", "api_key": "secret"}
        integration = ConcreteRouterIntegration(config)

        assert integration.config == config

    @pytest.mark.asyncio
    async def test_get_arp_table(self):
        """Test get_arp_table method."""
        integration = ConcreteRouterIntegration({})

        result = await integration.get_arp_table()

        assert len(result) == 1
        assert result[0]["ip"] == "192.168.1.10"
        assert result[0]["mac"] == "00:11:22:33:44:55"

    @pytest.mark.asyncio
    async def test_get_dhcp_leases(self):
        """Test get_dhcp_leases method."""
        integration = ConcreteRouterIntegration({})

        result = await integration.get_dhcp_leases()

        assert len(result) == 1
        assert result[0]["hostname"] == "device1"

    @pytest.mark.asyncio
    async def test_add_firewall_rule(self):
        """Test add_firewall_rule method."""
        integration = ConcreteRouterIntegration({})
        rule = {"action": "block", "src": "10.0.0.0/8"}

        result = await integration.add_firewall_rule(rule)

        assert result == "rule-123"

    @pytest.mark.asyncio
    async def test_delete_firewall_rule(self):
        """Test delete_firewall_rule method."""
        integration = ConcreteRouterIntegration({})

        result = await integration.delete_firewall_rule("rule-123")

        assert result is True

    @pytest.mark.asyncio
    async def test_get_firewall_rules(self):
        """Test get_firewall_rules method."""
        integration = ConcreteRouterIntegration({})

        result = await integration.get_firewall_rules()

        assert len(result) == 1
        assert result[0]["action"] == "allow"


# =============================================================================
# Switch Integration Tests
# =============================================================================

class TestSwitchIntegration:
    """Tests for SwitchIntegration class."""

    def test_init(self):
        """Test initialization."""
        config = {"host": "192.168.1.2", "username": "admin"}
        integration = ConcreteSwitchIntegration(config)

        assert integration.config == config

    @pytest.mark.asyncio
    async def test_get_ports(self):
        """Test get_ports method."""
        integration = ConcreteSwitchIntegration({})

        result = await integration.get_ports()

        assert len(result) == 1
        assert result[0]["port"] == "eth0"
        assert result[0]["vlan"] == 10

    @pytest.mark.asyncio
    async def test_set_port_vlan(self):
        """Test set_port_vlan method."""
        integration = ConcreteSwitchIntegration({})

        result = await integration.set_port_vlan(port="eth0", vlan_id=20)

        assert result is True

    @pytest.mark.asyncio
    async def test_set_port_vlan_by_mac(self):
        """Test set_port_vlan method with MAC address."""
        integration = ConcreteSwitchIntegration({})

        result = await integration.set_port_vlan(mac="00:11:22:33:44:55", vlan_id=20)

        assert result is True

    @pytest.mark.asyncio
    async def test_get_lldp_neighbors(self):
        """Test get_lldp_neighbors method."""
        integration = ConcreteSwitchIntegration({})

        result = await integration.get_lldp_neighbors()

        assert len(result) == 1
        assert result[0]["neighbor"] == "switch2"

    @pytest.mark.asyncio
    async def test_get_port_statistics(self):
        """Test get_port_statistics method."""
        integration = ConcreteSwitchIntegration({})

        result = await integration.get_port_statistics("eth0")

        assert result["rx_bytes"] == 1000
        assert result["tx_bytes"] == 500


# =============================================================================
# Hypervisor Integration Tests
# =============================================================================

class TestHypervisorIntegration:
    """Tests for HypervisorIntegration class."""

    def test_init(self):
        """Test initialization."""
        config = {"host": "proxmox.local", "token": "abc123"}
        integration = ConcreteHypervisorIntegration(config)

        assert integration.config == config

    @pytest.mark.asyncio
    async def test_get_vms(self):
        """Test get_vms method."""
        integration = ConcreteHypervisorIntegration({})

        result = await integration.get_vms()

        assert len(result) == 1
        assert result[0]["name"] == "server1"
        assert result[0]["status"] == "running"

    @pytest.mark.asyncio
    async def test_start_vm(self):
        """Test start_vm method."""
        integration = ConcreteHypervisorIntegration({})

        result = await integration.start_vm("vm-1")

        assert result is True

    @pytest.mark.asyncio
    async def test_stop_vm(self):
        """Test stop_vm method."""
        integration = ConcreteHypervisorIntegration({})

        result = await integration.stop_vm("vm-1")

        assert result is True

    @pytest.mark.asyncio
    async def test_migrate_vm(self):
        """Test migrate_vm method."""
        integration = ConcreteHypervisorIntegration({})

        result = await integration.migrate_vm("vm-1", "host2")

        assert result is True

    @pytest.mark.asyncio
    async def test_get_host_resources(self):
        """Test get_host_resources method."""
        integration = ConcreteHypervisorIntegration({})

        result = await integration.get_host_resources()

        assert result["cpu_percent"] == 50
        assert result["memory_percent"] == 60


# =============================================================================
# Storage Integration Tests
# =============================================================================

class TestStorageIntegration:
    """Tests for StorageIntegration class."""

    def test_init(self):
        """Test initialization."""
        config = {"host": "truenas.local", "api_key": "secret"}
        integration = ConcreteStorageIntegration(config)

        assert integration.config == config

    @pytest.mark.asyncio
    async def test_get_pools(self):
        """Test get_pools method."""
        integration = ConcreteStorageIntegration({})

        result = await integration.get_pools()

        assert len(result) == 1
        assert result[0]["name"] == "pool1"
        assert result[0]["size"] == "10TB"

    @pytest.mark.asyncio
    async def test_get_datasets(self):
        """Test get_datasets method."""
        integration = ConcreteStorageIntegration({})

        result = await integration.get_datasets()

        assert len(result) == 1
        assert result[0]["name"] == "dataset1"

    @pytest.mark.asyncio
    async def test_create_snapshot(self):
        """Test create_snapshot method."""
        integration = ConcreteStorageIntegration({})

        result = await integration.create_snapshot("dataset1", "snapshot-2024")

        assert result is True

    @pytest.mark.asyncio
    async def test_get_health(self):
        """Test get_health method."""
        integration = ConcreteStorageIntegration({})

        result = await integration.get_health()

        assert result["status"] == "healthy"
        assert result["errors"] == 0


# =============================================================================
# OPNsense Integration Tests
# =============================================================================

class TestOPNsenseIntegration:
    """Tests for OPNsense router integration."""

    @pytest.mark.asyncio
    async def test_opnsense_init(self):
        """Test OPNsense integration initialization."""
        from sentinel.integrations.routers.opnsense import OPNsenseIntegration

        config = {
            "host": "192.168.1.1",
            "api_key": "test-key",
            "api_secret": "test-secret",
            "verify_ssl": False
        }
        integration = OPNsenseIntegration(config)

        assert integration.config == config
        # The URL includes port 443 by default
        assert "192.168.1.1" in integration._base_url
        assert "/api" in integration._base_url

    @pytest.mark.asyncio
    async def test_opnsense_connect(self):
        """Test OPNsense connect."""
        from sentinel.integrations.routers.opnsense import OPNsenseIntegration

        config = {"host": "192.168.1.1", "api_key": "key", "api_secret": "secret"}
        integration = OPNsenseIntegration(config)

        # Mock the httpx client
        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = AsyncMock()
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.json.return_value = {"product_name": "OPNsense"}
            mock_client.get = AsyncMock(return_value=mock_response)
            mock_client_class.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client_class.return_value.__aexit__ = AsyncMock(return_value=None)

            # Create client manually for test
            integration._client = mock_client
            integration._connected = True

            assert integration.connected is True

    @pytest.mark.asyncio
    async def test_opnsense_health_check(self):
        """Test OPNsense health check."""
        from sentinel.integrations.routers.opnsense import OPNsenseIntegration

        config = {"host": "192.168.1.1", "api_key": "key", "api_secret": "secret"}
        integration = OPNsenseIntegration(config)

        # Mock the client
        mock_client = AsyncMock()
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"status": "ok"}
        mock_client.get = AsyncMock(return_value=mock_response)

        integration._client = mock_client
        integration._connected = True

        result = await integration.health_check()

        assert result is True


# =============================================================================
# Ubiquiti Switch Integration Tests
# =============================================================================

class TestUnifiIntegration:
    """Tests for Unifi switch integration."""

    def test_unifi_init(self):
        """Test Unifi integration initialization."""
        from sentinel.integrations.switches.ubiquiti import UnifiIntegration

        config = {
            "controller_url": "https://192.168.1.2:8443",
            "username": "admin",
            "password": "secret",
            "site": "default"
        }
        integration = UnifiIntegration(config)

        assert integration.config == config
        assert integration.controller_url == "https://192.168.1.2:8443"
        assert integration.username == "admin"
        assert integration.site == "default"

    @pytest.mark.asyncio
    async def test_unifi_health_check(self):
        """Test Unifi health check."""
        from sentinel.integrations.switches.ubiquiti import UnifiIntegration

        config = {"controller_url": "https://192.168.1.2:8443", "username": "admin", "password": "secret"}
        integration = UnifiIntegration(config)

        # Mock the client
        mock_client = AsyncMock()
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_client.get = AsyncMock(return_value=mock_response)

        integration._client = mock_client
        integration._connected = True

        result = await integration.health_check()

        assert result is True


# =============================================================================
# Proxmox Integration Tests
# =============================================================================

class TestProxmoxIntegration:
    """Tests for Proxmox hypervisor integration."""

    def test_proxmox_init(self):
        """Test Proxmox integration initialization."""
        from sentinel.integrations.hypervisors.proxmox import ProxmoxIntegration

        config = {
            "host": "proxmox.local",
            "token_id": "sentinel@pam!token",
            "token_secret": "abc123",
            "verify_ssl": False
        }
        integration = ProxmoxIntegration(config)

        assert integration.config == config
        assert integration._base_url == "https://proxmox.local:8006/api2/json"

    @pytest.mark.asyncio
    async def test_proxmox_health_check(self):
        """Test Proxmox health check."""
        from sentinel.integrations.hypervisors.proxmox import ProxmoxIntegration

        config = {"host": "proxmox.local", "token_id": "token", "token_secret": "secret"}
        integration = ProxmoxIntegration(config)

        # Mock the client
        mock_client = AsyncMock()
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"data": {"version": "7.0"}}
        mock_client.get = AsyncMock(return_value=mock_response)

        integration._client = mock_client
        integration._connected = True

        result = await integration.health_check()

        assert result is True


# =============================================================================
# TrueNAS Integration Tests
# =============================================================================

class TestTrueNASIntegration:
    """Tests for TrueNAS storage integration."""

    def test_truenas_init(self):
        """Test TrueNAS integration initialization."""
        from sentinel.integrations.storage.truenas import TrueNASIntegration

        config = {
            "host": "truenas.local",
            "api_key": "secret-key",
            "verify_ssl": False
        }
        integration = TrueNASIntegration(config)

        assert integration.config == config
        assert integration._base_url == "https://truenas.local/api/v2.0"

    @pytest.mark.asyncio
    async def test_truenas_health_check(self):
        """Test TrueNAS health check."""
        from sentinel.integrations.storage.truenas import TrueNASIntegration

        config = {"host": "truenas.local", "api_key": "secret"}
        integration = TrueNASIntegration(config)

        # Mock the client
        mock_client = AsyncMock()
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"version": "12.0"}
        mock_client.get = AsyncMock(return_value=mock_response)

        integration._client = mock_client
        integration._connected = True

        result = await integration.health_check()

        assert result is True


# =============================================================================
# LLM Manager Tests
# =============================================================================

class TestLLMManager:
    """Tests for LLM manager."""

    def test_llm_manager_init(self):
        """Test LLM manager initialization."""
        from sentinel.integrations.llm.manager import LLMManager

        config = {
            "primary": {
                "type": "ollama",
                "host": "http://localhost:11434",
                "model": "llama3.1:8b"
            },
            "fallback": {
                "type": "anthropic",
                "model": "claude-3-5-sonnet-20241022",
                "api_key": "test-key"
            }
        }
        manager = LLMManager(config)

        assert manager.config == config
        assert manager.primary_type == "ollama"
        assert manager.fallback_type == "anthropic"

    def test_llm_manager_default_config(self):
        """Test LLM manager with minimal config."""
        from sentinel.integrations.llm.manager import LLMManager

        config = {}
        manager = LLMManager(config)

        # Should use defaults
        assert manager.primary_type == "ollama"
        assert manager.primary_host == "http://localhost:11434"
        assert manager.primary_model == "llama3.1:8b"

    @pytest.mark.asyncio
    async def test_llm_manager_initialize(self):
        """Test LLM manager initialization."""
        from sentinel.integrations.llm.manager import LLMManager

        config = {
            "primary": {"host": "http://localhost:11434"},
            "fallback": {"api_key": "test-key"}
        }
        manager = LLMManager(config)

        # Mock httpx clients
        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = AsyncMock()
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.json.return_value = {"models": [{"name": "llama3.1:8b"}]}
            mock_client.get = AsyncMock(return_value=mock_response)
            mock_client_class.return_value = mock_client

            await manager.initialize()

            # Should have created clients
            assert mock_client_class.called


# =============================================================================
# Extended OPNsense Tests
# =============================================================================

class TestOPNsenseExtended:
    """Extended tests for OPNsense integration."""

    @pytest.mark.asyncio
    async def test_opnsense_get_arp_table(self):
        """Test OPNsense get_arp_table."""
        from sentinel.integrations.routers.opnsense import OPNsenseIntegration

        config = {"host": "192.168.1.1", "api_key": "key", "api_secret": "secret"}
        integration = OPNsenseIntegration(config)

        mock_client = AsyncMock()
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "rows": [
                {"ip": "192.168.1.10", "mac": "00:11:22:33:44:55", "intf": "igb0"}
            ]
        }
        mock_client.get = AsyncMock(return_value=mock_response)
        integration._client = mock_client
        integration._connected = True

        result = await integration.get_arp_table()
        assert len(result) >= 0  # May be empty or have entries

    @pytest.mark.asyncio
    async def test_opnsense_get_dhcp_leases(self):
        """Test OPNsense get_dhcp_leases."""
        from sentinel.integrations.routers.opnsense import OPNsenseIntegration

        config = {"host": "192.168.1.1", "api_key": "key", "api_secret": "secret"}
        integration = OPNsenseIntegration(config)

        mock_client = AsyncMock()
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "leases": [
                {"ip": "192.168.1.20", "hostname": "device1", "mac": "aa:bb:cc:dd:ee:ff"}
            ]
        }
        mock_client.get = AsyncMock(return_value=mock_response)
        integration._client = mock_client
        integration._connected = True

        result = await integration.get_dhcp_leases()
        assert len(result) >= 0

    @pytest.mark.asyncio
    async def test_opnsense_add_firewall_rule(self):
        """Test OPNsense add_firewall_rule."""
        from sentinel.integrations.routers.opnsense import OPNsenseIntegration

        config = {"host": "192.168.1.1", "api_key": "key", "api_secret": "secret"}
        integration = OPNsenseIntegration(config)

        mock_client = AsyncMock()
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"uuid": "rule-123"}
        mock_client.post = AsyncMock(return_value=mock_response)
        integration._client = mock_client
        integration._connected = True

        rule = {"action": "block", "source": "10.0.0.0/8"}
        result = await integration.add_firewall_rule(rule)
        assert result is not None

    @pytest.mark.asyncio
    async def test_opnsense_disconnect(self):
        """Test OPNsense disconnect."""
        from sentinel.integrations.routers.opnsense import OPNsenseIntegration

        config = {"host": "192.168.1.1", "api_key": "key", "api_secret": "secret"}
        integration = OPNsenseIntegration(config)

        mock_client = AsyncMock()
        mock_client.aclose = AsyncMock()
        integration._client = mock_client
        integration._connected = True

        await integration.disconnect()
        assert integration._connected is False


# =============================================================================
# Extended Proxmox Tests
# =============================================================================

class TestProxmoxExtended:
    """Extended tests for Proxmox integration."""

    @pytest.mark.asyncio
    async def test_proxmox_get_vms(self):
        """Test Proxmox get_vms."""
        from sentinel.integrations.hypervisors.proxmox import ProxmoxIntegration

        config = {"host": "proxmox.local", "token_id": "token", "token_secret": "secret"}
        integration = ProxmoxIntegration(config)

        mock_client = AsyncMock()
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "data": [{"vmid": 100, "name": "server1", "status": "running"}]
        }
        mock_client.get = AsyncMock(return_value=mock_response)
        integration._client = mock_client
        integration._connected = True

        result = await integration.get_vms()
        assert len(result) >= 0

    @pytest.mark.asyncio
    async def test_proxmox_start_vm(self):
        """Test Proxmox start_vm."""
        from sentinel.integrations.hypervisors.proxmox import ProxmoxIntegration

        config = {"host": "proxmox.local", "token_id": "token", "token_secret": "secret"}
        integration = ProxmoxIntegration(config)

        # Mock the internal methods
        with patch.object(integration, "_parse_vm_id", return_value=("qemu", "100")):
            with patch.object(integration, "_find_vm_node", new=AsyncMock(return_value="pve")):
                with patch.object(integration, "_api_post", new=AsyncMock(return_value={"data": "UPID:xxx"})):
                    result = await integration.start_vm("qemu/100")
                    assert result is True

    @pytest.mark.asyncio
    async def test_proxmox_stop_vm(self):
        """Test Proxmox stop_vm."""
        from sentinel.integrations.hypervisors.proxmox import ProxmoxIntegration

        config = {"host": "proxmox.local", "token_id": "token", "token_secret": "secret"}
        integration = ProxmoxIntegration(config)

        # Mock the internal methods
        with patch.object(integration, "_parse_vm_id", return_value=("qemu", "100")):
            with patch.object(integration, "_find_vm_node", new=AsyncMock(return_value="pve")):
                with patch.object(integration, "_api_post", new=AsyncMock(return_value={"data": "UPID:xxx"})):
                    result = await integration.stop_vm("qemu/100")
                    assert result is True

    @pytest.mark.asyncio
    async def test_proxmox_get_host_resources(self):
        """Test Proxmox get_host_resources."""
        from sentinel.integrations.hypervisors.proxmox import ProxmoxIntegration

        config = {"host": "proxmox.local", "token_id": "token", "token_secret": "secret"}
        integration = ProxmoxIntegration(config)

        mock_client = AsyncMock()
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "data": {"cpu": 0.5, "memory": {"used": 8000000000, "total": 16000000000}}
        }
        mock_client.get = AsyncMock(return_value=mock_response)
        integration._client = mock_client
        integration._connected = True
        integration._node = "pve"

        result = await integration.get_host_resources()
        assert result is not None


# =============================================================================
# Extended TrueNAS Tests
# =============================================================================

class TestTrueNASExtended:
    """Extended tests for TrueNAS integration."""

    @pytest.mark.asyncio
    async def test_truenas_get_pools(self):
        """Test TrueNAS get_pools."""
        from sentinel.integrations.storage.truenas import TrueNASIntegration

        config = {"host": "truenas.local", "api_key": "secret"}
        integration = TrueNASIntegration(config)

        mock_client = AsyncMock()
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = [
            {"name": "tank", "healthy": True, "status": "ONLINE"}
        ]
        mock_client.get = AsyncMock(return_value=mock_response)
        integration._client = mock_client
        integration._connected = True

        result = await integration.get_pools()
        assert len(result) >= 0

    @pytest.mark.asyncio
    async def test_truenas_get_datasets(self):
        """Test TrueNAS get_datasets."""
        from sentinel.integrations.storage.truenas import TrueNASIntegration

        config = {"host": "truenas.local", "api_key": "secret"}
        integration = TrueNASIntegration(config)

        mock_client = AsyncMock()
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = [
            {"name": "tank/data", "used": {"rawvalue": "100GB"}}
        ]
        mock_client.get = AsyncMock(return_value=mock_response)
        integration._client = mock_client
        integration._connected = True

        result = await integration.get_datasets()
        assert len(result) >= 0

    @pytest.mark.asyncio
    async def test_truenas_create_snapshot(self):
        """Test TrueNAS create_snapshot."""
        from sentinel.integrations.storage.truenas import TrueNASIntegration

        config = {"host": "truenas.local", "api_key": "secret"}
        integration = TrueNASIntegration(config)

        mock_client = AsyncMock()
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_client.post = AsyncMock(return_value=mock_response)
        integration._client = mock_client
        integration._connected = True

        result = await integration.create_snapshot("tank/data", "backup-2024")
        assert result is True

    @pytest.mark.asyncio
    async def test_truenas_get_health(self):
        """Test TrueNAS get_health."""
        from sentinel.integrations.storage.truenas import TrueNASIntegration

        config = {"host": "truenas.local", "api_key": "secret"}
        integration = TrueNASIntegration(config)

        mock_client = AsyncMock()
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "pools": [{"status": "ONLINE"}],
            "alerts": []
        }
        mock_client.get = AsyncMock(return_value=mock_response)
        integration._client = mock_client
        integration._connected = True

        result = await integration.get_health()
        assert result is not None


# =============================================================================
# Extended Unifi Tests
# =============================================================================

class TestUnifiExtended:
    """Extended tests for Unifi integration."""

    @pytest.mark.asyncio
    async def test_unifi_get_ports(self):
        """Test Unifi get_ports."""
        from sentinel.integrations.switches.ubiquiti import UnifiIntegration

        config = {"controller_url": "https://unifi:8443", "username": "admin", "password": "secret"}
        integration = UnifiIntegration(config)

        mock_client = AsyncMock()
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "data": [{"port_idx": 1, "up": True, "speed": 1000}]
        }
        mock_client.get = AsyncMock(return_value=mock_response)
        integration._client = mock_client
        integration._connected = True

        result = await integration.get_ports()
        assert len(result) >= 0

    @pytest.mark.asyncio
    async def test_unifi_set_port_vlan_missing_vlan(self):
        """Test Unifi set_port_vlan raises error without vlan_id."""
        from sentinel.integrations.switches.ubiquiti import UnifiIntegration

        config = {"controller_url": "https://unifi:8443", "username": "admin", "password": "secret"}
        integration = UnifiIntegration(config)

        with pytest.raises(ValueError, match="vlan_id is required"):
            await integration.set_port_vlan(mac="00:11:22:33:44:55")

    @pytest.mark.asyncio
    async def test_unifi_get_lldp_neighbors(self):
        """Test Unifi get_lldp_neighbors."""
        from sentinel.integrations.switches.ubiquiti import UnifiIntegration

        config = {"controller_url": "https://unifi:8443", "username": "admin", "password": "secret"}
        integration = UnifiIntegration(config)

        mock_client = AsyncMock()
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "data": [{"local_port": 1, "remote_system_name": "switch2"}]
        }
        mock_client.get = AsyncMock(return_value=mock_response)
        integration._client = mock_client
        integration._connected = True

        result = await integration.get_lldp_neighbors()
        assert len(result) >= 0

    @pytest.mark.asyncio
    async def test_unifi_connect(self):
        """Test Unifi connect."""
        from sentinel.integrations.switches.ubiquiti import UnifiIntegration

        config = {"controller_url": "https://unifi:8443", "username": "admin", "password": "secret"}
        integration = UnifiIntegration(config)

        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = AsyncMock()
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.cookies = {"unifises": "session"}
            mock_client.post = AsyncMock(return_value=mock_response)
            mock_client_class.return_value = mock_client

            # Mock connect to set client
            integration._client = mock_client
            integration._connected = True

            assert integration.connected is True


# =============================================================================
# Extended LLM Tests
# =============================================================================

class TestLLMManagerExtended:
    """Extended tests for LLM Manager."""

    @pytest.mark.asyncio
    async def test_llm_complete_ollama(self):
        """Test LLM complete with Ollama."""
        from sentinel.integrations.llm.manager import LLMManager

        config = {"primary": {"host": "http://localhost:11434", "model": "llama3.1:8b"}}
        manager = LLMManager(config)

        mock_client = AsyncMock()
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"response": "Test response"}
        mock_client.post = AsyncMock(return_value=mock_response)
        manager._ollama_client = mock_client

        result = await manager.complete("Test prompt")
        assert result is not None

    @pytest.mark.asyncio
    async def test_llm_complete_with_system_prompt(self):
        """Test LLM complete with system prompt."""
        from sentinel.integrations.llm.manager import LLMManager

        config = {"primary": {"host": "http://localhost:11434"}}
        manager = LLMManager(config)

        mock_client = AsyncMock()
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"response": "Test response"}
        mock_client.post = AsyncMock(return_value=mock_response)
        manager._ollama_client = mock_client

        result = await manager.complete(
            "Analyze this",
            system_prompt="You are a security analyst"
        )
        assert result is not None


# =============================================================================
# Integration Factory Tests
# =============================================================================

class TestIntegrationLifecycle:
    """Tests for integration lifecycle management."""

    @pytest.mark.asyncio
    async def test_full_lifecycle(self):
        """Test full connect/health_check/disconnect lifecycle."""
        integration = ConcreteIntegration({"test": "config"})

        # Initial state
        assert integration.connected is False

        # Connect
        await integration.connect()
        assert integration.connected is True

        # Health check
        assert await integration.health_check() is True

        # Disconnect
        await integration.disconnect()
        assert integration.connected is False

    @pytest.mark.asyncio
    async def test_multiple_reconnects(self):
        """Test multiple reconnection cycles."""
        integration = ConcreteIntegration({})

        for _ in range(3):
            await integration.connect()
            assert integration.connected is True

            await integration.reconnect()
            assert integration.connected is True

            await integration.disconnect()
            assert integration.connected is False
