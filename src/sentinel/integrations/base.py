"""
Base integration class for external systems.

This module provides the foundation for all Sentinel integrations
with external systems like routers, switches, and hypervisors.
"""
from abc import ABC, abstractmethod
from typing import Optional, Any
import logging

logger = logging.getLogger(__name__)


class BaseIntegration(ABC):
    """
    Abstract base class for all external integrations.
    
    Integrations provide connectivity to external systems and expose
    a consistent interface for agents to interact with infrastructure.
    
    Subclasses must implement:
    - connect(): Establish connection to the system
    - disconnect(): Close connection
    - health_check(): Verify connectivity
    
    Attributes:
        config: Integration configuration
        connected: Whether currently connected
    
    Example:
        ```python
        class MyIntegration(BaseIntegration):
            async def connect(self):
                self._client = await create_client(self.config)
                self._connected = True
            
            async def disconnect(self):
                await self._client.close()
                self._connected = False
            
            async def health_check(self):
                return await self._client.ping()
        ```
    """
    
    def __init__(self, config: dict):
        """
        Initialize the integration.
        
        Args:
            config: Integration-specific configuration
        """
        self.config = config
        self._connected = False
    
    @abstractmethod
    async def connect(self) -> None:
        """
        Establish connection to the external system.
        
        Should set self._connected = True on success.
        
        Raises:
            ConnectionError: If connection fails
        """
        pass
    
    @abstractmethod
    async def disconnect(self) -> None:
        """
        Close connection to the external system.
        
        Should set self._connected = False.
        """
        pass
    
    @abstractmethod
    async def health_check(self) -> bool:
        """
        Check if the integration is healthy.
        
        Returns:
            True if connection is healthy
        """
        pass
    
    @property
    def connected(self) -> bool:
        """Check if currently connected."""
        return self._connected
    
    async def reconnect(self) -> None:
        """Reconnect to the external system."""
        if self._connected:
            await self.disconnect()
        await self.connect()


class RouterIntegration(BaseIntegration):
    """Base class for router integrations."""
    
    @abstractmethod
    async def get_arp_table(self) -> list[dict]:
        """Get ARP table entries."""
        pass
    
    @abstractmethod
    async def get_dhcp_leases(self) -> list[dict]:
        """Get DHCP lease information."""
        pass
    
    @abstractmethod
    async def add_firewall_rule(self, rule: dict) -> str:
        """Add a firewall rule. Returns rule ID."""
        pass
    
    @abstractmethod
    async def delete_firewall_rule(self, rule_id: str) -> bool:
        """Delete a firewall rule."""
        pass
    
    @abstractmethod
    async def get_firewall_rules(self) -> list[dict]:
        """Get all firewall rules."""
        pass


class SwitchIntegration(BaseIntegration):
    """Base class for switch integrations."""
    
    @abstractmethod
    async def get_ports(self) -> list[dict]:
        """Get all switch ports with status."""
        pass
    
    @abstractmethod
    async def set_port_vlan(self, port: str = None, mac: str = None, vlan_id: int = None) -> bool:
        """Set VLAN for a port."""
        pass
    
    @abstractmethod
    async def get_lldp_neighbors(self) -> list[dict]:
        """Get LLDP neighbor information."""
        pass
    
    @abstractmethod
    async def get_port_statistics(self, port: str) -> dict:
        """Get statistics for a port."""
        pass


class HypervisorIntegration(BaseIntegration):
    """Base class for hypervisor integrations."""
    
    @abstractmethod
    async def get_vms(self) -> list[dict]:
        """Get all VMs."""
        pass
    
    @abstractmethod
    async def start_vm(self, vm_id: str) -> bool:
        """Start a VM."""
        pass
    
    @abstractmethod
    async def stop_vm(self, vm_id: str) -> bool:
        """Stop a VM."""
        pass
    
    @abstractmethod
    async def migrate_vm(self, vm_id: str, target_host: str) -> bool:
        """Migrate VM to another host."""
        pass
    
    @abstractmethod
    async def get_host_resources(self) -> dict:
        """Get host resource utilization."""
        pass


class StorageIntegration(BaseIntegration):
    """Base class for storage integrations."""
    
    @abstractmethod
    async def get_pools(self) -> list[dict]:
        """Get storage pools."""
        pass
    
    @abstractmethod
    async def get_datasets(self) -> list[dict]:
        """Get datasets/volumes."""
        pass
    
    @abstractmethod
    async def create_snapshot(self, dataset: str, name: str) -> bool:
        """Create a snapshot."""
        pass
    
    @abstractmethod
    async def get_health(self) -> dict:
        """Get storage health status."""
        pass
