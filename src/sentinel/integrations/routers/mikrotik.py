"""
MikroTik RouterOS Integration for Sentinel.

This module provides full integration with MikroTik RouterOS devices,
enabling Sentinel to manage routing, switching, firewalling, and QoS
on MikroTik hardware.

Supports:
- CRS series (Cloud Router Switches) - like CRS510-8XS-2XQ-IN
- CCR series (Cloud Core Routers)
- RB series (RouterBOARDs)
- CHR (Cloud Hosted Router)

Uses the RouterOS REST API (v7+) or legacy API for older versions.
"""

import asyncio
import hashlib
import binascii
import logging
import ssl
from typing import Optional, Any
from datetime import datetime, timedelta

import httpx

from sentinel.integrations.base import RouterIntegration
from sentinel.core.utils import utc_now

logger = logging.getLogger(__name__)


class MikroTikIntegration(RouterIntegration):
    """
    MikroTik RouterOS integration.

    Provides comprehensive management of MikroTik devices including:
    - Firewall rule management
    - VLAN configuration
    - Interface management
    - DHCP server/leases
    - Routing tables
    - QoS/queues
    - System monitoring
    - Backup/restore

    Example:
        ```python
        mikrotik = MikroTikIntegration({
            "host": "192.168.88.1",
            "username": "admin",
            "password": "secret",
            "port": 443,
            "use_ssl": True
        })

        await mikrotik.connect()

        # Get all interfaces
        interfaces = await mikrotik.get_interfaces()

        # Add firewall rule
        await mikrotik.add_firewall_rule({
            "chain": "forward",
            "action": "drop",
            "src-address": "10.0.0.100",
            "comment": "Blocked by Sentinel Guardian"
        })

        # Configure VLAN
        await mikrotik.create_vlan(
            interface="sfp-sfpplus1",
            vlan_id=100,
            name="IoT_VLAN"
        )
        ```
    """

    def __init__(self, config: dict):
        super().__init__(config)

        # Validate and set host
        self.host = config.get("host", "192.168.88.1")
        if not self.host:
            raise ValueError("MikroTik host is required")

        # Validate credentials
        self.username = config.get("username", "admin")
        self.password = config.get("password", "")
        if not self.username:
            raise ValueError("MikroTik username is required")

        # Validate and set port
        self.port = config.get("port", 443)
        if not isinstance(self.port, int) or not 1 <= self.port <= 65535:
            raise ValueError(f"Invalid port: {self.port}. Must be 1-65535")

        # SSL configuration - SECURE BY DEFAULT
        self.use_ssl = config.get("use_ssl", True)
        # SECURITY: SSL verification enabled by default. Disable only for testing.
        self.verify_ssl = config.get("verify_ssl", True)
        if not self.verify_ssl:
            logger.warning(
                "MikroTik SSL verification DISABLED - this is insecure! "
                "Only use for testing or with self-signed certificates."
            )

        self.api_version = config.get("api_version", "rest")  # rest or legacy
        if self.api_version not in ("rest", "legacy"):
            raise ValueError(f"Invalid api_version: {self.api_version}. Must be 'rest' or 'legacy'")

        # Build base URL
        protocol = "https" if self.use_ssl else "http"
        self._base_url = f"{protocol}://{self.host}:{self.port}/rest"

        # HTTP client
        self._client: Optional[httpx.AsyncClient] = None

        # Device info cache
        self._device_info: Optional[dict] = None
        self._interfaces_cache: Optional[list] = None
        self._cache_time: Optional[datetime] = None
        self._cache_ttl = timedelta(seconds=30)

    async def connect(self) -> None:
        """Connect to MikroTik device."""
        try:
            # Create HTTP client with auth
            self._client = httpx.AsyncClient(
                base_url=self._base_url,
                auth=(self.username, self.password),
                verify=self.verify_ssl,
                timeout=30.0,
            )

            # Test connection by getting system identity
            response = await self._client.get("/system/identity")
            response.raise_for_status()

            identity = response.json()
            logger.info(f"Connected to MikroTik: {identity.get('name', 'unknown')}")

            # Get device info
            self._device_info = await self._get_system_info()

            self._connected = True

        except httpx.HTTPStatusError as e:
            logger.error(f"MikroTik authentication failed: {e}")
            raise
        except Exception as e:
            logger.error(f"Failed to connect to MikroTik: {e}")
            raise

    async def disconnect(self) -> None:
        """Disconnect from MikroTik device."""
        if self._client:
            await self._client.aclose()
            self._client = None

        self._connected = False
        logger.info("Disconnected from MikroTik")

    async def health_check(self) -> bool:
        """Check if MikroTik device is reachable and healthy."""
        if not self._client:
            return False

        try:
            response = await self._client.get("/system/resource")
            response.raise_for_status()
            return True
        except Exception as e:
            logger.warning(f"MikroTik health check failed: {e}")
            return False

    async def _get_system_info(self) -> dict:
        """Get comprehensive system information."""
        info = {}

        try:
            # Get resource info
            response = await self._client.get("/system/resource")
            response.raise_for_status()
            resource = response.json()
            info["resource"] = resource

            # Get identity
            response = await self._client.get("/system/identity")
            response.raise_for_status()
            info["identity"] = response.json()

            # Get routerboard info
            response = await self._client.get("/system/routerboard")
            response.raise_for_status()
            info["routerboard"] = response.json()

        except Exception as e:
            logger.warning(f"Failed to get system info: {e}")

        return info

    # =========================================================================
    # RouterIntegration Implementation
    # =========================================================================

    async def get_arp_table(self) -> list[dict]:
        """Get ARP table from MikroTik."""
        try:
            response = await self._client.get("/ip/arp")
            response.raise_for_status()

            entries = []
            for entry in response.json():
                entries.append(
                    {
                        "ip": entry.get("address"),
                        "mac": entry.get("mac-address"),
                        "interface": entry.get("interface"),
                        "dynamic": entry.get("dynamic", "false") == "true",
                        "complete": entry.get("complete", "false") == "true",
                    }
                )

            return entries

        except Exception as e:
            logger.error(f"Failed to get ARP table: {e}")
            return []

    async def get_dhcp_leases(self) -> list[dict]:
        """Get DHCP leases from MikroTik."""
        try:
            response = await self._client.get("/ip/dhcp-server/lease")
            response.raise_for_status()

            leases = []
            for lease in response.json():
                leases.append(
                    {
                        "ip": lease.get("address"),
                        "mac": lease.get("mac-address"),
                        "hostname": lease.get("host-name", ""),
                        "server": lease.get("server"),
                        "status": lease.get("status"),
                        "expires_after": lease.get("expires-after"),
                        "last_seen": lease.get("last-seen"),
                        "dynamic": lease.get("dynamic", "false") == "true",
                        "blocked": lease.get("blocked", "false") == "true",
                    }
                )

            return leases

        except Exception as e:
            logger.error(f"Failed to get DHCP leases: {e}")
            return []

    async def add_firewall_rule(self, rule: dict) -> str:
        """
        Add a firewall rule to MikroTik.

        Args:
            rule: Dictionary with rule parameters:
                - chain: input, forward, output
                - action: accept, drop, reject, etc.
                - src-address: Source IP/CIDR
                - dst-address: Destination IP/CIDR
                - protocol: tcp, udp, icmp, etc.
                - dst-port: Destination port
                - src-port: Source port
                - in-interface: Input interface
                - out-interface: Output interface
                - comment: Rule comment

        Returns:
            Rule ID (.id from MikroTik)
        """
        try:
            # Ensure required fields
            if "chain" not in rule:
                rule["chain"] = "forward"
            if "action" not in rule:
                rule["action"] = "drop"

            response = await self._client.put("/ip/firewall/filter", json=rule)
            response.raise_for_status()

            result = response.json()
            rule_id = result.get(".id", "")

            logger.info(f"Added MikroTik firewall rule: {rule_id}")
            return rule_id

        except Exception as e:
            logger.error(f"Failed to add firewall rule: {e}")
            raise

    async def delete_firewall_rule(self, rule_id: str) -> bool:
        """Delete a firewall rule by ID."""
        try:
            response = await self._client.delete(f"/ip/firewall/filter/{rule_id}")
            response.raise_for_status()

            logger.info(f"Deleted MikroTik firewall rule: {rule_id}")
            return True

        except Exception as e:
            logger.error(f"Failed to delete firewall rule: {e}")
            return False

    async def get_firewall_rules(self) -> list[dict]:
        """Get all firewall filter rules."""
        try:
            response = await self._client.get("/ip/firewall/filter")
            response.raise_for_status()

            rules = []
            for rule in response.json():
                rules.append(
                    {
                        "id": rule.get(".id"),
                        "chain": rule.get("chain"),
                        "action": rule.get("action"),
                        "src_address": rule.get("src-address"),
                        "dst_address": rule.get("dst-address"),
                        "protocol": rule.get("protocol"),
                        "dst_port": rule.get("dst-port"),
                        "src_port": rule.get("src-port"),
                        "in_interface": rule.get("in-interface"),
                        "out_interface": rule.get("out-interface"),
                        "comment": rule.get("comment", ""),
                        "disabled": rule.get("disabled", "false") == "true",
                        "bytes": int(rule.get("bytes", 0)),
                        "packets": int(rule.get("packets", 0)),
                    }
                )

            return rules

        except Exception as e:
            logger.error(f"Failed to get firewall rules: {e}")
            return []

    # =========================================================================
    # Interface Management
    # =========================================================================

    async def get_interfaces(self, use_cache: bool = True) -> list[dict]:
        """Get all interfaces."""
        if use_cache and self._interfaces_cache and self._cache_time:
            if utc_now() - self._cache_time < self._cache_ttl:
                return self._interfaces_cache

        try:
            response = await self._client.get("/interface")
            response.raise_for_status()

            interfaces = []
            for iface in response.json():
                interfaces.append(
                    {
                        "name": iface.get("name"),
                        "type": iface.get("type"),
                        "mac_address": iface.get("mac-address"),
                        "mtu": iface.get("mtu"),
                        "running": iface.get("running", "false") == "true",
                        "disabled": iface.get("disabled", "false") == "true",
                        "rx_byte": int(iface.get("rx-byte", 0)),
                        "tx_byte": int(iface.get("tx-byte", 0)),
                        "rx_packet": int(iface.get("rx-packet", 0)),
                        "tx_packet": int(iface.get("tx-packet", 0)),
                        "link_downs": int(iface.get("link-downs", 0)),
                    }
                )

            self._interfaces_cache = interfaces
            self._cache_time = utc_now()

            return interfaces

        except Exception as e:
            logger.error(f"Failed to get interfaces: {e}")
            return []

    async def get_interface_stats(self, interface: str) -> dict:
        """Get detailed statistics for an interface."""
        try:
            response = await self._client.get(f"/interface?name={interface}")
            response.raise_for_status()

            data = response.json()
            if data:
                iface = data[0]
                return {
                    "name": iface.get("name"),
                    "type": iface.get("type"),
                    "running": iface.get("running", "false") == "true",
                    "rx_byte": int(iface.get("rx-byte", 0)),
                    "tx_byte": int(iface.get("tx-byte", 0)),
                    "rx_packet": int(iface.get("rx-packet", 0)),
                    "tx_packet": int(iface.get("tx-packet", 0)),
                    "rx_error": int(iface.get("rx-error", 0)),
                    "tx_error": int(iface.get("tx-error", 0)),
                    "rx_drop": int(iface.get("rx-drop", 0)),
                    "tx_drop": int(iface.get("tx-drop", 0)),
                    "fp_rx_byte": int(iface.get("fp-rx-byte", 0)),
                    "fp_tx_byte": int(iface.get("fp-tx-byte", 0)),
                }

            return {}

        except Exception as e:
            logger.error(f"Failed to get interface stats: {e}")
            return {}

    # =========================================================================
    # VLAN Management
    # =========================================================================

    async def get_vlans(self) -> list[dict]:
        """Get all configured VLANs."""
        try:
            response = await self._client.get("/interface/vlan")
            response.raise_for_status()

            vlans = []
            for vlan in response.json():
                vlans.append(
                    {
                        "id": vlan.get(".id"),
                        "name": vlan.get("name"),
                        "vlan_id": int(vlan.get("vlan-id", 0)),
                        "interface": vlan.get("interface"),
                        "mtu": vlan.get("mtu"),
                        "running": vlan.get("running", "false") == "true",
                        "disabled": vlan.get("disabled", "false") == "true",
                    }
                )

            return vlans

        except Exception as e:
            logger.error(f"Failed to get VLANs: {e}")
            return []

    async def create_vlan(self, interface: str, vlan_id: int, name: str = None) -> str:
        """
        Create a new VLAN interface.

        Args:
            interface: Parent interface (e.g., "sfp-sfpplus1")
            vlan_id: VLAN ID (1-4094)
            name: VLAN interface name (default: vlan{vlan_id})

        Returns:
            VLAN interface ID
        """
        if name is None:
            name = f"vlan{vlan_id}"

        try:
            payload = {"name": name, "vlan-id": str(vlan_id), "interface": interface}

            response = await self._client.put("/interface/vlan", json=payload)
            response.raise_for_status()

            result = response.json()
            logger.info(f"Created VLAN {vlan_id} on {interface}")

            return result.get(".id", "")

        except Exception as e:
            logger.error(f"Failed to create VLAN: {e}")
            raise

    async def delete_vlan(self, vlan_id: str) -> bool:
        """Delete a VLAN by its ID."""
        try:
            response = await self._client.delete(f"/interface/vlan/{vlan_id}")
            response.raise_for_status()

            logger.info(f"Deleted VLAN: {vlan_id}")
            return True

        except Exception as e:
            logger.error(f"Failed to delete VLAN: {e}")
            return False

    # =========================================================================
    # Bridge/Switch Management (for CRS series)
    # =========================================================================

    async def get_bridge_ports(self) -> list[dict]:
        """Get bridge port configuration (for switching)."""
        try:
            response = await self._client.get("/interface/bridge/port")
            response.raise_for_status()

            ports = []
            for port in response.json():
                ports.append(
                    {
                        "id": port.get(".id"),
                        "interface": port.get("interface"),
                        "bridge": port.get("bridge"),
                        "pvid": int(port.get("pvid", 1)),
                        "frame_types": port.get("frame-types"),
                        "ingress_filtering": port.get("ingress-filtering", "false") == "true",
                        "hw": port.get("hw", "false") == "true",
                        "disabled": port.get("disabled", "false") == "true",
                    }
                )

            return ports

        except Exception as e:
            logger.error(f"Failed to get bridge ports: {e}")
            return []

    async def set_port_vlan(
        self, port: str, pvid: int, frame_types: str = "admit-only-vlan-tagged"
    ) -> bool:
        """
        Configure VLAN settings on a bridge port.

        Args:
            port: Port interface name
            pvid: Port VLAN ID (untagged VLAN)
            frame_types: admit-all, admit-only-untagged-and-priority-tagged,
                        admit-only-vlan-tagged

        Returns:
            True if successful
        """
        try:
            # Find the bridge port entry
            response = await self._client.get(f"/interface/bridge/port?interface={port}")
            response.raise_for_status()

            ports = response.json()
            if not ports:
                logger.error(f"Port {port} not found in bridge")
                return False

            port_id = ports[0].get(".id")

            # Update the port
            payload = {"pvid": str(pvid), "frame-types": frame_types}

            response = await self._client.patch(f"/interface/bridge/port/{port_id}", json=payload)
            response.raise_for_status()

            logger.info(f"Set port {port} PVID to {pvid}")
            return True

        except Exception as e:
            logger.error(f"Failed to set port VLAN: {e}")
            return False

    async def get_bridge_vlans(self) -> list[dict]:
        """Get bridge VLAN configuration."""
        try:
            response = await self._client.get("/interface/bridge/vlan")
            response.raise_for_status()

            vlans = []
            for vlan in response.json():
                vlans.append(
                    {
                        "id": vlan.get(".id"),
                        "bridge": vlan.get("bridge"),
                        "vlan_ids": vlan.get("vlan-ids"),
                        "tagged": vlan.get("tagged", "").split(","),
                        "untagged": vlan.get("untagged", "").split(","),
                        "disabled": vlan.get("disabled", "false") == "true",
                    }
                )

            return vlans

        except Exception as e:
            logger.error(f"Failed to get bridge VLANs: {e}")
            return []

    # =========================================================================
    # QoS / Queue Management
    # =========================================================================

    async def get_queues(self) -> list[dict]:
        """Get simple queue configuration."""
        try:
            response = await self._client.get("/queue/simple")
            response.raise_for_status()

            queues = []
            for queue in response.json():
                queues.append(
                    {
                        "id": queue.get(".id"),
                        "name": queue.get("name"),
                        "target": queue.get("target"),
                        "max_limit": queue.get("max-limit"),
                        "burst_limit": queue.get("burst-limit"),
                        "burst_threshold": queue.get("burst-threshold"),
                        "burst_time": queue.get("burst-time"),
                        "priority": queue.get("priority"),
                        "disabled": queue.get("disabled", "false") == "true",
                        "bytes": queue.get("bytes"),
                        "packets": queue.get("packets"),
                    }
                )

            return queues

        except Exception as e:
            logger.error(f"Failed to get queues: {e}")
            return []

    async def create_queue(
        self, name: str, target: str, max_limit: str = "0/0", priority: int = 8, comment: str = ""
    ) -> str:
        """
        Create a simple queue for traffic shaping.

        Args:
            name: Queue name
            target: Target address or interface (e.g., "192.168.1.100/32")
            max_limit: Upload/Download limit (e.g., "10M/50M")
            priority: Queue priority (1-8, 1 is highest)
            comment: Queue comment

        Returns:
            Queue ID
        """
        try:
            payload = {
                "name": name,
                "target": target,
                "max-limit": max_limit,
                "priority": f"{priority}/{priority}",
                "comment": comment,
            }

            response = await self._client.put("/queue/simple", json=payload)
            response.raise_for_status()

            result = response.json()
            logger.info(f"Created queue {name} for {target}")

            return result.get(".id", "")

        except Exception as e:
            logger.error(f"Failed to create queue: {e}")
            raise

    async def delete_queue(self, queue_id: str) -> bool:
        """Delete a queue by ID."""
        try:
            response = await self._client.delete(f"/queue/simple/{queue_id}")
            response.raise_for_status()

            logger.info(f"Deleted queue: {queue_id}")
            return True

        except Exception as e:
            logger.error(f"Failed to delete queue: {e}")
            return False

    # =========================================================================
    # IP Address Management
    # =========================================================================

    async def get_ip_addresses(self) -> list[dict]:
        """Get all IP addresses configured on the device."""
        try:
            response = await self._client.get("/ip/address")
            response.raise_for_status()

            addresses = []
            for addr in response.json():
                addresses.append(
                    {
                        "id": addr.get(".id"),
                        "address": addr.get("address"),
                        "network": addr.get("network"),
                        "interface": addr.get("interface"),
                        "disabled": addr.get("disabled", "false") == "true",
                        "dynamic": addr.get("dynamic", "false") == "true",
                    }
                )

            return addresses

        except Exception as e:
            logger.error(f"Failed to get IP addresses: {e}")
            return []

    async def add_ip_address(self, address: str, interface: str, comment: str = "") -> str:
        """
        Add an IP address to an interface.

        Args:
            address: IP address with prefix (e.g., "192.168.1.1/24")
            interface: Interface name
            comment: Address comment

        Returns:
            Address ID
        """
        try:
            payload = {"address": address, "interface": interface, "comment": comment}

            response = await self._client.put("/ip/address", json=payload)
            response.raise_for_status()

            result = response.json()
            logger.info(f"Added IP {address} to {interface}")

            return result.get(".id", "")

        except Exception as e:
            logger.error(f"Failed to add IP address: {e}")
            raise

    # =========================================================================
    # Routing
    # =========================================================================

    async def get_routes(self) -> list[dict]:
        """Get routing table."""
        try:
            response = await self._client.get("/ip/route")
            response.raise_for_status()

            routes = []
            for route in response.json():
                routes.append(
                    {
                        "id": route.get(".id"),
                        "dst_address": route.get("dst-address"),
                        "gateway": route.get("gateway"),
                        "distance": int(route.get("distance", 0)),
                        "scope": route.get("scope"),
                        "target_scope": route.get("target-scope"),
                        "routing_mark": route.get("routing-mark"),
                        "active": route.get("active", "false") == "true",
                        "dynamic": route.get("dynamic", "false") == "true",
                        "disabled": route.get("disabled", "false") == "true",
                    }
                )

            return routes

        except Exception as e:
            logger.error(f"Failed to get routes: {e}")
            return []

    async def add_route(
        self, dst_address: str, gateway: str, distance: int = 1, comment: str = ""
    ) -> str:
        """Add a static route."""
        try:
            payload = {
                "dst-address": dst_address,
                "gateway": gateway,
                "distance": str(distance),
                "comment": comment,
            }

            response = await self._client.put("/ip/route", json=payload)
            response.raise_for_status()

            result = response.json()
            logger.info(f"Added route to {dst_address} via {gateway}")

            return result.get(".id", "")

        except Exception as e:
            logger.error(f"Failed to add route: {e}")
            raise

    # =========================================================================
    # System Monitoring
    # =========================================================================

    async def get_system_resources(self) -> dict:
        """Get current system resource usage."""
        try:
            response = await self._client.get("/system/resource")
            response.raise_for_status()

            data = response.json()
            return {
                "uptime": data.get("uptime"),
                "version": data.get("version"),
                "build_time": data.get("build-time"),
                "factory_software": data.get("factory-software"),
                "free_memory": int(data.get("free-memory", 0)),
                "total_memory": int(data.get("total-memory", 0)),
                "cpu": data.get("cpu"),
                "cpu_count": int(data.get("cpu-count", 1)),
                "cpu_frequency": int(data.get("cpu-frequency", 0)),
                "cpu_load": int(data.get("cpu-load", 0)),
                "free_hdd_space": int(data.get("free-hdd-space", 0)),
                "total_hdd_space": int(data.get("total-hdd-space", 0)),
                "architecture_name": data.get("architecture-name"),
                "board_name": data.get("board-name"),
                "platform": data.get("platform"),
            }

        except Exception as e:
            logger.error(f"Failed to get system resources: {e}")
            return {}

    async def get_interface_traffic(self) -> list[dict]:
        """Get real-time traffic statistics for all interfaces."""
        try:
            response = await self._client.get("/interface")
            response.raise_for_status()

            traffic = []
            for iface in response.json():
                if iface.get("running") == "true":
                    traffic.append(
                        {
                            "interface": iface.get("name"),
                            "type": iface.get("type"),
                            "rx_byte": int(iface.get("rx-byte", 0)),
                            "tx_byte": int(iface.get("tx-byte", 0)),
                            "rx_packet": int(iface.get("rx-packet", 0)),
                            "tx_packet": int(iface.get("tx-packet", 0)),
                        }
                    )

            return traffic

        except Exception as e:
            logger.error(f"Failed to get interface traffic: {e}")
            return []

    # =========================================================================
    # Backup and Restore
    # =========================================================================

    async def create_backup(self, name: str = "sentinel-backup") -> bool:
        """Create a configuration backup on the device."""
        try:
            response = await self._client.post("/system/backup/save", json={"name": name})
            response.raise_for_status()

            logger.info(f"Created backup: {name}")
            return True

        except Exception as e:
            logger.error(f"Failed to create backup: {e}")
            return False

    async def export_config(self) -> str:
        """Export configuration as RSC script."""
        try:
            response = await self._client.post("/export")
            response.raise_for_status()

            return response.text

        except Exception as e:
            logger.error(f"Failed to export config: {e}")
            return ""

    # =========================================================================
    # Convenience Methods for Sentinel Integration
    # =========================================================================

    async def block_ip(self, ip: str, comment: str = "Blocked by Sentinel") -> str:
        """
        Block an IP address in the firewall.

        Args:
            ip: IP address to block
            comment: Rule comment

        Returns:
            Rule ID
        """
        return await self.add_firewall_rule(
            {"chain": "forward", "action": "drop", "src-address": ip, "comment": comment}
        )

    async def unblock_ip(self, ip: str) -> bool:
        """
        Remove all blocking rules for an IP.

        Args:
            ip: IP address to unblock

        Returns:
            True if any rules were removed
        """
        rules = await self.get_firewall_rules()
        removed = False

        for rule in rules:
            if rule.get("src_address") == ip and rule.get("action") == "drop":
                if await self.delete_firewall_rule(rule["id"]):
                    removed = True

        return removed

    async def set_device_bandwidth(
        self, ip: str, upload: str, download: str, name: str = None
    ) -> str:
        """
        Set bandwidth limits for a device.

        Args:
            ip: Device IP address
            upload: Upload limit (e.g., "10M")
            download: Download limit (e.g., "100M")
            name: Queue name (default: based on IP)

        Returns:
            Queue ID
        """
        if name is None:
            name = f"sentinel_{ip.replace('.', '_')}"

        return await self.create_queue(
            name=name,
            target=f"{ip}/32",
            max_limit=f"{upload}/{download}",
            comment="Managed by Sentinel Optimizer",
        )

    @property
    def device_info(self) -> dict:
        """Get cached device information."""
        return self._device_info or {}

    @property
    def model(self) -> str:
        """Get device model name."""
        if self._device_info:
            rb = self._device_info.get("routerboard", {})
            return rb.get("model", "Unknown")
        return "Unknown"

    @property
    def version(self) -> str:
        """Get RouterOS version."""
        if self._device_info:
            res = self._device_info.get("resource", {})
            return res.get("version", "Unknown")
        return "Unknown"
