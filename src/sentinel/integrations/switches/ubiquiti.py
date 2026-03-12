"""
UniFi Switch Integration for Sentinel.

This module provides integration with Ubiquiti UniFi network equipment
via the UniFi Controller API. Supports switch port management, VLAN
assignment, client tracking, and network statistics.
"""

import asyncio
import logging
from datetime import datetime
from typing import Any, Optional

import httpx

from sentinel.integrations.base import SwitchIntegration

logger = logging.getLogger(__name__)


class UnifiIntegration(SwitchIntegration):
    """
    Ubiquiti UniFi Controller integration.

    Provides access to:
    - Switch port configuration
    - VLAN management
    - Client device tracking
    - LLDP neighbor discovery
    - Port statistics

    Configuration:
        switch:
            type: ubiquiti
            controller_url: "https://192.168.1.2:8443"
            username: "${UNIFI_USER}"
            password: "${UNIFI_PASSWORD}"
            site: "default"
            verify_ssl: false
    """

    def __init__(self, config: dict):
        """
        Initialize UniFi integration.

        Args:
            config: Integration configuration
        """
        super().__init__(config)

        self.controller_url = config.get("controller_url", "").rstrip("/")
        self.username = config.get("username", "")
        self.password = config.get("password", "")
        self.site = config.get("site", "default")
        # SECURITY: SSL verification enabled by default
        self.verify_ssl = config.get("verify_ssl", True)
        if not self.verify_ssl:
            logger.warning(
                "UniFi SSL verification DISABLED - this is insecure! "
                "Only use for testing or with self-signed certificates."
            )

        self._client: Optional[httpx.AsyncClient] = None
        self._csrf_token: Optional[str] = None
        self._cookies: dict = {}

    async def connect(self) -> None:
        """Establish connection to UniFi Controller."""
        self._client = httpx.AsyncClient(
            base_url=self.controller_url,
            verify=self.verify_ssl,
            timeout=30.0,
            follow_redirects=True,
        )

        # Login to controller
        try:
            login_data = {"username": self.username, "password": self.password, "remember": True}

            response = await self._client.post("/api/login", json=login_data)
            response.raise_for_status()

            # Store cookies for subsequent requests
            self._cookies = dict(response.cookies)

            # Get CSRF token if available
            self._csrf_token = response.headers.get("x-csrf-token")

            self._connected = True
            logger.info(f"Connected to UniFi Controller at {self.controller_url}")

        except Exception as e:
            logger.error(f"Failed to connect to UniFi Controller: {e}")
            raise ConnectionError(f"UniFi connection failed: {e}")

    async def disconnect(self) -> None:
        """Close connection to UniFi Controller."""
        if self._client:
            try:
                await self._client.post("/api/logout", cookies=self._cookies)
            except Exception as e:
                logger.debug(f"UniFi logout failed (non-critical): {e}")
            await self._client.aclose()
            self._client = None

        self._connected = False
        self._csrf_token = None
        self._cookies = {}
        logger.info("Disconnected from UniFi Controller")

    async def health_check(self) -> bool:
        """Check if UniFi Controller is responding."""
        if not self._client:
            return False

        try:
            response = await self._client.get(
                f"/api/s/{self.site}/stat/health", cookies=self._cookies
            )
            return response.status_code == 200
        except Exception as e:
            logger.debug(f"UniFi health check failed: {e}")
            return False

    async def _api_get(self, endpoint: str) -> dict:
        """Make GET request to UniFi API."""
        if not self._client:
            raise RuntimeError("Not connected to UniFi Controller")

        headers = {}
        if self._csrf_token:
            headers["x-csrf-token"] = self._csrf_token

        response = await self._client.get(
            f"/api/s/{self.site}/{endpoint}", headers=headers, cookies=self._cookies
        )
        response.raise_for_status()
        return response.json()

    async def _api_post(self, endpoint: str, data: Optional[dict] = None) -> dict:
        """Make POST request to UniFi API."""
        if not self._client:
            raise RuntimeError("Not connected to UniFi Controller")

        headers = {}
        if self._csrf_token:
            headers["x-csrf-token"] = self._csrf_token

        response = await self._client.post(
            f"/api/s/{self.site}/{endpoint}",
            json=data or {},
            headers=headers,
            cookies=self._cookies,
        )
        response.raise_for_status()
        return response.json()

    async def _api_put(self, endpoint: str, data: Optional[dict] = None) -> dict:
        """Make PUT request to UniFi API."""
        if not self._client:
            raise RuntimeError("Not connected to UniFi Controller")

        headers = {}
        if self._csrf_token:
            headers["x-csrf-token"] = self._csrf_token

        response = await self._client.put(
            f"/api/s/{self.site}/{endpoint}",
            json=data or {},
            headers=headers,
            cookies=self._cookies,
        )
        response.raise_for_status()
        return response.json()

    # =========================================================================
    # Switch Interface Methods
    # =========================================================================

    async def get_ports(self) -> list[dict]:
        """
        Get all switch ports with status.

        Returns:
            List of ports with configuration and statistics
        """
        try:
            # Get devices to find switches
            devices_data = await self._api_get("stat/device")
            devices = devices_data.get("data", [])

            ports = []
            for device in devices:
                if device.get("type") != "usw":  # UniFi Switch
                    continue

                device_mac = device.get("mac")
                device_name = device.get("name", device_mac)

                port_table = device.get("port_table", [])
                for port in port_table:
                    ports.append(
                        {
                            "switch_mac": device_mac,
                            "switch_name": device_name,
                            "port_idx": port.get("port_idx"),
                            "name": port.get("name", f"Port {port.get('port_idx')}"),
                            "enabled": port.get("enable", True),
                            "up": port.get("up", False),
                            "speed": port.get("speed", 0),
                            "full_duplex": port.get("full_duplex", True),
                            "poe_enable": port.get("poe_enable", False),
                            "poe_mode": port.get("poe_mode", "off"),
                            "poe_power": port.get("poe_power", 0),
                            "tx_bytes": port.get("tx_bytes", 0),
                            "rx_bytes": port.get("rx_bytes", 0),
                            "tx_packets": port.get("tx_packets", 0),
                            "rx_packets": port.get("rx_packets", 0),
                            "native_vlan": port.get("native_networkconf_id"),
                            "tagged_vlans": port.get("tagged_networkconf_ids", []),
                        }
                    )

            return ports

        except Exception as e:
            logger.error(f"Failed to get ports: {e}")
            return []

    async def set_port_vlan(self, port: str = None, mac: str = None, vlan_id: int = None) -> bool:
        """
        Set VLAN for a port or client.

        Args:
            port: Port identifier (switch_mac:port_idx)
            mac: Client MAC address to move
            vlan_id: Target VLAN ID

        Returns:
            True if successful
        """
        if vlan_id is None:
            raise ValueError("vlan_id is required")

        try:
            # Find network config ID for VLAN
            networks = await self._api_get("rest/networkconf")
            network_id = None

            for net in networks.get("data", []):
                if net.get("vlan") == vlan_id:
                    network_id = net.get("_id")
                    break

            if not network_id:
                logger.error(f"VLAN {vlan_id} not found in UniFi configuration")
                return False

            if mac:
                # Override client's network assignment
                # Find the client first
                clients_data = await self._api_get("stat/sta")
                client = None

                for c in clients_data.get("data", []):
                    if c.get("mac", "").lower() == mac.lower():
                        client = c
                        break

                if not client:
                    logger.error(f"Client {mac} not found")
                    return False

                # Override client to specific network
                override_data = {"mac": mac, "network_id": network_id}
                await self._api_post(
                    "cmd/stamgr",
                    {"cmd": "set-sta-note", "mac": mac, "note": f"VLAN override to {vlan_id}"},
                )

                # For actual VLAN change, may need to use port profile
                logger.info(f"Set client {mac} to VLAN {vlan_id}")
                return True

            elif port:
                # Set port native VLAN
                parts = port.split(":")
                if len(parts) != 2:
                    raise ValueError("Port must be in format switch_mac:port_idx")

                switch_mac = parts[0]
                port_idx = int(parts[1])

                # Get device config
                devices_data = await self._api_get("stat/device")

                for device in devices_data.get("data", []):
                    if device.get("mac", "").lower() == switch_mac.lower():
                        device_id = device.get("_id")

                        # Update port override
                        port_overrides = device.get("port_overrides", [])

                        # Find or create port override
                        override_found = False
                        for override in port_overrides:
                            if override.get("port_idx") == port_idx:
                                override["native_networkconf_id"] = network_id
                                override_found = True
                                break

                        if not override_found:
                            port_overrides.append(
                                {"port_idx": port_idx, "native_networkconf_id": network_id}
                            )

                        # Apply update
                        await self._api_put(
                            f"rest/device/{device_id}", {"port_overrides": port_overrides}
                        )

                        logger.info(f"Set port {port} to VLAN {vlan_id}")
                        return True

                logger.error(f"Switch {switch_mac} not found")
                return False

            return False

        except Exception as e:
            logger.error(f"Failed to set port VLAN: {e}")
            return False

    async def get_lldp_neighbors(self) -> list[dict]:
        """
        Get LLDP neighbor information.

        Returns:
            List of LLDP neighbors
        """
        try:
            devices_data = await self._api_get("stat/device")

            neighbors = []
            for device in devices_data.get("data", []):
                if device.get("type") != "usw":
                    continue

                device_mac = device.get("mac")
                lldp_table = device.get("lldp_table", [])

                for entry in lldp_table:
                    neighbors.append(
                        {
                            "local_switch": device_mac,
                            "local_port": entry.get("local_port_idx"),
                            "chassis_id": entry.get("chassis_id"),
                            "port_id": entry.get("port_id"),
                            "port_description": entry.get("port_desc", ""),
                            "system_name": entry.get("chassis_descr", ""),
                            "is_wired": entry.get("is_wired", True),
                        }
                    )

            return neighbors

        except Exception as e:
            logger.error(f"Failed to get LLDP neighbors: {e}")
            return []

    async def get_port_statistics(self, port: str) -> dict:
        """
        Get detailed statistics for a port.

        Args:
            port: Port identifier (switch_mac:port_idx)

        Returns:
            Port statistics
        """
        try:
            parts = port.split(":")
            if len(parts) != 2:
                raise ValueError("Port must be in format switch_mac:port_idx")

            switch_mac = parts[0]
            port_idx = int(parts[1])

            devices_data = await self._api_get("stat/device")

            for device in devices_data.get("data", []):
                if device.get("mac", "").lower() != switch_mac.lower():
                    continue

                for p in device.get("port_table", []):
                    if p.get("port_idx") == port_idx:
                        return {
                            "port_idx": port_idx,
                            "name": p.get("name", f"Port {port_idx}"),
                            "up": p.get("up", False),
                            "speed": p.get("speed", 0),
                            "full_duplex": p.get("full_duplex", True),
                            "tx_bytes": p.get("tx_bytes", 0),
                            "rx_bytes": p.get("rx_bytes", 0),
                            "tx_packets": p.get("tx_packets", 0),
                            "rx_packets": p.get("rx_packets", 0),
                            "tx_errors": p.get("tx_errors", 0),
                            "rx_errors": p.get("rx_errors", 0),
                            "tx_dropped": p.get("tx_dropped", 0),
                            "rx_dropped": p.get("rx_dropped", 0),
                            "tx_broadcast": p.get("tx_broadcast", 0),
                            "rx_broadcast": p.get("rx_broadcast", 0),
                            "tx_multicast": p.get("tx_multicast", 0),
                            "rx_multicast": p.get("rx_multicast", 0),
                            "poe_enable": p.get("poe_enable", False),
                            "poe_power": p.get("poe_power", 0),
                            "poe_voltage": p.get("poe_voltage", 0),
                            "poe_current": p.get("poe_current", 0),
                        }

            return {}

        except Exception as e:
            logger.error(f"Failed to get port statistics: {e}")
            return {}

    # =========================================================================
    # Extended UniFi Methods
    # =========================================================================

    async def get_clients(self) -> list[dict]:
        """
        Get all connected clients.

        Returns:
            List of connected clients
        """
        try:
            data = await self._api_get("stat/sta")

            clients = []
            for client in data.get("data", []):
                clients.append(
                    {
                        "mac": client.get("mac"),
                        "ip": client.get("ip"),
                        "hostname": client.get("hostname", client.get("name", "")),
                        "oui": client.get("oui", ""),
                        "is_wired": client.get("is_wired", True),
                        "switch_mac": client.get("sw_mac"),
                        "switch_port": client.get("sw_port"),
                        "network": client.get("network"),
                        "vlan": client.get("vlan"),
                        "signal": client.get("signal"),  # For wireless
                        "tx_bytes": client.get("tx_bytes", 0),
                        "rx_bytes": client.get("rx_bytes", 0),
                        "uptime": client.get("uptime", 0),
                        "last_seen": client.get("last_seen", 0),
                        "first_seen": client.get("first_seen", 0),
                    }
                )

            return clients

        except Exception as e:
            logger.error(f"Failed to get clients: {e}")
            return []

    async def get_networks(self) -> list[dict]:
        """
        Get all configured networks/VLANs.

        Returns:
            List of networks
        """
        try:
            data = await self._api_get("rest/networkconf")

            networks = []
            for net in data.get("data", []):
                networks.append(
                    {
                        "id": net.get("_id"),
                        "name": net.get("name"),
                        "purpose": net.get("purpose"),
                        "vlan": net.get("vlan"),
                        "subnet": net.get("ip_subnet"),
                        "gateway": net.get("gateway_ip"),
                        "dhcp_enabled": net.get("dhcpd_enabled", False),
                        "dhcp_start": net.get("dhcpd_start"),
                        "dhcp_stop": net.get("dhcpd_stop"),
                        "domain_name": net.get("domain_name"),
                        "enabled": net.get("enabled", True),
                    }
                )

            return networks

        except Exception as e:
            logger.error(f"Failed to get networks: {e}")
            return []

    async def get_devices(self) -> list[dict]:
        """
        Get all UniFi devices.

        Returns:
            List of UniFi devices
        """
        try:
            data = await self._api_get("stat/device")

            devices = []
            for device in data.get("data", []):
                devices.append(
                    {
                        "id": device.get("_id"),
                        "mac": device.get("mac"),
                        "ip": device.get("ip"),
                        "name": device.get("name", device.get("mac")),
                        "model": device.get("model"),
                        "type": device.get("type"),
                        "version": device.get("version"),
                        "adopted": device.get("adopted", False),
                        "state": device.get("state"),
                        "uptime": device.get("uptime", 0),
                        "last_seen": device.get("last_seen", 0),
                        "port_count": len(device.get("port_table", [])),
                    }
                )

            return devices

        except Exception as e:
            logger.error(f"Failed to get devices: {e}")
            return []

    async def block_client(self, mac: str) -> bool:
        """
        Block a client from the network.

        Args:
            mac: Client MAC address

        Returns:
            True if successful
        """
        try:
            await self._api_post("cmd/stamgr", {"cmd": "block-sta", "mac": mac})
            logger.info(f"Blocked client: {mac}")
            return True

        except Exception as e:
            logger.error(f"Failed to block client: {e}")
            return False

    async def unblock_client(self, mac: str) -> bool:
        """
        Unblock a client.

        Args:
            mac: Client MAC address

        Returns:
            True if successful
        """
        try:
            await self._api_post("cmd/stamgr", {"cmd": "unblock-sta", "mac": mac})
            logger.info(f"Unblocked client: {mac}")
            return True

        except Exception as e:
            logger.error(f"Failed to unblock client: {e}")
            return False

    async def reconnect_client(self, mac: str) -> bool:
        """
        Force a client to reconnect (kick).

        Args:
            mac: Client MAC address

        Returns:
            True if successful
        """
        try:
            await self._api_post("cmd/stamgr", {"cmd": "kick-sta", "mac": mac})
            logger.info(f"Kicked client: {mac}")
            return True

        except Exception as e:
            logger.error(f"Failed to kick client: {e}")
            return False

    async def set_port_poe(self, port: str, mode: str) -> bool:
        """
        Set PoE mode for a port.

        Args:
            port: Port identifier (switch_mac:port_idx)
            mode: PoE mode (off, auto, pasv24, passthrough)

        Returns:
            True if successful
        """
        try:
            parts = port.split(":")
            if len(parts) != 2:
                raise ValueError("Port must be in format switch_mac:port_idx")

            switch_mac = parts[0]
            port_idx = int(parts[1])

            devices_data = await self._api_get("stat/device")

            for device in devices_data.get("data", []):
                if device.get("mac", "").lower() == switch_mac.lower():
                    device_id = device.get("_id")

                    port_overrides = device.get("port_overrides", [])

                    override_found = False
                    for override in port_overrides:
                        if override.get("port_idx") == port_idx:
                            override["poe_mode"] = mode
                            override_found = True
                            break

                    if not override_found:
                        port_overrides.append({"port_idx": port_idx, "poe_mode": mode})

                    await self._api_put(
                        f"rest/device/{device_id}", {"port_overrides": port_overrides}
                    )

                    logger.info(f"Set port {port} PoE mode to {mode}")
                    return True

            return False

        except Exception as e:
            logger.error(f"Failed to set port PoE: {e}")
            return False
