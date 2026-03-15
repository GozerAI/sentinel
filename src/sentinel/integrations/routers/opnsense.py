"""
OPNsense Router Integration for Sentinel.

This module provides integration with OPNsense firewalls via their REST API.
Supports firewall rules, ARP table, DHCP leases, and system status.
"""
import asyncio
import logging
from datetime import datetime
from typing import Any, Optional

import httpx

from sentinel.integrations.base import RouterIntegration

logger = logging.getLogger(__name__)


class OPNsenseIntegration(RouterIntegration):
    """
    OPNsense firewall integration.

    Provides access to:
    - Firewall rules management
    - ARP table lookups
    - DHCP lease information
    - System status and health
    - Interface statistics

    Configuration:
        router:
            type: opnsense
            host: "192.168.1.1"
            port: 443
            api_key: "${ROUTER_API_KEY}"
            api_secret: "${ROUTER_API_SECRET}"
            verify_ssl: false
            timeout: 30
    """

    def __init__(self, config: dict):
        """
        Initialize OPNsense integration.

        Args:
            config: Integration configuration
        """
        super().__init__(config)

        self.host = config.get("host", "192.168.1.1")
        self.port = config.get("port", 443)
        self.api_key = config.get("api_key", "")
        self.api_secret = config.get("api_secret", "")
        # SECURITY: SSL verification enabled by default
        self.verify_ssl = config.get("verify_ssl", True)
        if not self.verify_ssl:
            logger.warning(
                "OPNsense SSL verification DISABLED - this is insecure! "
                "Only use for testing or with self-signed certificates."
            )
        self.timeout = config.get("timeout", 30)

        self._base_url = f"https://{self.host}:{self.port}/api"
        self._client: Optional[httpx.AsyncClient] = None

    async def connect(self) -> None:
        """Establish connection to OPNsense API."""
        self._client = httpx.AsyncClient(
            base_url=self._base_url,
            auth=(self.api_key, self.api_secret),
            verify=self.verify_ssl,
            timeout=self.timeout
        )

        # Test connection
        try:
            response = await self._client.get("/core/firmware/status")
            response.raise_for_status()
            self._connected = True
            logger.info(f"Connected to OPNsense at {self.host}")
        except Exception as e:
            logger.error(f"Failed to connect to OPNsense: {e}")
            raise ConnectionError(f"OPNsense connection failed: {e}")

    async def disconnect(self) -> None:
        """Close connection to OPNsense API."""
        if self._client:
            await self._client.aclose()
            self._client = None
        self._connected = False
        logger.info("Disconnected from OPNsense")

    async def health_check(self) -> bool:
        """Check if OPNsense is responding."""
        if not self._client:
            return False

        try:
            response = await self._client.get("/core/system/status")
            return response.status_code == 200
        except Exception as e:
            logger.debug(f"OPNsense health check failed: {e}")
            return False

    async def _api_get(self, endpoint: str) -> dict:
        """Make GET request to OPNsense API."""
        if not self._client:
            raise RuntimeError("Not connected to OPNsense")

        response = await self._client.get(endpoint)
        response.raise_for_status()
        return response.json()

    async def _api_post(self, endpoint: str, data: Optional[dict] = None) -> dict:
        """Make POST request to OPNsense API."""
        if not self._client:
            raise RuntimeError("Not connected to OPNsense")

        response = await self._client.post(endpoint, json=data or {})
        response.raise_for_status()
        return response.json()

    # =========================================================================
    # Router Interface Methods
    # =========================================================================

    async def get_arp_table(self) -> list[dict]:
        """
        Get ARP table from OPNsense.

        Returns:
            List of ARP entries with ip, mac, interface, hostname
        """
        try:
            data = await self._api_get("/diagnostics/interface/getArp")

            entries = []
            for entry in data.get("arp", []):
                entries.append({
                    "ip": entry.get("ip"),
                    "mac": entry.get("mac"),
                    "interface": entry.get("intf"),
                    "hostname": entry.get("hostname", ""),
                    "expires": entry.get("expires", ""),
                    "type": entry.get("type", "dynamic")
                })

            return entries

        except Exception as e:
            logger.error(f"Failed to get ARP table: {e}")
            return []

    async def get_dhcp_leases(self) -> list[dict]:
        """
        Get DHCP leases from OPNsense.

        Returns:
            List of DHCP leases with ip, mac, hostname, start, end
        """
        try:
            data = await self._api_get("/dhcpv4/leases/searchLease")

            leases = []
            for lease in data.get("rows", []):
                leases.append({
                    "ip": lease.get("address"),
                    "mac": lease.get("mac"),
                    "hostname": lease.get("hostname", ""),
                    "start": lease.get("starts"),
                    "end": lease.get("ends"),
                    "state": lease.get("state", "active"),
                    "interface": lease.get("if", ""),
                    "active": lease.get("state") == "active"
                })

            return leases

        except Exception as e:
            logger.error(f"Failed to get DHCP leases: {e}")
            return []

    async def add_firewall_rule(self, rule: dict) -> str:
        """
        Add a firewall rule to OPNsense.

        Args:
            rule: Rule definition with name, action, source, destination, etc.

        Returns:
            Rule UUID
        """
        try:
            # Map our rule format to OPNsense format
            opn_rule = {
                "rule": {
                    "enabled": "1",
                    "action": self._map_action(rule.get("action", "deny")),
                    "interface": rule.get("interface", "lan"),
                    "direction": rule.get("direction", "in"),
                    "ipprotocol": rule.get("ip_protocol", "inet"),
                    "protocol": rule.get("protocol", "any"),
                    "source_net": rule.get("source_ip", "any"),
                    "destination_net": rule.get("destination_ip", "any"),
                    "description": rule.get("description", rule.get("name", ""))
                }
            }

            if rule.get("source_port"):
                opn_rule["rule"]["source_port"] = rule["source_port"]
            if rule.get("destination_port"):
                opn_rule["rule"]["destination_port"] = rule["destination_port"]

            # Add the rule
            response = await self._api_post("/firewall/filter/addRule", opn_rule)
            rule_uuid = response.get("uuid", "")

            if rule_uuid:
                # Apply changes
                await self._api_post("/firewall/filter/apply")
                logger.info(f"Added firewall rule: {rule.get('name')} (UUID: {rule_uuid})")

            return rule_uuid

        except Exception as e:
            logger.error(f"Failed to add firewall rule: {e}")
            raise

    async def delete_firewall_rule(self, rule_id: str) -> bool:
        """
        Delete a firewall rule from OPNsense.

        Args:
            rule_id: Rule UUID

        Returns:
            True if successful
        """
        try:
            await self._api_post(f"/firewall/filter/delRule/{rule_id}")
            await self._api_post("/firewall/filter/apply")
            logger.info(f"Deleted firewall rule: {rule_id}")
            return True

        except Exception as e:
            logger.error(f"Failed to delete firewall rule: {e}")
            return False

    async def get_firewall_rules(self) -> list[dict]:
        """
        Get all firewall rules from OPNsense.

        Returns:
            List of firewall rules
        """
        try:
            data = await self._api_get("/firewall/filter/searchRule")

            rules = []
            for rule in data.get("rows", []):
                rules.append({
                    "id": rule.get("uuid"),
                    "enabled": rule.get("enabled") == "1",
                    "action": rule.get("action"),
                    "interface": rule.get("interface"),
                    "direction": rule.get("direction"),
                    "protocol": rule.get("protocol"),
                    "source": rule.get("source_net"),
                    "source_port": rule.get("source_port"),
                    "destination": rule.get("destination_net"),
                    "destination_port": rule.get("destination_port"),
                    "description": rule.get("description", "")
                })

            return rules

        except Exception as e:
            logger.error(f"Failed to get firewall rules: {e}")
            return []

    # =========================================================================
    # Extended OPNsense Methods
    # =========================================================================

    async def get_system_status(self) -> dict:
        """
        Get OPNsense system status.

        Returns:
            System status information
        """
        try:
            data = await self._api_get("/core/system/status")
            return {
                "uptime": data.get("uptime"),
                "datetime": data.get("datetime"),
                "cpu_usage": data.get("cpu"),
                "memory_usage": data.get("memory"),
                "disk_usage": data.get("disk"),
                "temperature": data.get("temperature")
            }
        except Exception as e:
            logger.error(f"Failed to get system status: {e}")
            return {}

    async def get_interfaces(self) -> list[dict]:
        """
        Get network interfaces.

        Returns:
            List of interfaces with status
        """
        try:
            data = await self._api_get("/diagnostics/interface/getInterfaceStatistics")

            interfaces = []
            for name, stats in data.get("statistics", {}).items():
                interfaces.append({
                    "name": name,
                    "bytes_in": stats.get("bytes received", 0),
                    "bytes_out": stats.get("bytes transmitted", 0),
                    "packets_in": stats.get("packets received", 0),
                    "packets_out": stats.get("packets transmitted", 0),
                    "errors_in": stats.get("input errors", 0),
                    "errors_out": stats.get("output errors", 0)
                })

            return interfaces

        except Exception as e:
            logger.error(f"Failed to get interfaces: {e}")
            return []

    async def get_gateway_status(self) -> list[dict]:
        """
        Get gateway status.

        Returns:
            List of gateways with status
        """
        try:
            data = await self._api_get("/routes/gateway/status")

            gateways = []
            for gw in data.get("items", []):
                gateways.append({
                    "name": gw.get("name"),
                    "address": gw.get("address"),
                    "status": gw.get("status_translated", gw.get("status")),
                    "delay": gw.get("delay"),
                    "stddev": gw.get("stddev"),
                    "loss": gw.get("loss")
                })

            return gateways

        except Exception as e:
            logger.error(f"Failed to get gateway status: {e}")
            return []

    async def get_unbound_stats(self) -> dict:
        """
        Get Unbound DNS statistics.

        Returns:
            DNS statistics
        """
        try:
            data = await self._api_get("/unbound/diagnostics/stats")
            return data
        except Exception as e:
            logger.error(f"Failed to get Unbound stats: {e}")
            return {}

    async def flush_arp_cache(self) -> bool:
        """
        Flush the ARP cache.

        Returns:
            True if successful
        """
        try:
            await self._api_post("/diagnostics/interface/flushArp")
            logger.info("Flushed ARP cache")
            return True
        except Exception as e:
            logger.error(f"Failed to flush ARP cache: {e}")
            return False

    async def create_alias(self, name: str, alias_type: str, content: list[str], description: str = "") -> str:
        """
        Create a firewall alias.

        Args:
            name: Alias name
            alias_type: Type (host, network, port)
            content: List of values
            description: Optional description

        Returns:
            Alias UUID
        """
        try:
            alias_data = {
                "alias": {
                    "enabled": "1",
                    "name": name,
                    "type": alias_type,
                    "content": "\n".join(content),
                    "description": description
                }
            }

            response = await self._api_post("/firewall/alias/addItem", alias_data)
            uuid = response.get("uuid", "")

            if uuid:
                await self._api_post("/firewall/alias/reconfigure")
                logger.info(f"Created alias: {name} (UUID: {uuid})")

            return uuid

        except Exception as e:
            logger.error(f"Failed to create alias: {e}")
            raise

    async def delete_alias(self, uuid: str) -> bool:
        """
        Delete a firewall alias.

        Args:
            uuid: Alias UUID

        Returns:
            True if successful
        """
        try:
            await self._api_post(f"/firewall/alias/delItem/{uuid}")
            await self._api_post("/firewall/alias/reconfigure")
            logger.info(f"Deleted alias: {uuid}")
            return True
        except Exception as e:
            logger.error(f"Failed to delete alias: {e}")
            return False

    async def get_aliases(self) -> list[dict]:
        """
        Get all firewall aliases.

        Returns:
            List of aliases
        """
        try:
            data = await self._api_get("/firewall/alias/searchItem")

            aliases = []
            for alias in data.get("rows", []):
                aliases.append({
                    "uuid": alias.get("uuid"),
                    "name": alias.get("name"),
                    "type": alias.get("type"),
                    "content": alias.get("content", "").split("\n"),
                    "description": alias.get("description", ""),
                    "enabled": alias.get("enabled") == "1"
                })

            return aliases

        except Exception as e:
            logger.error(f"Failed to get aliases: {e}")
            return []

    # =========================================================================
    # Helper Methods
    # =========================================================================

    def _map_action(self, action: str) -> str:
        """Map our action names to OPNsense action names."""
        mapping = {
            "allow": "pass",
            "permit": "pass",
            "pass": "pass",
            "deny": "block",
            "block": "block",
            "drop": "block",
            "reject": "reject"
        }
        return mapping.get(action.lower(), "block")
