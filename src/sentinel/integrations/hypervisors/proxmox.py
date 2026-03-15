"""
Proxmox VE Integration for Sentinel.

This module provides integration with Proxmox Virtual Environment
via the Proxmox API. Supports VM management, resource monitoring,
live migration, and cluster operations.
"""
import asyncio
import logging
from datetime import datetime
from typing import Any, Optional

import httpx

from sentinel.integrations.base import HypervisorIntegration

logger = logging.getLogger(__name__)


class ProxmoxIntegration(HypervisorIntegration):
    """
    Proxmox VE hypervisor integration.

    Provides access to:
    - VM and container management
    - Resource utilization monitoring
    - Live migration
    - Snapshot management
    - Cluster status

    Configuration:
        hypervisor:
            type: proxmox
            host: "192.168.1.10"
            port: 8006
            user: "root@pam"
            token_name: "${PROXMOX_TOKEN_NAME}"
            token_value: "${PROXMOX_TOKEN_VALUE}"
            verify_ssl: false
    """

    def __init__(self, config: dict):
        """
        Initialize Proxmox integration.

        Args:
            config: Integration configuration
        """
        super().__init__(config)

        self.host = config.get("host", "")
        self.port = config.get("port", 8006)
        self.user = config.get("user", "root@pam")
        self.token_name = config.get("token_name", "")
        self.token_value = config.get("token_value", "")
        # SECURITY: SSL verification enabled by default
        self.verify_ssl = config.get("verify_ssl", True)
        if not self.verify_ssl:
            logger.warning(
                "Proxmox SSL verification DISABLED - this is insecure! "
                "Only use for testing or with self-signed certificates."
            )

        # Alternative: password-based auth
        self.password = config.get("password", "")

        self._base_url = f"https://{self.host}:{self.port}/api2/json"
        self._client: Optional[httpx.AsyncClient] = None
        self._ticket: Optional[str] = None
        self._csrf_token: Optional[str] = None

    async def connect(self) -> None:
        """Establish connection to Proxmox API."""
        self._client = httpx.AsyncClient(
            base_url=self._base_url,
            verify=self.verify_ssl,
            timeout=30.0
        )

        try:
            if self.token_name and self.token_value:
                # Token-based authentication
                self._client.headers["Authorization"] = (
                    f"PVEAPIToken={self.user}!{self.token_name}={self.token_value}"
                )
            elif self.password:
                # Password-based authentication - get ticket
                response = await self._client.post(
                    "/access/ticket",
                    data={
                        "username": self.user,
                        "password": self.password
                    }
                )
                response.raise_for_status()
                data = response.json()["data"]

                self._ticket = data["ticket"]
                self._csrf_token = data["CSRFPreventionToken"]

                self._client.cookies.set("PVEAuthCookie", self._ticket)
                self._client.headers["CSRFPreventionToken"] = self._csrf_token
            else:
                raise ValueError("Either token or password must be provided")

            # Test connection
            response = await self._client.get("/version")
            response.raise_for_status()

            self._connected = True
            version = response.json()["data"]["version"]
            logger.info(f"Connected to Proxmox VE {version} at {self.host}")

        except Exception as e:
            logger.error(f"Failed to connect to Proxmox: {e}")
            raise ConnectionError(f"Proxmox connection failed: {e}")

    async def disconnect(self) -> None:
        """Close connection to Proxmox API."""
        if self._client:
            await self._client.aclose()
            self._client = None

        self._connected = False
        self._ticket = None
        self._csrf_token = None
        logger.info("Disconnected from Proxmox")

    async def health_check(self) -> bool:
        """Check if Proxmox is responding."""
        if not self._client:
            return False

        try:
            response = await self._client.get("/version")
            return response.status_code == 200
        except Exception as e:
            logger.debug(f"Proxmox health check failed: {e}")
            return False

    async def _api_get(self, endpoint: str) -> dict:
        """Make GET request to Proxmox API."""
        if not self._client:
            raise RuntimeError("Not connected to Proxmox")

        response = await self._client.get(endpoint)
        response.raise_for_status()
        return response.json().get("data", {})

    async def _api_post(self, endpoint: str, data: Optional[dict] = None) -> dict:
        """Make POST request to Proxmox API."""
        if not self._client:
            raise RuntimeError("Not connected to Proxmox")

        response = await self._client.post(endpoint, data=data or {})
        response.raise_for_status()
        return response.json().get("data", {})

    async def _api_delete(self, endpoint: str) -> dict:
        """Make DELETE request to Proxmox API."""
        if not self._client:
            raise RuntimeError("Not connected to Proxmox")

        response = await self._client.delete(endpoint)
        response.raise_for_status()
        return response.json().get("data", {})

    # =========================================================================
    # Hypervisor Interface Methods
    # =========================================================================

    async def get_vms(self) -> list[dict]:
        """
        Get all VMs and containers across the cluster.

        Returns:
            List of VMs with status and resource usage
        """
        try:
            # Get all nodes
            nodes = await self._api_get("/nodes")

            vms = []
            for node in nodes:
                node_name = node["node"]

                # Get VMs (QEMU)
                try:
                    qemu_vms = await self._api_get(f"/nodes/{node_name}/qemu")
                    for vm in qemu_vms:
                        vms.append({
                            "id": f"qemu/{vm['vmid']}",
                            "vmid": vm["vmid"],
                            "type": "qemu",
                            "name": vm.get("name", f"VM {vm['vmid']}"),
                            "host": node_name,
                            "status": vm.get("status", "unknown"),
                            "cpu_usage": vm.get("cpu", 0),
                            "memory_usage": vm.get("mem", 0),
                            "memory_max": vm.get("maxmem", 0),
                            "disk_read": vm.get("diskread", 0),
                            "disk_write": vm.get("diskwrite", 0),
                            "net_in": vm.get("netin", 0),
                            "net_out": vm.get("netout", 0),
                            "uptime": vm.get("uptime", 0),
                            "template": vm.get("template", 0) == 1
                        })
                except Exception as e:
                    logger.warning(f"Failed to get QEMU VMs from {node_name}: {e}")

                # Get containers (LXC)
                try:
                    lxc_cts = await self._api_get(f"/nodes/{node_name}/lxc")
                    for ct in lxc_cts:
                        vms.append({
                            "id": f"lxc/{ct['vmid']}",
                            "vmid": ct["vmid"],
                            "type": "lxc",
                            "name": ct.get("name", f"CT {ct['vmid']}"),
                            "host": node_name,
                            "status": ct.get("status", "unknown"),
                            "cpu_usage": ct.get("cpu", 0),
                            "memory_usage": ct.get("mem", 0),
                            "memory_max": ct.get("maxmem", 0),
                            "disk_read": ct.get("diskread", 0),
                            "disk_write": ct.get("diskwrite", 0),
                            "net_in": ct.get("netin", 0),
                            "net_out": ct.get("netout", 0),
                            "uptime": ct.get("uptime", 0),
                            "template": ct.get("template", 0) == 1
                        })
                except Exception as e:
                    logger.warning(f"Failed to get LXC containers from {node_name}: {e}")

            return vms

        except Exception as e:
            logger.error(f"Failed to get VMs: {e}")
            return []

    async def start_vm(self, vm_id: str) -> bool:
        """
        Start a VM or container.

        Args:
            vm_id: VM identifier (type/vmid, e.g., "qemu/100")

        Returns:
            True if start initiated successfully
        """
        try:
            vm_type, vmid = self._parse_vm_id(vm_id)
            node = await self._find_vm_node(vm_type, vmid)

            if not node:
                logger.error(f"VM {vm_id} not found")
                return False

            await self._api_post(f"/nodes/{node}/{vm_type}/{vmid}/status/start")
            logger.info(f"Started {vm_type} {vmid} on {node}")
            return True

        except Exception as e:
            logger.error(f"Failed to start VM {vm_id}: {e}")
            return False

    async def stop_vm(self, vm_id: str) -> bool:
        """
        Stop a VM or container.

        Args:
            vm_id: VM identifier (type/vmid)

        Returns:
            True if stop initiated successfully
        """
        try:
            vm_type, vmid = self._parse_vm_id(vm_id)
            node = await self._find_vm_node(vm_type, vmid)

            if not node:
                logger.error(f"VM {vm_id} not found")
                return False

            await self._api_post(f"/nodes/{node}/{vm_type}/{vmid}/status/stop")
            logger.info(f"Stopped {vm_type} {vmid} on {node}")
            return True

        except Exception as e:
            logger.error(f"Failed to stop VM {vm_id}: {e}")
            return False

    async def migrate_vm(self, vm_id: str, target_host: str) -> bool:
        """
        Migrate a VM to another node.

        Args:
            vm_id: VM identifier (type/vmid)
            target_host: Target node name, or "auto" for automatic selection

        Returns:
            True if migration initiated successfully
        """
        try:
            vm_type, vmid = self._parse_vm_id(vm_id)
            current_node = await self._find_vm_node(vm_type, vmid)

            if not current_node:
                logger.error(f"VM {vm_id} not found")
                return False

            # Auto-select target if needed
            if target_host == "auto":
                target_host = await self._select_migration_target(current_node)
                if not target_host:
                    logger.error("No suitable migration target found")
                    return False

            # Initiate migration
            migrate_data = {
                "target": target_host,
                "online": 1  # Live migration
            }

            await self._api_post(
                f"/nodes/{current_node}/{vm_type}/{vmid}/migrate",
                migrate_data
            )

            logger.info(f"Initiated migration of {vm_type} {vmid} from {current_node} to {target_host}")
            return True

        except Exception as e:
            logger.error(f"Failed to migrate VM {vm_id}: {e}")
            return False

    async def get_host_resources(self) -> dict:
        """
        Get resource utilization for the cluster/primary node.

        Returns:
            Dictionary with CPU, memory, disk usage
        """
        try:
            nodes = await self._api_get("/nodes")

            # Aggregate resources from all nodes
            total_cpu = 0
            total_cpu_used = 0
            total_mem = 0
            total_mem_used = 0
            total_disk = 0
            total_disk_used = 0

            for node in nodes:
                status = await self._api_get(f"/nodes/{node['node']}/status")

                total_cpu += status.get("cpuinfo", {}).get("cpus", 0)
                total_cpu_used += status.get("cpu", 0) * status.get("cpuinfo", {}).get("cpus", 0)

                total_mem += status.get("memory", {}).get("total", 0)
                total_mem_used += status.get("memory", {}).get("used", 0)

                rootfs = status.get("rootfs", {})
                total_disk += rootfs.get("total", 0)
                total_disk_used += rootfs.get("used", 0)

            cpu_percent = (total_cpu_used / total_cpu * 100) if total_cpu > 0 else 0
            memory_percent = (total_mem_used / total_mem * 100) if total_mem > 0 else 0
            disk_percent = (total_disk_used / total_disk * 100) if total_disk > 0 else 0

            return {
                "cpu_count": total_cpu,
                "cpu_percent": round(cpu_percent, 2),
                "memory_total": total_mem,
                "memory_used": total_mem_used,
                "memory_percent": round(memory_percent, 2),
                "disk_total": total_disk,
                "disk_used": total_disk_used,
                "disk_percent": round(disk_percent, 2),
                "node_count": len(nodes)
            }

        except Exception as e:
            logger.error(f"Failed to get host resources: {e}")
            return {}

    # =========================================================================
    # Extended Proxmox Methods
    # =========================================================================

    async def get_nodes(self) -> list[dict]:
        """
        Get all cluster nodes.

        Returns:
            List of nodes with status
        """
        try:
            nodes = await self._api_get("/nodes")

            result = []
            for node in nodes:
                node_name = node["node"]
                status = await self._api_get(f"/nodes/{node_name}/status")

                result.append({
                    "name": node_name,
                    "status": node.get("status", "unknown"),
                    "cpu_count": status.get("cpuinfo", {}).get("cpus", 0),
                    "cpu_percent": round(status.get("cpu", 0) * 100, 2),
                    "memory_total": status.get("memory", {}).get("total", 0),
                    "memory_used": status.get("memory", {}).get("used", 0),
                    "memory_percent": round(
                        status.get("memory", {}).get("used", 0) /
                        max(status.get("memory", {}).get("total", 1), 1) * 100,
                        2
                    ),
                    "uptime": status.get("uptime", 0),
                    "kernel": status.get("kversion", ""),
                    "pve_version": status.get("pveversion", "")
                })

            return result

        except Exception as e:
            logger.error(f"Failed to get nodes: {e}")
            return []

    async def get_storage(self) -> list[dict]:
        """
        Get storage status across the cluster.

        Returns:
            List of storage locations with usage
        """
        try:
            storage = await self._api_get("/storage")

            result = []
            for store in storage:
                store_name = store["storage"]

                # Get status from first available node
                nodes = await self._api_get("/nodes")
                if nodes:
                    try:
                        status = await self._api_get(
                            f"/nodes/{nodes[0]['node']}/storage/{store_name}/status"
                        )
                        result.append({
                            "name": store_name,
                            "type": store.get("type"),
                            "content": store.get("content", "").split(","),
                            "shared": store.get("shared", 0) == 1,
                            "total": status.get("total", 0),
                            "used": status.get("used", 0),
                            "available": status.get("avail", 0),
                            "active": status.get("active", True)
                        })
                    except Exception as e:
                        logger.debug(f"Failed to get storage status for {store_name}: {e}")
                        result.append({
                            "name": store_name,
                            "type": store.get("type"),
                            "content": store.get("content", "").split(","),
                            "shared": store.get("shared", 0) == 1
                        })

            return result

        except Exception as e:
            logger.error(f"Failed to get storage: {e}")
            return []

    async def create_snapshot(self, vm_id: str, name: str, description: str = "") -> bool:
        """
        Create a snapshot of a VM.

        Args:
            vm_id: VM identifier (type/vmid)
            name: Snapshot name
            description: Optional description

        Returns:
            True if successful
        """
        try:
            vm_type, vmid = self._parse_vm_id(vm_id)
            node = await self._find_vm_node(vm_type, vmid)

            if not node:
                logger.error(f"VM {vm_id} not found")
                return False

            await self._api_post(
                f"/nodes/{node}/{vm_type}/{vmid}/snapshot",
                {
                    "snapname": name,
                    "description": description
                }
            )

            logger.info(f"Created snapshot '{name}' for {vm_type} {vmid}")
            return True

        except Exception as e:
            logger.error(f"Failed to create snapshot: {e}")
            return False

    async def get_snapshots(self, vm_id: str) -> list[dict]:
        """
        Get snapshots for a VM.

        Args:
            vm_id: VM identifier (type/vmid)

        Returns:
            List of snapshots
        """
        try:
            vm_type, vmid = self._parse_vm_id(vm_id)
            node = await self._find_vm_node(vm_type, vmid)

            if not node:
                return []

            snapshots = await self._api_get(
                f"/nodes/{node}/{vm_type}/{vmid}/snapshot"
            )

            return [
                {
                    "name": snap.get("name"),
                    "description": snap.get("description", ""),
                    "parent": snap.get("parent"),
                    "snaptime": snap.get("snaptime")
                }
                for snap in snapshots
                if snap.get("name") != "current"
            ]

        except Exception as e:
            logger.error(f"Failed to get snapshots: {e}")
            return []

    async def reboot_vm(self, vm_id: str) -> bool:
        """
        Reboot a VM.

        Args:
            vm_id: VM identifier (type/vmid)

        Returns:
            True if successful
        """
        try:
            vm_type, vmid = self._parse_vm_id(vm_id)
            node = await self._find_vm_node(vm_type, vmid)

            if not node:
                return False

            await self._api_post(f"/nodes/{node}/{vm_type}/{vmid}/status/reboot")
            logger.info(f"Rebooted {vm_type} {vmid}")
            return True

        except Exception as e:
            logger.error(f"Failed to reboot VM: {e}")
            return False

    async def shutdown_vm(self, vm_id: str) -> bool:
        """
        Gracefully shutdown a VM.

        Args:
            vm_id: VM identifier (type/vmid)

        Returns:
            True if successful
        """
        try:
            vm_type, vmid = self._parse_vm_id(vm_id)
            node = await self._find_vm_node(vm_type, vmid)

            if not node:
                return False

            await self._api_post(f"/nodes/{node}/{vm_type}/{vmid}/status/shutdown")
            logger.info(f"Shutdown {vm_type} {vmid}")
            return True

        except Exception as e:
            logger.error(f"Failed to shutdown VM: {e}")
            return False

    # =========================================================================
    # Helper Methods
    # =========================================================================

    def _parse_vm_id(self, vm_id: str) -> tuple[str, str]:
        """Parse VM ID into type and vmid."""
        if "/" in vm_id:
            parts = vm_id.split("/")
            return parts[0], parts[1]
        else:
            # Assume QEMU if no type specified
            return "qemu", vm_id

    async def _find_vm_node(self, vm_type: str, vmid: str) -> Optional[str]:
        """Find which node a VM is on."""
        try:
            nodes = await self._api_get("/nodes")

            for node in nodes:
                node_name = node["node"]
                try:
                    await self._api_get(f"/nodes/{node_name}/{vm_type}/{vmid}/status/current")
                    return node_name
                except Exception as e:
                    logger.debug(f"VM {vmid} not found on node {node_name}: {e}")
                    continue

            return None

        except Exception as e:
            logger.debug(f"Failed to find VM node: {e}")
            return None

    async def _select_migration_target(self, exclude_node: str) -> Optional[str]:
        """Select best node for migration based on available resources."""
        try:
            nodes = await self._api_get("/nodes")

            best_node = None
            best_score = -1

            for node in nodes:
                node_name = node["node"]

                if node_name == exclude_node:
                    continue

                if node.get("status") != "online":
                    continue

                # Get node resources
                status = await self._api_get(f"/nodes/{node_name}/status")

                # Calculate score based on available resources
                cpu_free = 1 - status.get("cpu", 1)
                mem_info = status.get("memory", {})
                mem_free = 1 - (mem_info.get("used", 0) / max(mem_info.get("total", 1), 1))

                score = (cpu_free + mem_free) / 2

                if score > best_score:
                    best_score = score
                    best_node = node_name

            return best_node

        except Exception as e:
            logger.error(f"Failed to select migration target: {e}")
            return None
