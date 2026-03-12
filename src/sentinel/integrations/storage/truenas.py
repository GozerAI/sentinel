"""
TrueNAS Integration for Sentinel.

This module provides integration with TrueNAS SCALE/CORE via REST API.
Supports pool monitoring, dataset management, snapshot operations,
and system health monitoring.
"""

import asyncio
import logging
from datetime import datetime
from typing import Any, Optional

import httpx

from sentinel.integrations.base import StorageIntegration

logger = logging.getLogger(__name__)


class TrueNASIntegration(StorageIntegration):
    """
    TrueNAS storage integration.

    Provides access to:
    - ZFS pool status and health
    - Dataset management
    - Snapshot operations
    - Replication status
    - System health monitoring
    - Alert management

    Configuration:
        storage:
            type: truenas
            host: "192.168.1.20"
            api_key: "${TRUENAS_API_KEY}"
            verify_ssl: false
    """

    def __init__(self, config: dict):
        """
        Initialize TrueNAS integration.

        Args:
            config: Integration configuration
        """
        super().__init__(config)

        self.host = config.get("host", "")
        self.api_key = config.get("api_key", "")
        # SECURITY: SSL verification enabled by default
        self.verify_ssl = config.get("verify_ssl", True)
        if not self.verify_ssl:
            logger.warning(
                "TrueNAS SSL verification DISABLED - this is insecure! "
                "Only use for testing or with self-signed certificates."
            )

        # Alternative: username/password auth
        self.username = config.get("username", "")
        self.password = config.get("password", "")

        self._base_url = f"https://{self.host}/api/v2.0"
        self._client: Optional[httpx.AsyncClient] = None

    async def connect(self) -> None:
        """Establish connection to TrueNAS API."""
        headers = {}

        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"

        self._client = httpx.AsyncClient(
            base_url=self._base_url, headers=headers, verify=self.verify_ssl, timeout=30.0
        )

        # If using username/password, we need to get a token
        if not self.api_key and self.username:
            try:
                response = await self._client.post(
                    "/auth/login", json={"username": self.username, "password": self.password}
                )
                response.raise_for_status()
                # TrueNAS SCALE uses session cookies after login
            except Exception as e:
                logger.error(f"Failed to login to TrueNAS: {e}")
                raise ConnectionError(f"TrueNAS login failed: {e}")

        # Test connection
        try:
            response = await self._client.get("/system/info")
            response.raise_for_status()
            info = response.json()

            self._connected = True
            logger.info(f"Connected to TrueNAS {info.get('version', 'unknown')} at {self.host}")

        except Exception as e:
            logger.error(f"Failed to connect to TrueNAS: {e}")
            raise ConnectionError(f"TrueNAS connection failed: {e}")

    async def disconnect(self) -> None:
        """Close connection to TrueNAS API."""
        if self._client:
            await self._client.aclose()
            self._client = None

        self._connected = False
        logger.info("Disconnected from TrueNAS")

    async def health_check(self) -> bool:
        """Check if TrueNAS is responding."""
        if not self._client:
            return False

        try:
            response = await self._client.get("/system/info")
            return response.status_code == 200
        except Exception as e:
            logger.debug(f"TrueNAS health check failed: {e}")
            return False

    async def _api_get(self, endpoint: str) -> Any:
        """Make GET request to TrueNAS API."""
        if not self._client:
            raise RuntimeError("Not connected to TrueNAS")

        response = await self._client.get(endpoint)
        response.raise_for_status()
        return response.json()

    async def _api_post(self, endpoint: str, data: Optional[dict] = None) -> Any:
        """Make POST request to TrueNAS API."""
        if not self._client:
            raise RuntimeError("Not connected to TrueNAS")

        response = await self._client.post(endpoint, json=data or {})
        response.raise_for_status()
        return response.json()

    async def _api_delete(self, endpoint: str) -> Any:
        """Make DELETE request to TrueNAS API."""
        if not self._client:
            raise RuntimeError("Not connected to TrueNAS")

        response = await self._client.delete(endpoint)
        response.raise_for_status()
        return response.json()

    # =========================================================================
    # Storage Interface Methods
    # =========================================================================

    async def get_pools(self) -> list[dict]:
        """
        Get ZFS pool status.

        Returns:
            List of pools with health status
        """
        try:
            pools = await self._api_get("/pool")

            result = []
            for pool in pools:
                # Get pool status details
                status = pool.get("status", "UNKNOWN")

                result.append(
                    {
                        "id": pool.get("id"),
                        "name": pool.get("name"),
                        "path": pool.get("path"),
                        "status": status,
                        "healthy": status == "ONLINE",
                        "size": pool.get("size"),
                        "allocated": pool.get("allocated"),
                        "free": pool.get("free"),
                        "fragmentation": pool.get("fragmentation"),
                        "capacity": pool.get("capacity"),
                        "autotrim": pool.get("autotrim", {}).get("value") == "on",
                        "topology": pool.get("topology", {}),
                    }
                )

            return result

        except Exception as e:
            logger.error(f"Failed to get pools: {e}")
            return []

    async def get_datasets(self) -> list[dict]:
        """
        Get all datasets/filesystems.

        Returns:
            List of datasets with properties
        """
        try:
            datasets = await self._api_get("/pool/dataset")

            result = []
            for ds in datasets:
                result.append(
                    {
                        "id": ds.get("id"),
                        "name": ds.get("name"),
                        "pool": ds.get("pool"),
                        "type": ds.get("type"),
                        "mountpoint": ds.get("mountpoint"),
                        "quota": ds.get("quota", {}).get("parsed"),
                        "refquota": ds.get("refquota", {}).get("parsed"),
                        "used": ds.get("used", {}).get("parsed"),
                        "available": ds.get("available", {}).get("parsed"),
                        "compression": ds.get("compression", {}).get("value"),
                        "deduplication": ds.get("deduplication", {}).get("value"),
                        "sync": ds.get("sync", {}).get("value"),
                        "readonly": ds.get("readonly", {}).get("parsed", False),
                        "encrypted": ds.get("encrypted", False),
                        "key_loaded": ds.get("key_loaded", True),
                    }
                )

            return result

        except Exception as e:
            logger.error(f"Failed to get datasets: {e}")
            return []

    async def create_snapshot(self, dataset: str, name: str) -> bool:
        """
        Create a ZFS snapshot.

        Args:
            dataset: Dataset name
            name: Snapshot name

        Returns:
            True if successful
        """
        try:
            await self._api_post(
                "/zfs/snapshot", {"dataset": dataset, "name": name, "recursive": False}
            )

            logger.info(f"Created snapshot {dataset}@{name}")
            return True

        except Exception as e:
            logger.error(f"Failed to create snapshot: {e}")
            return False

    async def get_health(self) -> dict:
        """
        Get overall storage system health.

        Returns:
            Health status dictionary
        """
        try:
            # Get system info
            info = await self._api_get("/system/info")

            # Get alerts
            alerts = await self._api_get("/alert/list")
            critical_alerts = [a for a in alerts if a.get("level") == "CRITICAL"]
            warning_alerts = [a for a in alerts if a.get("level") == "WARNING"]

            # Get pool status
            pools = await self.get_pools()
            unhealthy_pools = [p for p in pools if not p.get("healthy", True)]

            # Get disk status
            disks = await self._api_get("/disk")
            failed_disks = [d for d in disks if d.get("status") == "FAILED"]

            healthy = (
                len(critical_alerts) == 0 and len(unhealthy_pools) == 0 and len(failed_disks) == 0
            )

            return {
                "healthy": healthy,
                "status": "HEALTHY" if healthy else "DEGRADED",
                "version": info.get("version"),
                "hostname": info.get("hostname"),
                "uptime_seconds": info.get("uptime_seconds", 0),
                "critical_alerts": len(critical_alerts),
                "warning_alerts": len(warning_alerts),
                "unhealthy_pools": len(unhealthy_pools),
                "failed_disks": len(failed_disks),
                "pool_count": len(pools),
                "disk_count": len(disks),
            }

        except Exception as e:
            logger.error(f"Failed to get health: {e}")
            return {"healthy": False, "status": "UNKNOWN", "error": str(e)}

    # =========================================================================
    # Extended TrueNAS Methods
    # =========================================================================

    async def get_snapshots(self, dataset: Optional[str] = None) -> list[dict]:
        """
        Get ZFS snapshots.

        Args:
            dataset: Optional dataset to filter by

        Returns:
            List of snapshots
        """
        try:
            endpoint = "/zfs/snapshot"
            if dataset:
                endpoint += f"?dataset={dataset}"

            snapshots = await self._api_get(endpoint)

            return [
                {
                    "id": snap.get("id"),
                    "name": snap.get("name"),
                    "dataset": snap.get("dataset"),
                    "pool": snap.get("pool"),
                    "type": snap.get("type"),
                    "properties": snap.get("properties", {}),
                    "holds": snap.get("holds", {}),
                    "created": snap.get("properties", {}).get("creation", {}).get("parsed"),
                }
                for snap in snapshots
            ]

        except Exception as e:
            logger.error(f"Failed to get snapshots: {e}")
            return []

    async def delete_snapshot(self, snapshot_id: str) -> bool:
        """
        Delete a ZFS snapshot.

        Args:
            snapshot_id: Snapshot ID

        Returns:
            True if successful
        """
        try:
            await self._api_delete(f"/zfs/snapshot/id/{snapshot_id}")
            logger.info(f"Deleted snapshot {snapshot_id}")
            return True

        except Exception as e:
            logger.error(f"Failed to delete snapshot: {e}")
            return False

    async def get_disks(self) -> list[dict]:
        """
        Get all disks.

        Returns:
            List of disks with status
        """
        try:
            disks = await self._api_get("/disk")

            return [
                {
                    "identifier": disk.get("identifier"),
                    "name": disk.get("name"),
                    "serial": disk.get("serial"),
                    "model": disk.get("model"),
                    "size": disk.get("size"),
                    "type": disk.get("type"),
                    "rotationrate": disk.get("rotationrate"),
                    "pool": disk.get("pool"),
                    "status": disk.get("status", "UNKNOWN"),
                    "temperature": disk.get("temperature"),
                    "smart_enabled": disk.get("togglesmart", False),
                }
                for disk in disks
            ]

        except Exception as e:
            logger.error(f"Failed to get disks: {e}")
            return []

    async def get_smart_data(self, disk_name: str) -> dict:
        """
        Get SMART data for a disk.

        Args:
            disk_name: Disk name (e.g., "sda")

        Returns:
            SMART data dictionary
        """
        try:
            data = await self._api_post(f"/disk/smart_attributes", {"name": disk_name})
            return data

        except Exception as e:
            logger.error(f"Failed to get SMART data: {e}")
            return {}

    async def get_alerts(self) -> list[dict]:
        """
        Get system alerts.

        Returns:
            List of alerts
        """
        try:
            alerts = await self._api_get("/alert/list")

            return [
                {
                    "id": alert.get("id"),
                    "uuid": alert.get("uuid"),
                    "level": alert.get("level"),
                    "formatted": alert.get("formatted"),
                    "text": alert.get("text"),
                    "klass": alert.get("klass"),
                    "dismissed": alert.get("dismissed", False),
                    "datetime": alert.get("datetime", {}).get("$date"),
                }
                for alert in alerts
            ]

        except Exception as e:
            logger.error(f"Failed to get alerts: {e}")
            return []

    async def dismiss_alert(self, alert_uuid: str) -> bool:
        """
        Dismiss an alert.

        Args:
            alert_uuid: Alert UUID

        Returns:
            True if successful
        """
        try:
            await self._api_post(f"/alert/dismiss", alert_uuid)
            logger.info(f"Dismissed alert {alert_uuid}")
            return True

        except Exception as e:
            logger.error(f"Failed to dismiss alert: {e}")
            return False

    async def get_replication_tasks(self) -> list[dict]:
        """
        Get replication task status.

        Returns:
            List of replication tasks
        """
        try:
            tasks = await self._api_get("/replication")

            return [
                {
                    "id": task.get("id"),
                    "name": task.get("name"),
                    "direction": task.get("direction"),
                    "source_datasets": task.get("source_datasets", []),
                    "target_dataset": task.get("target_dataset"),
                    "enabled": task.get("enabled", False),
                    "state": task.get("state", {}).get("state"),
                    "last_snapshot": task.get("state", {}).get("last_snapshot"),
                    "schedule": task.get("schedule"),
                }
                for task in tasks
            ]

        except Exception as e:
            logger.error(f"Failed to get replication tasks: {e}")
            return []

    async def get_scrub_tasks(self) -> list[dict]:
        """
        Get pool scrub task status.

        Returns:
            List of scrub tasks
        """
        try:
            tasks = await self._api_get("/pool/scrub")

            return [
                {
                    "id": task.get("id"),
                    "pool": task.get("pool"),
                    "pool_name": task.get("pool_name"),
                    "enabled": task.get("enabled", False),
                    "schedule": task.get("schedule"),
                }
                for task in tasks
            ]

        except Exception as e:
            logger.error(f"Failed to get scrub tasks: {e}")
            return []

    async def start_scrub(self, pool_name: str) -> bool:
        """
        Start a pool scrub.

        Args:
            pool_name: Pool name

        Returns:
            True if successful
        """
        try:
            await self._api_post(f"/pool/id/{pool_name}/scrub", {"action": "START"})
            logger.info(f"Started scrub on pool {pool_name}")
            return True

        except Exception as e:
            logger.error(f"Failed to start scrub: {e}")
            return False

    async def get_shares(self) -> dict:
        """
        Get all shares (SMB, NFS, iSCSI).

        Returns:
            Dictionary with share types and configurations
        """
        try:
            result = {"smb": [], "nfs": [], "iscsi": []}

            # SMB shares
            try:
                smb = await self._api_get("/sharing/smb")
                result["smb"] = [
                    {
                        "id": share.get("id"),
                        "name": share.get("name"),
                        "path": share.get("path"),
                        "enabled": share.get("enabled", True),
                        "comment": share.get("comment", ""),
                        "ro": share.get("ro", False),
                        "browsable": share.get("browsable", True),
                    }
                    for share in smb
                ]
            except Exception as e:
                logger.debug(f"Failed to get SMB shares: {e}")

            # NFS shares
            try:
                nfs = await self._api_get("/sharing/nfs")
                result["nfs"] = [
                    {
                        "id": share.get("id"),
                        "path": share.get("path"),
                        "enabled": share.get("enabled", True),
                        "hosts": share.get("hosts", []),
                        "networks": share.get("networks", []),
                        "maproot_user": share.get("maproot_user"),
                        "mapall_user": share.get("mapall_user"),
                        "comment": share.get("comment", ""),
                    }
                    for share in nfs
                ]
            except Exception as e:
                logger.debug(f"Failed to get NFS shares: {e}")

            # iSCSI targets
            try:
                iscsi = await self._api_get("/iscsi/target")
                result["iscsi"] = [
                    {
                        "id": target.get("id"),
                        "name": target.get("name"),
                        "alias": target.get("alias"),
                        "mode": target.get("mode"),
                    }
                    for target in iscsi
                ]
            except Exception as e:
                logger.debug(f"Failed to get iSCSI targets: {e}")

            return result

        except Exception as e:
            logger.error(f"Failed to get shares: {e}")
            return {"smb": [], "nfs": [], "iscsi": []}

    async def get_system_info(self) -> dict:
        """
        Get system information.

        Returns:
            System info dictionary
        """
        try:
            info = await self._api_get("/system/info")
            return {
                "version": info.get("version"),
                "hostname": info.get("hostname"),
                "timezone": info.get("timezone"),
                "uptime_seconds": info.get("uptime_seconds"),
                "uptime": info.get("uptime"),
                "model": info.get("system_product"),
                "serial": info.get("system_serial"),
                "cores": info.get("cores"),
                "physical_cores": info.get("physical_cores"),
                "memory": info.get("physmem"),
            }

        except Exception as e:
            logger.error(f"Failed to get system info: {e}")
            return {}
