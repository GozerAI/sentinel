"""
WAN Manager for Sentinel.

Provides comprehensive management of WAN/ISP connections:
- Multi-WAN failover with automatic switching
- Load balancing across connections
- Bandwidth monitoring and SLA tracking
- Speed testing and quality measurements
- Cost optimization recommendations
"""

import asyncio
import logging
import json
import subprocess
import statistics
from typing import Optional, Any, TYPE_CHECKING
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import UUID

from sentinel.integrations.base import BaseIntegration
from sentinel.integrations.wan.connection import (
    WANConnection,
    ConnectionType,
    ConnectionStatus,
    BandwidthMetrics,
    ConnectionQuality,
)
from sentinel.core.utils import utc_now

if TYPE_CHECKING:
    from sentinel.core.engine import SentinelEngine

logger = logging.getLogger(__name__)


class FailoverEvent:
    """Records a failover event."""

    def __init__(
        self, from_connection: Optional[WANConnection], to_connection: WANConnection, reason: str
    ):
        self.timestamp = utc_now()
        self.from_connection_id = from_connection.id if from_connection else None
        self.from_connection_name = from_connection.name if from_connection else None
        self.to_connection_id = to_connection.id
        self.to_connection_name = to_connection.name
        self.reason = reason

    def to_dict(self) -> dict:
        return {
            "timestamp": self.timestamp.isoformat(),
            "from_connection_id": str(self.from_connection_id) if self.from_connection_id else None,
            "from_connection_name": self.from_connection_name,
            "to_connection_id": str(self.to_connection_id),
            "to_connection_name": self.to_connection_name,
            "reason": self.reason,
        }


class WANManager(BaseIntegration):
    """
    Manages WAN connections and ISP relationships for Sentinel.

    Provides:
    - Multi-WAN failover with health-based switching
    - Load balancing across multiple connections
    - Continuous bandwidth and quality monitoring
    - Speed testing on schedule
    - SLA compliance tracking
    - Cost optimization insights
    - Integration with MikroTik/router for actual failover

    Example:
        ```python
        wan = WANManager({
            "monitor_interval": 30,
            "speedtest_interval": 3600,
            "failover_threshold_ms": 200,
            "failover_packet_loss_threshold": 5.0,
        })

        await wan.connect()

        # Add a connection
        primary = WANConnection(
            name="Primary Fiber",
            isp_name="Acme Fiber",
            connection_type=ConnectionType.FIBER,
            interface_name="ether1",
            gateway_ip="192.168.1.1",
            is_primary=True,
        )
        primary.bandwidth.contracted_download_mbps = 1000
        primary.bandwidth.contracted_upload_mbps = 1000
        primary.monthly_cost = 99.99

        await wan.add_connection(primary)

        # Check status
        status = await wan.get_status()
        ```
    """

    def __init__(self, config: dict):
        super().__init__(config)

        # Monitoring configuration with validation
        self.monitor_interval = config.get("monitor_interval", 30)  # seconds
        if not isinstance(self.monitor_interval, (int, float)) or self.monitor_interval < 5:
            raise ValueError(f"monitor_interval must be >= 5 seconds, got {self.monitor_interval}")

        self.speedtest_interval = config.get("speedtest_interval", 3600)  # 1 hour
        if not isinstance(self.speedtest_interval, (int, float)) or self.speedtest_interval < 60:
            raise ValueError(
                f"speedtest_interval must be >= 60 seconds, got {self.speedtest_interval}"
            )

        # Failover thresholds with validation
        self.failover_latency_threshold_ms = config.get("failover_threshold_ms", 200)
        if (
            not isinstance(self.failover_latency_threshold_ms, (int, float))
            or self.failover_latency_threshold_ms <= 0
        ):
            raise ValueError(
                f"failover_threshold_ms must be > 0, got {self.failover_latency_threshold_ms}"
            )

        self.failover_packet_loss_threshold = config.get("failover_packet_loss_threshold", 5.0)
        if (
            not isinstance(self.failover_packet_loss_threshold, (int, float))
            or not 0 <= self.failover_packet_loss_threshold <= 100
        ):
            raise ValueError(
                f"failover_packet_loss_threshold must be 0-100, got {self.failover_packet_loss_threshold}"
            )

        self.failover_consecutive_failures = config.get("failover_consecutive_failures", 3)
        if (
            not isinstance(self.failover_consecutive_failures, int)
            or self.failover_consecutive_failures < 1
        ):
            raise ValueError(
                f"failover_consecutive_failures must be >= 1, got {self.failover_consecutive_failures}"
            )

        # Test targets for connectivity checks with validation
        self.ping_targets = config.get(
            "ping_targets",
            ["8.8.8.8", "1.1.1.1", "208.67.222.222"],  # Google DNS  # Cloudflare DNS  # OpenDNS
        )
        if not self.ping_targets:
            raise ValueError("At least one ping_target is required for connectivity monitoring")
        # Validate IP addresses
        self._validate_ping_targets()

        self.dns_test_domain = config.get("dns_test_domain", "google.com")
        if not self.dns_test_domain or not isinstance(self.dns_test_domain, str):
            raise ValueError("dns_test_domain must be a valid domain name")

        # Persistence
        self.persistence_path = Path(config.get("persistence_path", "/var/lib/sentinel/wan.json"))

        # Connections registry
        self._connections: dict[UUID, WANConnection] = {}
        self._active_connection_id: Optional[UUID] = None
        self._failure_counts: dict[UUID, int] = {}

        # Failover history
        self._failover_events: list[FailoverEvent] = []
        self._max_failover_history = 100

        # Speed test results history
        self._speedtest_history: list[dict] = []
        self._max_speedtest_history = 720  # 30 days at 1 test/hour

        # Background tasks
        self._monitor_task: Optional[asyncio.Task] = None
        self._speedtest_task: Optional[asyncio.Task] = None

        # Router integration (will be set by engine)
        self._router_integration = None

        # Error tracking for backoff
        self._consecutive_monitor_errors = 0
        self._max_backoff_seconds = 300  # Max 5 minutes backoff

    def _validate_ping_targets(self) -> None:
        """Validate that ping targets are valid IP addresses."""
        import ipaddress

        for target in self.ping_targets:
            try:
                ipaddress.ip_address(target)
            except ValueError:
                raise ValueError(f"Invalid ping target IP address: {target}")

    async def connect(self) -> None:
        """Initialize the WAN manager."""
        await self._load_state()

        # Verify connectivity of all connections
        for conn in self._connections.values():
            status = await self._check_connection(conn)
            conn.set_status(status)

        # Determine active connection
        await self._select_best_connection()

        # Start background tasks
        self._monitor_task = asyncio.create_task(self._monitor_loop())
        self._speedtest_task = asyncio.create_task(self._speedtest_loop())

        self._connected = True
        logger.info(f"WAN manager started with {len(self._connections)} connections")

    async def disconnect(self) -> None:
        """Shutdown the WAN manager."""
        if self._monitor_task:
            self._monitor_task.cancel()
            try:
                await self._monitor_task
            except asyncio.CancelledError:
                pass

        if self._speedtest_task:
            self._speedtest_task.cancel()
            try:
                await self._speedtest_task
            except asyncio.CancelledError:
                pass

        await self._save_state()
        self._connected = False
        logger.info("WAN manager stopped")

    async def health_check(self) -> bool:
        """Check if at least one connection is up."""
        return any(c.is_up for c in self._connections.values())

    def set_router_integration(self, router) -> None:
        """Set the router integration for failover actions."""
        self._router_integration = router

    # =========================================================================
    # Connection Management
    # =========================================================================

    async def add_connection(self, connection: WANConnection) -> None:
        """Add a WAN connection."""
        self._connections[connection.id] = connection
        self._failure_counts[connection.id] = 0

        # Check initial status
        status = await self._check_connection(connection)
        connection.set_status(status)

        # If this is primary and up, make it active
        if connection.is_primary and connection.is_up:
            await self._activate_connection(connection)

        await self._save_state()
        logger.info(f"Added WAN connection: {connection.name} ({connection.isp_name})")

    async def remove_connection(self, connection_id: UUID) -> bool:
        """Remove a WAN connection."""
        if connection_id not in self._connections:
            return False

        conn = self._connections[connection_id]

        # If this is active, failover first
        if self._active_connection_id == connection_id:
            await self._failover(reason="Connection removed")

        del self._connections[connection_id]
        if connection_id in self._failure_counts:
            del self._failure_counts[connection_id]

        await self._save_state()
        logger.info(f"Removed WAN connection: {conn.name}")
        return True

    def get_connection(self, identifier: str) -> Optional[WANConnection]:
        """Get connection by UUID, name, or interface."""
        # Try as UUID
        try:
            uuid = UUID(identifier)
            return self._connections.get(uuid)
        except ValueError:
            pass

        # Try by name or interface
        for conn in self._connections.values():
            if conn.name == identifier or conn.interface_name == identifier:
                return conn

        return None

    def get_connections(self) -> list[WANConnection]:
        """Get all connections sorted by priority."""
        return sorted(self._connections.values(), key=lambda c: c.priority)

    def get_active_connection(self) -> Optional[WANConnection]:
        """Get the currently active connection."""
        if self._active_connection_id:
            return self._connections.get(self._active_connection_id)
        return None

    def get_primary_connection(self) -> Optional[WANConnection]:
        """Get the designated primary connection."""
        for conn in self._connections.values():
            if conn.is_primary:
                return conn
        return None

    # =========================================================================
    # Connectivity Testing
    # =========================================================================

    async def _check_connection(self, connection: WANConnection) -> ConnectionStatus:
        """
        Check the status of a connection via ping tests.

        Returns the determined connection status.
        """
        if not connection.gateway_ip:
            return ConnectionStatus.UNKNOWN

        latencies = []
        losses = 0
        total_pings = len(self.ping_targets) * 3  # 3 pings per target

        for target in self.ping_targets:
            for _ in range(3):
                latency = await self._ping(target, connection)
                if latency is None:
                    losses += 1
                else:
                    latencies.append(latency)

        # Calculate metrics
        if latencies:
            connection.quality.latency_ms = statistics.mean(latencies)
            if len(latencies) > 1:
                connection.quality.jitter_ms = statistics.stdev(latencies)

        connection.quality.packet_loss_percent = (losses / total_pings) * 100
        connection.quality.calculate_quality_score()

        # Determine status
        if losses == total_pings:
            return ConnectionStatus.DOWN
        elif (
            connection.quality.latency_ms > self.failover_latency_threshold_ms
            or connection.quality.packet_loss_percent > self.failover_packet_loss_threshold
        ):
            return ConnectionStatus.DEGRADED
        else:
            return ConnectionStatus.UP

    async def _ping(
        self, target: str, connection: WANConnection, timeout: int = 2
    ) -> Optional[float]:
        """
        Ping a target through a specific connection.

        In a real implementation, this would use source routing or
        interface binding to ensure the ping goes through the right connection.

        Returns latency in ms or None if failed.
        """
        try:
            # Use ping command with timeout
            # On Linux with multiple interfaces, we'd use -I to specify interface
            proc = await asyncio.create_subprocess_exec(
                "ping",
                "-c",
                "1",
                "-W",
                str(timeout),
                target,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout + 1)

            if proc.returncode == 0:
                # Parse latency from ping output
                output = stdout.decode()
                if "time=" in output:
                    # Extract time=XX.X ms
                    time_part = output.split("time=")[1].split()[0]
                    return float(time_part.replace("ms", ""))

        except asyncio.TimeoutError:
            logger.debug(f"Ping timeout to {target}")
        except Exception as e:
            logger.debug(f"Ping test failed: {e}")

        return None

    async def _test_dns(self, connection: WANConnection) -> Optional[float]:
        """
        Test DNS resolution through a connection.

        Returns resolution time in ms or None if failed.
        """
        import socket

        start = datetime.now(timezone.utc)

        try:
            # In production, this would use the connection's DNS servers
            loop = asyncio.get_event_loop()
            await loop.getaddrinfo(self.dns_test_domain, 80, family=socket.AF_INET)
            duration = (datetime.now(timezone.utc) - start).total_seconds() * 1000
            return duration

        except Exception as e:
            logger.debug(f"DNS test failed for {self.dns_test_domain}: {e}")
            return None

    # =========================================================================
    # Speed Testing
    # =========================================================================

    async def run_speedtest(self, connection: Optional[WANConnection] = None) -> dict:
        """
        Run a speed test on a connection.

        Uses speedtest-cli or similar tool. Falls back to download test
        if speedtest-cli is not available.

        Args:
            connection: Connection to test, or active connection if None

        Returns:
            Dict with download/upload speeds in Mbps
        """
        target = connection or self.get_active_connection()
        if not target:
            return {"error": "No connection available"}

        results = {
            "connection_id": str(target.id),
            "connection_name": target.name,
            "timestamp": utc_now().isoformat(),
            "download_mbps": 0.0,
            "upload_mbps": 0.0,
            "latency_ms": 0.0,
            "server": None,
        }

        try:
            # Try speedtest-cli first
            proc = await asyncio.create_subprocess_exec(
                "speedtest-cli",
                "--json",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(
                proc.communicate(), timeout=120  # Speed tests can take a while
            )

            if proc.returncode == 0:
                data = json.loads(stdout.decode())
                results["download_mbps"] = data.get("download", 0) / 1_000_000
                results["upload_mbps"] = data.get("upload", 0) / 1_000_000
                results["latency_ms"] = data.get("ping", 0)
                results["server"] = data.get("server", {}).get("sponsor")

        except FileNotFoundError:
            logger.warning("speedtest-cli not found, using fallback method")
            # Fallback: test download from a known fast server
            results = await self._fallback_speedtest(target)

        except Exception as e:
            logger.error(f"Speed test failed: {e}")
            results["error"] = str(e)

        # Update connection metrics
        if "error" not in results:
            target.bandwidth.last_speedtest_download = results["download_mbps"]
            target.bandwidth.last_speedtest_upload = results["upload_mbps"]
            target.bandwidth.last_speedtest_time = utc_now()

            # Store in history
            self._speedtest_history.append(results)
            if len(self._speedtest_history) > self._max_speedtest_history:
                self._speedtest_history = self._speedtest_history[-self._max_speedtest_history :]

        await self._save_state()
        return results

    async def _fallback_speedtest(self, connection: WANConnection) -> dict:
        """Fallback speed test using HTTP download."""
        results = {
            "connection_id": str(connection.id),
            "connection_name": connection.name,
            "timestamp": utc_now().isoformat(),
            "download_mbps": 0.0,
            "upload_mbps": 0.0,
            "latency_ms": connection.quality.latency_ms,
            "method": "fallback",
        }

        # Test URLs (100MB files from various CDNs)
        test_urls = [
            "http://speedtest.tele2.net/10MB.zip",
            "http://proof.ovh.net/files/10Mb.dat",
        ]

        for url in test_urls:
            try:
                import urllib.request

                start = datetime.now(timezone.utc)

                # Download with timeout
                response = urllib.request.urlopen(url, timeout=30)
                data = response.read()

                duration = (datetime.now(timezone.utc) - start).total_seconds()
                size_mb = len(data) / 1_000_000
                speed_mbps = (size_mb * 8) / duration

                results["download_mbps"] = speed_mbps
                break

            except Exception as e:
                logger.debug(f"Fallback speedtest failed for {url}: {e}")
                continue

        return results

    # =========================================================================
    # Failover Logic
    # =========================================================================

    async def _select_best_connection(self) -> Optional[WANConnection]:
        """Select the best available connection based on priority and health."""
        candidates = [c for c in self._connections.values() if c.is_up and c.failover_enabled]

        if not candidates:
            logger.warning("No healthy WAN connections available!")
            return None

        # Sort by priority (lower is better) then quality score (higher is better)
        candidates.sort(key=lambda c: (c.priority, -c.quality.quality_score))

        best = candidates[0]

        # If different from current, switch
        if self._active_connection_id != best.id:
            await self._activate_connection(best)

        return best

    async def _activate_connection(self, connection: WANConnection) -> None:
        """Activate a connection as the primary route."""
        old_active = self.get_active_connection()

        # Update statuses
        if old_active:
            old_active.set_status(ConnectionStatus.STANDBY)

        connection.set_status(ConnectionStatus.UP)
        self._active_connection_id = connection.id

        # Apply to router if available
        if self._router_integration:
            try:
                await self._apply_failover_to_router(connection)
            except Exception as e:
                logger.error(f"Failed to apply failover to router: {e}")

        logger.info(f"Activated WAN connection: {connection.name}")

    async def _apply_failover_to_router(self, connection: WANConnection) -> None:
        """
        Apply failover configuration to the router.

        This would update the default route or policy routing to use
        the new active connection.
        """
        if not self._router_integration:
            return

        # For MikroTik, we'd update the default route
        # This is a simplified example
        try:
            # Get current routes
            routes = await self._router_integration.execute(
                "/ip/route/print", params={"?dst-address": "0.0.0.0/0"}
            )

            # Find and update the default route
            for route in routes:
                if route.get("gateway") == connection.gateway_ip:
                    # Enable this route
                    await self._router_integration.execute(
                        f"/ip/route/enable", params={".id": route[".id"]}
                    )
                else:
                    # Disable other default routes
                    await self._router_integration.execute(
                        f"/ip/route/disable", params={".id": route[".id"]}
                    )

        except Exception as e:
            logger.error(f"Router failover configuration failed: {e}")

    async def _failover(self, reason: str) -> Optional[WANConnection]:
        """
        Perform failover to next available connection.

        Args:
            reason: Reason for failover (for logging)

        Returns:
            New active connection or None if no alternatives
        """
        current = self.get_active_connection()

        # Find next best connection
        candidates = [
            c
            for c in self._connections.values()
            if c.is_up and c.failover_enabled and c.id != self._active_connection_id
        ]

        if not candidates:
            logger.error(f"Failover needed ({reason}) but no alternatives available!")
            return None

        candidates.sort(key=lambda c: (c.priority, -c.quality.quality_score))
        new_active = candidates[0]

        # Record failover event
        event = FailoverEvent(current, new_active, reason)
        self._failover_events.append(event)
        if len(self._failover_events) > self._max_failover_history:
            self._failover_events = self._failover_events[-self._max_failover_history :]

        # Activate new connection
        await self._activate_connection(new_active)

        logger.warning(
            f"Failover: {current.name if current else 'None'} -> "
            f"{new_active.name} (reason: {reason})"
        )

        return new_active

    async def force_failover(self, target_id: Optional[UUID] = None) -> Optional[WANConnection]:
        """
        Force failover to a specific connection or next available.

        Args:
            target_id: Specific connection to failover to, or None for auto-select

        Returns:
            New active connection
        """
        if target_id:
            target = self._connections.get(target_id)
            if target and target.is_up:
                event = FailoverEvent(self.get_active_connection(), target, "Manual failover")
                self._failover_events.append(event)
                await self._activate_connection(target)
                return target
            else:
                logger.error(f"Cannot failover to {target_id}: connection not available")
                return None
        else:
            return await self._failover("Manual failover")

    # =========================================================================
    # Monitoring
    # =========================================================================

    async def _monitor_loop(self) -> None:
        """Background monitoring loop with exponential backoff on errors."""
        while True:
            try:
                # Add jitter to prevent thundering herd
                import random

                jitter = random.uniform(0, self.monitor_interval * 0.1)
                await asyncio.sleep(self.monitor_interval + jitter)

                for conn in self._connections.values():
                    old_status = conn.status
                    new_status = await self._check_connection(conn)
                    conn.set_status(new_status)

                    # Track consecutive failures for active connection
                    if conn.id == self._active_connection_id:
                        if new_status in [ConnectionStatus.DOWN, ConnectionStatus.DEGRADED]:
                            self._failure_counts[conn.id] = self._failure_counts.get(conn.id, 0) + 1

                            if self._failure_counts[conn.id] >= self.failover_consecutive_failures:
                                reason = (
                                    f"Connection degraded: "
                                    f"latency={conn.quality.latency_ms:.1f}ms, "
                                    f"loss={conn.quality.packet_loss_percent:.1f}%"
                                )
                                await self._failover(reason)
                        else:
                            self._failure_counts[conn.id] = 0

                    # Check if we should failback to primary
                    if conn.is_primary and conn.is_up:
                        active = self.get_active_connection()
                        if active and not active.is_primary:
                            # Primary is back, consider failback
                            if conn.quality.quality_score > active.quality.quality_score:
                                await self._failover("Primary connection restored")

                    # Update outage tracking
                    if old_status == ConnectionStatus.UP and new_status == ConnectionStatus.DOWN:
                        conn.quality.last_outage_start = utc_now()
                        conn.quality.outages_30d += 1
                    elif old_status == ConnectionStatus.DOWN and new_status == ConnectionStatus.UP:
                        if conn.quality.last_outage_start:
                            duration = (utc_now() - conn.quality.last_outage_start).total_seconds()
                            conn.quality.last_outage_duration_seconds = int(duration)

                # Reset error count on successful iteration
                self._consecutive_monitor_errors = 0

            except asyncio.CancelledError:
                break
            except ConnectionError as e:
                self._consecutive_monitor_errors += 1
                backoff = min(
                    self._max_backoff_seconds,
                    self.monitor_interval * (2**self._consecutive_monitor_errors),
                )
                logger.warning(
                    f"Monitor connection error (attempt {self._consecutive_monitor_errors}): {e}. Backing off {backoff:.0f}s"
                )
                await asyncio.sleep(backoff)
            except OSError as e:
                self._consecutive_monitor_errors += 1
                backoff = min(
                    self._max_backoff_seconds,
                    self.monitor_interval * (2**self._consecutive_monitor_errors),
                )
                logger.warning(
                    f"Monitor OS error (attempt {self._consecutive_monitor_errors}): {e}. Backing off {backoff:.0f}s"
                )
                await asyncio.sleep(backoff)
            except Exception as e:
                self._consecutive_monitor_errors += 1
                backoff = min(
                    self._max_backoff_seconds,
                    self.monitor_interval * (2**self._consecutive_monitor_errors),
                )
                logger.error(
                    f"Monitor loop error (attempt {self._consecutive_monitor_errors}): {e}. Backing off {backoff:.0f}s"
                )

    async def _speedtest_loop(self) -> None:
        """Background speed testing loop."""
        # Initial delay to not run immediately at startup
        await asyncio.sleep(60)

        while True:
            try:
                # Run speed test on active connection
                active = self.get_active_connection()
                if active:
                    await self.run_speedtest(active)

                await asyncio.sleep(self.speedtest_interval)

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Speedtest loop error: {e}")

    # =========================================================================
    # Status and Reporting
    # =========================================================================

    async def get_status(self) -> dict:
        """Get comprehensive WAN status report."""
        active = self.get_active_connection()
        connections = self.get_connections()

        return {
            "active_connection": {
                "id": str(active.id) if active else None,
                "name": active.name if active else None,
                "status": active.status.value if active else None,
                "quality_score": active.quality.quality_score if active else None,
            },
            "connections": [
                {
                    "id": str(c.id),
                    "name": c.name,
                    "isp": c.isp_name,
                    "type": c.connection_type.value,
                    "status": c.status.value,
                    "is_primary": c.is_primary,
                    "is_active": c.id == self._active_connection_id,
                    "quality_score": c.quality.quality_score,
                    "latency_ms": c.quality.latency_ms,
                    "packet_loss": c.quality.packet_loss_percent,
                    "download_mbps": c.bandwidth.contracted_download_mbps,
                    "upload_mbps": c.bandwidth.contracted_upload_mbps,
                }
                for c in connections
            ],
            "summary": {
                "total_connections": len(connections),
                "healthy_connections": len([c for c in connections if c.is_healthy]),
                "total_bandwidth_mbps": sum(
                    c.bandwidth.contracted_download_mbps for c in connections if c.is_up
                ),
                "monthly_cost": sum(c.monthly_cost for c in connections),
                "failover_events_30d": len(
                    [
                        e
                        for e in self._failover_events
                        if e.timestamp > utc_now() - timedelta(days=30)
                    ]
                ),
            },
        }

    def get_failover_history(self, days: int = 30) -> list[dict]:
        """Get recent failover events."""
        cutoff = utc_now() - timedelta(days=days)
        return [e.to_dict() for e in self._failover_events if e.timestamp > cutoff]

    def get_sla_report(self) -> dict:
        """Generate SLA compliance report for all connections."""
        report = {}

        for conn in self._connections.values():
            report[conn.name] = {
                "isp": conn.isp_name,
                "contracted_download": conn.bandwidth.contracted_download_mbps,
                "actual_download": conn.bandwidth.last_speedtest_download,
                "sla_compliance_percent": conn.sla_compliance,
                "uptime_30d": conn.quality.uptime_percent_30d,
                "outages_30d": conn.quality.outages_30d,
                "quality_score": conn.quality.quality_score,
                "monthly_cost": conn.monthly_cost,
                "cost_per_mbps": conn.cost_effectiveness,
            }

        return report

    def get_cost_report(self) -> dict:
        """Generate cost analysis report."""
        connections = list(self._connections.values())

        total_cost = sum(c.monthly_cost for c in connections)
        total_download = sum(c.bandwidth.contracted_download_mbps for c in connections)
        total_upload = sum(c.bandwidth.contracted_upload_mbps for c in connections)

        return {
            "total_monthly_cost": total_cost,
            "total_contracted_download_mbps": total_download,
            "total_contracted_upload_mbps": total_upload,
            "average_cost_per_mbps": total_cost / total_download if total_download > 0 else 0,
            "connections": sorted(
                [
                    {
                        "name": c.name,
                        "isp": c.isp_name,
                        "monthly_cost": c.monthly_cost,
                        "download_mbps": c.bandwidth.contracted_download_mbps,
                        "upload_mbps": c.bandwidth.contracted_upload_mbps,
                        "cost_per_mbps": c.cost_effectiveness,
                        "sla_compliance": c.sla_compliance,
                    }
                    for c in connections
                ],
                key=lambda x: x["cost_per_mbps"],
            ),
        }

    # =========================================================================
    # Persistence
    # =========================================================================

    async def _save_state(self) -> None:
        """Save state to disk."""
        try:
            self.persistence_path.parent.mkdir(parents=True, exist_ok=True)

            data = {
                "connections": [c.to_dict() for c in self._connections.values()],
                "active_connection_id": (
                    str(self._active_connection_id) if self._active_connection_id else None
                ),
                "failover_events": [
                    e.to_dict() for e in self._failover_events[-self._max_failover_history :]
                ],
                "speedtest_history": self._speedtest_history[-self._max_speedtest_history :],
                "saved_at": utc_now().isoformat(),
            }

            with open(self.persistence_path, "w") as f:
                json.dump(data, f, indent=2)

        except Exception as e:
            logger.error(f"Failed to save WAN state: {e}")

    async def _load_state(self) -> None:
        """Load state from disk."""
        try:
            if not self.persistence_path.exists():
                return

            with open(self.persistence_path, "r") as f:
                data = json.load(f)

            # Load connections
            for conn_data in data.get("connections", []):
                conn = WANConnection.from_dict(conn_data)
                self._connections[conn.id] = conn
                self._failure_counts[conn.id] = 0

            # Load active connection
            if data.get("active_connection_id"):
                self._active_connection_id = UUID(data["active_connection_id"])

            # Load speedtest history
            self._speedtest_history = data.get("speedtest_history", [])

            logger.info(f"Loaded WAN state: {len(self._connections)} connections")

        except Exception as e:
            logger.error(f"Failed to load WAN state: {e}")

    @property
    def stats(self) -> dict:
        """Get quick stats summary."""
        connections = list(self._connections.values())
        active = self.get_active_connection()

        return {
            "total_connections": len(connections),
            "active_connection": active.name if active else None,
            "healthy_connections": len([c for c in connections if c.is_healthy]),
            "total_bandwidth_mbps": sum(
                c.bandwidth.contracted_download_mbps for c in connections if c.is_up
            ),
            "overall_quality": (
                statistics.mean([c.quality.quality_score for c in connections])
                if connections
                else 0
            ),
        }
