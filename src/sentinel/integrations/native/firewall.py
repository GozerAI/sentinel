"""
Native Linux Firewall Integration using nftables.

This module allows Sentinel to manage firewall rules directly on the host,
eliminating the need for external router/firewall appliances like OPNsense.

Sentinel can either:
1. Run as a router/firewall appliance itself
2. Manage the local firewall on the host it runs on
3. Manage firewalls on remote Linux hosts via SSH

Requires:
- Linux with nftables (kernel 3.13+, recommended 4.10+)
- Root/sudo access for rule management
- Optional: SSH access for remote management
"""
import asyncio
import json
import logging
import subprocess
import shutil
from typing import Optional, Any
from datetime import datetime, timedelta
from pathlib import Path
from ipaddress import ip_address, ip_network

from sentinel.integrations.base import RouterIntegration
from sentinel.core.utils import utc_now

logger = logging.getLogger(__name__)


class FirewallRule:
    """
    Represents a firewall rule.

    Supports both nftables and iptables syntax internally,
    with a common abstraction layer.
    """

    def __init__(
        self,
        rule_id: str,
        action: str,  # accept, drop, reject
        direction: str = "input",  # input, output, forward
        protocol: str = "all",  # tcp, udp, icmp, all
        source: str = None,  # IP, CIDR, or None for any
        destination: str = None,
        source_port: int = None,
        dest_port: int = None,
        interface: str = None,
        comment: str = "",
        enabled: bool = True,
        created_by: str = "sentinel",
        expires_at: datetime = None
    ):
        self.rule_id = rule_id
        self.action = action.lower()
        self.direction = direction.lower()
        self.protocol = protocol.lower()
        self.source = source
        self.destination = destination
        self.source_port = source_port
        self.dest_port = dest_port
        self.interface = interface
        self.comment = comment
        self.enabled = enabled
        self.created_by = created_by
        self.created_at = utc_now()
        self.expires_at = expires_at

    def to_nftables(self) -> str:
        """Convert rule to nftables syntax."""
        parts = []

        # Protocol
        if self.protocol != "all":
            parts.append(f"{self.protocol}")

        # Source
        if self.source:
            parts.append(f"ip saddr {self.source}")

        # Destination
        if self.destination:
            parts.append(f"ip daddr {self.destination}")

        # Ports
        if self.dest_port:
            parts.append(f"dport {self.dest_port}")
        if self.source_port:
            parts.append(f"sport {self.source_port}")

        # Interface
        if self.interface:
            if self.direction == "input":
                parts.append(f"iifname \"{self.interface}\"")
            else:
                parts.append(f"oifname \"{self.interface}\"")

        # Action
        parts.append(self.action)

        # Comment
        if self.comment:
            parts.append(f"comment \"{self.comment}\"")

        return " ".join(parts)

    def to_iptables(self) -> list[str]:
        """Convert rule to iptables command arguments."""
        args = []

        # Chain
        chain_map = {"input": "INPUT", "output": "OUTPUT", "forward": "FORWARD"}
        args.extend(["-A", chain_map.get(self.direction, "INPUT")])

        # Protocol
        if self.protocol != "all":
            args.extend(["-p", self.protocol])

        # Source
        if self.source:
            args.extend(["-s", self.source])

        # Destination
        if self.destination:
            args.extend(["-d", self.destination])

        # Ports
        if self.dest_port:
            args.extend(["--dport", str(self.dest_port)])
        if self.source_port:
            args.extend(["--sport", str(self.source_port)])

        # Interface
        if self.interface:
            if self.direction == "input":
                args.extend(["-i", self.interface])
            else:
                args.extend(["-o", self.interface])

        # Action
        action_map = {"accept": "ACCEPT", "drop": "DROP", "reject": "REJECT"}
        args.extend(["-j", action_map.get(self.action, "DROP")])

        # Comment
        if self.comment:
            args.extend(["-m", "comment", "--comment", self.comment])

        return args

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "action": self.action,
            "direction": self.direction,
            "protocol": self.protocol,
            "source": self.source,
            "destination": self.destination,
            "source_port": self.source_port,
            "dest_port": self.dest_port,
            "interface": self.interface,
            "comment": self.comment,
            "enabled": self.enabled,
            "created_by": self.created_by,
            "created_at": self.created_at.isoformat(),
            "expires_at": self.expires_at.isoformat() if self.expires_at else None
        }

    @classmethod
    def from_dict(cls, data: dict) -> "FirewallRule":
        rule = cls(
            rule_id=data["rule_id"],
            action=data["action"],
            direction=data.get("direction", "input"),
            protocol=data.get("protocol", "all"),
            source=data.get("source"),
            destination=data.get("destination"),
            source_port=data.get("source_port"),
            dest_port=data.get("dest_port"),
            interface=data.get("interface"),
            comment=data.get("comment", ""),
            enabled=data.get("enabled", True),
            created_by=data.get("created_by", "sentinel")
        )
        if data.get("expires_at"):
            rule.expires_at = datetime.fromisoformat(data["expires_at"])
        return rule


class NativeFirewall(RouterIntegration):
    """
    Native Linux firewall integration using nftables or iptables.

    This allows Sentinel to manage firewall rules directly without
    requiring external appliances like OPNsense.

    Features:
    - Rule management (add, delete, list)
    - Automatic expiration of temporary blocks
    - Persistence across restarts
    - Support for both nftables and iptables
    - ARP table access
    - Basic routing capabilities

    Example:
        ```python
        firewall = NativeFirewall({
            "backend": "nftables",  # or "iptables"
            "table_name": "sentinel",
            "persistence_path": "/var/lib/sentinel/firewall.json"
        })

        await firewall.connect()

        # Block an IP
        rule_id = await firewall.add_firewall_rule({
            "action": "drop",
            "source": "10.0.0.100",
            "comment": "Blocked by Guardian agent"
        })

        # Temporary block (1 hour)
        await firewall.block_ip(
            "10.0.0.50",
            duration=3600,
            reason="Port scan detected"
        )
        ```
    """

    def __init__(self, config: dict):
        super().__init__(config)

        # Configuration
        self.backend = config.get("backend", "auto")  # auto, nftables, iptables
        self.table_name = config.get("table_name", "sentinel")
        self.persistence_path = Path(config.get(
            "persistence_path",
            "/var/lib/sentinel/firewall.json"
        ))
        self.sudo = config.get("sudo", True)
        self.dry_run = config.get("dry_run", False)  # For testing

        # State
        self._rules: dict[str, FirewallRule] = {}
        self._blocked_ips: dict[str, datetime] = {}  # IP -> expiry time
        self._rule_counter = 0
        self._backend_detected: Optional[str] = None

        # Expiry checker task
        self._expiry_task: Optional[asyncio.Task] = None

    async def connect(self) -> None:
        """Initialize the firewall backend."""
        # Detect backend
        if self.backend == "auto":
            self._backend_detected = await self._detect_backend()
        else:
            self._backend_detected = self.backend

        if not self._backend_detected:
            logger.warning("No firewall backend available - running in monitor-only mode")
            self._connected = True
            return

        logger.info(f"Using firewall backend: {self._backend_detected}")

        # Initialize nftables table if using nftables
        if self._backend_detected == "nftables":
            await self._init_nftables()

        # Load persisted rules
        await self._load_rules()

        # Start expiry checker
        self._expiry_task = asyncio.create_task(self._expiry_checker())

        self._connected = True
        logger.info("Native firewall connected")

    async def disconnect(self) -> None:
        """Disconnect and persist state."""
        if self._expiry_task:
            self._expiry_task.cancel()
            try:
                await self._expiry_task
            except asyncio.CancelledError:
                pass

        # Persist rules
        await self._persist_rules()

        self._connected = False
        logger.info("Native firewall disconnected")

    async def health_check(self) -> bool:
        """Check if firewall is operational."""
        if not self._backend_detected:
            return True  # Monitor-only mode is always "healthy"

        try:
            if self._backend_detected == "nftables":
                result = await self._run_command(["nft", "list", "tables"])
                return result is not None
            else:
                result = await self._run_command(["iptables", "-L", "-n"])
                return result is not None
        except Exception as e:
            logger.error(f"Health check failed: {e}")
            return False

    async def _detect_backend(self) -> Optional[str]:
        """Detect available firewall backend."""
        # Check for nftables
        if shutil.which("nft"):
            try:
                result = await self._run_command(["nft", "--version"], check=False)
                if result is not None:
                    logger.debug("nftables detected")
                    return "nftables"
            except Exception as e:
                logger.debug(f"nftables detection failed: {e}")

        # Check for iptables
        if shutil.which("iptables"):
            try:
                result = await self._run_command(["iptables", "--version"], check=False)
                if result is not None:
                    logger.debug("iptables detected")
                    return "iptables"
            except Exception as e:
                logger.debug(f"iptables detection failed: {e}")

        logger.warning("No firewall backend detected")
        return None

    async def _init_nftables(self) -> None:
        """Initialize nftables table and chains."""
        # Create table
        await self._run_command([
            "nft", "add", "table", "inet", self.table_name
        ], check=False)

        # Create chains
        for chain in ["input", "forward", "output"]:
            await self._run_command([
                "nft", "add", "chain", "inet", self.table_name, chain,
                f"{{ type filter hook {chain} priority 0; policy accept; }}"
            ], check=False)

        logger.debug(f"Initialized nftables table: {self.table_name}")

    async def _run_command(
        self,
        cmd: list[str],
        check: bool = True
    ) -> Optional[str]:
        """Run a command with optional sudo."""
        if self.dry_run:
            logger.debug(f"[DRY RUN] Would execute: {' '.join(cmd)}")
            return ""

        if self.sudo and cmd[0] not in ["sudo"]:
            cmd = ["sudo"] + cmd

        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await process.communicate()

            if check and process.returncode != 0:
                logger.error(f"Command failed: {stderr.decode()}")
                return None

            return stdout.decode()

        except Exception as e:
            logger.error(f"Failed to run command {cmd}: {e}")
            if check:
                return None
            raise

    # =========================================================================
    # RouterIntegration Implementation
    # =========================================================================

    async def get_arp_table(self) -> list[dict]:
        """Get ARP table from the system."""
        try:
            # Read /proc/net/arp
            arp_path = Path("/proc/net/arp")
            if not arp_path.exists():
                # Try ip neigh on systems without /proc/net/arp
                result = await self._run_command(["ip", "neigh", "show"], check=False)
                if result:
                    return self._parse_ip_neigh(result)
                return []

            content = arp_path.read_text()
            entries = []

            for line in content.strip().split("\n")[1:]:  # Skip header
                parts = line.split()
                if len(parts) >= 6:
                    entries.append({
                        "ip": parts[0],
                        "mac": parts[3],
                        "interface": parts[5],
                        "flags": parts[2]
                    })

            return entries

        except Exception as e:
            logger.error(f"Failed to get ARP table: {e}")
            return []

    def _parse_ip_neigh(self, output: str) -> list[dict]:
        """Parse 'ip neigh' output."""
        entries = []
        for line in output.strip().split("\n"):
            parts = line.split()
            if len(parts) >= 5 and "lladdr" in parts:
                mac_idx = parts.index("lladdr") + 1
                entries.append({
                    "ip": parts[0],
                    "mac": parts[mac_idx] if mac_idx < len(parts) else "unknown",
                    "interface": parts[2] if "dev" in parts else "unknown",
                    "state": parts[-1] if parts else "unknown"
                })
        return entries

    async def get_dhcp_leases(self) -> list[dict]:
        """Get DHCP leases (from dnsmasq if available)."""
        leases = []

        # Check common DHCP lease file locations
        lease_files = [
            Path("/var/lib/dhcp/dhcpd.leases"),
            Path("/var/lib/dnsmasq/dnsmasq.leases"),
            Path("/tmp/dhcp.leases"),
            Path("/var/lib/misc/dnsmasq.leases"),
        ]

        for lease_file in lease_files:
            if lease_file.exists():
                try:
                    content = lease_file.read_text()
                    leases.extend(self._parse_dhcp_leases(content, lease_file.name))
                except Exception as e:
                    logger.warning(f"Failed to parse {lease_file}: {e}")

        return leases

    def _parse_dhcp_leases(self, content: str, source: str) -> list[dict]:
        """Parse DHCP lease file content."""
        leases = []

        if "dnsmasq" in source:
            # dnsmasq format: timestamp mac ip hostname client-id
            for line in content.strip().split("\n"):
                parts = line.split()
                if len(parts) >= 4:
                    leases.append({
                        "expires": int(parts[0]),
                        "mac": parts[1],
                        "ip": parts[2],
                        "hostname": parts[3] if parts[3] != "*" else "",
                        "source": "dnsmasq"
                    })
        else:
            # ISC DHCP format (basic parsing)
            current_lease = {}
            for line in content.split("\n"):
                line = line.strip()
                if line.startswith("lease "):
                    current_lease = {"ip": line.split()[1]}
                elif line.startswith("hardware ethernet"):
                    current_lease["mac"] = line.split()[-1].rstrip(";")
                elif line.startswith("client-hostname"):
                    current_lease["hostname"] = line.split('"')[1]
                elif line == "}" and current_lease:
                    leases.append(current_lease)
                    current_lease = {}

        return leases

    async def add_firewall_rule(self, rule: dict) -> str:
        """
        Add a firewall rule.

        Args:
            rule: Dictionary with rule parameters:
                - action: accept, drop, reject
                - source: Source IP/CIDR (optional)
                - destination: Destination IP/CIDR (optional)
                - protocol: tcp, udp, icmp, all
                - dest_port: Destination port
                - direction: input, output, forward
                - comment: Rule description

        Returns:
            Rule ID
        """
        self._rule_counter += 1
        rule_id = f"sentinel_{self._rule_counter}"

        fw_rule = FirewallRule(
            rule_id=rule_id,
            action=rule.get("action", "drop"),
            direction=rule.get("direction", "input"),
            protocol=rule.get("protocol", "all"),
            source=rule.get("source"),
            destination=rule.get("destination"),
            source_port=rule.get("source_port"),
            dest_port=rule.get("dest_port"),
            interface=rule.get("interface"),
            comment=rule.get("comment", f"Sentinel rule {rule_id}"),
            expires_at=rule.get("expires_at")
        )

        # Apply to system
        success = await self._apply_rule(fw_rule)
        if success:
            self._rules[rule_id] = fw_rule
            await self._persist_rules()
            logger.info(f"Added firewall rule: {rule_id}")
        else:
            logger.error(f"Failed to add firewall rule: {rule_id}")

        return rule_id

    async def delete_firewall_rule(self, rule_id: str) -> bool:
        """Delete a firewall rule."""
        rule = self._rules.get(rule_id)
        if not rule:
            logger.warning(f"Rule not found: {rule_id}")
            return False

        success = await self._remove_rule(rule)
        if success:
            del self._rules[rule_id]
            await self._persist_rules()
            logger.info(f"Deleted firewall rule: {rule_id}")

        return success

    async def get_firewall_rules(self) -> list[dict]:
        """Get all firewall rules managed by Sentinel."""
        return [rule.to_dict() for rule in self._rules.values()]

    async def _apply_rule(self, rule: FirewallRule) -> bool:
        """Apply a rule to the firewall."""
        if not self._backend_detected:
            logger.debug("No backend - rule not applied")
            return True

        try:
            if self._backend_detected == "nftables":
                chain_map = {"input": "input", "output": "output", "forward": "forward"}
                chain = chain_map.get(rule.direction, "input")
                cmd = [
                    "nft", "add", "rule", "inet", self.table_name, chain,
                    rule.to_nftables()
                ]
                # nft needs the rule as a single argument after chain
                cmd = ["nft", "add", "rule", "inet", self.table_name, chain]
                cmd.extend(rule.to_nftables().split())

            else:  # iptables
                cmd = ["iptables"] + rule.to_iptables()

            result = await self._run_command(cmd, check=False)
            return result is not None

        except Exception as e:
            logger.error(f"Failed to apply rule: {e}")
            return False

    async def _remove_rule(self, rule: FirewallRule) -> bool:
        """Remove a rule from the firewall."""
        if not self._backend_detected:
            return True

        try:
            if self._backend_detected == "nftables":
                # nftables requires handle to delete, easier to flush and re-add
                # For now, we'll use a comment-based approach
                chain_map = {"input": "input", "output": "output", "forward": "forward"}
                chain = chain_map.get(rule.direction, "input")

                # List rules to find handle
                result = await self._run_command([
                    "nft", "-a", "list", "chain", "inet", self.table_name, chain
                ])
                if result:
                    # Find rule by comment and get handle
                    for line in result.split("\n"):
                        if rule.comment in line and "handle" in line:
                            handle = line.split("handle")[-1].strip()
                            await self._run_command([
                                "nft", "delete", "rule", "inet",
                                self.table_name, chain, "handle", handle
                            ])
                            return True

            else:  # iptables
                cmd = ["iptables", "-D"] + rule.to_iptables()[2:]  # Skip -A CHAIN
                await self._run_command(cmd, check=False)
                return True

        except Exception as e:
            logger.error(f"Failed to remove rule: {e}")

        return False

    # =========================================================================
    # Convenience Methods
    # =========================================================================

    async def block_ip(
        self,
        ip: str,
        duration: int = 3600,
        reason: str = ""
    ) -> str:
        """
        Block an IP address temporarily.

        Args:
            ip: IP address to block
            duration: Block duration in seconds (default: 1 hour)
            reason: Reason for blocking

        Returns:
            Rule ID
        """
        # Validate IP
        try:
            ip_address(ip)
        except ValueError:
            raise ValueError(f"Invalid IP address: {ip}")

        expires_at = utc_now() + timedelta(seconds=duration)

        rule_id = await self.add_firewall_rule({
            "action": "drop",
            "source": ip,
            "comment": f"Blocked: {reason}" if reason else f"Blocked by Sentinel",
            "expires_at": expires_at
        })

        self._blocked_ips[ip] = expires_at
        logger.info(f"Blocked IP {ip} for {duration}s: {reason}")

        return rule_id

    async def unblock_ip(self, ip: str) -> bool:
        """Unblock a previously blocked IP."""
        # Find rule(s) for this IP
        rules_to_delete = [
            rule_id for rule_id, rule in self._rules.items()
            if rule.source == ip
        ]

        success = True
        for rule_id in rules_to_delete:
            if not await self.delete_firewall_rule(rule_id):
                success = False

        if ip in self._blocked_ips:
            del self._blocked_ips[ip]

        return success

    async def is_blocked(self, ip: str) -> bool:
        """Check if an IP is currently blocked."""
        if ip in self._blocked_ips:
            if self._blocked_ips[ip] > utc_now():
                return True
            # Expired, clean up
            del self._blocked_ips[ip]

        # Also check rules
        for rule in self._rules.values():
            if rule.source == ip and rule.action == "drop":
                return True

        return False

    async def get_blocked_ips(self) -> list[dict]:
        """Get list of currently blocked IPs."""
        blocked = []
        now = utc_now()

        for ip, expires_at in self._blocked_ips.items():
            if expires_at > now:
                blocked.append({
                    "ip": ip,
                    "expires_at": expires_at.isoformat(),
                    "remaining_seconds": (expires_at - now).total_seconds()
                })

        return blocked

    # =========================================================================
    # Persistence
    # =========================================================================

    async def _persist_rules(self) -> None:
        """Persist rules to disk."""
        try:
            self.persistence_path.parent.mkdir(parents=True, exist_ok=True)

            data = {
                "rules": {rid: rule.to_dict() for rid, rule in self._rules.items()},
                "blocked_ips": {
                    ip: exp.isoformat()
                    for ip, exp in self._blocked_ips.items()
                },
                "rule_counter": self._rule_counter,
                "persisted_at": utc_now().isoformat()
            }

            with open(self.persistence_path, 'w') as f:
                json.dump(data, f, indent=2)

        except Exception as e:
            logger.error(f"Failed to persist firewall rules: {e}")

    async def _load_rules(self) -> None:
        """Load persisted rules."""
        try:
            if not self.persistence_path.exists():
                return

            with open(self.persistence_path, 'r') as f:
                data = json.load(f)

            self._rule_counter = data.get("rule_counter", 0)

            # Load rules
            for rule_id, rule_data in data.get("rules", {}).items():
                rule = FirewallRule.from_dict(rule_data)

                # Check if expired
                if rule.expires_at and rule.expires_at < utc_now():
                    continue

                # Re-apply rule
                if await self._apply_rule(rule):
                    self._rules[rule_id] = rule

            # Load blocked IPs
            for ip, expires_str in data.get("blocked_ips", {}).items():
                expires_at = datetime.fromisoformat(expires_str)
                if expires_at > utc_now():
                    self._blocked_ips[ip] = expires_at

            logger.info(f"Loaded {len(self._rules)} firewall rules")

        except Exception as e:
            logger.error(f"Failed to load firewall rules: {e}")

    async def _expiry_checker(self) -> None:
        """Background task to expire temporary rules."""
        while True:
            try:
                await asyncio.sleep(60)  # Check every minute

                now = utc_now()
                expired_rules = []

                for rule_id, rule in self._rules.items():
                    if rule.expires_at and rule.expires_at < now:
                        expired_rules.append(rule_id)

                for rule_id in expired_rules:
                    logger.info(f"Expiring rule: {rule_id}")
                    await self.delete_firewall_rule(rule_id)

                # Clean up blocked IPs
                expired_ips = [
                    ip for ip, exp in self._blocked_ips.items()
                    if exp < now
                ]
                for ip in expired_ips:
                    del self._blocked_ips[ip]

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Expiry checker error: {e}")

    @property
    def backend(self) -> Optional[str]:
        """Get the detected firewall backend."""
        return self._backend_detected
