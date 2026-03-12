"""
Discovery Agent - Network scanning and topology management.

This agent is responsible for:
- Continuous network scanning and device discovery
- Device fingerprinting and classification using IoT classifier
- Hardware auto-detection (MikroTik, RPi5, NAS, etc.)
- Topology mapping and visualization
- New device detection and alerting
- Automatic device segmentation via IoT segmenter
- Integration discovery (finding manageable infrastructure)
"""

import asyncio
import logging
from datetime import datetime, timedelta
from typing import Optional, TYPE_CHECKING
from uuid import UUID

from sentinel.core.utils import utc_now
from sentinel.agents.base import BaseAgent
from sentinel.core.models.device import (
    Device,
    DeviceType,
    DeviceStatus,
    TrustLevel,
    NetworkInterface,
    DeviceFingerprint,
    DeviceInventory,
)
from sentinel.core.models.network import NetworkTopology, TopologyNode, NetworkLink
from sentinel.core.models.event import (
    Event,
    EventCategory,
    EventSeverity,
    AgentAction,
    AgentDecision,
)

# IoT classification integration
try:
    from sentinel.iot.classifier import IoTClassifier, DeviceClass, SecurityRisk
    from sentinel.iot.segmenter import IoTSegmenter

    IOT_CLASSIFIER_AVAILABLE = True
except ImportError:
    IOT_CLASSIFIER_AVAILABLE = False

if TYPE_CHECKING:
    from sentinel.integrations.compute.cluster import ComputeClusterManager

logger = logging.getLogger(__name__)


# Device fingerprint database - MAC OUI to vendor mapping
VENDOR_MAC_PREFIXES = {
    "00:1A:2B": "Apple",
    "00:50:56": "VMware",
    "00:0C:29": "VMware",
    "B8:27:EB": "Raspberry Pi",
    "DC:A6:32": "Raspberry Pi",
    "E4:5F:01": "Raspberry Pi",
    "28:CD:C1": "Raspberry Pi",
    "00:1E:06": "WIBRAIN",
    "00:17:88": "Philips Hue",
    "AC:CF:23": "Hi-Flying",
    "5C:CF:7F": "Espressif",
    "24:0A:C4": "Espressif",
    "A0:20:A6": "Espressif",
    "30:AE:A4": "Espressif",
    "60:01:94": "Espressif",
    "68:C6:3A": "Espressif",
    "84:0D:8E": "Espressif",
    "84:F3:EB": "Espressif",
    "EC:FA:BC": "Espressif",
    "00:23:24": "Cisco",
    "00:1B:54": "Cisco",
    "00:24:14": "Cisco",
    "00:1E:4F": "Dell",
    "00:14:22": "Dell",
    "00:1D:09": "Dell",
    "00:21:9B": "Dell",
    "00:1C:23": "Dell",
    "00:24:E8": "Dell",
    "18:03:73": "Dell",
    "A4:BA:DB": "Dell",
    "00:1F:16": "HP",
    "00:21:5A": "HP",
    "00:25:B3": "HP",
    "3C:D9:2B": "HP",
    "94:57:A5": "HP",
    "B4:99:BA": "HP",
    "FC:15:B4": "HP",
    "00:0D:3A": "Microsoft",
    "00:12:5A": "Microsoft",
    "00:15:5D": "Microsoft",
    "00:17:FA": "Microsoft",
    "00:1D:D8": "Microsoft",
    "00:50:F2": "Microsoft",
    "28:18:78": "Microsoft",
    "7C:1E:52": "Microsoft",
}

# Service signatures for device classification
SERVICE_SIGNATURES = {
    "iot": {
        "ports": [80, 443, 8080, 8443, 1883, 8883, 5683],
        "services": ["upnp", "mdns", "mqtt", "coap"],
        "vendors": ["espressif", "philips", "ring", "nest", "wyze", "tuya"],
    },
    "server": {
        "ports": [22, 80, 443, 3306, 5432, 6379, 8080, 9090, 27017],
        "services": ["ssh", "http", "https", "mysql", "postgresql", "redis"],
    },
    "workstation": {"ports": [22, 3389, 5900, 5901], "services": ["ssh", "rdp", "vnc"]},
    "printer": {"ports": [9100, 515, 631], "services": ["jetdirect", "lpd", "ipp"]},
    "camera": {"ports": [554, 8554, 80, 443], "services": ["rtsp"]},
    "storage": {"ports": [111, 2049, 445, 139, 3260], "services": ["nfs", "smb", "cifs", "iscsi"]},
}

# VLAN recommendations by device type
VLAN_RECOMMENDATIONS = {
    DeviceType.WORKSTATION: 10,
    DeviceType.SERVER: 20,
    DeviceType.STORAGE: 30,
    DeviceType.IOT: 100,
    DeviceType.CAMERA: 100,
    DeviceType.PRINTER: 50,
    DeviceType.MOBILE: 50,
    DeviceType.NETWORK: 1,
    DeviceType.UNKNOWN: 200,
}

# Hardware detection signatures for infrastructure devices
INFRASTRUCTURE_SIGNATURES = {
    "mikrotik": {
        "oui_prefixes": [
            "00:0C:42",
            "08:55:31",
            "2C:C8:1B",
            "4C:5E:0C",
            "64:D1:54",
            "6C:3B:6B",
            "74:4D:28",
            "B8:69:F4",
            "C4:AD:34",
            "CC:2D:E0",
            "D4:01:C3",
            "DC:2C:6E",
            "E4:8D:8C",
        ],
        "ports": [80, 443, 8291, 8728, 8729],  # Winbox and API ports
        "hostname_patterns": ["mikrotik", "crs", "ccr", "rb", "hex", "hap"],
        "integration_type": "mikrotik",
    },
    "ubiquiti_unifi": {
        "oui_prefixes": [
            "00:27:22",
            "04:18:D6",
            "18:E8:29",
            "24:5A:4C",
            "44:D9:E7",
            "68:72:51",
            "74:83:C2",
            "78:45:58",
            "80:2A:A8",
            "B4:FB:E4",
            "DC:9F:DB",
            "F0:9F:C2",
            "FC:EC:DA",
        ],
        "ports": [22, 443, 8080, 8443, 8843, 8880],
        "hostname_patterns": ["unifi", "ubnt", "uap", "usw", "usg", "udm"],
        "integration_type": "unifi",
    },
    "synology_nas": {
        "oui_prefixes": ["00:11:32"],
        "ports": [5000, 5001, 22, 80, 443],  # DSM ports
        "hostname_patterns": ["synology", "ds", "rs", "diskstation"],
        "integration_type": "synology",
    },
    "qnap_nas": {
        "oui_prefixes": ["00:08:9B", "24:5E:BE"],
        "ports": [8080, 443, 22, 80],
        "hostname_patterns": ["qnap", "ts-", "tvs-"],
        "integration_type": "qnap",
    },
    "raspberry_pi": {
        "oui_prefixes": ["B8:27:EB", "DC:A6:32", "E4:5F:01", "D8:3A:DD", "2C:CF:67"],
        "ports": [22],
        "hostname_patterns": ["raspberrypi", "rpi", "pi-"],
        "integration_type": "compute_node",
    },
    "proxmox": {
        "ports": [8006, 22],  # Proxmox web UI
        "hostname_patterns": ["proxmox", "pve", "pm-"],
        "integration_type": "proxmox",
    },
    "esxi_vcenter": {
        "ports": [443, 902, 903],
        "hostname_patterns": ["esxi", "vcenter", "vmware"],
        "integration_type": "vmware",
    },
    "truenas": {
        "ports": [80, 443, 22],
        "hostname_patterns": ["truenas", "freenas"],
        "integration_type": "truenas",
    },
    "mokerlink_switch": {
        "oui_prefixes": [],  # Would need actual OUIs
        "ports": [80, 443],
        "hostname_patterns": ["mokerlink", "poe-switch"],
        "integration_type": "managed_switch",
    },
}

# Map DeviceClass to DeviceType for backward compatibility
DEVICE_CLASS_TO_TYPE = {
    "router": DeviceType.NETWORK,
    "switch": DeviceType.NETWORK,
    "access_point": DeviceType.NETWORK,
    "nas": DeviceType.STORAGE,
    "server": DeviceType.SERVER,
    "desktop": DeviceType.WORKSTATION,
    "laptop": DeviceType.WORKSTATION,
    "workstation": DeviceType.WORKSTATION,
    "raspberry_pi": DeviceType.SERVER,
    "single_board_computer": DeviceType.SERVER,
    "smartphone": DeviceType.MOBILE,
    "tablet": DeviceType.MOBILE,
    "security_camera": DeviceType.CAMERA,
    "nvr": DeviceType.STORAGE,
    "dvr": DeviceType.STORAGE,
    "doorbell": DeviceType.IOT,
    "smart_lock": DeviceType.IOT,
    "thermostat": DeviceType.IOT,
    "smart_bulb": DeviceType.IOT,
    "smart_switch": DeviceType.IOT,
    "smart_tv": DeviceType.IOT,
    "streaming_device": DeviceType.IOT,
    "smart_speaker": DeviceType.IOT,
    "game_console": DeviceType.IOT,
    "smart_plug": DeviceType.IOT,
    "robot_vacuum": DeviceType.IOT,
    "printer": DeviceType.PRINTER,
    "iot_generic": DeviceType.IOT,
    "unknown": DeviceType.UNKNOWN,
}


class DiscoveryAgent(BaseAgent):
    """
    Network discovery and device classification agent.

    This agent continuously scans the network to discover devices,
    fingerprint them, and recommend appropriate segmentation.

    Configuration:
        - scan_interval_seconds: Time between quick scans (default: 300)
        - full_scan_interval_seconds: Time between full scans (default: 3600)
        - networks: List of networks to scan in CIDR notation
        - auto_execute_threshold: Confidence for auto-execution (default: 0.95)
        - enable_iot_classification: Use advanced IoT classifier (default: True)
        - enable_auto_segmentation: Automatically segment devices (default: True)
        - enable_infrastructure_discovery: Find manageable infrastructure (default: True)

    Events Published:
        - device.discovered: New device found
        - device.updated: Device information updated
        - device.offline: Device went offline
        - topology.updated: Network topology changed
        - infrastructure.discovered: Manageable infrastructure found

    Events Subscribed:
        - network.dhcp.lease: DHCP lease events from router
        - network.arp.new: New ARP entries
    """

    agent_name = "discovery"
    agent_description = "Network discovery and topology management"

    def __init__(self, engine, config: dict):
        super().__init__(engine, config)

        # Scan configuration
        self.scan_interval = config.get("scan_interval_seconds", 300)
        self.full_scan_interval = config.get("full_scan_interval_seconds", 3600)
        configured_networks = config.get("networks", [])

        # SAFETY: Network scanning is disabled by default
        # Set "enable_scanning": true in config to enable
        self._scanning_enabled = config.get("enable_scanning", False)

        # Auto-detect local networks if not configured
        if configured_networks:
            self.networks_to_scan = configured_networks
        else:
            self.networks_to_scan = self._detect_local_networks()

        if not self._scanning_enabled:
            logger.info(
                "Network scanning DISABLED by default. Set 'enable_scanning: true' in config to enable."
            )

        # Scanning options
        self.port_scan_enabled = config.get("port_scan_enabled", True)
        self.service_detection_enabled = config.get("service_detection_enabled", True)

        # IoT classification and segmentation
        self.enable_iot_classification = config.get("enable_iot_classification", True)
        self.enable_auto_segmentation = config.get("enable_auto_segmentation", True)
        self.enable_infrastructure_discovery = config.get("enable_infrastructure_discovery", True)

        # State
        self._last_quick_scan: Optional[datetime] = None
        self._last_full_scan: Optional[datetime] = None
        self._inventory = DeviceInventory()
        self._topology = NetworkTopology()

        # IoT classifier and segmenter (initialized if available)
        self._iot_classifier: Optional["IoTClassifier"] = None
        self._iot_segmenter: Optional["IoTSegmenter"] = None

        # Discovered infrastructure
        self._discovered_infrastructure: dict[str, dict] = {}

        # Initialize IoT subsystem if available
        if IOT_CLASSIFIER_AVAILABLE and self.enable_iot_classification:
            self._iot_classifier = IoTClassifier()
            if self.enable_auto_segmentation:
                self._iot_segmenter = IoTSegmenter(self._iot_classifier)
                logger.info("IoT classifier and segmenter initialized")

    def _detect_local_networks(self) -> list[str]:
        """Auto-detect local networks to scan based on system interfaces."""
        import socket
        import ipaddress

        networks = []

        try:
            # Get all local IP addresses
            hostname = socket.gethostname()
            # Get all addresses for this host
            addrs = socket.getaddrinfo(hostname, None, socket.AF_INET)

            seen_networks = set()
            for addr in addrs:
                ip = addr[4][0]
                # Skip loopback and link-local
                if ip.startswith("127.") or ip.startswith("169.254."):
                    continue

                # Assume /24 for most home/small office networks
                try:
                    network = ipaddress.ip_network(f"{ip}/24", strict=False)
                    network_str = str(network)
                    if network_str not in seen_networks:
                        seen_networks.add(network_str)
                        networks.append(network_str)
                        logger.info(f"Auto-detected network to scan: {network_str}")
                except ValueError:
                    pass

        except Exception as e:
            logger.warning(f"Failed to auto-detect networks: {e}")

        # Fall back to common private networks if detection failed
        if not networks:
            networks = ["192.168.1.0/24"]
            logger.info("Using default network 192.168.1.0/24")

        return networks

    async def _subscribe_events(self) -> None:
        """Subscribe to network events."""
        self.engine.event_bus.subscribe(self._handle_dhcp_event, event_type="network.dhcp.lease")
        self.engine.event_bus.subscribe(self._handle_arp_event, event_type="network.arp.new")
        self.engine.event_bus.subscribe(
            self._handle_scan_request, event_type="discovery.scan_requested"
        )

    async def _handle_scan_request(self, event: Event) -> None:
        """Handle manual scan request from GUI or API."""
        logger.info(f"Scan request received from {event.source}")

        # SAFETY: Check if scanning is enabled
        if not self._scanning_enabled:
            logger.warning("Scan requested but scanning is DISABLED. Enable in config to scan.")
            await self.engine.event_bus.publish(
                Event(
                    category=EventCategory.DEVICE,
                    event_type="discovery.scan_skipped",
                    severity=EventSeverity.INFO,
                    source="sentinel.agents.discovery",
                    title="Network Scan Skipped",
                    description="Scanning is disabled. Set 'enable_scanning: true' in discovery agent config.",
                )
            )
            return

        try:
            # Force a full scan by resetting the last scan time
            self._last_full_scan = None
            await self._perform_full_scan()
            self._last_full_scan = utc_now()

            # Publish completion event
            await self.engine.event_bus.publish(
                Event(
                    category=EventCategory.DEVICE,
                    event_type="discovery.scan_completed",
                    severity=EventSeverity.INFO,
                    source="sentinel.agents.discovery",
                    title="Network Scan Completed",
                    description=f"Manual scan completed. Found {len(self._inventory.devices)} devices.",
                )
            )
        except Exception as e:
            logger.error(f"Error handling scan request: {e}")

    async def _main_loop(self) -> None:
        """Main discovery loop."""
        while self._running:
            try:
                # SAFETY: Skip all scanning if disabled
                if not self._scanning_enabled:
                    await asyncio.sleep(30)
                    continue

                now = utc_now()

                # Check if full scan needed
                if (
                    self._last_full_scan is None
                    or (now - self._last_full_scan).total_seconds() > self.full_scan_interval
                ):
                    await self._perform_full_scan()
                    self._last_full_scan = now

                # Quick scan (ARP only)
                elif (
                    self._last_quick_scan is None
                    or (now - self._last_quick_scan).total_seconds() > self.scan_interval
                ):
                    await self._perform_quick_scan()
                    self._last_quick_scan = now

                # Check for offline devices
                await self._check_offline_devices()

                await asyncio.sleep(10)

            except Exception as e:
                logger.error(f"Discovery loop error: {e}")
                await asyncio.sleep(30)

    async def _perform_quick_scan(self) -> None:
        """Perform quick ARP-only scan."""
        logger.debug("Performing quick network scan")

        for network in self.networks_to_scan:
            devices = await self._arp_scan(network)
            await self._process_discovered_devices(devices, full_scan=False)

    async def _perform_full_scan(self) -> None:
        """Perform comprehensive network scan."""
        logger.info("Performing full network scan")
        start_time = utc_now()

        all_devices = []

        for network in self.networks_to_scan:
            # ARP scan first
            devices = await self._arp_scan(network)

            # Then fingerprint each device
            for device in devices:
                if self.port_scan_enabled:
                    await self._fingerprint_device(device)

            all_devices.extend(devices)

        await self._process_discovered_devices(all_devices, full_scan=True)

        # Update topology
        await self._update_topology()

        # Store state
        await self.engine.state.set("discovery:inventory", self._inventory.model_dump())

        duration = (utc_now() - start_time).total_seconds()
        logger.info(f"Full scan completed in {duration:.1f}s - found {len(all_devices)} devices")

    async def _arp_scan(self, network: str) -> list[Device]:
        """
        Perform ARP scan of network.

        Uses router integration if available, otherwise falls back
        to direct scanning using system ARP table and ping sweep.
        """
        devices = []

        router = self.engine.get_integration("router")
        if router:
            try:
                arp_table = await router.get_arp_table()
                for entry in arp_table:
                    device = Device(
                        interfaces=[
                            NetworkInterface(
                                mac_address=entry["mac"],
                                ip_addresses=[entry["ip"]],
                                is_primary=True,
                            )
                        ]
                    )
                    # Quick vendor lookup
                    device.fingerprint.vendor = self._lookup_vendor(entry["mac"])
                    devices.append(device)

            except Exception as e:
                logger.error(f"Failed to get ARP table from router: {e}")
        else:
            # Direct scanning using system tools
            logger.info(f"Performing direct network scan of {network}")
            devices = await self._direct_network_scan(network)

        return devices

    async def _direct_network_scan(self, network: str) -> list[Device]:
        """
        Perform direct network scanning without router integration.

        Uses TCP connect probes and system ARP table to discover devices.
        NO subprocess spawning - uses pure Python sockets.
        """
        import ipaddress
        import platform

        devices = []
        discovered_ips = set()

        try:
            # Parse network CIDR
            net = ipaddress.ip_network(network, strict=False)

            # Limit scan to reasonable size
            if net.num_addresses > 1024:
                logger.warning(f"Network {network} too large, limiting to /22")
                net = ipaddress.ip_network(f"{net.network_address}/22", strict=False)

            is_windows = platform.system().lower() == "windows"

            # Step 1: TCP connect scan (no subprocess spawning!)
            logger.info(f"Scanning {net.num_addresses} addresses using TCP probes...")
            hosts = list(net.hosts())

            # Use TCP connect to discover hosts - CONSERVATIVE limits
            # This populates the ARP cache without spawning processes
            semaphore = asyncio.Semaphore(20)  # Reduced from 50 - limit concurrent connections

            async def probe_host(ip_addr: str) -> tuple[str, bool]:
                async with semaphore:
                    result = await self._tcp_probe(ip_addr)
                    return (ip_addr, result)

            # Process in smaller batches with delays
            batch_size = 30  # Reduced from 100
            for i in range(0, len(hosts), batch_size):
                batch = hosts[i : i + batch_size]
                tasks = [probe_host(str(ip)) for ip in batch]
                results = await asyncio.gather(*tasks, return_exceptions=True)

                for result in results:
                    if isinstance(result, tuple) and result[1] is True:
                        discovered_ips.add(result[0])

                # Small delay between batches to prevent resource exhaustion
                await asyncio.sleep(0.05)

            logger.info(f"TCP probe found {len(discovered_ips)} responding hosts")

            # Step 2: Read system ARP table (single subprocess call, hidden)
            arp_entries = await self._get_system_arp_table(is_windows)
            logger.info(f"System ARP table has {len(arp_entries)} entries")

            # Step 3: Build device list from ARP entries
            for entry in arp_entries:
                ip = entry.get("ip", "")
                mac = entry.get("mac", "")

                # Skip invalid entries
                if not ip or not mac or mac == "ff:ff:ff:ff:ff:ff":
                    continue
                if mac == "00:00:00:00:00:00":
                    continue

                # Check if IP is in our target network
                try:
                    if ipaddress.ip_address(ip) not in net:
                        continue
                except ValueError:
                    continue

                device = Device(
                    interfaces=[
                        NetworkInterface(mac_address=mac, ip_addresses=[ip], is_primary=True)
                    ],
                    status=DeviceStatus.ONLINE if ip in discovered_ips else DeviceStatus.OFFLINE,
                )

                # Vendor lookup
                device.fingerprint.vendor = self._lookup_vendor(mac)

                devices.append(device)
                logger.debug(
                    f"Discovered: {ip} ({mac}) - {device.fingerprint.vendor or 'Unknown vendor'}"
                )

            # Step 4: Add responding hosts without ARP entries
            arp_ips = {e.get("ip") for e in arp_entries}
            for ip in discovered_ips:
                if ip not in arp_ips:
                    # Use empty MAC for hosts without ARP entry
                    device = Device(
                        interfaces=[
                            NetworkInterface(
                                mac_address="00:00:00:00:00:00",  # Unknown MAC
                                ip_addresses=[ip],
                                is_primary=True,
                            )
                        ],
                        status=DeviceStatus.ONLINE,
                    )
                    devices.append(device)

            logger.info(f"Direct scan completed - found {len(devices)} devices")

        except Exception as e:
            logger.error(f"Direct network scan failed: {e}")

        return devices

    async def _tcp_probe(self, ip: str) -> bool:
        """
        Probe a host using TCP connect - NO subprocess spawning.

        Tries to connect to a single common port to check if host is alive.
        This also populates the system ARP cache.
        """
        import socket

        # Only try ONE port to minimize resource usage
        # Port 445 (SMB) is commonly open on Windows, 80 on others
        port = 445

        try:
            loop = asyncio.get_event_loop()
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setblocking(False)

            try:
                await asyncio.wait_for(
                    loop.sock_connect(sock, (ip, port)), timeout=0.3  # 300ms timeout
                )
                sock.close()
                return True  # Connection succeeded
            except (ConnectionRefusedError, OSError) as e:
                # Connection refused means host is UP (just port closed)
                sock.close()
                # Check if it's a "connection refused" vs "no route" error
                if isinstance(e, ConnectionRefusedError):
                    return True
                # For OSError, check the error code
                err_str = str(e).lower()
                if "refused" in err_str or "reset" in err_str:
                    return True
                return False
            except asyncio.TimeoutError:
                sock.close()
                return False

        except Exception:
            try:
                sock.close()
            except Exception:
                pass
            return False

    async def _get_system_arp_table(self, is_windows: bool) -> list[dict]:
        """
        Read the system ARP table using a single subprocess call.

        On Windows, uses subprocess.run with CREATE_NO_WINDOW to hide console.
        """
        import subprocess
        import re

        entries = []

        try:
            # Use subprocess.run (synchronous) in executor to avoid async subprocess issues
            loop = asyncio.get_event_loop()

            def read_arp():
                if is_windows:
                    # Use subprocess.run with hidden window
                    startupinfo = subprocess.STARTUPINFO()
                    startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
                    startupinfo.wShowWindow = subprocess.SW_HIDE

                    result = subprocess.run(
                        ["arp", "-a"],
                        capture_output=True,
                        text=True,
                        creationflags=subprocess.CREATE_NO_WINDOW,
                        startupinfo=startupinfo,
                        timeout=10,
                    )
                else:
                    result = subprocess.run(
                        ["arp", "-n"], capture_output=True, text=True, timeout=10
                    )
                return result.stdout

            output = await loop.run_in_executor(None, read_arp)

            # Parse ARP output
            if is_windows:
                # Windows format: "  192.168.1.1     00-1a-2b-3c-4d-5e     dynamic"
                pattern = r"(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F-]{17})\s+\w+"
                for match in re.finditer(pattern, output):
                    ip = match.group(1)
                    mac = match.group(2).replace("-", ":").lower()
                    entries.append({"ip": ip, "mac": mac})
            else:
                # Linux format: "192.168.1.1  ether  00:1a:2b:3c:4d:5e  C  eth0"
                pattern = r"(\d+\.\d+\.\d+\.\d+)\s+\w+\s+([0-9a-fA-F:]{17})"
                for match in re.finditer(pattern, output):
                    ip = match.group(1)
                    mac = match.group(2).lower()
                    entries.append({"ip": ip, "mac": mac})

        except Exception as e:
            logger.error(f"Failed to read ARP table: {e}")

        return entries

    async def _resolve_hostname(self, ip: str) -> Optional[str]:
        """Try to resolve hostname via reverse DNS."""
        import socket

        try:
            loop = asyncio.get_event_loop()
            hostname, _, _ = await asyncio.wait_for(
                loop.run_in_executor(None, socket.gethostbyaddr, ip), timeout=1.0
            )
            return hostname
        except (socket.herror, socket.gaierror, asyncio.TimeoutError, OSError):
            return None

    async def _fingerprint_device(self, device: Device) -> None:
        """Perform detailed device fingerprinting."""
        ip = device.primary_ip
        mac = device.primary_mac
        hostname = device.hostname or ""

        if not ip:
            return

        # Port scan
        if self.port_scan_enabled:
            open_ports = await self._scan_ports(ip)
            device.fingerprint.open_ports = open_ports

        # Service detection
        if self.service_detection_enabled and device.fingerprint.open_ports:
            services = self._detect_services(device.fingerprint.open_ports)
            device.fingerprint.services = services

        # Use IoT classifier if available for enhanced classification
        if self._iot_classifier and mac:
            try:
                classification = await self._iot_classifier.classify(
                    mac_address=mac,
                    ip_address=ip,
                    hostname=hostname,
                    open_ports=device.fingerprint.open_ports,
                )

                # Map IoT DeviceClass to our DeviceType
                device_class_str = classification.device_class.value
                if device_class_str in DEVICE_CLASS_TO_TYPE:
                    device.device_type = DEVICE_CLASS_TO_TYPE[device_class_str]

                # Update vendor from classifier (usually more accurate)
                if classification.manufacturer:
                    device.fingerprint.vendor = classification.manufacturer

                # Store IoT classification data in fingerprint
                device.fingerprint.confidence = classification.confidence

                # Store risk assessment
                if hasattr(device, "metadata"):
                    device.metadata = device.metadata or {}
                    device.metadata["iot_classification"] = classification.to_dict()

                logger.debug(
                    f"IoT classified {ip} as {classification.device_class.value} "
                    f"(confidence: {classification.confidence:.0%})"
                )

            except Exception as e:
                logger.warning(f"IoT classification failed for {ip}: {e}")
                # Fall back to legacy classification
                device.device_type = self._classify_device(device.fingerprint)
                device.fingerprint.confidence = self._calculate_confidence(device.fingerprint)
        else:
            # Legacy classification
            device.device_type = self._classify_device(device.fingerprint)
            device.fingerprint.confidence = self._calculate_confidence(device.fingerprint)

        # Check for infrastructure devices
        if self.enable_infrastructure_discovery:
            await self._check_infrastructure_device(device)

    async def _scan_ports(
        self, ip: str, ports: list[int] = None, timeout: float = 1.0
    ) -> list[int]:
        """Scan common ports on a device."""
        if ports is None:
            # Common ports to scan
            ports = [
                22,
                23,
                80,
                443,
                445,
                139,  # Common services
                3389,
                5900,
                5901,  # Remote desktop
                8080,
                8443,
                9090,  # Web alternatives
                3306,
                5432,
                6379,
                27017,  # Databases
                1883,
                8883,  # MQTT
                554,
                8554,  # RTSP
                9100,
                515,
                631,  # Printing
                111,
                2049,
                3260,  # Storage
            ]

        open_ports = []

        # Scan ports concurrently in batches
        batch_size = 20
        for i in range(0, len(ports), batch_size):
            batch = ports[i : i + batch_size]
            tasks = [self._check_port(ip, port, timeout) for port in batch]
            results = await asyncio.gather(*tasks, return_exceptions=True)

            for port, result in zip(batch, results):
                if result is True:
                    open_ports.append(port)

        return sorted(open_ports)

    async def _check_port(self, ip: str, port: int, timeout: float) -> bool:
        """Check if a port is open."""
        try:
            _, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=timeout)
            writer.close()
            await writer.wait_closed()
            return True
        except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
            return False

    def _detect_services(self, ports: list[int]) -> list[str]:
        """Detect services based on open ports."""
        port_service_map = {
            22: "ssh",
            23: "telnet",
            80: "http",
            443: "https",
            445: "smb",
            139: "netbios",
            3389: "rdp",
            5900: "vnc",
            5901: "vnc",
            8080: "http-alt",
            8443: "https-alt",
            3306: "mysql",
            5432: "postgresql",
            6379: "redis",
            27017: "mongodb",
            1883: "mqtt",
            8883: "mqtts",
            554: "rtsp",
            8554: "rtsp-alt",
            9100: "jetdirect",
            515: "lpd",
            631: "ipp",
            111: "rpcbind",
            2049: "nfs",
            3260: "iscsi",
            9090: "prometheus",
        }

        services = []
        for port in ports:
            if port in port_service_map:
                services.append(port_service_map[port])

        return services

    def _lookup_vendor(self, mac: str) -> Optional[str]:
        """Look up vendor from MAC address OUI."""
        if not mac:
            return None

        # Normalize MAC and get OUI
        mac_clean = mac.upper().replace("-", ":").replace(".", ":")
        oui = mac_clean[:8]

        return VENDOR_MAC_PREFIXES.get(oui)

    def _classify_device(self, fingerprint: DeviceFingerprint) -> DeviceType:
        """Classify device type based on fingerprint."""
        vendor_lower = (fingerprint.vendor or "").lower()

        # Check vendor-based classification first
        if any(v in vendor_lower for v in ["raspberry", "pi"]):
            # Could be server or IoT depending on ports
            if 22 in fingerprint.open_ports:
                return DeviceType.SERVER

        if any(v in vendor_lower for v in SERVICE_SIGNATURES["iot"]["vendors"]):
            return DeviceType.IOT

        # Check port/service signatures
        for device_type, sigs in [
            (DeviceType.PRINTER, SERVICE_SIGNATURES["printer"]),
            (DeviceType.CAMERA, SERVICE_SIGNATURES["camera"]),
            (DeviceType.STORAGE, SERVICE_SIGNATURES["storage"]),
            (DeviceType.SERVER, SERVICE_SIGNATURES["server"]),
            (DeviceType.IOT, SERVICE_SIGNATURES["iot"]),
            (DeviceType.WORKSTATION, SERVICE_SIGNATURES["workstation"]),
        ]:
            port_matches = sum(1 for p in fingerprint.open_ports if p in sigs["ports"])
            if port_matches >= 2:
                return device_type

        # Check for IoT characteristics
        if fingerprint.open_ports:
            # IoT typically has limited ports and specific patterns
            if set(fingerprint.open_ports).issubset({80, 443, 8080, 1883, 8883}):
                if len(fingerprint.open_ports) <= 3:
                    return DeviceType.IOT

        return DeviceType.UNKNOWN

    def _calculate_confidence(self, fingerprint: DeviceFingerprint) -> float:
        """Calculate confidence score for classification."""
        score = 0.0

        # Vendor identification
        if fingerprint.vendor:
            score += 0.30

        # OS detection
        if fingerprint.os_family:
            score += 0.25

        # Service detection
        if fingerprint.services:
            score += 0.25

        # Port scan results
        if fingerprint.open_ports:
            score += 0.20

        return min(score, 1.0)

    async def _check_infrastructure_device(self, device: Device) -> None:
        """
        Check if device is manageable infrastructure.

        Detects MikroTik routers, NAS devices, Raspberry Pis, etc.
        that Sentinel can integrate with and manage.
        """
        mac = device.primary_mac or ""
        ip = device.primary_ip or ""
        hostname = (device.hostname or "").lower()
        open_ports = device.fingerprint.open_ports or []
        mac_prefix = mac.upper()[:8].replace("-", ":") if mac else ""

        for infra_type, signature in INFRASTRUCTURE_SIGNATURES.items():
            score = 0.0
            matched = []

            # Check OUI prefix
            if mac_prefix and signature.get("oui_prefixes"):
                if mac_prefix in signature["oui_prefixes"]:
                    score += 0.5
                    matched.append(f"oui:{mac_prefix}")

            # Check hostname patterns
            if hostname and signature.get("hostname_patterns"):
                for pattern in signature["hostname_patterns"]:
                    if pattern in hostname:
                        score += 0.3
                        matched.append(f"hostname:{pattern}")
                        break

            # Check ports
            if open_ports and signature.get("ports"):
                matching_ports = set(open_ports) & set(signature["ports"])
                if matching_ports:
                    port_score = len(matching_ports) / len(signature["ports"]) * 0.4
                    score += port_score
                    matched.append(f"ports:{','.join(map(str, matching_ports))}")

            # If score high enough, mark as infrastructure
            if score >= 0.4:
                self._discovered_infrastructure[ip] = {
                    "type": infra_type,
                    "integration_type": signature.get("integration_type"),
                    "ip": ip,
                    "mac": mac,
                    "hostname": device.hostname,
                    "confidence": score,
                    "matched_patterns": matched,
                    "discovered_at": utc_now().isoformat(),
                }

                logger.info(
                    f"Discovered {infra_type} infrastructure at {ip} " f"(confidence: {score:.0%})"
                )

                # Emit infrastructure discovery event
                await self.engine.event_bus.publish(
                    Event(
                        category=EventCategory.NETWORK,
                        event_type="infrastructure.discovered",
                        severity=EventSeverity.INFO,
                        source=f"sentinel.agents.{self.agent_name}",
                        source_device_id=device.id,
                        title=f"Infrastructure discovered: {infra_type}",
                        description=(
                            f"Found {infra_type} at {ip} ({device.hostname or 'no hostname'}). "
                            f"Integration type: {signature.get('integration_type')}"
                        ),
                        data=self._discovered_infrastructure[ip],
                    )
                )

                # Only match first infrastructure type
                break

    async def _auto_segment_device(self, device: Device) -> None:
        """Automatically segment device using IoT segmenter."""
        if not self._iot_segmenter or not self._iot_classifier:
            return

        mac = device.primary_mac
        if not mac:
            return

        try:
            # Get or create classification
            classification = self._iot_classifier.get_cached_classification(mac)
            if not classification:
                classification = await self._iot_classifier.classify(
                    mac_address=mac,
                    ip_address=device.primary_ip or "",
                    hostname=device.hostname or "",
                    open_ports=device.fingerprint.open_ports or [],
                )

            # Segment the device
            action = await self._iot_segmenter.segment_device(classification)

            if action.success and action.from_vlan != action.to_vlan:
                logger.info(
                    f"Auto-segmented {mac} to VLAN {action.to_vlan} "
                    f"(class: {classification.device_class.value})"
                )

                # Update device state
                device.assigned_vlan = action.to_vlan
                device.managed_by_agent = True
                device.agent_last_action = f"Auto-segmented to VLAN {action.to_vlan}"

        except Exception as e:
            logger.error(f"Auto-segmentation failed for {mac}: {e}")

    async def _process_discovered_devices(self, devices: list[Device], full_scan: bool) -> None:
        """Process discovered devices and emit events."""
        for device in devices:
            mac = device.primary_mac
            if not mac:
                continue

            existing = self._inventory.get_by_mac(mac)

            if not existing:
                # New device discovered
                device.first_seen = utc_now()
                device.last_seen = utc_now()
                device.status = DeviceStatus.ONLINE

                self._inventory.add_device(device)

                await self.engine.event_bus.publish(
                    Event(
                        category=EventCategory.DEVICE,
                        event_type="device.discovered",
                        severity=EventSeverity.INFO,
                        source=f"sentinel.agents.{self.agent_name}",
                        source_device_id=device.id,
                        title=f"New device discovered: {device.primary_ip}",
                        description=(
                            f"Type: {device.device_type.value}, "
                            f"Vendor: {device.fingerprint.vendor or 'Unknown'}, "
                            f"Confidence: {device.fingerprint.confidence:.0%}"
                        ),
                        data=device.model_dump(),
                    )
                )

                # Analyze for auto-segmentation
                await self._propose_segmentation(device)

            else:
                # Update existing device
                existing.last_seen = utc_now()
                existing.status = DeviceStatus.ONLINE

                # Update fingerprint on full scan
                if full_scan:
                    old_type = existing.device_type
                    existing.fingerprint = device.fingerprint
                    existing.device_type = device.device_type

                    # Emit update if type changed
                    if old_type != existing.device_type:
                        await self.engine.event_bus.publish(
                            Event(
                                category=EventCategory.DEVICE,
                                event_type="device.reclassified",
                                severity=EventSeverity.INFO,
                                source=f"sentinel.agents.{self.agent_name}",
                                source_device_id=existing.id,
                                title=f"Device reclassified: {existing.primary_ip}",
                                description=f"Changed from {old_type.value} to {existing.device_type.value}",
                                data=existing.model_dump(),
                            )
                        )

    async def _propose_segmentation(self, device: Device) -> None:
        """Propose VLAN segmentation for a device."""
        # Use IoT segmenter if available for smarter segmentation
        if self._iot_segmenter and self.enable_auto_segmentation:
            await self._auto_segment_device(device)
            return

        # Fall back to legacy VLAN recommendations
        recommended_vlan = VLAN_RECOMMENDATIONS.get(
            device.device_type, VLAN_RECOMMENDATIONS[DeviceType.UNKNOWN]
        )

        # Create decision record
        decision = AgentDecision(
            agent_name=self.agent_name,
            decision_type="device_segmentation",
            input_events=[],
            input_state={"device": device.model_dump()},
            analysis=(
                f"Device classified as {device.device_type.value} with "
                f"{device.fingerprint.confidence:.0%} confidence. "
                f"Recommending VLAN {recommended_vlan}."
            ),
            options_considered=[
                {
                    "vlan": recommended_vlan,
                    "reason": f"Standard VLAN for {device.device_type.value} devices",
                }
            ],
            selected_option={"vlan": recommended_vlan},
            confidence=device.fingerprint.confidence,
        )

        self._decisions.append(decision)

        # If confidence high enough, execute
        if decision.confidence >= self.confirm_threshold:
            await self.execute_action(
                action_type="assign_vlan",
                target_type="device",
                target_id=str(device.id),
                parameters={
                    "vlan_id": recommended_vlan,
                    "mac": device.primary_mac,
                    "ip": device.primary_ip,
                },
                reasoning=decision.analysis,
                confidence=decision.confidence,
                reversible=True,
            )

    async def _check_offline_devices(self) -> None:
        """Check for devices that have gone offline."""
        now = utc_now()
        offline_threshold = timedelta(minutes=15)

        for device in self._inventory.devices.values():
            if device.status == DeviceStatus.ONLINE:
                if device.last_seen and (now - device.last_seen) > offline_threshold:
                    device.status = DeviceStatus.OFFLINE

                    await self.engine.event_bus.publish(
                        Event(
                            category=EventCategory.DEVICE,
                            event_type="device.offline",
                            severity=EventSeverity.WARNING,
                            source=f"sentinel.agents.{self.agent_name}",
                            source_device_id=device.id,
                            title=f"Device went offline: {device.primary_ip}",
                            description=f"Last seen: {device.last_seen.isoformat()}",
                            data=device.model_dump(),
                        )
                    )

    async def _update_topology(self) -> None:
        """Update network topology graph from LLDP/CDP data."""
        nodes_updated = 0
        links_updated = 0

        # Get LLDP/CDP data from switches if available
        switch = self.engine.get_integration("switch")
        if switch:
            try:
                lldp_data = await switch.get_lldp_neighbors()
                if lldp_data:
                    nodes_updated, links_updated = await self._build_topology_from_lldp(lldp_data)
                    logger.info(
                        f"Built topology from LLDP: {nodes_updated} nodes, {links_updated} links"
                    )
            except Exception as e:
                logger.error(f"Failed to get LLDP data: {e}")

        # Also try to get topology from router if available
        router = self.engine.get_integration("router")
        if router:
            try:
                # Get interface data to understand router connections
                if hasattr(router, "get_interfaces"):
                    interfaces = await router.get_interfaces()
                    await self._add_router_interfaces_to_topology(interfaces)
            except Exception as e:
                logger.debug(f"Failed to get router interfaces: {e}")

        # Add devices from inventory as nodes if not already present
        for device in self._inventory.devices.values():
            if device.primary_mac and device.primary_mac not in [
                n.mac_address for n in self._topology.nodes.values()
            ]:
                node = TopologyNode(
                    id=str(device.id),
                    name=device.hostname or device.primary_ip or "Unknown",
                    node_type=self._device_type_to_node_type(device.device_type),
                    ip_address=device.primary_ip,
                    mac_address=device.primary_mac,
                    vendor=device.fingerprint.vendor,
                    device_id=device.id,
                )
                self._topology.nodes[node.id] = node
                nodes_updated += 1

        # Save topology to state
        self._topology.last_scan = utc_now()
        await self.engine.state.set("topology", self._topology.model_dump())

        await self.engine.event_bus.publish(
            Event(
                category=EventCategory.NETWORK,
                event_type="topology.updated",
                severity=EventSeverity.INFO,
                source=f"sentinel.agents.{self.agent_name}",
                title="Network topology updated",
                description=f"Topology scan completed: {len(self._topology.nodes)} nodes, {len(self._topology.links)} links",
                data={
                    "device_count": len(self._inventory.devices),
                    "node_count": len(self._topology.nodes),
                    "link_count": len(self._topology.links),
                    "nodes_updated": nodes_updated,
                    "links_updated": links_updated,
                },
            )
        )

    async def _build_topology_from_lldp(self, lldp_data: list[dict]) -> tuple[int, int]:
        """
        Build network topology from LLDP neighbor data.

        LLDP data typically contains:
        - local_port: The port on this switch
        - remote_chassis_id: Remote device identifier (often MAC)
        - remote_port_id: Port on remote device
        - remote_system_name: Hostname of remote device
        - remote_system_description: Device description
        - remote_capabilities: Device capabilities (router, switch, etc.)

        Returns:
            Tuple of (nodes_added, links_added)
        """
        nodes_added = 0
        links_added = 0

        for neighbor in lldp_data:
            try:
                # Extract neighbor information
                local_port = neighbor.get("local_port", "")
                remote_chassis_id = neighbor.get("remote_chassis_id", "")
                remote_port = neighbor.get("remote_port_id", "")
                remote_name = neighbor.get("remote_system_name", "")
                remote_desc = neighbor.get("remote_system_description", "")
                capabilities = neighbor.get("remote_capabilities", [])

                if not remote_chassis_id:
                    continue

                # Determine node type from LLDP capabilities
                node_type = self._lldp_capabilities_to_node_type(capabilities, remote_desc)

                # Create or update remote node
                node_id = f"lldp_{remote_chassis_id.replace(':', '_')}"
                if node_id not in self._topology.nodes:
                    node = TopologyNode(
                        id=node_id,
                        name=remote_name or remote_chassis_id,
                        node_type=node_type,
                        mac_address=remote_chassis_id if ":" in remote_chassis_id else None,
                        vendor=(
                            self._lookup_vendor(remote_chassis_id)
                            if ":" in remote_chassis_id
                            else None
                        ),
                    )

                    # Try to match to a device in inventory
                    if ":" in remote_chassis_id:
                        device = self._inventory.get_by_mac(remote_chassis_id)
                        if device:
                            node.ip_address = device.primary_ip
                            node.device_id = device.id
                            node.name = device.hostname or node.name

                    self._topology.nodes[node_id] = node
                    nodes_added += 1
                    logger.debug(f"Added topology node: {node.name} ({node_type})")

                # Create link between local switch and remote device
                # We need a node for the local switch too
                local_switch_id = "local_switch"
                if local_switch_id not in self._topology.nodes:
                    switch_int = self.engine.get_integration("switch")
                    switch_name = "Managed Switch"
                    if switch_int and hasattr(switch_int, "host"):
                        switch_name = f"Switch ({switch_int.host})"

                    self._topology.nodes[local_switch_id] = TopologyNode(
                        id=local_switch_id, name=switch_name, node_type="switch"
                    )
                    nodes_added += 1

                # Create the link
                link_id = f"{local_switch_id}:{local_port}-{node_id}:{remote_port}"
                if link_id not in self._topology.links:
                    link = NetworkLink(
                        id=link_id,
                        source_node_id=local_switch_id,
                        target_node_id=node_id,
                        source_port=local_port,
                        target_port=remote_port,
                        link_type="ethernet",
                        discovered_via="lldp",
                    )
                    self._topology.links[link_id] = link
                    links_added += 1
                    logger.debug(
                        f"Added topology link: {local_port} -> {remote_name}:{remote_port}"
                    )

            except Exception as e:
                logger.warning(f"Error processing LLDP neighbor: {e}")

        return nodes_added, links_added

    async def _add_router_interfaces_to_topology(self, interfaces: list[dict]) -> None:
        """Add router interfaces as topology nodes/links."""
        router_node_id = "router_gateway"

        if router_node_id not in self._topology.nodes:
            router = self.engine.get_integration("router")
            router_name = "Gateway Router"
            if router and hasattr(router, "host"):
                router_name = f"Router ({router.host})"

            self._topology.nodes[router_node_id] = TopologyNode(
                id=router_node_id, name=router_name, node_type="router"
            )

        # Add interfaces as potential link points
        for iface in interfaces:
            iface_name = iface.get("name", "")
            # Router interfaces could connect to switches or other segments
            # We'll track these for potential VLAN/segment topology
            if iface_name:
                self._topology.nodes[router_node_id].metadata = (
                    self._topology.nodes[router_node_id].metadata or {}
                )
                ifaces = self._topology.nodes[router_node_id].metadata.get("interfaces", [])
                ifaces.append(iface)
                self._topology.nodes[router_node_id].metadata["interfaces"] = ifaces

    def _lldp_capabilities_to_node_type(self, capabilities: list, description: str = "") -> str:
        """Convert LLDP capability flags to topology node type."""
        cap_lower = [c.lower() for c in capabilities] if capabilities else []
        desc_lower = description.lower() if description else ""

        # Check capabilities first
        if "router" in cap_lower:
            return "router"
        if "bridge" in cap_lower or "switch" in cap_lower:
            return "switch"
        if "wlan" in cap_lower or "access point" in cap_lower:
            return "access_point"
        if "telephone" in cap_lower or "voip" in cap_lower:
            return "voip_phone"

        # Fall back to description parsing
        if "router" in desc_lower:
            return "router"
        if "switch" in desc_lower:
            return "switch"
        if "access point" in desc_lower or "ap" in desc_lower:
            return "access_point"

        return "endpoint"

    def _device_type_to_node_type(self, device_type: DeviceType) -> str:
        """Convert DeviceType to topology node type string."""
        mapping = {
            DeviceType.NETWORK: "switch",
            DeviceType.SERVER: "server",
            DeviceType.WORKSTATION: "workstation",
            DeviceType.STORAGE: "storage",
            DeviceType.IOT: "iot",
            DeviceType.CAMERA: "camera",
            DeviceType.PRINTER: "printer",
            DeviceType.MOBILE: "mobile",
            DeviceType.UNKNOWN: "endpoint",
        }
        return mapping.get(device_type, "endpoint")

    async def _handle_dhcp_event(self, event: Event) -> None:
        """Handle DHCP lease events from router."""
        data = event.data
        mac = data.get("mac")
        ip = data.get("ip")
        hostname = data.get("hostname")

        if mac and ip:
            existing = self._inventory.get_by_mac(mac)

            if not existing:
                # New device via DHCP
                device = Device(
                    hostname=hostname,
                    interfaces=[
                        NetworkInterface(mac_address=mac, ip_addresses=[ip], is_primary=True)
                    ],
                )
                device.fingerprint.vendor = self._lookup_vendor(mac)

                # Trigger fingerprinting
                await self._fingerprint_device(device)
                await self._process_discovered_devices([device], full_scan=False)

    async def _handle_arp_event(self, event: Event) -> None:
        """Handle new ARP entries."""
        data = event.data
        mac = data.get("mac")
        ip = data.get("ip")

        if mac and ip:
            existing = self._inventory.get_by_mac(mac)
            if existing:
                # Update last seen
                existing.last_seen = utc_now()
                existing.status = DeviceStatus.ONLINE
            # New devices will be picked up in next scan

    async def analyze(self, event: Event) -> Optional[AgentDecision]:
        """Analyze events for device-related decisions."""
        # This agent primarily acts on device.discovered events
        # which are handled in _propose_segmentation
        return None

    async def _do_execute(self, action: AgentAction) -> dict:
        """Execute VLAN assignment action."""
        if action.action_type == "assign_vlan":
            vlan_id = action.parameters["vlan_id"]
            mac = action.parameters.get("mac")

            # Execute via switch integration
            switch = self.engine.get_integration("switch")
            if switch:
                await switch.set_port_vlan(mac=mac, vlan_id=vlan_id)

            # Update device state
            device = self._inventory.get_by_mac(mac)
            if device:
                device.assigned_vlan = vlan_id
                device.managed_by_agent = True
                device.agent_last_action = f"Assigned to VLAN {vlan_id}"

            return {"assigned_vlan": vlan_id, "mac": mac, "success": True}

        raise ValueError(f"Unknown action type: {action.action_type}")

    async def _capture_rollback_data(self, action: AgentAction) -> Optional[dict]:
        """Capture current VLAN assignment for rollback."""
        if action.action_type == "assign_vlan":
            mac = action.parameters.get("mac")
            device = self._inventory.get_by_mac(mac)
            if device:
                return {"previous_vlan": device.assigned_vlan, "mac": mac}
        return None

    async def _do_rollback(self, action: AgentAction) -> None:
        """Rollback VLAN assignment."""
        if action.action_type == "assign_vlan" and action.rollback_data:
            previous_vlan = action.rollback_data.get("previous_vlan")
            mac = action.rollback_data.get("mac")

            if previous_vlan is not None:
                switch = self.engine.get_integration("switch")
                if switch:
                    await switch.set_port_vlan(mac=mac, vlan_id=previous_vlan)

                device = self._inventory.get_by_mac(mac)
                if device:
                    device.assigned_vlan = previous_vlan

    async def _get_relevant_state(self) -> dict:
        """Get state relevant to discovery decisions."""
        return {
            "device_count": len(self._inventory.devices),
            "device_types": {
                dtype.value: len(self._inventory.get_by_type(dtype)) for dtype in DeviceType
            },
        }

    @property
    def inventory(self) -> DeviceInventory:
        """Get the device inventory."""
        return self._inventory

    @property
    def topology(self) -> NetworkTopology:
        """Get the network topology."""
        return self._topology

    @property
    def discovered_infrastructure(self) -> dict[str, dict]:
        """Get discovered infrastructure devices."""
        return self._discovered_infrastructure

    @property
    def iot_classifier(self) -> Optional["IoTClassifier"]:
        """Get the IoT classifier instance."""
        return self._iot_classifier

    @property
    def iot_segmenter(self) -> Optional["IoTSegmenter"]:
        """Get the IoT segmenter instance."""
        return self._iot_segmenter

    def get_infrastructure_by_type(self, infra_type: str) -> list[dict]:
        """Get discovered infrastructure of a specific type."""
        return [
            info
            for info in self._discovered_infrastructure.values()
            if info.get("type") == infra_type
        ]

    def get_mikrotik_devices(self) -> list[dict]:
        """Get all discovered MikroTik devices."""
        return self.get_infrastructure_by_type("mikrotik")

    def get_raspberry_pis(self) -> list[dict]:
        """Get all discovered Raspberry Pi devices."""
        return self.get_infrastructure_by_type("raspberry_pi")

    def get_nas_devices(self) -> list[dict]:
        """Get all discovered NAS devices."""
        synology = self.get_infrastructure_by_type("synology_nas")
        qnap = self.get_infrastructure_by_type("qnap_nas")
        truenas = self.get_infrastructure_by_type("truenas")
        return synology + qnap + truenas

    async def get_discovery_summary(self) -> dict:
        """Get a summary of all discovered devices and infrastructure."""
        device_types = {}
        for device in self._inventory.devices.values():
            dtype = device.device_type.value
            device_types[dtype] = device_types.get(dtype, 0) + 1

        infra_types = {}
        for info in self._discovered_infrastructure.values():
            itype = info.get("type", "unknown")
            infra_types[itype] = infra_types.get(itype, 0) + 1

        # IoT classification summary
        iot_summary = {}
        if self._iot_classifier:
            for classification in self._iot_classifier.get_all_classifications():
                cls = classification.device_class.value
                iot_summary[cls] = iot_summary.get(cls, 0) + 1

        # High risk devices
        high_risk_count = 0
        if self._iot_classifier:
            high_risk_count = len(self._iot_classifier.get_high_risk_devices())

        return {
            "total_devices": len(self._inventory.devices),
            "online_devices": len(
                [d for d in self._inventory.devices.values() if d.status == DeviceStatus.ONLINE]
            ),
            "offline_devices": len(
                [d for d in self._inventory.devices.values() if d.status == DeviceStatus.OFFLINE]
            ),
            "device_types": device_types,
            "infrastructure_devices": len(self._discovered_infrastructure),
            "infrastructure_types": infra_types,
            "iot_classifications": iot_summary,
            "high_risk_devices": high_risk_count,
            "last_full_scan": self._last_full_scan.isoformat() if self._last_full_scan else None,
            "last_quick_scan": self._last_quick_scan.isoformat() if self._last_quick_scan else None,
            "networks_scanned": self.networks_to_scan,
        }
