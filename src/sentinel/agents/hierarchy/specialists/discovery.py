"""
Discovery Specialists - Real implementations for network discovery.

These specialists perform actual network discovery operations:
- ARP scanning with scapy or system tools
- SNMP polling for device information
- Vendor identification via MAC OUI lookup
- Device fingerprinting with LLM analysis
"""

import asyncio
import json
import logging
import re
import socket
import struct
from datetime import datetime
from typing import Dict, List, Any, Optional, TYPE_CHECKING

import ipaddress as _ipaddress

from sentinel.core.hierarchy.base import (
    Specialist,
    Task,
    TaskResult,
    SpecialistCapability,
)

if TYPE_CHECKING:
    from nexus.core.llm import LLMRouter

logger = logging.getLogger(__name__)


def _validate_network(network: str) -> str:
    """Validate a network CIDR string."""
    _ipaddress.ip_network(network, strict=False)  # Raises ValueError if invalid
    return network


def _validate_ip(ip_str: str) -> str:
    """Validate and return a safe IP address string."""
    addr = _ipaddress.ip_address(ip_str)  # Raises ValueError if invalid
    return str(addr)


# OUI (Organizationally Unique Identifier) database for vendor lookup
# This is a small subset - in production, use a full OUI database
OUI_DATABASE = {
    "00:50:56": "VMware",
    "00:0C:29": "VMware",
    "00:1C:42": "Parallels",
    "08:00:27": "VirtualBox",
    "52:54:00": "QEMU/KVM",
    "DC:A6:32": "Raspberry Pi",
    "B8:27:EB": "Raspberry Pi",
    "E4:5F:01": "Raspberry Pi",
    "00:1A:79": "Mikrotik",
    "64:D1:54": "Mikrotik",
    "D4:01:C3": "Ubiquiti",
    "FC:EC:DA": "Ubiquiti",
    "24:A4:3C": "Ubiquiti",
    "78:8A:20": "Ubiquiti",
    "00:1B:21": "Intel",
    "00:1E:67": "Intel",
    "3C:97:0E": "Apple",
    "A8:66:7F": "Apple",
    "F0:18:98": "Apple",
    "00:11:32": "Synology",
    "00:50:43": "QNAP",
    "00:08:9B": "ICP Electronics",
    "00:0D:B9": "PC Engines",
}


# ============================================================================
# ARP SCAN SPECIALIST
# ============================================================================


class ARPScanSpecialist(Specialist):
    """
    ARP scan specialist for Layer 2 device discovery.

    Capabilities:
    - Performs ARP scans on local network segments
    - Discovers active hosts and their MAC addresses
    - Can use scapy or system ARP tools
    """

    def __init__(
        self,
        specialist_id: Optional[str] = None,
        llm_router: Optional["LLMRouter"] = None,
        use_scapy: bool = True,
    ):
        super().__init__(specialist_id, llm_router)
        self._use_scapy = use_scapy
        self._scapy_available = self._check_scapy()

    def _check_scapy(self) -> bool:
        """Check if scapy is available."""
        try:
            import scapy.all

            return True
        except ImportError:
            return False

    @property
    def capability(self) -> SpecialistCapability:
        return SpecialistCapability(
            name="ARP Scan Specialist",
            task_types=[
                "scan.arp",
                "discovery.scan.arp",
                "discovery.scan_network",
            ],
            protocols=["ARP", "Ethernet"],
            confidence=0.95,
            max_concurrent=3,
            description="Discovers hosts via ARP scanning",
        )

    async def _do_execute(self, task: Task) -> TaskResult:
        """Perform ARP scan."""
        network = task.parameters.get("network", "192.168.1.0/24")
        interface = task.parameters.get("interface")
        timeout = task.parameters.get("timeout", 3)

        start_time = datetime.now()

        # Try scapy first, fall back to system tools
        if self._scapy_available and self._use_scapy:
            devices = await self._scan_with_scapy(network, interface, timeout)
        else:
            devices = await self._scan_with_arp_command(network, timeout)

        scan_duration = (datetime.now() - start_time).total_seconds()

        # Enrich with vendor info
        for device in devices:
            device["vendor"] = self._lookup_vendor(device.get("mac", ""))

        return TaskResult(
            success=True,
            output={
                "scan_type": "arp",
                "network": network,
                "interface": interface,
                "devices_found": len(devices),
                "devices": devices,
                "scan_duration_seconds": round(scan_duration, 2),
                "method": "scapy" if self._scapy_available else "system",
            },
            confidence=0.95,
            metadata={"scan_type": "arp", "network": network},
        )

    async def _scan_with_scapy(
        self, network: str, interface: Optional[str], timeout: int
    ) -> List[Dict[str, Any]]:
        """Perform ARP scan using scapy."""
        try:
            from scapy.all import ARP, Ether, srp

            # Run in thread pool to avoid blocking
            loop = asyncio.get_event_loop()

            def do_scan():
                arp_request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=network)
                kwargs = {"timeout": timeout, "verbose": False}
                if interface:
                    kwargs["iface"] = interface

                answered, _ = srp(arp_request, **kwargs)

                devices = []
                for sent, received in answered:
                    devices.append(
                        {
                            "ip": received.psrc,
                            "mac": received.hwsrc.upper(),
                            "discovered_at": datetime.now().isoformat(),
                        }
                    )
                return devices

            return await loop.run_in_executor(None, do_scan)

        except Exception as e:
            logger.error(f"Scapy ARP scan failed: {e}")
            return []

    async def _scan_with_arp_command(self, network: str, timeout: int) -> List[Dict[str, Any]]:
        """Perform ARP scan using system commands."""
        devices = []

        try:
            network = _validate_network(network)
            # First ping the network to populate ARP cache
            # This is a simplistic approach - real implementation would be more thorough
            import subprocess

            # Parse network to get IP range
            base_ip, prefix = network.rsplit("/", 1) if "/" in network else (network, "24")
            prefix = int(prefix)

            if prefix >= 24:
                # For /24 and smaller, we can ping sweep
                base_parts = base_ip.rsplit(".", 1)
                if len(base_parts) == 2:
                    base = base_parts[0]
                    for i in range(1, 255):
                        ip = f"{base}.{i}"
                        ip = _validate_ip(ip)
                        # Quick ping (non-blocking)
                        proc = await asyncio.create_subprocess_exec(
                            "ping",
                            "-c",
                            "1",
                            "-W",
                            "1",
                            ip,
                            stdout=asyncio.subprocess.DEVNULL,
                            stderr=asyncio.subprocess.DEVNULL,
                        )
                        await asyncio.wait_for(proc.wait(), timeout=2)

            # Read ARP cache
            proc = await asyncio.create_subprocess_exec(
                "arp",
                "-a",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            stdout, _ = await proc.communicate()

            # Parse ARP output
            for line in stdout.decode().split("\n"):
                # Different formats on different systems
                # Linux: hostname (ip) at mac [ether] on interface
                # macOS: hostname (ip) at mac on interface
                match = re.search(r"\((\d+\.\d+\.\d+\.\d+)\) at ([0-9a-fA-F:]+)", line)
                if match:
                    ip, mac = match.groups()
                    if mac != "(incomplete)":
                        devices.append(
                            {
                                "ip": ip,
                                "mac": mac.upper().replace("-", ":"),
                                "discovered_at": datetime.now().isoformat(),
                            }
                        )

        except Exception as e:
            logger.error(f"System ARP scan failed: {e}")

        return devices

    def _lookup_vendor(self, mac: str) -> Optional[str]:
        """Look up vendor from MAC OUI."""
        if not mac:
            return None

        # Normalize MAC format
        mac = mac.upper().replace("-", ":")
        oui = mac[:8]

        return OUI_DATABASE.get(oui)


# ============================================================================
# SNMP SCAN SPECIALIST
# ============================================================================


class SNMPScanSpecialist(Specialist):
    """
    SNMP scan specialist for device information gathering.

    Capabilities:
    - Polls SNMP-enabled devices for system info
    - Retrieves interface, routing, and ARP tables
    - Supports SNMPv1, v2c, and v3
    """

    # Common SNMP OIDs
    OIDS = {
        "sysDescr": "1.3.6.1.2.1.1.1.0",
        "sysObjectID": "1.3.6.1.2.1.1.2.0",
        "sysUpTime": "1.3.6.1.2.1.1.3.0",
        "sysContact": "1.3.6.1.2.1.1.4.0",
        "sysName": "1.3.6.1.2.1.1.5.0",
        "sysLocation": "1.3.6.1.2.1.1.6.0",
        "ifNumber": "1.3.6.1.2.1.2.1.0",
    }

    def __init__(
        self,
        specialist_id: Optional[str] = None,
        llm_router: Optional["LLMRouter"] = None,
        default_community: str = "public",
    ):
        super().__init__(specialist_id, llm_router)
        self._default_community = default_community
        self._pysnmp_available = self._check_pysnmp()

    def _check_pysnmp(self) -> bool:
        """Check if pysnmp is available."""
        try:
            import pysnmp

            return True
        except ImportError:
            return False

    @property
    def capability(self) -> SpecialistCapability:
        return SpecialistCapability(
            name="SNMP Scan Specialist",
            task_types=[
                "scan.snmp",
                "discovery.scan.snmp",
                "discovery.device_info",
            ],
            protocols=["SNMP"],
            confidence=0.9,
            max_concurrent=5,
            description="Gathers device info via SNMP",
        )

    async def _do_execute(self, task: Task) -> TaskResult:
        """Perform SNMP scan."""
        target = task.parameters.get("target")
        community = task.parameters.get("community", self._default_community)
        version = task.parameters.get("version", "2c")
        port = task.parameters.get("port", 161)
        oids = task.parameters.get("oids", list(self.OIDS.keys()))

        if not target:
            return TaskResult(
                success=False,
                error="Target IP required for SNMP scan",
            )

        if self._pysnmp_available:
            results = await self._scan_with_pysnmp(target, community, version, port, oids)
        else:
            results = await self._scan_with_snmpwalk(target, community, version, oids)

        # Analyze results with LLM if available
        device_analysis = None
        if self._llm_router and results.get("sysDescr"):
            device_analysis = await self._analyze_device_with_llm(results)

        return TaskResult(
            success=True,
            output={
                "scan_type": "snmp",
                "target": target,
                "version": version,
                "system_info": {
                    "name": results.get("sysName"),
                    "description": results.get("sysDescr"),
                    "location": results.get("sysLocation"),
                    "contact": results.get("sysContact"),
                    "uptime": results.get("sysUpTime"),
                    "interface_count": results.get("ifNumber"),
                },
                "raw_oids": results,
                "device_analysis": device_analysis,
            },
            confidence=0.9,
            metadata={"scan_type": "snmp", "target": target},
        )

    async def _scan_with_pysnmp(
        self, target: str, community: str, version: str, port: int, oids: List[str]
    ) -> Dict[str, Any]:
        """Scan using pysnmp library."""
        try:
            from pysnmp.hlapi.asyncio import (
                getCmd,
                CommunityData,
                UdpTransportTarget,
                ContextData,
                ObjectType,
                ObjectIdentity,
            )

            results = {}

            for oid_name in oids:
                oid_value = self.OIDS.get(oid_name, oid_name)

                errorIndication, errorStatus, errorIndex, varBinds = await getCmd(
                    CommunityData(community, mpModel=1 if version == "2c" else 0),
                    UdpTransportTarget((target, port), timeout=5, retries=1),
                    ContextData(),
                    ObjectType(ObjectIdentity(oid_value)),
                )

                if errorIndication or errorStatus:
                    logger.debug(f"SNMP error for {oid_name}: {errorIndication or errorStatus}")
                    continue

                for varBind in varBinds:
                    results[oid_name] = str(varBind[1])

            return results

        except Exception as e:
            logger.error(f"pysnmp scan failed: {e}")
            return {}

    async def _scan_with_snmpwalk(
        self, target: str, community: str, version: str, oids: List[str]
    ) -> Dict[str, Any]:
        """Scan using snmpget command."""
        results = {}

        try:
            version_flag = "-v2c" if version == "2c" else "-v1"

            for oid_name in oids:
                oid_value = self.OIDS.get(oid_name, oid_name)

                proc = await asyncio.create_subprocess_exec(
                    "snmpget",
                    version_flag,
                    "-c",
                    community,
                    target,
                    oid_value,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.DEVNULL,
                )
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10)

                if stdout:
                    # Parse output: OID = TYPE: value
                    output = stdout.decode().strip()
                    if "=" in output:
                        value = output.split("=", 1)[1].strip()
                        # Remove type prefix (STRING:, INTEGER:, etc.)
                        if ":" in value:
                            value = value.split(":", 1)[1].strip().strip('"')
                        results[oid_name] = value

        except Exception as e:
            logger.error(f"snmpget scan failed: {e}")

        return results

    async def _analyze_device_with_llm(self, snmp_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Analyze SNMP data with LLM to identify device type."""
        system_prompt = """You are a network device identification expert.
Analyze the SNMP data and identify the device.
Respond with JSON:
{
    "device_type": "router/switch/firewall/server/printer/iot/unknown",
    "vendor": "manufacturer name",
    "model": "model if identifiable",
    "os": "operating system if identifiable",
    "role": "likely network role",
    "confidence": 0.0-1.0
}"""

        prompt = f"""Identify this network device from its SNMP data:

System Description: {snmp_data.get('sysDescr', 'N/A')}
System Name: {snmp_data.get('sysName', 'N/A')}
Object ID: {snmp_data.get('sysObjectID', 'N/A')}

Provide device identification as JSON:"""

        try:
            response = await self.llm_complete(
                prompt=prompt,
                task_category="anomaly_detection",  # Use fast model
                system_prompt=system_prompt,
            )

            if response:
                json_match = re.search(r"\{[\s\S]*\}", response)
                if json_match:
                    return json.loads(json_match.group())
        except Exception as e:
            logger.warning(f"LLM device analysis failed: {e}")

        return None


# ============================================================================
# VENDOR IDENTIFICATION SPECIALIST
# ============================================================================


class VendorIdentificationSpecialist(Specialist):
    """
    Vendor identification specialist using MAC OUI and LLM.

    Capabilities:
    - Looks up vendor from MAC OUI
    - Uses LLM to analyze device characteristics
    - Maintains confidence scores for identifications
    """

    def __init__(
        self,
        specialist_id: Optional[str] = None,
        llm_router: Optional["LLMRouter"] = None,
        oui_database: Optional[Dict[str, str]] = None,
    ):
        super().__init__(specialist_id, llm_router)
        self._oui_db = oui_database or OUI_DATABASE

    @property
    def capability(self) -> SpecialistCapability:
        return SpecialistCapability(
            name="Vendor Identification Specialist",
            task_types=[
                "classify.vendor",
                "discovery.classify.vendor",
                "discovery.identify",
            ],
            confidence=0.9,
            max_concurrent=10,
            description="Identifies device vendors from MAC addresses",
        )

    async def _do_execute(self, task: Task) -> TaskResult:
        """Identify device vendor."""
        mac = task.parameters.get("mac", "").upper().replace("-", ":")
        additional_info = task.parameters.get("additional_info", {})

        if not mac:
            return TaskResult(
                success=False,
                error="MAC address required for vendor identification",
            )

        # OUI lookup
        oui = mac[:8]
        vendor = self._oui_db.get(oui)
        confidence = 0.95 if vendor else 0.0

        # Try LLM analysis if no OUI match or additional info available
        llm_analysis = None
        if self._llm_router and (not vendor or additional_info):
            llm_analysis = await self._analyze_with_llm(mac, vendor, additional_info)
            if llm_analysis and not vendor:
                vendor = llm_analysis.get("vendor")
                confidence = llm_analysis.get("confidence", 0.7)

        return TaskResult(
            success=True,
            output={
                "mac": mac,
                "oui": oui,
                "vendor": vendor,
                "confidence": confidence,
                "llm_analysis": llm_analysis,
                "additional_info": additional_info,
            },
            confidence=confidence,
            metadata={"mac": mac},
        )

    async def _analyze_with_llm(
        self, mac: str, oui_vendor: Optional[str], additional_info: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        """Use LLM to analyze device characteristics."""
        system_prompt = """You are a network device identification expert.
Analyze the provided information and identify the device vendor and type.
Respond with JSON:
{
    "vendor": "manufacturer name",
    "device_type": "likely device type",
    "confidence": 0.0-1.0,
    "reasoning": "brief explanation"
}"""

        info_text = "\n".join([f"- {k}: {v}" for k, v in additional_info.items()])

        prompt = f"""Identify the vendor of this network device:

MAC Address: {mac}
OUI Vendor (if known): {oui_vendor or 'Unknown'}
Additional Information:
{info_text if info_text else 'None available'}

Provide identification as JSON:"""

        try:
            response = await self.llm_complete(
                prompt=prompt,
                task_category="anomaly_detection",
                system_prompt=system_prompt,
            )

            if response:
                json_match = re.search(r"\{[\s\S]*\}", response)
                if json_match:
                    return json.loads(json_match.group())
        except Exception as e:
            logger.warning(f"LLM vendor analysis failed: {e}")

        return None


# ============================================================================
# DEVICE FINGERPRINTING SPECIALIST
# ============================================================================


class DeviceFingerprintSpecialist(Specialist):
    """
    Device fingerprinting specialist using multiple signals.

    Capabilities:
    - Combines multiple data points for device identification
    - Uses TCP/IP stack fingerprinting hints
    - Leverages LLM for intelligent analysis
    """

    def __init__(
        self,
        specialist_id: Optional[str] = None,
        llm_router: Optional["LLMRouter"] = None,
    ):
        super().__init__(specialist_id, llm_router)

    @property
    def capability(self) -> SpecialistCapability:
        return SpecialistCapability(
            name="Device Fingerprint Specialist",
            task_types=[
                "classify.fingerprint",
                "discovery.classify.fingerprint",
                "discovery.fingerprint",
            ],
            confidence=0.85,
            max_concurrent=5,
            description="Fingerprints devices using multiple signals",
        )

    async def _do_execute(self, task: Task) -> TaskResult:
        """Fingerprint a device."""
        params = task.parameters

        # Collect all available signals
        signals = {
            "mac": params.get("mac"),
            "ip": params.get("ip"),
            "open_ports": params.get("open_ports", []),
            "ttl": params.get("ttl"),
            "tcp_window": params.get("tcp_window"),
            "snmp_data": params.get("snmp_data", {}),
            "http_headers": params.get("http_headers", {}),
            "hostname": params.get("hostname"),
            "mdns_name": params.get("mdns_name"),
        }

        # Rule-based fingerprinting
        rule_based = self._rule_based_fingerprint(signals)

        # LLM-based fingerprinting
        llm_fingerprint = None
        if self._llm_router:
            llm_fingerprint = await self._llm_fingerprint(signals)

        # Merge results
        final = self._merge_fingerprints(rule_based, llm_fingerprint)

        return TaskResult(
            success=True,
            output={
                "fingerprint": final,
                "signals_used": {k: v for k, v in signals.items() if v},
                "rule_based": rule_based,
                "llm_analysis": llm_fingerprint,
            },
            confidence=final.get("confidence", 0.7),
            metadata={"ip": params.get("ip"), "mac": params.get("mac")},
        )

    def _rule_based_fingerprint(self, signals: Dict[str, Any]) -> Dict[str, Any]:
        """Apply rule-based fingerprinting."""
        result = {
            "device_type": "unknown",
            "os_family": "unknown",
            "confidence": 0.5,
        }

        open_ports = signals.get("open_ports", [])
        ttl = signals.get("ttl")

        # OS detection from TTL
        if ttl:
            if ttl <= 64:
                result["os_family"] = "linux"
            elif ttl <= 128:
                result["os_family"] = "windows"
            else:
                result["os_family"] = "network_device"

        # Device type from ports
        if 22 in open_ports and 80 not in open_ports:
            result["device_type"] = "server"
        elif 80 in open_ports or 443 in open_ports:
            if 22 in open_ports:
                result["device_type"] = "server"
            else:
                result["device_type"] = "iot_or_appliance"
        elif 161 in open_ports:  # SNMP
            result["device_type"] = "network_device"
        elif 3389 in open_ports:  # RDP
            result["device_type"] = "windows_workstation"
            result["os_family"] = "windows"

        # Vendor hints from MAC
        mac = signals.get("mac", "").upper()
        if mac:
            oui = mac[:8]
            if oui in ["DC:A6:32", "B8:27:EB", "E4:5F:01"]:
                result["device_type"] = "raspberry_pi"
                result["os_family"] = "linux"
            elif oui in ["00:1A:79", "64:D1:54"]:
                result["device_type"] = "mikrotik_router"
                result["os_family"] = "routeros"
            elif oui in ["D4:01:C3", "FC:EC:DA", "24:A4:3C"]:
                result["device_type"] = "ubiquiti"
                result["os_family"] = "unifi"

        return result

    async def _llm_fingerprint(self, signals: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Use LLM for intelligent fingerprinting."""
        system_prompt = """You are a network device fingerprinting expert.
Analyze all available signals to identify the device.
Respond with JSON:
{
    "device_type": "specific device type",
    "os_family": "operating system family",
    "os_version": "version if identifiable",
    "vendor": "manufacturer",
    "model": "model if identifiable",
    "role": "network role (server, workstation, iot, network_device, etc.)",
    "confidence": 0.0-1.0,
    "reasoning": "brief explanation of identification"
}"""

        # Format signals for LLM
        signals_text = []
        for key, value in signals.items():
            if value:
                signals_text.append(f"- {key}: {value}")

        prompt = f"""Fingerprint this network device from the following signals:

{chr(10).join(signals_text)}

Provide device fingerprint as JSON:"""

        try:
            response = await self.llm_complete(
                prompt=prompt,
                task_category="log_analysis",  # Balanced model for analysis
                system_prompt=system_prompt,
            )

            if response:
                json_match = re.search(r"\{[\s\S]*\}", response)
                if json_match:
                    return json.loads(json_match.group())
        except Exception as e:
            logger.warning(f"LLM fingerprinting failed: {e}")

        return None

    def _merge_fingerprints(
        self, rule_based: Dict[str, Any], llm_based: Optional[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Merge rule-based and LLM fingerprints."""
        if not llm_based:
            return rule_based

        # Prefer LLM for most fields, but validate against rules
        result = llm_based.copy()

        # If rule-based has high confidence on OS, verify LLM agrees
        if rule_based.get("os_family") != "unknown":
            if rule_based["os_family"] == llm_based.get("os_family"):
                result["confidence"] = min(result.get("confidence", 0.8) + 0.1, 1.0)
            else:
                # Disagreement, lower confidence
                result["confidence"] = max(result.get("confidence", 0.8) - 0.2, 0.3)
                result["os_family_conflict"] = {
                    "rule_based": rule_based["os_family"],
                    "llm_based": llm_based.get("os_family"),
                }

        return result
