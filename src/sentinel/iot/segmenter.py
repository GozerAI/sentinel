"""
IoT Device Segmenter for Sentinel.

Automatically segments IoT devices into appropriate VLANs based on
their classification, security risk, and network behavior. Integrates
with MikroTik/router to apply segmentation rules.
"""
import asyncio
import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional, Any, TYPE_CHECKING
from uuid import UUID

from sentinel.iot.classifier import (
    IoTClassifier,
    DeviceClass,
    ClassificationResult,
    SecurityRisk,
)

if TYPE_CHECKING:
    from sentinel.integrations.routers.mikrotik import MikroTikIntegration

logger = logging.getLogger(__name__)


@dataclass
class VLANPolicy:
    """Policy defining a VLAN and what devices belong in it."""
    vlan_id: int
    name: str
    description: str = ""

    # Device classes assigned to this VLAN
    device_classes: list[DeviceClass] = field(default_factory=list)

    # Security settings
    internet_access: bool = True
    local_access: bool = True  # Can talk to other devices on same VLAN
    cross_vlan_access: list[int] = field(default_factory=list)  # Other VLANs it can reach

    # Rate limits (0 = unlimited)
    rate_limit_upload_kbps: int = 0
    rate_limit_download_kbps: int = 0

    # Firewall rules
    allowed_ports_out: list[int] = field(default_factory=list)  # Empty = all allowed
    blocked_ports_out: list[int] = field(default_factory=list)
    allowed_ports_in: list[int] = field(default_factory=list)  # Inbound allowed
    blocked_ports_in: list[int] = field(default_factory=list)

    # DNS settings
    force_dns: Optional[str] = None  # Force devices to use specific DNS
    block_dns_over_https: bool = False

    # Isolation
    isolate_clients: bool = False  # Prevent devices from seeing each other

    def matches_device(self, result: ClassificationResult) -> bool:
        """Check if a device belongs in this VLAN based on its classification."""
        return result.device_class in self.device_classes


@dataclass
class SegmentationAction:
    """Record of a segmentation action taken."""
    device_mac: str
    device_ip: str
    device_class: DeviceClass
    from_vlan: Optional[int]
    to_vlan: int
    reason: str
    timestamp: datetime = field(default_factory=datetime.utcnow)
    success: bool = True
    error: str = ""

    def to_dict(self) -> dict:
        return {
            "device_mac": self.device_mac,
            "device_ip": self.device_ip,
            "device_class": self.device_class.value,
            "from_vlan": self.from_vlan,
            "to_vlan": self.to_vlan,
            "reason": self.reason,
            "timestamp": self.timestamp.isoformat(),
            "success": self.success,
            "error": self.error,
        }


class IoTSegmenter:
    """
    Automatically segments IoT devices into appropriate VLANs.

    Uses device classification to determine appropriate network segment,
    then applies VLAN assignment via router integration (MikroTik).

    Example:
        ```python
        classifier = IoTClassifier()
        segmenter = IoTSegmenter(classifier)

        # Define VLANs
        segmenter.add_policy(VLANPolicy(
            vlan_id=50,
            name="IoT",
            device_classes=[
                DeviceClass.SMART_SPEAKER,
                DeviceClass.SMART_TV,
                DeviceClass.STREAMING_DEVICE,
            ],
            internet_access=True,
            local_access=True,
            cross_vlan_access=[],  # Isolated from other VLANs
        ))

        # Set router integration
        segmenter.set_router(mikrotik)

        # Segment a device
        result = await classifier.classify(mac="AA:BB:CC:DD:EE:FF", ip="192.168.1.100")
        action = await segmenter.segment_device(result)
        ```
    """

    def __init__(self, classifier: IoTClassifier):
        self.classifier = classifier
        self._router: Optional[Any] = None  # MikroTik or similar

        # VLAN policies
        self._policies: dict[int, VLANPolicy] = {}

        # Device assignments (MAC -> VLAN)
        self._assignments: dict[str, int] = {}

        # Action history
        self._actions: list[SegmentationAction] = []
        self._max_history = 1000

        # Default policies
        self._setup_default_policies()

    def _setup_default_policies(self) -> None:
        """Setup default VLAN policies."""
        # VLAN 1 - Management (default/native)
        self.add_policy(VLANPolicy(
            vlan_id=1,
            name="Management",
            description="Network infrastructure and management",
            device_classes=[
                DeviceClass.ROUTER,
                DeviceClass.SWITCH,
                DeviceClass.ACCESS_POINT,
            ],
            internet_access=True,
            local_access=True,
            cross_vlan_access=[10, 20, 50, 100],  # Can manage all VLANs
        ))

        # VLAN 10 - Trusted Devices
        self.add_policy(VLANPolicy(
            vlan_id=10,
            name="Trusted",
            description="Personal computers and trusted devices",
            device_classes=[
                DeviceClass.DESKTOP,
                DeviceClass.LAPTOP,
                DeviceClass.WORKSTATION,
                DeviceClass.SMARTPHONE,
                DeviceClass.TABLET,
            ],
            internet_access=True,
            local_access=True,
            cross_vlan_access=[50, 100],  # Can access IoT and servers
        ))

        # VLAN 20 - Guest Network
        self.add_policy(VLANPolicy(
            vlan_id=20,
            name="Guest",
            description="Guest devices with internet only",
            device_classes=[],  # Manually assigned
            internet_access=True,
            local_access=False,
            cross_vlan_access=[],
            isolate_clients=True,
            rate_limit_download_kbps=50000,  # 50 Mbps
            rate_limit_upload_kbps=10000,    # 10 Mbps
        ))

        # VLAN 50 - IoT Devices
        self.add_policy(VLANPolicy(
            vlan_id=50,
            name="IoT",
            description="Smart home and IoT devices",
            device_classes=[
                DeviceClass.SMART_TV,
                DeviceClass.STREAMING_DEVICE,
                DeviceClass.SMART_SPEAKER,
                DeviceClass.SMART_PLUG,
                DeviceClass.SMART_BULB,
                DeviceClass.SMART_SWITCH,
                DeviceClass.SMART_DIMMER,
                DeviceClass.THERMOSTAT,
                DeviceClass.ROBOT_VACUUM,
                DeviceClass.SMART_APPLIANCE,
                DeviceClass.SMART_HUB,
                DeviceClass.ZIGBEE_HUB,
                DeviceClass.ZWAVE_HUB,
                DeviceClass.MATTER_HUB,
                DeviceClass.GAME_CONSOLE,
                DeviceClass.PRINTER,
                DeviceClass.VOIP_PHONE,
                DeviceClass.IOT_GENERIC,
            ],
            internet_access=True,
            local_access=True,
            cross_vlan_access=[],  # Can't reach other VLANs
            block_dns_over_https=True,
        ))

        # VLAN 55 - Security/Isolated IoT
        self.add_policy(VLANPolicy(
            vlan_id=55,
            name="Security",
            description="Security cameras and high-risk IoT",
            device_classes=[
                DeviceClass.SECURITY_CAMERA,
                DeviceClass.NVR,
                DeviceClass.DVR,
                DeviceClass.DOORBELL,
                DeviceClass.SMART_LOCK,
                DeviceClass.MOTION_SENSOR,
                DeviceClass.ALARM_PANEL,
            ],
            internet_access=False,  # No cloud access by default
            local_access=True,
            cross_vlan_access=[100],  # Can only reach NVR/storage
            isolate_clients=False,  # Cameras need to reach NVR
            allowed_ports_out=[554, 80, 443],  # RTSP and HTTP
        ))

        # VLAN 100 - Servers/Infrastructure
        self.add_policy(VLANPolicy(
            vlan_id=100,
            name="Infrastructure",
            description="Servers, NAS, and compute resources",
            device_classes=[
                DeviceClass.SERVER,
                DeviceClass.NAS,
                DeviceClass.RASPBERRY_PI,
                DeviceClass.SINGLE_BOARD,
            ],
            internet_access=True,
            local_access=True,
            cross_vlan_access=[1, 10, 50, 55],  # Full access for management
        ))

    def add_policy(self, policy: VLANPolicy) -> None:
        """Add or update a VLAN policy."""
        self._policies[policy.vlan_id] = policy
        logger.info(f"Added VLAN policy: {policy.vlan_id} ({policy.name})")

    def remove_policy(self, vlan_id: int) -> bool:
        """Remove a VLAN policy."""
        if vlan_id in self._policies:
            del self._policies[vlan_id]
            return True
        return False

    def get_policy(self, vlan_id: int) -> Optional[VLANPolicy]:
        """Get a VLAN policy by ID."""
        return self._policies.get(vlan_id)

    def get_policies(self) -> list[VLANPolicy]:
        """Get all VLAN policies."""
        return list(self._policies.values())

    def set_router(self, router) -> None:
        """Set the router integration for applying segmentation."""
        self._router = router

    def determine_vlan(self, result: ClassificationResult) -> Optional[int]:
        """
        Determine the appropriate VLAN for a classified device.

        Args:
            result: Device classification result

        Returns:
            VLAN ID or None if no matching policy
        """
        # Check if device has a recommended VLAN from its profile
        if result.profile and result.profile.recommended_vlan:
            return result.profile.recommended_vlan

        # Find matching policy by device class
        for policy in self._policies.values():
            if policy.matches_device(result):
                return policy.vlan_id

        # High-risk devices go to isolated VLAN
        if result.security_risk in [SecurityRisk.HIGH, SecurityRisk.CRITICAL]:
            return 55  # Security VLAN

        # Default: unknown devices to IoT VLAN
        if result.device_class == DeviceClass.UNKNOWN:
            return 50

        return None

    async def segment_device(
        self,
        result: ClassificationResult,
        force_vlan: Optional[int] = None,
        dry_run: bool = False
    ) -> SegmentationAction:
        """
        Segment a device into appropriate VLAN.

        Args:
            result: Device classification result
            force_vlan: Override automatic VLAN selection
            dry_run: If True, don't apply changes

        Returns:
            SegmentationAction with results
        """
        # Determine target VLAN
        target_vlan = force_vlan or self.determine_vlan(result)

        if target_vlan is None:
            return SegmentationAction(
                device_mac=result.mac_address,
                device_ip=result.ip_address,
                device_class=result.device_class,
                from_vlan=None,
                to_vlan=0,
                reason="No matching VLAN policy",
                success=False,
                error="Could not determine target VLAN",
            )

        # Get current VLAN assignment
        current_vlan = self._assignments.get(result.mac_address)

        # Skip if already in correct VLAN
        if current_vlan == target_vlan:
            return SegmentationAction(
                device_mac=result.mac_address,
                device_ip=result.ip_address,
                device_class=result.device_class,
                from_vlan=current_vlan,
                to_vlan=target_vlan,
                reason="Already in correct VLAN",
                success=True,
            )

        # Build reason string
        reason = f"Classified as {result.device_class.value}"
        if result.security_risk in [SecurityRisk.HIGH, SecurityRisk.CRITICAL]:
            reason += f" (risk: {result.security_risk.value})"
        if force_vlan:
            reason = f"Manual assignment to VLAN {force_vlan}"

        action = SegmentationAction(
            device_mac=result.mac_address,
            device_ip=result.ip_address,
            device_class=result.device_class,
            from_vlan=current_vlan,
            to_vlan=target_vlan,
            reason=reason,
        )

        if dry_run:
            action.reason = f"[DRY RUN] {action.reason}"
            return action

        # Apply segmentation via router
        if self._router:
            try:
                await self._apply_vlan_assignment(
                    result.mac_address,
                    result.ip_address,
                    target_vlan
                )
                action.success = True
            except Exception as e:
                action.success = False
                action.error = str(e)
                logger.error(f"Failed to segment {result.mac_address}: {e}")
        else:
            # No router, just track locally
            action.success = True

        # Update local tracking
        if action.success:
            self._assignments[result.mac_address] = target_vlan

        # Record action
        self._actions.append(action)
        if len(self._actions) > self._max_history:
            self._actions = self._actions[-self._max_history:]

        return action

    async def _apply_vlan_assignment(
        self,
        mac_address: str,
        ip_address: str,
        vlan_id: int
    ) -> None:
        """
        Apply VLAN assignment via router.

        For MikroTik, this creates a MAC-based VLAN assignment in
        the bridge VLAN table and optionally a firewall rule.
        """
        if not self._router:
            return

        policy = self._policies.get(vlan_id)
        if not policy:
            raise ValueError(f"No policy for VLAN {vlan_id}")

        # MikroTik-specific implementation
        # This would vary based on router type

        try:
            # Add to bridge VLAN
            await self._router.execute("/interface/bridge/vlan/add", params={
                "bridge": "bridge",
                "tagged": "",
                "untagged": "",  # Would need port info
                "vlan-ids": str(vlan_id),
            })

            # Create firewall filter for the device
            if not policy.internet_access:
                await self._router.execute("/ip/firewall/filter/add", params={
                    "chain": "forward",
                    "src-address": ip_address,
                    "out-interface": "ether1",  # WAN interface
                    "action": "drop",
                    "comment": f"Sentinel: Block internet for {mac_address}",
                })

            # Apply rate limits if configured
            if policy.rate_limit_download_kbps > 0 or policy.rate_limit_upload_kbps > 0:
                await self._router.execute("/queue/simple/add", params={
                    "name": f"sentinel-{mac_address.replace(':', '')}",
                    "target": ip_address,
                    "max-limit": f"{policy.rate_limit_upload_kbps}k/{policy.rate_limit_download_kbps}k",
                    "comment": f"Sentinel: Rate limit for {mac_address}",
                })

            logger.info(f"Applied VLAN {vlan_id} to {mac_address} ({ip_address})")

        except Exception as e:
            logger.error(f"Router configuration failed: {e}")
            raise

    async def segment_all_devices(self, dry_run: bool = False) -> list[SegmentationAction]:
        """
        Segment all classified devices.

        Args:
            dry_run: If True, don't apply changes

        Returns:
            List of all segmentation actions
        """
        actions = []

        for result in self.classifier.get_all_classifications():
            action = await self.segment_device(result, dry_run=dry_run)
            actions.append(action)

        return actions

    async def audit_segmentation(self) -> dict:
        """
        Audit current network segmentation.

        Returns summary of devices per VLAN, policy violations, etc.
        """
        audit = {
            "vlans": {},
            "unassigned": [],
            "violations": [],
            "high_risk": [],
        }

        # Count devices per VLAN
        for mac, vlan in self._assignments.items():
            if vlan not in audit["vlans"]:
                audit["vlans"][vlan] = {
                    "policy": self._policies.get(vlan),
                    "devices": [],
                }
            audit["vlans"][vlan]["devices"].append(mac)

        # Find unassigned devices
        for result in self.classifier.get_all_classifications():
            if result.mac_address not in self._assignments:
                audit["unassigned"].append({
                    "mac": result.mac_address,
                    "ip": result.ip_address,
                    "class": result.device_class.value,
                })

            # Check for policy violations
            current_vlan = self._assignments.get(result.mac_address)
            expected_vlan = self.determine_vlan(result)

            if current_vlan and expected_vlan and current_vlan != expected_vlan:
                audit["violations"].append({
                    "mac": result.mac_address,
                    "current_vlan": current_vlan,
                    "expected_vlan": expected_vlan,
                    "class": result.device_class.value,
                })

            # Track high-risk devices
            if result.security_risk in [SecurityRisk.HIGH, SecurityRisk.CRITICAL]:
                audit["high_risk"].append({
                    "mac": result.mac_address,
                    "ip": result.ip_address,
                    "class": result.device_class.value,
                    "risk": result.security_risk.value,
                    "vlan": current_vlan,
                    "factors": result.risk_factors,
                })

        return audit

    def get_device_vlan(self, mac_address: str) -> Optional[int]:
        """Get current VLAN assignment for a device."""
        return self._assignments.get(mac_address.upper())

    def get_devices_in_vlan(self, vlan_id: int) -> list[str]:
        """Get all devices assigned to a VLAN."""
        return [mac for mac, vlan in self._assignments.items() if vlan == vlan_id]

    def get_action_history(self, limit: int = 100) -> list[SegmentationAction]:
        """Get recent segmentation actions."""
        return self._actions[-limit:]

    def get_statistics(self) -> dict:
        """Get segmentation statistics."""
        vlan_counts = {}
        for vlan in self._assignments.values():
            vlan_counts[vlan] = vlan_counts.get(vlan, 0) + 1

        return {
            "total_devices": len(self._assignments),
            "vlan_distribution": vlan_counts,
            "policies_defined": len(self._policies),
            "actions_taken": len(self._actions),
        }
