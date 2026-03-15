"""
IoT Device Classifier for Sentinel.

Automatically identifies and classifies IoT devices on the network
using multiple fingerprinting techniques:
- MAC OUI (Manufacturer) lookup
- DHCP fingerprinting
- HTTP User-Agent analysis
- mDNS/Bonjour discovery
- Traffic pattern analysis
- Open port signatures
"""
import asyncio
import logging
import re
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional, Any
from uuid import UUID, uuid4

logger = logging.getLogger(__name__)


class DeviceClass(Enum):
    """High-level device classification."""
    # Infrastructure
    ROUTER = "router"
    SWITCH = "switch"
    ACCESS_POINT = "access_point"
    NAS = "nas"
    SERVER = "server"

    # Compute
    DESKTOP = "desktop"
    LAPTOP = "laptop"
    WORKSTATION = "workstation"
    RASPBERRY_PI = "raspberry_pi"
    SINGLE_BOARD = "single_board_computer"

    # Mobile
    SMARTPHONE = "smartphone"
    TABLET = "tablet"

    # Smart Home - Security
    SECURITY_CAMERA = "security_camera"
    NVR = "nvr"
    DVR = "dvr"
    DOORBELL = "doorbell"
    SMART_LOCK = "smart_lock"
    MOTION_SENSOR = "motion_sensor"
    ALARM_PANEL = "alarm_panel"

    # Smart Home - Climate
    THERMOSTAT = "thermostat"
    HVAC_CONTROLLER = "hvac_controller"
    SMART_VENT = "smart_vent"
    WEATHER_STATION = "weather_station"
    AIR_QUALITY = "air_quality_sensor"

    # Smart Home - Lighting
    SMART_BULB = "smart_bulb"
    SMART_SWITCH = "smart_switch"
    SMART_DIMMER = "smart_dimmer"
    LED_CONTROLLER = "led_controller"

    # Smart Home - Entertainment
    SMART_TV = "smart_tv"
    STREAMING_DEVICE = "streaming_device"
    SMART_SPEAKER = "smart_speaker"
    GAME_CONSOLE = "game_console"
    MEDIA_PLAYER = "media_player"

    # Smart Home - Appliances
    SMART_PLUG = "smart_plug"
    SMART_APPLIANCE = "smart_appliance"
    ROBOT_VACUUM = "robot_vacuum"
    WASHER_DRYER = "washer_dryer"
    REFRIGERATOR = "refrigerator"
    OVEN = "oven"
    DISHWASHER = "dishwasher"
    GARAGE_DOOR = "garage_door"
    SPRINKLER = "sprinkler_controller"
    POOL_CONTROLLER = "pool_controller"

    # Smart Home - Hubs
    SMART_HUB = "smart_hub"
    ZIGBEE_HUB = "zigbee_hub"
    ZWAVE_HUB = "zwave_hub"
    MATTER_HUB = "matter_hub"

    # Health & Wellness
    FITNESS_TRACKER = "fitness_tracker"
    SMART_SCALE = "smart_scale"
    HEALTH_MONITOR = "health_monitor"
    SLEEP_TRACKER = "sleep_tracker"

    # Printers & Office
    PRINTER = "printer"
    SCANNER = "scanner"
    MFP = "multifunction_printer"
    VOIP_PHONE = "voip_phone"

    # Industrial
    PLC = "plc"
    HMI = "hmi"
    INDUSTRIAL_SENSOR = "industrial_sensor"

    # Unknown/Other
    IOT_GENERIC = "iot_generic"
    UNKNOWN = "unknown"


class SecurityRisk(Enum):
    """Security risk level for devices."""
    CRITICAL = "critical"  # Known vulnerabilities, no updates
    HIGH = "high"          # Poor security practices
    MEDIUM = "medium"      # Limited security features
    LOW = "low"            # Good security model
    MINIMAL = "minimal"    # Well-secured device


@dataclass
class DeviceProfile:
    """
    Known device profile for fingerprinting.

    Contains patterns to match devices and their characteristics.
    """
    name: str
    manufacturer: str
    device_class: DeviceClass
    security_risk: SecurityRisk = SecurityRisk.MEDIUM

    # Matching patterns
    oui_prefixes: list[str] = field(default_factory=list)  # MAC OUI prefixes
    hostname_patterns: list[str] = field(default_factory=list)  # Regex patterns
    dhcp_vendor_class: list[str] = field(default_factory=list)
    user_agent_patterns: list[str] = field(default_factory=list)
    mdns_services: list[str] = field(default_factory=list)
    open_ports: list[int] = field(default_factory=list)

    # Network behavior
    typical_bandwidth_kbps: int = 0
    typical_connections_per_hour: int = 0
    cloud_dependent: bool = False
    requires_internet: bool = False

    # Recommended settings
    recommended_vlan: Optional[int] = None
    block_internet: bool = False
    block_local: bool = False
    rate_limit_kbps: Optional[int] = None

    # Risk factors
    risk_factors: list[str] = field(default_factory=list)


@dataclass
class ClassificationResult:
    """Result of device classification."""
    device_id: UUID = field(default_factory=uuid4)
    mac_address: str = ""
    ip_address: str = ""
    hostname: str = ""

    # Classification
    device_class: DeviceClass = DeviceClass.UNKNOWN
    profile: Optional[DeviceProfile] = None
    confidence: float = 0.0  # 0.0 to 1.0

    # Identification
    manufacturer: str = ""
    model: str = ""
    firmware_version: str = ""

    # Risk assessment
    security_risk: SecurityRisk = SecurityRisk.MEDIUM
    risk_factors: list[str] = field(default_factory=list)

    # Classification details
    classification_method: str = ""  # Which method determined the class
    matched_patterns: list[str] = field(default_factory=list)

    # Timestamps
    first_seen: datetime = field(default_factory=datetime.utcnow)
    last_seen: datetime = field(default_factory=datetime.utcnow)
    classified_at: datetime = field(default_factory=datetime.utcnow)

    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            "device_id": str(self.device_id),
            "mac_address": self.mac_address,
            "ip_address": self.ip_address,
            "hostname": self.hostname,
            "device_class": self.device_class.value,
            "confidence": self.confidence,
            "manufacturer": self.manufacturer,
            "model": self.model,
            "firmware_version": self.firmware_version,
            "security_risk": self.security_risk.value,
            "risk_factors": self.risk_factors,
            "classification_method": self.classification_method,
            "matched_patterns": self.matched_patterns,
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
            "classified_at": self.classified_at.isoformat(),
        }


class IoTClassifier:
    """
    Classifies IoT devices using multiple fingerprinting methods.

    Example:
        ```python
        classifier = IoTClassifier()

        # Classify by MAC address
        result = await classifier.classify(
            mac_address="AA:BB:CC:DD:EE:FF",
            ip_address="192.168.1.100"
        )

        print(f"Device: {result.device_class.value}")
        print(f"Confidence: {result.confidence:.0%}")
        print(f"Risk: {result.security_risk.value}")
        ```
    """

    def __init__(self):
        self._profiles: list[DeviceProfile] = []
        self._oui_database: dict[str, str] = {}
        self._classified_devices: dict[str, ClassificationResult] = {}  # By MAC

        # Load built-in profiles
        self._load_default_profiles()
        self._load_oui_database()

    def _load_default_profiles(self) -> None:
        """Load default device profiles."""
        # This would typically load from a file/database
        # Here we define common profiles inline

        self._profiles = [
            # Raspberry Pi
            DeviceProfile(
                name="Raspberry Pi",
                manufacturer="Raspberry Pi Foundation",
                device_class=DeviceClass.RASPBERRY_PI,
                security_risk=SecurityRisk.LOW,
                oui_prefixes=["B8:27:EB", "DC:A6:32", "E4:5F:01", "D8:3A:DD", "2C:CF:67"],
                hostname_patterns=[r"^raspberrypi.*", r"^rpi.*"],
                mdns_services=["_ssh._tcp", "_sftp-ssh._tcp"],
                recommended_vlan=100,  # Infrastructure
            ),

            # Ring Doorbell/Camera
            DeviceProfile(
                name="Ring Doorbell/Camera",
                manufacturer="Ring (Amazon)",
                device_class=DeviceClass.DOORBELL,
                security_risk=SecurityRisk.MEDIUM,
                oui_prefixes=["34:76:C5", "4C:83:DE", "64:9B:24", "F0:AE:D7"],
                hostname_patterns=[r"^ring.*", r".*ring.*doorbell.*"],
                dhcp_vendor_class=["ring"],
                cloud_dependent=True,
                requires_internet=True,
                recommended_vlan=50,  # IoT
            ),

            # Nest Thermostat
            DeviceProfile(
                name="Nest Thermostat",
                manufacturer="Google/Nest",
                device_class=DeviceClass.THERMOSTAT,
                security_risk=SecurityRisk.LOW,
                oui_prefixes=["18:B4:30", "64:16:66", "D8:EB:46"],
                hostname_patterns=[r"^nest.*", r".*thermostat.*"],
                cloud_dependent=True,
                requires_internet=True,
                recommended_vlan=50,
            ),

            # Philips Hue
            DeviceProfile(
                name="Philips Hue Bridge",
                manufacturer="Signify (Philips)",
                device_class=DeviceClass.ZIGBEE_HUB,
                security_risk=SecurityRisk.LOW,
                oui_prefixes=["00:17:88", "EC:B5:FA"],
                hostname_patterns=[r"^philips-hue.*", r"^hue-bridge.*"],
                open_ports=[80, 443, 8080],
                cloud_dependent=False,
                requires_internet=False,
                recommended_vlan=50,
            ),

            # Amazon Echo
            DeviceProfile(
                name="Amazon Echo",
                manufacturer="Amazon",
                device_class=DeviceClass.SMART_SPEAKER,
                security_risk=SecurityRisk.MEDIUM,
                oui_prefixes=["18:74:2E", "34:D2:70", "44:65:0D", "68:54:FD", "84:D6:D0", "A0:02:DC", "FC:65:DE"],
                hostname_patterns=[r"^amazon-.*", r"^echo-.*"],
                cloud_dependent=True,
                requires_internet=True,
                recommended_vlan=50,
            ),

            # Google Home/Nest
            DeviceProfile(
                name="Google Home/Nest",
                manufacturer="Google",
                device_class=DeviceClass.SMART_SPEAKER,
                security_risk=SecurityRisk.LOW,
                oui_prefixes=["20:DF:B9", "30:FD:38", "44:07:0B", "54:60:09", "6C:AD:F8", "94:EB:2C", "F4:F5:D8"],
                hostname_patterns=[r"^google-home.*", r"^google-nest.*"],
                cloud_dependent=True,
                requires_internet=True,
                recommended_vlan=50,
            ),

            # Samsung SmartTV
            DeviceProfile(
                name="Samsung Smart TV",
                manufacturer="Samsung",
                device_class=DeviceClass.SMART_TV,
                security_risk=SecurityRisk.MEDIUM,
                oui_prefixes=["00:07:AB", "00:1A:8A", "00:1E:E1", "14:49:BC", "18:67:B0", "28:6A:BA", "40:0E:85"],
                hostname_patterns=[r"^samsung.*tv.*", r"^tizen.*"],
                open_ports=[8001, 8002, 9197],  # Samsung TV ports
                recommended_vlan=50,
            ),

            # Apple TV
            DeviceProfile(
                name="Apple TV",
                manufacturer="Apple",
                device_class=DeviceClass.STREAMING_DEVICE,
                security_risk=SecurityRisk.MINIMAL,
                oui_prefixes=["28:6A:B8", "40:6C:8F", "60:C5:47", "7C:C3:A1", "90:DD:5D"],
                hostname_patterns=[r"^apple-tv.*", r"^appletv.*"],
                mdns_services=["_airplay._tcp", "_raop._tcp"],
                recommended_vlan=50,
            ),

            # Roku
            DeviceProfile(
                name="Roku Streaming Device",
                manufacturer="Roku",
                device_class=DeviceClass.STREAMING_DEVICE,
                security_risk=SecurityRisk.LOW,
                oui_prefixes=["00:0D:4B", "84:EA:ED", "B0:A7:37", "B8:3E:59", "C8:3A:6B", "D8:31:34"],
                hostname_patterns=[r"^roku.*"],
                open_ports=[8060],  # Roku ECP
                recommended_vlan=50,
            ),

            # Chromecast
            DeviceProfile(
                name="Chromecast",
                manufacturer="Google",
                device_class=DeviceClass.STREAMING_DEVICE,
                security_risk=SecurityRisk.LOW,
                oui_prefixes=["54:60:09", "6C:AD:F8", "80:D2:1D", "94:EB:2C", "F4:F5:D8"],
                hostname_patterns=[r"^chromecast.*", r"^google-cast.*"],
                mdns_services=["_googlecast._tcp"],
                recommended_vlan=50,
            ),

            # Roomba/iRobot
            DeviceProfile(
                name="iRobot Roomba",
                manufacturer="iRobot",
                device_class=DeviceClass.ROBOT_VACUUM,
                security_risk=SecurityRisk.MEDIUM,
                oui_prefixes=["50:14:79", "80:C5:48"],
                hostname_patterns=[r"^irobot.*", r"^roomba.*"],
                cloud_dependent=True,
                requires_internet=True,
                recommended_vlan=50,
            ),

            # Wyze Camera
            DeviceProfile(
                name="Wyze Camera",
                manufacturer="Wyze",
                device_class=DeviceClass.SECURITY_CAMERA,
                security_risk=SecurityRisk.HIGH,  # Known security issues
                oui_prefixes=["2C:AA:8E", "D0:3F:27"],
                hostname_patterns=[r"^wyze.*"],
                cloud_dependent=True,
                requires_internet=True,
                recommended_vlan=50,
                risk_factors=["Cloud-dependent", "History of security vulnerabilities"],
            ),

            # TP-Link/Kasa
            DeviceProfile(
                name="TP-Link Kasa Smart Plug",
                manufacturer="TP-Link",
                device_class=DeviceClass.SMART_PLUG,
                security_risk=SecurityRisk.MEDIUM,
                oui_prefixes=["50:C7:BF", "54:AF:97", "60:A4:B7", "68:FF:7B", "70:4F:57", "98:DA:C4", "B0:95:75"],
                hostname_patterns=[r"^hs.*", r"^ks.*", r"^kasa.*"],
                open_ports=[9999],  # Kasa protocol
                recommended_vlan=50,
            ),

            # UniFi Devices
            DeviceProfile(
                name="Ubiquiti UniFi Device",
                manufacturer="Ubiquiti",
                device_class=DeviceClass.ACCESS_POINT,
                security_risk=SecurityRisk.MINIMAL,
                oui_prefixes=["00:27:22", "04:18:D6", "18:E8:29", "24:5A:4C", "44:D9:E7", "68:72:51", "74:83:C2", "78:45:58", "80:2A:A8", "B4:FB:E4", "DC:9F:DB", "F0:9F:C2", "FC:EC:DA"],
                hostname_patterns=[r"^uap.*", r"^usw.*", r"^ubnt.*", r".*unifi.*"],
                open_ports=[22, 443, 8080],
                recommended_vlan=1,  # Management VLAN
            ),

            # Synology NAS
            DeviceProfile(
                name="Synology NAS",
                manufacturer="Synology",
                device_class=DeviceClass.NAS,
                security_risk=SecurityRisk.LOW,
                oui_prefixes=["00:11:32"],
                hostname_patterns=[r"^synology.*", r"^ds\d+.*", r"^rs\d+.*"],
                open_ports=[5000, 5001],  # DSM ports
                recommended_vlan=100,
            ),

            # QNAP NAS
            DeviceProfile(
                name="QNAP NAS",
                manufacturer="QNAP",
                device_class=DeviceClass.NAS,
                security_risk=SecurityRisk.MEDIUM,  # Some historical vulnerabilities
                oui_prefixes=["00:08:9B", "24:5E:BE"],
                hostname_patterns=[r"^qnap.*", r"^ts-\d+.*"],
                open_ports=[8080, 443],
                recommended_vlan=100,
            ),

            # PlayStation
            DeviceProfile(
                name="Sony PlayStation",
                manufacturer="Sony",
                device_class=DeviceClass.GAME_CONSOLE,
                security_risk=SecurityRisk.LOW,
                oui_prefixes=["00:04:1F", "00:1D:0D", "00:19:C5", "00:24:8D", "28:0D:FC", "70:9E:29", "A8:E3:EE", "F8:46:1C"],
                hostname_patterns=[r"^playstation.*", r"^ps[345].*"],
                recommended_vlan=50,
            ),

            # Xbox
            DeviceProfile(
                name="Microsoft Xbox",
                manufacturer="Microsoft",
                device_class=DeviceClass.GAME_CONSOLE,
                security_risk=SecurityRisk.LOW,
                oui_prefixes=["00:0D:3A", "00:50:F2", "28:18:78", "60:45:BD", "7C:ED:8D", "98:5F:D3", "C8:3F:26"],
                hostname_patterns=[r"^xbox.*"],
                recommended_vlan=50,
            ),

            # Nintendo Switch
            DeviceProfile(
                name="Nintendo Switch",
                manufacturer="Nintendo",
                device_class=DeviceClass.GAME_CONSOLE,
                security_risk=SecurityRisk.LOW,
                oui_prefixes=["00:1B:EA", "00:1E:35", "00:1F:32", "00:22:4C", "00:22:AA", "00:24:F3", "00:25:A0", "2C:10:C1", "34:AF:2C", "40:F4:07", "58:BD:A3", "78:A2:A0", "7C:BB:8A", "8C:CD:E8", "98:41:5C", "98:B6:E9", "A4:38:CC", "A4:C0:E1", "B8:8A:EC", "CC:9E:00", "D8:6B:F7", "E0:E7:51", "E8:4E:CE"],
                hostname_patterns=[r"^nintendo.*", r"^switch.*"],
                recommended_vlan=50,
            ),

            # HP Printer
            DeviceProfile(
                name="HP Printer",
                manufacturer="HP",
                device_class=DeviceClass.PRINTER,
                security_risk=SecurityRisk.MEDIUM,
                oui_prefixes=["00:00:63", "00:01:E6", "00:0F:20", "00:10:83", "00:11:0A", "00:12:79", "00:14:38", "00:14:C2", "00:17:A4", "00:1A:4B", "00:1B:78", "00:1C:C4", "00:1E:0B", "00:1F:29", "00:21:5A", "00:22:64", "00:23:7D", "00:24:81", "00:25:B3", "1C:C1:DE", "2C:27:D7", "30:CD:A7", "3C:2A:F4", "40:B9:3C", "64:51:06", "6C:C2:17", "80:CE:62", "94:57:A5", "A0:D3:C1", "C4:34:6B", "E4:11:5B", "F4:30:B9"],
                hostname_patterns=[r"^hp.*printer.*", r"^hpofficejet.*", r"^hplaserjet.*", r"^hpenvy.*"],
                open_ports=[80, 443, 631, 9100],
                recommended_vlan=50,
            ),

            # Brother Printer
            DeviceProfile(
                name="Brother Printer",
                manufacturer="Brother",
                device_class=DeviceClass.PRINTER,
                security_risk=SecurityRisk.MEDIUM,
                oui_prefixes=["00:0B:A2", "00:1B:A9", "00:80:77", "30:57:8E", "60:B6:19"],
                hostname_patterns=[r"^brother.*", r"^brw.*"],
                open_ports=[80, 443, 9100],
                recommended_vlan=50,
            ),

            # Hikvision Camera
            DeviceProfile(
                name="Hikvision Camera/NVR",
                manufacturer="Hikvision",
                device_class=DeviceClass.SECURITY_CAMERA,
                security_risk=SecurityRisk.HIGH,  # Security concerns
                oui_prefixes=["1C:C3:16", "28:57:BE", "44:19:B6", "54:C4:15", "64:DB:43", "74:DA:EA", "80:A4:A8", "84:DF:0C", "BC:AD:28", "C0:56:E3", "C4:2F:90"],
                hostname_patterns=[r"^hikvision.*", r"^hikam.*", r"^ds-.*"],
                open_ports=[80, 443, 554, 8000],  # RTSP and Hikvision ports
                recommended_vlan=55,  # Isolated IoT
                block_internet=True,  # Security recommendation
                risk_factors=["Multiple CVEs", "Backdoor concerns", "Consider isolating from internet"],
            ),

            # Dahua Camera
            DeviceProfile(
                name="Dahua Camera/NVR",
                manufacturer="Dahua",
                device_class=DeviceClass.SECURITY_CAMERA,
                security_risk=SecurityRisk.HIGH,
                oui_prefixes=["0C:47:C9", "14:A7:8B", "24:01:C7", "34:A2:A2", "3C:EF:8C", "40:89:98", "4C:11:BF", "58:10:8C", "60:69:44", "90:02:A9", "A0:BD:1D", "B8:A9:FC", "BC:22:28", "D4:43:0E", "E4:24:6C", "E4:3E:C6"],
                hostname_patterns=[r"^dahua.*", r"^ipc-.*", r"^nvr.*"],
                open_ports=[80, 443, 554, 37777],
                recommended_vlan=55,
                block_internet=True,
                risk_factors=["Security vulnerabilities", "Consider isolating"],
            ),
        ]

    def _load_oui_database(self) -> None:
        """Load OUI (MAC prefix) to manufacturer database."""
        # This would typically load from IEEE OUI database
        # Here's a subset for common manufacturers

        self._oui_database = {
            # Apple
            "00:03:93": "Apple", "00:0A:27": "Apple", "00:0D:93": "Apple",
            "00:11:24": "Apple", "00:14:51": "Apple", "00:16:CB": "Apple",
            "00:17:F2": "Apple", "00:19:E3": "Apple", "00:1B:63": "Apple",
            "00:1C:B3": "Apple", "00:1D:4F": "Apple", "00:1E:52": "Apple",
            "00:1E:C2": "Apple", "00:1F:5B": "Apple", "00:1F:F3": "Apple",
            "00:21:E9": "Apple", "00:22:41": "Apple", "00:23:12": "Apple",
            "00:23:32": "Apple", "00:23:6C": "Apple", "00:23:DF": "Apple",
            "00:24:36": "Apple", "00:25:00": "Apple", "00:25:4B": "Apple",
            "00:25:BC": "Apple", "00:26:08": "Apple", "00:26:4A": "Apple",
            "00:26:B0": "Apple", "00:26:BB": "Apple",

            # Samsung
            "00:00:F0": "Samsung", "00:02:78": "Samsung", "00:07:AB": "Samsung",
            "00:09:18": "Samsung", "00:0D:AE": "Samsung", "00:0F:73": "Samsung",
            "00:12:47": "Samsung", "00:12:FB": "Samsung", "00:13:77": "Samsung",
            "00:15:99": "Samsung", "00:15:B9": "Samsung", "00:16:32": "Samsung",
            "00:16:6B": "Samsung", "00:16:6C": "Samsung", "00:16:DB": "Samsung",
            "00:17:C9": "Samsung", "00:17:D5": "Samsung", "00:18:AF": "Samsung",

            # Microsoft
            "00:03:FF": "Microsoft", "00:0D:3A": "Microsoft", "00:12:5A": "Microsoft",
            "00:15:5D": "Microsoft", "00:17:FA": "Microsoft", "00:1D:D8": "Microsoft",
            "00:22:48": "Microsoft", "00:25:AE": "Microsoft", "00:50:F2": "Microsoft",

            # Google
            "54:60:09": "Google", "94:EB:2C": "Google", "F4:F5:D8": "Google",

            # Amazon
            "00:FC:8B": "Amazon", "0C:47:C9": "Amazon", "18:74:2E": "Amazon",
            "34:D2:70": "Amazon", "38:F7:3D": "Amazon", "40:B4:CD": "Amazon",
            "44:65:0D": "Amazon", "68:54:FD": "Amazon", "6C:56:97": "Amazon",

            # Raspberry Pi
            "B8:27:EB": "Raspberry Pi Foundation",
            "DC:A6:32": "Raspberry Pi Foundation",
            "E4:5F:01": "Raspberry Pi Foundation",
            "D8:3A:DD": "Raspberry Pi Foundation",
            "2C:CF:67": "Raspberry Pi Trading",

            # Dell
            "00:06:5B": "Dell", "00:08:74": "Dell", "00:0B:DB": "Dell",
            "00:0D:56": "Dell", "00:0F:1F": "Dell", "00:11:43": "Dell",
            "00:12:3F": "Dell", "00:13:72": "Dell", "00:14:22": "Dell",

            # HP
            "00:00:63": "HP", "00:01:E6": "HP", "00:0A:57": "HP",
            "00:0B:CD": "HP", "00:0D:9D": "HP", "00:0E:7F": "HP",
            "00:0F:20": "HP", "00:0F:61": "HP", "00:10:83": "HP",

            # Intel
            "00:02:B3": "Intel", "00:03:47": "Intel", "00:04:23": "Intel",
            "00:07:E9": "Intel", "00:0C:F1": "Intel", "00:0E:0C": "Intel",
            "00:0E:35": "Intel", "00:11:11": "Intel", "00:12:F0": "Intel",

            # Ubiquiti
            "00:27:22": "Ubiquiti",
            "04:18:D6": "Ubiquiti",
            "18:E8:29": "Ubiquiti",
            "24:5A:4C": "Ubiquiti",
            "44:D9:E7": "Ubiquiti",
            "68:72:51": "Ubiquiti",
            "74:83:C2": "Ubiquiti",
            "78:45:58": "Ubiquiti",
            "80:2A:A8": "Ubiquiti",
            "B4:FB:E4": "Ubiquiti",
            "DC:9F:DB": "Ubiquiti",
            "F0:9F:C2": "Ubiquiti",
            "FC:EC:DA": "Ubiquiti",

            # MikroTik
            "00:0C:42": "MikroTik",
            "08:55:31": "MikroTik",
            "2C:C8:1B": "MikroTik",
            "4C:5E:0C": "MikroTik",
            "64:D1:54": "MikroTik",
            "6C:3B:6B": "MikroTik",
            "74:4D:28": "MikroTik",
            "B8:69:F4": "MikroTik",
            "C4:AD:34": "MikroTik",
            "CC:2D:E0": "MikroTik",
            "D4:01:C3": "MikroTik",
            "DC:2C:6E": "MikroTik",
            "E4:8D:8C": "MikroTik",

            # TP-Link
            "00:27:19": "TP-Link",
            "1C:3B:F3": "TP-Link",
            "50:C7:BF": "TP-Link",
            "54:AF:97": "TP-Link",
            "60:A4:B7": "TP-Link",
            "68:FF:7B": "TP-Link",
            "70:4F:57": "TP-Link",
            "98:DA:C4": "TP-Link",
            "B0:95:75": "TP-Link",

            # Synology
            "00:11:32": "Synology",

            # QNAP
            "00:08:9B": "QNAP",
            "24:5E:BE": "QNAP",
        }

    def add_profile(self, profile: DeviceProfile) -> None:
        """Add a device profile."""
        self._profiles.append(profile)

    def get_manufacturer(self, mac_address: str) -> str:
        """Look up manufacturer from MAC address OUI."""
        mac_clean = mac_address.upper().replace("-", ":").replace(".", ":")
        oui = mac_clean[:8]
        return self._oui_database.get(oui, "Unknown")

    async def classify(
        self,
        mac_address: str,
        ip_address: str = "",
        hostname: str = "",
        dhcp_vendor_class: str = "",
        user_agent: str = "",
        open_ports: list[int] = None,
        mdns_services: list[str] = None,
    ) -> ClassificationResult:
        """
        Classify a device using available information.

        Uses multiple fingerprinting methods in order of reliability:
        1. Known device profiles (MAC OUI + other signals)
        2. DHCP vendor class
        3. mDNS services
        4. Hostname patterns
        5. User-Agent analysis
        6. Port signatures
        7. MAC OUI fallback

        Args:
            mac_address: Device MAC address (required)
            ip_address: Device IP address
            hostname: Device hostname from DHCP or DNS
            dhcp_vendor_class: DHCP vendor class string
            user_agent: HTTP User-Agent if observed
            open_ports: List of open ports discovered
            mdns_services: List of advertised mDNS services

        Returns:
            ClassificationResult with device type and confidence
        """
        result = ClassificationResult(
            mac_address=mac_address.upper(),
            ip_address=ip_address,
            hostname=hostname,
        )

        open_ports = open_ports or []
        mdns_services = mdns_services or []

        # Get manufacturer from OUI
        result.manufacturer = self.get_manufacturer(mac_address)

        # Try to match against known profiles
        best_match: Optional[DeviceProfile] = None
        best_score = 0.0
        matched_methods = []

        for profile in self._profiles:
            score = 0.0
            methods = []

            # Check OUI prefix (high confidence)
            mac_prefix = mac_address.upper()[:8].replace("-", ":")
            if mac_prefix in profile.oui_prefixes:
                score += 0.4
                methods.append(f"OUI:{mac_prefix}")

            # Check hostname patterns
            if hostname:
                for pattern in profile.hostname_patterns:
                    if re.match(pattern, hostname.lower()):
                        score += 0.25
                        methods.append(f"hostname:{pattern}")
                        break

            # Check DHCP vendor class
            if dhcp_vendor_class:
                for vc in profile.dhcp_vendor_class:
                    if vc.lower() in dhcp_vendor_class.lower():
                        score += 0.3
                        methods.append(f"dhcp:{vc}")
                        break

            # Check mDNS services
            if mdns_services:
                for svc in profile.mdns_services:
                    if svc in mdns_services:
                        score += 0.2
                        methods.append(f"mdns:{svc}")
                        break

            # Check open ports
            if open_ports and profile.open_ports:
                matching_ports = set(open_ports) & set(profile.open_ports)
                if matching_ports:
                    port_score = len(matching_ports) / len(profile.open_ports) * 0.15
                    score += port_score
                    methods.append(f"ports:{','.join(map(str, matching_ports))}")

            # Check user agent
            if user_agent:
                for pattern in profile.user_agent_patterns:
                    if re.search(pattern, user_agent, re.IGNORECASE):
                        score += 0.2
                        methods.append(f"ua:{pattern}")
                        break

            # Update best match
            if score > best_score:
                best_score = score
                best_match = profile
                matched_methods = methods

        # Apply best match
        if best_match and best_score >= 0.3:
            result.device_class = best_match.device_class
            result.profile = best_match
            result.confidence = min(1.0, best_score)
            result.model = best_match.name
            result.manufacturer = best_match.manufacturer
            result.security_risk = best_match.security_risk
            result.classification_method = matched_methods[0].split(":")[0] if matched_methods else "profile"
            result.matched_patterns = matched_methods

            if hasattr(best_match, 'risk_factors') and best_match.risk_factors:
                result.risk_factors.extend(best_match.risk_factors)
        else:
            # Fallback classification by manufacturer
            result.device_class = self._classify_by_manufacturer(result.manufacturer)
            result.confidence = 0.2
            result.classification_method = "manufacturer"

        # Additional risk assessment
        result.risk_factors.extend(self._assess_risk_factors(
            result, open_ports, hostname
        ))

        # Cache result
        self._classified_devices[mac_address.upper()] = result

        return result

    def _classify_by_manufacturer(self, manufacturer: str) -> DeviceClass:
        """Fallback classification based on manufacturer."""
        manufacturer_lower = manufacturer.lower()

        if manufacturer_lower in ["apple"]:
            return DeviceClass.SMARTPHONE  # Could be many things
        elif manufacturer_lower in ["samsung"]:
            return DeviceClass.IOT_GENERIC  # Could be phone, TV, etc
        elif manufacturer_lower in ["google"]:
            return DeviceClass.IOT_GENERIC
        elif manufacturer_lower in ["amazon"]:
            return DeviceClass.SMART_SPEAKER
        elif manufacturer_lower in ["raspberry pi foundation", "raspberry pi trading"]:
            return DeviceClass.RASPBERRY_PI
        elif manufacturer_lower in ["ubiquiti"]:
            return DeviceClass.ACCESS_POINT
        elif manufacturer_lower in ["mikrotik"]:
            return DeviceClass.ROUTER
        elif manufacturer_lower in ["synology", "qnap"]:
            return DeviceClass.NAS
        elif manufacturer_lower in ["hp", "brother", "canon", "epson"]:
            return DeviceClass.PRINTER
        elif manufacturer_lower in ["dell", "lenovo", "acer", "asus"]:
            return DeviceClass.DESKTOP
        elif manufacturer_lower in ["microsoft"]:
            return DeviceClass.DESKTOP  # Or Xbox

        return DeviceClass.UNKNOWN

    def _assess_risk_factors(
        self,
        result: ClassificationResult,
        open_ports: list[int],
        hostname: str
    ) -> list[str]:
        """Assess additional risk factors."""
        factors = []

        # Check for dangerous open ports
        dangerous_ports = {
            23: "Telnet exposed",
            21: "FTP exposed",
            3389: "RDP exposed",
            5900: "VNC exposed",
            1433: "MSSQL exposed",
            3306: "MySQL exposed",
            6379: "Redis exposed",
        }

        for port in open_ports or []:
            if port in dangerous_ports:
                factors.append(dangerous_ports[port])

        # Check hostname for concerning patterns
        if hostname:
            hostname_lower = hostname.lower()
            if "default" in hostname_lower or "admin" in hostname_lower:
                factors.append("Generic/default hostname suggests unconfigured device")
            if any(pw in hostname_lower for pw in ["password", "pass", "admin"]):
                factors.append("Hostname may contain credentials")

        # Unknown manufacturer is a risk
        if result.manufacturer == "Unknown":
            factors.append("Unknown manufacturer - cannot verify device origin")

        return factors

    def get_cached_classification(self, mac_address: str) -> Optional[ClassificationResult]:
        """Get cached classification result for a MAC address."""
        return self._classified_devices.get(mac_address.upper())

    def get_all_classifications(self) -> list[ClassificationResult]:
        """Get all cached classifications."""
        return list(self._classified_devices.values())

    def get_devices_by_class(self, device_class: DeviceClass) -> list[ClassificationResult]:
        """Get all devices of a specific class."""
        return [
            d for d in self._classified_devices.values()
            if d.device_class == device_class
        ]

    def get_high_risk_devices(self) -> list[ClassificationResult]:
        """Get all high/critical risk devices."""
        return [
            d for d in self._classified_devices.values()
            if d.security_risk in [SecurityRisk.HIGH, SecurityRisk.CRITICAL]
        ]
