"""
WAN Connection models for Sentinel.

Represents individual ISP/WAN connections with their properties,
bandwidth metrics, and quality measurements.
"""
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional
from uuid import UUID, uuid4

from sentinel.core.utils import utc_now


class ConnectionType(Enum):
    """Type of WAN connection."""
    FIBER = "fiber"
    CABLE = "cable"
    DSL = "dsl"
    CELLULAR_4G = "4g"
    CELLULAR_5G = "5g"
    SATELLITE = "satellite"
    FIXED_WIRELESS = "fixed_wireless"
    ETHERNET = "ethernet"  # Business ethernet
    LEASED_LINE = "leased_line"
    UNKNOWN = "unknown"


class ConnectionStatus(Enum):
    """Status of a WAN connection."""
    UP = "up"
    DOWN = "down"
    DEGRADED = "degraded"
    TESTING = "testing"
    FAILOVER = "failover"  # Acting as backup
    STANDBY = "standby"    # Ready but not active
    UNKNOWN = "unknown"


@dataclass
class BandwidthMetrics:
    """Current bandwidth metrics for a connection."""
    # Contracted/advertised rates (Mbps)
    contracted_download_mbps: float = 0.0
    contracted_upload_mbps: float = 0.0

    # Current measured throughput (Mbps)
    current_download_mbps: float = 0.0
    current_upload_mbps: float = 0.0

    # Usage over time
    bytes_downloaded_today: int = 0
    bytes_uploaded_today: int = 0
    bytes_downloaded_month: int = 0
    bytes_uploaded_month: int = 0

    # Data caps (if applicable)
    monthly_cap_gb: Optional[float] = None
    cap_reset_day: int = 1  # Day of month cap resets

    # Historical averages
    avg_download_mbps_24h: float = 0.0
    avg_upload_mbps_24h: float = 0.0
    peak_download_mbps_24h: float = 0.0
    peak_upload_mbps_24h: float = 0.0

    # Last speed test results
    last_speedtest_download: float = 0.0
    last_speedtest_upload: float = 0.0
    last_speedtest_time: Optional[datetime] = None

    @property
    def download_utilization_percent(self) -> float:
        """Current download utilization as percentage of contracted rate."""
        if self.contracted_download_mbps <= 0:
            return 0.0
        return (self.current_download_mbps / self.contracted_download_mbps) * 100

    @property
    def upload_utilization_percent(self) -> float:
        """Current upload utilization as percentage of contracted rate."""
        if self.contracted_upload_mbps <= 0:
            return 0.0
        return (self.current_upload_mbps / self.contracted_upload_mbps) * 100

    @property
    def monthly_usage_gb(self) -> float:
        """Total monthly usage in GB."""
        return (self.bytes_downloaded_month + self.bytes_uploaded_month) / (1024**3)

    @property
    def cap_usage_percent(self) -> Optional[float]:
        """Percentage of monthly cap used, if applicable."""
        if self.monthly_cap_gb is None or self.monthly_cap_gb <= 0:
            return None
        return (self.monthly_usage_gb / self.monthly_cap_gb) * 100

    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            "contracted_download_mbps": self.contracted_download_mbps,
            "contracted_upload_mbps": self.contracted_upload_mbps,
            "current_download_mbps": self.current_download_mbps,
            "current_upload_mbps": self.current_upload_mbps,
            "bytes_downloaded_today": self.bytes_downloaded_today,
            "bytes_uploaded_today": self.bytes_uploaded_today,
            "bytes_downloaded_month": self.bytes_downloaded_month,
            "bytes_uploaded_month": self.bytes_uploaded_month,
            "monthly_cap_gb": self.monthly_cap_gb,
            "cap_reset_day": self.cap_reset_day,
            "avg_download_mbps_24h": self.avg_download_mbps_24h,
            "avg_upload_mbps_24h": self.avg_upload_mbps_24h,
            "peak_download_mbps_24h": self.peak_download_mbps_24h,
            "peak_upload_mbps_24h": self.peak_upload_mbps_24h,
            "last_speedtest_download": self.last_speedtest_download,
            "last_speedtest_upload": self.last_speedtest_upload,
            "last_speedtest_time": self.last_speedtest_time.isoformat() if self.last_speedtest_time else None,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "BandwidthMetrics":
        """Create from dictionary."""
        metrics = cls(
            contracted_download_mbps=data.get("contracted_download_mbps", 0.0),
            contracted_upload_mbps=data.get("contracted_upload_mbps", 0.0),
            current_download_mbps=data.get("current_download_mbps", 0.0),
            current_upload_mbps=data.get("current_upload_mbps", 0.0),
            bytes_downloaded_today=data.get("bytes_downloaded_today", 0),
            bytes_uploaded_today=data.get("bytes_uploaded_today", 0),
            bytes_downloaded_month=data.get("bytes_downloaded_month", 0),
            bytes_uploaded_month=data.get("bytes_uploaded_month", 0),
            monthly_cap_gb=data.get("monthly_cap_gb"),
            cap_reset_day=data.get("cap_reset_day", 1),
            avg_download_mbps_24h=data.get("avg_download_mbps_24h", 0.0),
            avg_upload_mbps_24h=data.get("avg_upload_mbps_24h", 0.0),
            peak_download_mbps_24h=data.get("peak_download_mbps_24h", 0.0),
            peak_upload_mbps_24h=data.get("peak_upload_mbps_24h", 0.0),
            last_speedtest_download=data.get("last_speedtest_download", 0.0),
            last_speedtest_upload=data.get("last_speedtest_upload", 0.0),
        )
        if data.get("last_speedtest_time"):
            metrics.last_speedtest_time = datetime.fromisoformat(data["last_speedtest_time"])
        return metrics


@dataclass
class ConnectionQuality:
    """Quality metrics for a WAN connection."""
    # Latency measurements (ms)
    latency_ms: float = 0.0
    jitter_ms: float = 0.0

    # Packet loss
    packet_loss_percent: float = 0.0

    # DNS performance
    dns_latency_ms: float = 0.0

    # Historical
    avg_latency_24h: float = 0.0
    max_latency_24h: float = 0.0
    avg_packet_loss_24h: float = 0.0

    # Uptime tracking
    uptime_percent_30d: float = 100.0
    last_outage_start: Optional[datetime] = None
    last_outage_duration_seconds: int = 0
    outages_30d: int = 0

    # Quality score (0-100)
    quality_score: float = 100.0

    def calculate_quality_score(self) -> float:
        """
        Calculate overall quality score.

        Factors:
        - Latency (lower is better)
        - Jitter (lower is better)
        - Packet loss (lower is better)
        - Uptime (higher is better)
        """
        score = 100.0

        # Latency penalty (0-30 points)
        if self.latency_ms > 0:
            if self.latency_ms < 20:
                score -= 0
            elif self.latency_ms < 50:
                score -= 5
            elif self.latency_ms < 100:
                score -= 15
            else:
                score -= 30

        # Jitter penalty (0-20 points)
        if self.jitter_ms > 5:
            score -= min(20, self.jitter_ms)

        # Packet loss penalty (0-30 points)
        if self.packet_loss_percent > 0:
            score -= min(30, self.packet_loss_percent * 10)

        # Uptime penalty (0-20 points)
        score -= max(0, (100 - self.uptime_percent_30d)) * 2

        self.quality_score = max(0, score)
        return self.quality_score

    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            "latency_ms": self.latency_ms,
            "jitter_ms": self.jitter_ms,
            "packet_loss_percent": self.packet_loss_percent,
            "dns_latency_ms": self.dns_latency_ms,
            "avg_latency_24h": self.avg_latency_24h,
            "max_latency_24h": self.max_latency_24h,
            "avg_packet_loss_24h": self.avg_packet_loss_24h,
            "uptime_percent_30d": self.uptime_percent_30d,
            "last_outage_start": self.last_outage_start.isoformat() if self.last_outage_start else None,
            "last_outage_duration_seconds": self.last_outage_duration_seconds,
            "outages_30d": self.outages_30d,
            "quality_score": self.quality_score,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "ConnectionQuality":
        """Create from dictionary."""
        quality = cls(
            latency_ms=data.get("latency_ms", 0.0),
            jitter_ms=data.get("jitter_ms", 0.0),
            packet_loss_percent=data.get("packet_loss_percent", 0.0),
            dns_latency_ms=data.get("dns_latency_ms", 0.0),
            avg_latency_24h=data.get("avg_latency_24h", 0.0),
            max_latency_24h=data.get("max_latency_24h", 0.0),
            avg_packet_loss_24h=data.get("avg_packet_loss_24h", 0.0),
            uptime_percent_30d=data.get("uptime_percent_30d", 100.0),
            last_outage_duration_seconds=data.get("last_outage_duration_seconds", 0),
            outages_30d=data.get("outages_30d", 0),
            quality_score=data.get("quality_score", 100.0),
        )
        if data.get("last_outage_start"):
            quality.last_outage_start = datetime.fromisoformat(data["last_outage_start"])
        return quality


@dataclass
class WANConnection:
    """
    Represents a single WAN/ISP connection.

    Tracks all relevant information about an internet connection:
    - ISP details and contract info
    - Bandwidth capabilities and usage
    - Quality metrics and SLA tracking
    - Failover configuration
    """
    # Identity
    id: UUID = field(default_factory=uuid4)
    name: str = ""  # Human-friendly name like "Primary Fiber"

    # ISP Information
    isp_name: str = ""
    account_number: str = ""
    support_phone: str = ""
    support_email: str = ""
    contract_end_date: Optional[datetime] = None

    # Connection details
    connection_type: ConnectionType = ConnectionType.UNKNOWN
    interface_name: str = ""  # e.g., "ether1-wan" for MikroTik
    gateway_ip: str = ""
    public_ip: str = ""
    dns_servers: list[str] = field(default_factory=list)

    # Status
    status: ConnectionStatus = ConnectionStatus.UNKNOWN
    last_status_change: Optional[datetime] = None

    # Failover configuration
    priority: int = 100  # Lower = higher priority (100 is default)
    weight: int = 1      # For load balancing
    failover_enabled: bool = True
    is_primary: bool = False
    is_backup: bool = False

    # Metrics
    bandwidth: BandwidthMetrics = field(default_factory=BandwidthMetrics)
    quality: ConnectionQuality = field(default_factory=ConnectionQuality)

    # Cost tracking
    monthly_cost: float = 0.0
    cost_per_gb_overage: float = 0.0

    # Timestamps
    created_at: datetime = field(default_factory=utc_now)
    updated_at: datetime = field(default_factory=utc_now)

    # Labels for organization
    labels: dict[str, str] = field(default_factory=dict)

    def set_status(self, status: ConnectionStatus) -> None:
        """Update connection status with timestamp."""
        if self.status != status:
            self.status = status
            self.last_status_change = utc_now()
            self.updated_at = utc_now()

    @property
    def is_up(self) -> bool:
        """Check if connection is operational."""
        return self.status in [ConnectionStatus.UP, ConnectionStatus.FAILOVER]

    @property
    def is_healthy(self) -> bool:
        """Check if connection is healthy (up and not degraded)."""
        return self.status == ConnectionStatus.UP and self.quality.quality_score >= 70

    @property
    def cost_effectiveness(self) -> float:
        """
        Calculate cost per Mbps of contracted bandwidth.

        Lower is better. Returns 0 if no cost or no bandwidth.
        """
        total_mbps = self.bandwidth.contracted_download_mbps + self.bandwidth.contracted_upload_mbps
        if self.monthly_cost <= 0 or total_mbps <= 0:
            return 0.0
        return self.monthly_cost / total_mbps

    @property
    def sla_compliance(self) -> float:
        """
        Calculate SLA compliance based on actual vs contracted speeds.

        Returns percentage (0-100+). Over 100 means exceeding contracted speeds.
        """
        if self.bandwidth.contracted_download_mbps <= 0:
            return 100.0

        # Use speed test results for accuracy
        if self.bandwidth.last_speedtest_download > 0:
            return (self.bandwidth.last_speedtest_download /
                    self.bandwidth.contracted_download_mbps) * 100

        # Fall back to average measurements
        if self.bandwidth.avg_download_mbps_24h > 0:
            return (self.bandwidth.avg_download_mbps_24h /
                    self.bandwidth.contracted_download_mbps) * 100

        return 100.0

    def to_dict(self) -> dict:
        """Convert to dictionary for serialization."""
        return {
            "id": str(self.id),
            "name": self.name,
            "isp_name": self.isp_name,
            "account_number": self.account_number,
            "support_phone": self.support_phone,
            "support_email": self.support_email,
            "contract_end_date": self.contract_end_date.isoformat() if self.contract_end_date else None,
            "connection_type": self.connection_type.value,
            "interface_name": self.interface_name,
            "gateway_ip": self.gateway_ip,
            "public_ip": self.public_ip,
            "dns_servers": self.dns_servers,
            "status": self.status.value,
            "last_status_change": self.last_status_change.isoformat() if self.last_status_change else None,
            "priority": self.priority,
            "weight": self.weight,
            "failover_enabled": self.failover_enabled,
            "is_primary": self.is_primary,
            "is_backup": self.is_backup,
            "bandwidth": self.bandwidth.to_dict(),
            "quality": self.quality.to_dict(),
            "monthly_cost": self.monthly_cost,
            "cost_per_gb_overage": self.cost_per_gb_overage,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "labels": self.labels,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "WANConnection":
        """Create from dictionary."""
        conn = cls(
            id=UUID(data["id"]) if "id" in data else uuid4(),
            name=data.get("name", ""),
            isp_name=data.get("isp_name", ""),
            account_number=data.get("account_number", ""),
            support_phone=data.get("support_phone", ""),
            support_email=data.get("support_email", ""),
            connection_type=ConnectionType(data.get("connection_type", "unknown")),
            interface_name=data.get("interface_name", ""),
            gateway_ip=data.get("gateway_ip", ""),
            public_ip=data.get("public_ip", ""),
            dns_servers=data.get("dns_servers", []),
            status=ConnectionStatus(data.get("status", "unknown")),
            priority=data.get("priority", 100),
            weight=data.get("weight", 1),
            failover_enabled=data.get("failover_enabled", True),
            is_primary=data.get("is_primary", False),
            is_backup=data.get("is_backup", False),
            monthly_cost=data.get("monthly_cost", 0.0),
            cost_per_gb_overage=data.get("cost_per_gb_overage", 0.0),
            labels=data.get("labels", {}),
        )

        if data.get("contract_end_date"):
            conn.contract_end_date = datetime.fromisoformat(data["contract_end_date"])
        if data.get("last_status_change"):
            conn.last_status_change = datetime.fromisoformat(data["last_status_change"])
        if data.get("created_at"):
            conn.created_at = datetime.fromisoformat(data["created_at"])
        if data.get("updated_at"):
            conn.updated_at = datetime.fromisoformat(data["updated_at"])
        if data.get("bandwidth"):
            conn.bandwidth = BandwidthMetrics.from_dict(data["bandwidth"])
        if data.get("quality"):
            conn.quality = ConnectionQuality.from_dict(data["quality"])

        return conn
