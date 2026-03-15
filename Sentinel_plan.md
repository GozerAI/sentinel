Sentinel Security Platform
Design & Implementation Plan for Claude Code

Executive Summary
Sentinel is an AI-native security platform that provides zero-trust architecture, autonomous network management, and comprehensive threat detection. This document provides the complete technical specification for implementation using Claude Code.

Part 1: Architecture Overview
System Naming Convention
Component CategoryModule NamePurposeCore PlatformSentinelRoot namespace and orchestrationIdentityGatekeeperZero-trust identity and accessCredentialsKeymasterCertificate lifecycle and licensingNetworkNetMeshSoftware-defined network fabricFirewallShieldL3-L7 inspection and WAFDetectionObserverSIEM and XDR capabilitiesDeceptionDecoyHoneypots and threat deceptionEndpointAgentEDR and workload protectionIsolationEnclaveSecure computing environmentsData ProtectionVaultDLP and encryptionComplianceAuditorCompliance automationAnalyticsIntelThreat intelligence and riskOperationsCommandSOC automationResponseResponderIncident response automationResilienceRecoveryBusiness continuityAI ComputeCortexAI model serving and security
AI Agent Naming
AgentPurposeDiscoveryNetwork scanning and topologyOptimizerTraffic engineering and QoSPlannerSegmentation and VLAN managementOrchestratorWorkload placement and scalingForecasterPredictive analyticsHealerSelf-repair and failoverGuardianSecurity policy enforcement

Part 2: Repository Structure
sentinel/
├── README.md
├── pyproject.toml
├── docker-compose.yml
├── Makefile
│
├── docs/
│   ├── architecture/
│   │   ├── overview.md
│   │   ├── data-flow.md
│   │   └── security-model.md
│   ├── api/
│   │   └── openapi.yaml
│   ├── deployment/
│   │   ├── docker.md
│   │   ├── kubernetes.md
│   │   └── homelab.md
│   └── runbooks/
│       └── incident-response.md
│
├── src/
│   └── sentinel/
│       ├── __init__.py
│       ├── config.py
│       ├── main.py
│       │
│       ├── core/
│       │   ├── __init__.py
│       │   ├── engine.py              # Main orchestration engine
│       │   ├── event_bus.py           # Internal message passing
│       │   ├── scheduler.py           # Task scheduling
│       │   ├── state.py               # Global state management
│       │   └── models/
│       │       ├── __init__.py
│       │       ├── device.py
│       │       ├── network.py
│       │       ├── policy.py
│       │       └── event.py
│       │
│       ├── gatekeeper/                # Identity & Access
│       │   ├── __init__.py
│       │   ├── identity.py
│       │   ├── authentication.py
│       │   ├── authorization.py
│       │   ├── session.py
│       │   └── mfa.py
│       │
│       ├── keymaster/                 # Credentials & Licensing
│       │   ├── __init__.py
│       │   ├── certificates.py
│       │   ├── secrets.py
│       │   ├── rotation.py
│       │   └── licensing.py
│       │
│       ├── netmesh/                   # Network Fabric
│       │   ├── __init__.py
│       │   ├── topology.py
│       │   ├── vlan.py
│       │   ├── routing.py
│       │   ├── dns.py
│       │   └── overlay.py
│       │
│       ├── shield/                    # Firewall
│       │   ├── __init__.py
│       │   ├── rules.py
│       │   ├── inspection.py
│       │   ├── waf.py
│       │   └── ddos.py
│       │
│       ├── observer/                  # SIEM/XDR
│       │   ├── __init__.py
│       │   ├── collector.py
│       │   ├── parser.py
│       │   ├── correlator.py
│       │   ├── alerting.py
│       │   └── storage.py
│       │
│       ├── agents/                    # AI Agents
│       │   ├── __init__.py
│       │   ├── base.py                # Base agent class
│       │   ├── council.py             # Agent coordination
│       │   ├── discovery.py           # Network discovery
│       │   ├── optimizer.py           # Traffic optimization
│       │   ├── planner.py             # Segmentation planning
│       │   ├── orchestrator.py        # Workload management
│       │   ├── forecaster.py          # Predictive analytics
│       │   ├── healer.py              # Self-repair
│       │   └── guardian.py            # Security enforcement
│       │
│       ├── integrations/              # External Systems
│       │   ├── __init__.py
│       │   ├── switches/
│       │   │   ├── base.py
│       │   │   ├── ubiquiti.py
│       │   │   ├── cisco.py
│       │   │   └── netgear.py
│       │   ├── routers/
│       │   │   ├── base.py
│       │   │   ├── opnsense.py
│       │   │   ├── pfsense.py
│       │   │   └── mikrotik.py
│       │   ├── hypervisors/
│       │   │   ├── base.py
│       │   │   ├── proxmox.py
│       │   │   └── docker.py
│       │   ├── storage/
│       │   │   ├── base.py
│       │   │   └── truenas.py
│       │   ├── kubernetes/
│       │   │   ├── base.py
│       │   │   └── k3s.py
│       │   └── llm/
│       │       ├── base.py
│       │       ├── ollama.py
│       │       └── anthropic.py
│       │
│       ├── api/                       # REST API
│       │   ├── __init__.py
│       │   ├── app.py
│       │   ├── routes/
│       │   │   ├── __init__.py
│       │   │   ├── devices.py
│       │   │   ├── network.py
│       │   │   ├── policies.py
│       │   │   ├── agents.py
│       │   │   └── events.py
│       │   ├── middleware/
│       │   │   ├── auth.py
│       │   │   └── logging.py
│       │   └── schemas/
│       │       └── __init__.py
│       │
│       ├── ui/                        # Dashboard (optional)
│       │   ├── __init__.py
│       │   └── dashboard.py
│       │
│       └── cli/                       # Command Line Interface
│           ├── __init__.py
│           └── commands.py
│
├── tests/
│   ├── __init__.py
│   ├── conftest.py
│   ├── unit/
│   │   ├── test_core.py
│   │   ├── test_agents.py
│   │   └── test_integrations.py
│   ├── integration/
│   │   └── test_api.py
│   └── e2e/
│       └── test_scenarios.py
│
├── scripts/
│   ├── setup.sh
│   ├── deploy.sh
│   └── backup.sh
│
├── deploy/
│   ├── docker/
│   │   ├── Dockerfile
│   │   └── docker-compose.prod.yml
│   └── kubernetes/
│       ├── namespace.yaml
│       ├── deployment.yaml
│       ├── service.yaml
│       └── configmap.yaml
│
└── config/
    ├── default.yaml
    ├── development.yaml
    ├── production.yaml
    └── homelab.yaml

Part 3: Core Data Models
File: src/sentinel/core/models/device.py
python"""
Device models for network asset tracking.
"""
from datetime import datetime
from enum import Enum
from typing import Optional
from pydantic import BaseModel, Field
from uuid import UUID, uuid4


class DeviceType(str, Enum):
    WORKSTATION = "workstation"
    SERVER = "server"
    NETWORK = "network"
    STORAGE = "storage"
    IOT = "iot"
    MOBILE = "mobile"
    PRINTER = "printer"
    CAMERA = "camera"
    UNKNOWN = "unknown"


class DeviceStatus(str, Enum):
    ONLINE = "online"
    OFFLINE = "offline"
    QUARANTINED = "quarantined"
    MAINTENANCE = "maintenance"


class TrustLevel(str, Enum):
    TRUSTED = "trusted"
    VERIFIED = "verified"
    UNKNOWN = "unknown"
    UNTRUSTED = "untrusted"
    QUARANTINED = "quarantined"


class NetworkInterface(BaseModel):
    """Represents a network interface on a device."""
    mac_address: str
    ip_addresses: list[str] = Field(default_factory=list)
    vlan_id: Optional[int] = None
    speed_mbps: Optional[int] = None
    is_primary: bool = False


class DeviceFingerprint(BaseModel):
    """Device identification fingerprint."""
    vendor: Optional[str] = None
    model: Optional[str] = None
    os_family: Optional[str] = None
    os_version: Optional[str] = None
    services: list[str] = Field(default_factory=list)
    open_ports: list[int] = Field(default_factory=list)
    confidence: float = Field(ge=0.0, le=1.0, default=0.0)


class Device(BaseModel):
    """
    Core device model representing any network-connected asset.
    Uses opaque identifiers to maintain information silo architecture.
    """
    id: UUID = Field(default_factory=uuid4)
    hostname: Optional[str] = None
    display_name: Optional[str] = None
    
    device_type: DeviceType = DeviceType.UNKNOWN
    status: DeviceStatus = DeviceStatus.ONLINE
    trust_level: TrustLevel = TrustLevel.UNKNOWN
    
    interfaces: list[NetworkInterface] = Field(default_factory=list)
    fingerprint: DeviceFingerprint = Field(default_factory=DeviceFingerprint)
    
    # Segmentation
    assigned_vlan: Optional[int] = None
    assigned_zone: Optional[str] = None
    
    # Timestamps
    first_seen: datetime = Field(default_factory=datetime.utcnow)
    last_seen: datetime = Field(default_factory=datetime.utcnow)
    last_activity: Optional[datetime] = None
    
    # Metadata
    tags: list[str] = Field(default_factory=list)
    custom_attributes: dict = Field(default_factory=dict)
    
    # Agent tracking
    managed_by_agent: bool = False
    agent_last_action: Optional[str] = None
    
    @property
    def primary_ip(self) -> Optional[str]:
        """Get the primary IP address."""
        for iface in self.interfaces:
            if iface.is_primary and iface.ip_addresses:
                return iface.ip_addresses[0]
        # Fallback to first available
        for iface in self.interfaces:
            if iface.ip_addresses:
                return iface.ip_addresses[0]
        return None
    
    @property
    def primary_mac(self) -> Optional[str]:
        """Get the primary MAC address."""
        for iface in self.interfaces:
            if iface.is_primary:
                return iface.mac_address
        return self.interfaces[0].mac_address if self.interfaces else None


class DeviceGroup(BaseModel):
    """Logical grouping of devices."""
    id: UUID = Field(default_factory=uuid4)
    name: str
    description: Optional[str] = None
    device_ids: list[UUID] = Field(default_factory=list)
    auto_membership_rules: dict = Field(default_factory=dict)
    policies: list[str] = Field(default_factory=list)
File: src/sentinel/core/models/network.py
python"""
Network topology and configuration models.
"""
from datetime import datetime
from enum import Enum
from typing import Optional, Any
from pydantic import BaseModel, Field
from uuid import UUID, uuid4


class VLANPurpose(str, Enum):
    MANAGEMENT = "management"
    WORKSTATIONS = "workstations"
    SERVERS = "servers"
    STORAGE = "storage"
    IOT = "iot"
    GUEST = "guest"
    DMZ = "dmz"
    QUARANTINE = "quarantine"
    AI_COMPUTE = "ai_compute"
    CUSTOM = "custom"


class VLAN(BaseModel):
    """VLAN configuration."""
    id: int = Field(ge=1, le=4094)
    name: str
    purpose: VLANPurpose = VLANPurpose.CUSTOM
    subnet: str  # CIDR notation
    gateway: str
    dns_zone: Optional[str] = None
    dhcp_enabled: bool = True
    dhcp_range_start: Optional[str] = None
    dhcp_range_end: Optional[str] = None
    
    # Security
    isolated: bool = False
    allowed_destinations: list[int] = Field(default_factory=list)  # Other VLAN IDs
    
    # Metadata
    auto_managed: bool = False
    created_at: datetime = Field(default_factory=datetime.utcnow)


class LinkType(str, Enum):
    ETHERNET = "ethernet"
    WIFI = "wifi"
    AGGREGATE = "aggregate"
    VIRTUAL = "virtual"
    VPN = "vpn"


class LinkStatus(str, Enum):
    UP = "up"
    DOWN = "down"
    DEGRADED = "degraded"


class NetworkLink(BaseModel):
    """Represents a network connection between two nodes."""
    id: UUID = Field(default_factory=uuid4)
    source_device_id: UUID
    source_port: Optional[str] = None
    target_device_id: UUID
    target_port: Optional[str] = None
    
    link_type: LinkType = LinkType.ETHERNET
    status: LinkStatus = LinkStatus.UP
    
    speed_mbps: Optional[int] = None
    duplex: Optional[str] = None
    
    # Traffic metrics
    utilization_percent: float = 0.0
    bytes_in: int = 0
    bytes_out: int = 0
    errors_in: int = 0
    errors_out: int = 0
    
    last_updated: datetime = Field(default_factory=datetime.utcnow)


class TopologyNode(BaseModel):
    """Node in the network topology graph."""
    device_id: UUID
    node_type: str  # router, switch, endpoint, etc.
    layer: int  # Network layer (core=1, distribution=2, access=3, endpoint=4)
    position: Optional[dict] = None  # For visualization
    children: list[UUID] = Field(default_factory=list)
    parent: Optional[UUID] = None


class NetworkTopology(BaseModel):
    """Complete network topology representation."""
    id: UUID = Field(default_factory=uuid4)
    name: str = "default"
    
    nodes: dict[UUID, TopologyNode] = Field(default_factory=dict)
    links: list[NetworkLink] = Field(default_factory=list)
    vlans: list[VLAN] = Field(default_factory=list)
    
    last_scan: Optional[datetime] = None
    scan_duration_seconds: Optional[float] = None
    
    def get_device_neighbors(self, device_id: UUID) -> list[UUID]:
        """Get all devices directly connected to a device."""
        neighbors = []
        for link in self.links:
            if link.source_device_id == device_id:
                neighbors.append(link.target_device_id)
            elif link.target_device_id == device_id:
                neighbors.append(link.source_device_id)
        return neighbors


class TrafficFlow(BaseModel):
    """Represents a traffic flow for analysis."""
    id: UUID = Field(default_factory=uuid4)
    
    source_ip: str
    source_port: int
    destination_ip: str
    destination_port: int
    protocol: str  # TCP, UDP, ICMP, etc.
    
    application: Optional[str] = None  # Detected application
    
    bytes_total: int = 0
    packets_total: int = 0
    
    start_time: datetime = Field(default_factory=datetime.utcnow)
    last_seen: datetime = Field(default_factory=datetime.utcnow)
    
    # QoS
    dscp_marking: Optional[int] = None
    priority: Optional[str] = None


class QoSPolicy(BaseModel):
    """Quality of Service policy."""
    id: UUID = Field(default_factory=uuid4)
    name: str
    description: Optional[str] = None
    
    # Matching criteria
    match_applications: list[str] = Field(default_factory=list)
    match_source_vlans: list[int] = Field(default_factory=list)
    match_destination_vlans: list[int] = Field(default_factory=list)
    match_dscp: list[int] = Field(default_factory=list)
    
    # Actions
    set_dscp: Optional[int] = None
    bandwidth_limit_mbps: Optional[int] = None
    bandwidth_guarantee_mbps: Optional[int] = None
    priority_queue: Optional[int] = None
    
    enabled: bool = True
File: src/sentinel/core/models/policy.py
python"""
Security and network policy models.
"""
from datetime import datetime
from enum import Enum
from typing import Optional, Any
from pydantic import BaseModel, Field
from uuid import UUID, uuid4


class PolicyAction(str, Enum):
    ALLOW = "allow"
    DENY = "deny"
    LOG = "log"
    ALERT = "alert"
    QUARANTINE = "quarantine"
    RATE_LIMIT = "rate_limit"


class PolicyScope(str, Enum):
    GLOBAL = "global"
    VLAN = "vlan"
    DEVICE_GROUP = "device_group"
    DEVICE = "device"


class FirewallRule(BaseModel):
    """Individual firewall rule."""
    id: UUID = Field(default_factory=uuid4)
    name: str
    description: Optional[str] = None
    
    # Source
    source_zones: list[str] = Field(default_factory=list)
    source_addresses: list[str] = Field(default_factory=list)  # CIDR or IP
    source_ports: list[str] = Field(default_factory=list)
    
    # Destination
    destination_zones: list[str] = Field(default_factory=list)
    destination_addresses: list[str] = Field(default_factory=list)
    destination_ports: list[str] = Field(default_factory=list)
    
    # Match
    protocols: list[str] = Field(default_factory=lambda: ["any"])
    applications: list[str] = Field(default_factory=list)
    
    # Action
    action: PolicyAction = PolicyAction.DENY
    log_enabled: bool = False
    
    # Metadata
    priority: int = 100
    enabled: bool = True
    auto_generated: bool = False
    generated_by_agent: Optional[str] = None
    
    created_at: datetime = Field(default_factory=datetime.utcnow)
    expires_at: Optional[datetime] = None


class SegmentationPolicy(BaseModel):
    """
    Defines allowed communication between network segments.
    Used by Planner agent to auto-generate firewall rules.
    """
    id: UUID = Field(default_factory=uuid4)
    name: str
    description: Optional[str] = None
    
    source_vlan: int
    destination_vlan: int
    
    allowed_services: list[str] = Field(default_factory=list)
    denied_services: list[str] = Field(default_factory=list)
    
    # Default action if service not explicitly listed
    default_action: PolicyAction = PolicyAction.DENY
    
    enabled: bool = True


class DevicePolicy(BaseModel):
    """Policy applied to devices based on classification."""
    id: UUID = Field(default_factory=uuid4)
    name: str
    
    # Matching
    match_device_types: list[str] = Field(default_factory=list)
    match_vendors: list[str] = Field(default_factory=list)
    match_tags: list[str] = Field(default_factory=list)
    
    # Assignment
    assign_vlan: Optional[int] = None
    assign_zone: Optional[str] = None
    assign_trust_level: Optional[str] = None
    
    # Restrictions
    internet_access: bool = True
    lan_access: bool = True
    allowed_destinations: list[str] = Field(default_factory=list)
    blocked_destinations: list[str] = Field(default_factory=list)
    
    # QoS
    qos_policy_id: Optional[UUID] = None
    
    priority: int = 100
    enabled: bool = True


class AutomationRule(BaseModel):
    """
    Rules for agent automation.
    Defines conditions and actions that agents can take automatically.
    """
    id: UUID = Field(default_factory=uuid4)
    name: str
    description: Optional[str] = None
    
    # Trigger
    trigger_event: str  # Event type that triggers this rule
    trigger_conditions: dict = Field(default_factory=dict)  # Additional conditions
    
    # Action
    action_type: str  # What action to take
    action_params: dict = Field(default_factory=dict)
    
    # Constraints
    requires_confirmation: bool = False
    confidence_threshold: float = Field(ge=0.0, le=1.0, default=0.8)
    max_executions_per_hour: Optional[int] = None
    
    # Rollback
    rollback_enabled: bool = True
    rollback_timeout_seconds: int = 3600
    
    enabled: bool = True
    
    # Stats
    execution_count: int = 0
    last_executed: Optional[datetime] = None
    last_result: Optional[str] = None
File: src/sentinel/core/models/event.py
python"""
Event models for the event bus and logging.
"""
from datetime import datetime
from enum import Enum
from typing import Optional, Any
from pydantic import BaseModel, Field
from uuid import UUID, uuid4


class EventSeverity(str, Enum):
    DEBUG = "debug"
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


class EventCategory(str, Enum):
    NETWORK = "network"
    SECURITY = "security"
    DEVICE = "device"
    AGENT = "agent"
    SYSTEM = "system"
    COMPLIANCE = "compliance"


class Event(BaseModel):
    """Base event model for all system events."""
    id: UUID = Field(default_factory=uuid4)
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    
    category: EventCategory
    event_type: str
    severity: EventSeverity = EventSeverity.INFO
    
    source: str  # Component that generated the event
    source_device_id: Optional[UUID] = None
    
    title: str
    description: Optional[str] = None
    
    data: dict = Field(default_factory=dict)
    
    # Correlation
    correlation_id: Optional[UUID] = None
    parent_event_id: Optional[UUID] = None
    
    # Processing
    acknowledged: bool = False
    acknowledged_by: Optional[str] = None
    acknowledged_at: Optional[datetime] = None


class SecurityAlert(Event):
    """Security-specific alert with additional context."""
    category: EventCategory = EventCategory.SECURITY
    
    # Threat context
    threat_type: Optional[str] = None
    mitre_tactic: Optional[str] = None
    mitre_technique: Optional[str] = None
    
    # Risk assessment
    risk_score: float = Field(ge=0.0, le=10.0, default=5.0)
    confidence: float = Field(ge=0.0, le=1.0, default=0.5)
    
    # Affected assets
    affected_device_ids: list[UUID] = Field(default_factory=list)
    affected_user_ids: list[str] = Field(default_factory=list)
    
    # Response
    auto_response_taken: bool = False
    auto_response_action: Optional[str] = None
    requires_investigation: bool = True


class AgentAction(BaseModel):
    """
    Records an action taken by an AI agent.
    Critical for auditability and rollback.
    """
    id: UUID = Field(default_factory=uuid4)
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    
    agent_name: str
    action_type: str
    
    # Decision context
    trigger_event_id: Optional[UUID] = None
    reasoning: str
    confidence: float = Field(ge=0.0, le=1.0)
    
    # Execution
    target_type: str  # device, vlan, rule, etc.
    target_id: str
    
    parameters: dict = Field(default_factory=dict)
    
    # Results
    status: str = "pending"  # pending, executed, failed, rolled_back
    result: Optional[dict] = None
    error_message: Optional[str] = None
    
    # Rollback
    reversible: bool = True
    rollback_data: Optional[dict] = None  # State needed to undo
    rolled_back_at: Optional[datetime] = None
    
    # Approval
    required_confirmation: bool = False
    confirmed_by: Optional[str] = None
    confirmed_at: Optional[datetime] = None


class AgentDecision(BaseModel):
    """
    Records the decision-making process of an agent.
    Used for explainability and debugging.
    """
    id: UUID = Field(default_factory=uuid4)
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    
    agent_name: str
    decision_type: str
    
    # Input
    input_events: list[UUID] = Field(default_factory=list)
    input_state: dict = Field(default_factory=dict)
    
    # Reasoning
    analysis: str
    options_considered: list[dict] = Field(default_factory=list)
    selected_option: Optional[dict] = None
    rejection_reasons: dict = Field(default_factory=dict)
    
    # Output
    confidence: float = Field(ge=0.0, le=1.0)
    action_ids: list[UUID] = Field(default_factory=list)
    
    # LLM context (if used)
    llm_model: Optional[str] = None
    llm_prompt_tokens: Optional[int] = None
    llm_completion_tokens: Optional[int] = None

Part 4: Core Engine Implementation
File: src/sentinel/core/engine.py
python"""
Sentinel Core Engine - Main orchestration component.
"""
import asyncio
import logging
from datetime import datetime
from typing import Optional
from uuid import UUID

from sentinel.core.event_bus import EventBus
from sentinel.core.scheduler import Scheduler
from sentinel.core.state import StateManager
from sentinel.core.models.event import Event, EventCategory, EventSeverity

logger = logging.getLogger(__name__)


class SentinelEngine:
    """
    Central orchestration engine for the Sentinel platform.
    
    Responsibilities:
    - Initialize and coordinate all subsystems
    - Manage the agent council
    - Handle event routing
    - Provide unified state access
    """
    
    def __init__(self, config: dict):
        self.config = config
        self.event_bus = EventBus()
        self.scheduler = Scheduler()
        self.state = StateManager(config.get("state", {}))
        
        self._agents: dict[str, "BaseAgent"] = {}
        self._integrations: dict[str, "BaseIntegration"] = {}
        
        self._running = False
        self._start_time: Optional[datetime] = None
    
    async def start(self) -> None:
        """Start the Sentinel engine and all subsystems."""
        logger.info("Starting Sentinel Engine...")
        
        self._start_time = datetime.utcnow()
        self._running = True
        
        # Initialize state
        await self.state.initialize()
        
        # Start event bus
        await self.event_bus.start()
        
        # Load integrations
        await self._load_integrations()
        
        # Initialize agents
        await self._initialize_agents()
        
        # Start scheduler
        await self.scheduler.start()
        
        # Emit startup event
        await self.event_bus.publish(Event(
            category=EventCategory.SYSTEM,
            event_type="engine.started",
            severity=EventSeverity.INFO,
            source="sentinel.engine",
            title="Sentinel Engine Started",
            description=f"Engine started with {len(self._agents)} agents"
        ))
        
        logger.info(f"Sentinel Engine started with {len(self._agents)} agents")
    
    async def stop(self) -> None:
        """Gracefully stop the engine."""
        logger.info("Stopping Sentinel Engine...")
        
        self._running = False
        
        # Stop scheduler
        await self.scheduler.stop()
        
        # Stop agents
        for agent in self._agents.values():
            await agent.stop()
        
        # Stop event bus
        await self.event_bus.stop()
        
        # Persist state
        await self.state.persist()
        
        logger.info("Sentinel Engine stopped")
    
    async def _load_integrations(self) -> None:
        """Load configured integrations."""
        integration_config = self.config.get("integrations", {})
        
        # Example: Load router integration
        if "router" in integration_config:
            router_type = integration_config["router"]["type"]
            if router_type == "opnsense":
                from sentinel.integrations.routers.opnsense import OPNsenseIntegration
                self._integrations["router"] = OPNsenseIntegration(
                    integration_config["router"]
                )
        
        # Example: Load switch integration
        if "switch" in integration_config:
            switch_type = integration_config["switch"]["type"]
            if switch_type == "ubiquiti":
                from sentinel.integrations.switches.ubiquiti import UnifiIntegration
                self._integrations["switch"] = UnifiIntegration(
                    integration_config["switch"]
                )
        
        # Initialize all integrations
        for name, integration in self._integrations.items():
            try:
                await integration.connect()
                logger.info(f"Integration '{name}' connected")
            except Exception as e:
                logger.error(f"Failed to connect integration '{name}': {e}")
    
    async def _initialize_agents(self) -> None:
        """Initialize AI agents based on configuration."""
        agent_config = self.config.get("agents", {})
        
        # Discovery Agent
        if agent_config.get("discovery", {}).get("enabled", True):
            from sentinel.agents.discovery import DiscoveryAgent
            self._agents["discovery"] = DiscoveryAgent(
                engine=self,
                config=agent_config.get("discovery", {})
            )
        
        # Optimizer Agent
        if agent_config.get("optimizer", {}).get("enabled", True):
            from sentinel.agents.optimizer import OptimizerAgent
            self._agents["optimizer"] = OptimizerAgent(
                engine=self,
                config=agent_config.get("optimizer", {})
            )
        
        # Planner Agent
        if agent_config.get("planner", {}).get("enabled", True):
            from sentinel.agents.planner import PlannerAgent
            self._agents["planner"] = PlannerAgent(
                engine=self,
                config=agent_config.get("planner", {})
            )
        
        # Healer Agent
        if agent_config.get("healer", {}).get("enabled", True):
            from sentinel.agents.healer import HealerAgent
            self._agents["healer"] = HealerAgent(
                engine=self,
                config=agent_config.get("healer", {})
            )
        
        # Start all agents
        for name, agent in self._agents.items():
            await agent.start()
            logger.info(f"Agent '{name}' started")
    
    def get_integration(self, name: str) -> Optional["BaseIntegration"]:
        """Get an integration by name."""
        return self._integrations.get(name)
    
    def get_agent(self, name: str) -> Optional["BaseAgent"]:
        """Get an agent by name."""
        return self._agents.get(name)
    
    @property
    def uptime_seconds(self) -> float:
        """Get engine uptime in seconds."""
        if self._start_time:
            return (datetime.utcnow() - self._start_time).total_seconds()
        return 0.0
File: src/sentinel/core/event_bus.py
python"""
Event bus for internal message passing.
"""
import asyncio
import logging
from collections import defaultdict
from typing import Callable, Awaitable, Optional
from uuid import UUID

from sentinel.core.models.event import Event, EventCategory

logger = logging.getLogger(__name__)

EventHandler = Callable[[Event], Awaitable[None]]


class EventBus:
    """
    Async event bus for decoupled communication between components.
    
    Supports:
    - Pub/sub pattern
    - Event filtering by category and type
    - Async handlers
    - Event persistence (optional)
    """
    
    def __init__(self, persist_events: bool = True, max_queue_size: int = 10000):
        self._handlers: dict[str, list[EventHandler]] = defaultdict(list)
        self._category_handlers: dict[EventCategory, list[EventHandler]] = defaultdict(list)
        self._global_handlers: list[EventHandler] = []
        
        self._queue: asyncio.Queue[Event] = asyncio.Queue(maxsize=max_queue_size)
        self._persist_events = persist_events
        self._event_history: list[Event] = []
        self._max_history = 10000
        
        self._running = False
        self._processor_task: Optional[asyncio.Task] = None
    
    async def start(self) -> None:
        """Start the event processor."""
        self._running = True
        self._processor_task = asyncio.create_task(self._process_events())
        logger.info("Event bus started")
    
    async def stop(self) -> None:
        """Stop the event processor."""
        self._running = False
        if self._processor_task:
            self._processor_task.cancel()
            try:
                await self._processor_task
            except asyncio.CancelledError:
                pass
        logger.info("Event bus stopped")
    
    def subscribe(
        self,
        handler: EventHandler,
        event_type: Optional[str] = None,
        category: Optional[EventCategory] = None
    ) -> None:
        """
        Subscribe a handler to events.
        
        Args:
            handler: Async function to handle events
            event_type: Specific event type to subscribe to
            category: Event category to subscribe to
        """
        if event_type:
            self._handlers[event_type].append(handler)
        elif category:
            self._category_handlers[category].append(handler)
        else:
            self._global_handlers.append(handler)
    
    def unsubscribe(
        self,
        handler: EventHandler,
        event_type: Optional[str] = None,
        category: Optional[EventCategory] = None
    ) -> None:
        """Unsubscribe a handler."""
        if event_type and handler in self._handlers[event_type]:
            self._handlers[event_type].remove(handler)
        elif category and handler in self._category_handlers[category]:
            self._category_handlers[category].remove(handler)
        elif handler in self._global_handlers:
            self._global_handlers.remove(handler)
    
    async def publish(self, event: Event) -> None:
        """Publish an event to the bus."""
        await self._queue.put(event)
    
    async def _process_events(self) -> None:
        """Process events from the queue."""
        while self._running:
            try:
                event = await asyncio.wait_for(
                    self._queue.get(),
                    timeout=1.0
                )
                
                # Persist event
                if self._persist_events:
                    self._event_history.append(event)
                    if len(self._event_history) > self._max_history:
                        self._event_history = self._event_history[-self._max_history:]
                
                # Dispatch to handlers
                await self._dispatch(event)
                
            except asyncio.TimeoutError:
                continue
            except Exception as e:
                logger.error(f"Error processing event: {e}")
    
    async def _dispatch(self, event: Event) -> None:
        """Dispatch event to all matching handlers."""
        handlers = []
        
        # Global handlers
        handlers.extend(self._global_handlers)
        
        # Category handlers
        handlers.extend(self._category_handlers.get(event.category, []))
        
        # Type-specific handlers
        handlers.extend(self._handlers.get(event.event_type, []))
        
        # Execute handlers concurrently
        if handlers:
            await asyncio.gather(
                *[self._safe_handle(h, event) for h in handlers],
                return_exceptions=True
            )
    
    async def _safe_handle(self, handler: EventHandler, event: Event) -> None:
        """Safely execute a handler with error handling."""
        try:
            await handler(event)
        except Exception as e:
            logger.error(f"Handler error for event {event.id}: {e}")
    
    def get_recent_events(
        self,
        count: int = 100,
        category: Optional[EventCategory] = None,
        event_type: Optional[str] = None
    ) -> list[Event]:
        """Get recent events from history."""
        events = self._event_history
        
        if category:
            events = [e for e in events if e.category == category]
        if event_type:
            events = [e for e in events if e.event_type == event_type]
        
        return events[-count:]

Part 5: Base Agent Implementation
File: src/sentinel/agents/base.py
python"""
Base agent class for all AI agents.
"""
import asyncio
import logging
from abc import ABC, abstractmethod
from datetime import datetime
from typing import Optional, Any, TYPE_CHECKING
from uuid import UUID, uuid4

from sentinel.core.models.event import (
    Event, EventCategory, EventSeverity,
    AgentAction, AgentDecision
)

if TYPE_CHECKING:
    from sentinel.core.engine import SentinelEngine

logger = logging.getLogger(__name__)


class BaseAgent(ABC):
    """
    Base class for all Sentinel AI agents.
    
    Provides:
    - Lifecycle management (start/stop)
    - Event subscription
    - Action execution with audit logging
    - Confidence-based decision framework
    - LLM integration (local-first)
    """
    
    # Class attributes
    agent_name: str = "base"
    agent_description: str = "Base agent"
    
    def __init__(self, engine: "SentinelEngine", config: dict):
        self.engine = engine
        self.config = config
        
        self.id = uuid4()
        self._running = False
        self._task: Optional[asyncio.Task] = None
        
        # Decision thresholds
        self.auto_execute_threshold = config.get("auto_execute_threshold", 0.95)
        self.log_execute_threshold = config.get("log_execute_threshold", 0.80)
        self.confirm_threshold = config.get("confirm_threshold", 0.60)
        
        # Rate limiting
        self.max_actions_per_minute = config.get("max_actions_per_minute", 10)
        self._action_timestamps: list[datetime] = []
        
        # LLM configuration
        self.llm_enabled = config.get("llm_enabled", True)
        self.llm_model = config.get("llm_model", "llama3.1:8b")
        self.llm_fallback = config.get("llm_fallback", "claude-3-5-sonnet")
    
    async def start(self) -> None:
        """Start the agent."""
        self._running = True
        
        # Subscribe to relevant events
        await self._subscribe_events()
        
        # Start main loop if agent has one
        if hasattr(self, '_main_loop'):
            self._task = asyncio.create_task(self._main_loop())
        
        logger.info(f"Agent '{self.agent_name}' started")
    
    async def stop(self) -> None:
        """Stop the agent."""
        self._running = False
        
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        
        logger.info(f"Agent '{self.agent_name}' stopped")
    
    @abstractmethod
    async def _subscribe_events(self) -> None:
        """Subscribe to events this agent cares about."""
        pass
    
    @abstractmethod
    async def analyze(self, event: Event) -> Optional[AgentDecision]:
        """
        Analyze an event and decide on action.
        
        Returns AgentDecision with confidence score and proposed actions.
        """
        pass
    
    async def execute_action(
        self,
        action_type: str,
        target_type: str,
        target_id: str,
        parameters: dict,
        reasoning: str,
        confidence: float,
        trigger_event: Optional[Event] = None,
        reversible: bool = True
    ) -> AgentAction:
        """
        Execute an action with full audit logging.
        
        Handles:
        - Confidence-based approval routing
        - Rate limiting
        - Audit logging
        - Rollback data capture
        """
        # Check rate limit
        if not self._check_rate_limit():
            raise RuntimeError(f"Agent '{self.agent_name}' rate limit exceeded")
        
        # Create action record
        action = AgentAction(
            agent_name=self.agent_name,
            action_type=action_type,
            trigger_event_id=trigger_event.id if trigger_event else None,
            reasoning=reasoning,
            confidence=confidence,
            target_type=target_type,
            target_id=target_id,
            parameters=parameters,
            reversible=reversible,
            required_confirmation=confidence < self.auto_execute_threshold
        )
        
        # Determine execution path based on confidence
        if confidence >= self.auto_execute_threshold:
            # Auto-execute
            action = await self._execute_action_internal(action)
        elif confidence >= self.log_execute_threshold:
            # Execute with prominent logging
            logger.warning(
                f"Agent '{self.agent_name}' executing with confidence {confidence:.2f}: "
                f"{action_type} on {target_type}/{target_id}"
            )
            action = await self._execute_action_internal(action)
        elif confidence >= self.confirm_threshold:
            # Request confirmation
            action.status = "pending_confirmation"
            await self._request_confirmation(action)
        else:
            # Escalate to LLM for better analysis
            action.status = "escalated"
            await self._escalate_to_llm(action, trigger_event)
        
        # Publish action event
        await self.engine.event_bus.publish(Event(
            category=EventCategory.AGENT,
            event_type=f"agent.action.{action.status}",
            severity=EventSeverity.INFO,
            source=f"sentinel.agents.{self.agent_name}",
            title=f"Agent Action: {action_type}",
            description=reasoning,
            data=action.model_dump()
        ))
        
        return action
    
    async def _execute_action_internal(self, action: AgentAction) -> AgentAction:
        """Internal action execution - override in subclasses."""
        try:
            # Capture rollback data before execution
            if action.reversible:
                action.rollback_data = await self._capture_rollback_data(action)
            
            # Execute the action
            result = await self._do_execute(action)
            
            action.status = "executed"
            action.result = result
            
            self._action_timestamps.append(datetime.utcnow())
            
        except Exception as e:
            action.status = "failed"
            action.error_message = str(e)
            logger.error(f"Action execution failed: {e}")
        
        return action
    
    @abstractmethod
    async def _do_execute(self, action: AgentAction) -> dict:
        """
        Perform the actual action execution.
        Override in subclasses with specific logic.
        """
        pass
    
    async def _capture_rollback_data(self, action: AgentAction) -> Optional[dict]:
        """Capture state needed to rollback an action."""
        # Override in subclasses
        return None
    
    async def rollback_action(self, action: AgentAction) -> bool:
        """Rollback a previously executed action."""
        if not action.reversible or not action.rollback_data:
            logger.warning(f"Action {action.id} cannot be rolled back")
            return False
        
        try:
            await self._do_rollback(action)
            action.rolled_back_at = datetime.utcnow()
            action.status = "rolled_back"
            
            logger.info(f"Action {action.id} rolled back successfully")
            return True
        except Exception as e:
            logger.error(f"Rollback failed for action {action.id}: {e}")
            return False
    
    async def _do_rollback(self, action: AgentAction) -> None:
        """Perform the actual rollback. Override in subclasses."""
        pass
    
    async def _request_confirmation(self, action: AgentAction) -> None:
        """Request human confirmation for an action."""
        await self.engine.event_bus.publish(Event(
            category=EventCategory.AGENT,
            event_type="agent.confirmation_required",
            severity=EventSeverity.WARNING,
            source=f"sentinel.agents.{self.agent_name}",
            title=f"Confirmation Required: {action.action_type}",
            description=action.reasoning,
            data={
                "action_id": str(action.id),
                "action": action.model_dump()
            }
        ))
    
    async def _escalate_to_llm(
        self,
        action: AgentAction,
        trigger_event: Optional[Event]
    ) -> None:
        """Escalate low-confidence decision to LLM for analysis."""
        # Get LLM integration
        llm = self.engine.get_integration("llm")
        if not llm:
            logger.warning("No LLM integration available for escalation")
            return
        
        # Build context for LLM
        context = {
            "agent": self.agent_name,
            "action": action.model_dump(),
            "trigger_event": trigger_event.model_dump() if trigger_event else None,
            "current_state": await self._get_relevant_state()
        }
        
        # Query LLM
        try:
            response = await llm.analyze_decision(context)
            # Handle LLM response...
        except Exception as e:
            logger.error(f"LLM escalation failed: {e}")
    
    async def _get_relevant_state(self) -> dict:
        """Get state relevant to this agent's decisions."""
        return {}
    
    def _check_rate_limit(self) -> bool:
        """Check if agent is within rate limits."""
        now = datetime.utcnow()
        # Remove timestamps older than 1 minute
        self._action_timestamps = [
            ts for ts in self._action_timestamps
            if (now - ts).total_seconds() < 60
        ]
        return len(self._action_timestamps) < self.max_actions_per_minute
    
    async def query_llm(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        prefer_local: bool = True
    ) -> str:
        """
        Query LLM for reasoning assistance.
        
        Uses local Ollama by default, falls back to Claude for complex queries.
        """
        llm = self.engine.get_integration("llm")
        if not llm:
            raise RuntimeError("No LLM integration available")
        
        return await llm.complete(
            prompt=prompt,
            system_prompt=system_prompt,
            model=self.llm_model if prefer_local else self.llm_fallback
        )

Part 6: Discovery Agent Implementation
File: src/sentinel/agents/discovery.py
python"""
Discovery Agent - Network scanning and topology management.
"""
import asyncio
import logging
from datetime import datetime, timedelta
from typing import Optional
from uuid import UUID

from sentinel.agents.base import BaseAgent
from sentinel.core.models.device import (
    Device, DeviceType, DeviceStatus, TrustLevel,
    NetworkInterface, DeviceFingerprint
)
from sentinel.core.models.network import NetworkTopology, TopologyNode, NetworkLink
from sentinel.core.models.event import (
    Event, EventCategory, EventSeverity,
    AgentAction, AgentDecision
)

logger = logging.getLogger(__name__)


# Device fingerprint database
FINGERPRINT_PATTERNS = {
    "vendor_mac_prefixes": {
        "00:1A:2B": "Apple",
        "00:50:56": "VMware",
        "B8:27:EB": "Raspberry Pi",
        "DC:A6:32": "Raspberry Pi",
        "00:0C:29": "VMware",
        # Extended in real implementation...
    },
    "service_signatures": {
        "iot": {
            "ports": [80, 443, 8080, 8443],
            "services": ["upnp", "mdns"],
            "keywords": ["camera", "thermostat", "hub", "smart"]
        },
        "server": {
            "ports": [22, 80, 443, 3306, 5432, 6379, 8080],
            "services": ["ssh", "http", "https", "mysql", "postgresql"]
        },
        "workstation": {
            "ports": [22, 3389, 5900],
            "services": ["ssh", "rdp", "vnc"]
        }
    }
}


class DiscoveryAgent(BaseAgent):
    """
    Network discovery and device classification agent.
    
    Responsibilities:
    - Continuous network scanning
    - Device fingerprinting and classification
    - Topology mapping
    - New device detection and alerting
    """
    
    agent_name = "discovery"
    agent_description = "Network discovery and topology management"
    
    def __init__(self, engine, config: dict):
        super().__init__(engine, config)
        
        # Scan configuration
        self.scan_interval = config.get("scan_interval_seconds", 300)
        self.full_scan_interval = config.get("full_scan_interval_seconds", 3600)
        self.networks_to_scan = config.get("networks", ["192.168.1.0/24"])
        
        # State
        self._last_quick_scan: Optional[datetime] = None
        self._last_full_scan: Optional[datetime] = None
        self._known_devices: dict[str, Device] = {}  # MAC -> Device
    
    async def _subscribe_events(self) -> None:
        """Subscribe to relevant events."""
        self.engine.event_bus.subscribe(
            self._handle_dhcp_event,
            event_type="network.dhcp.lease"
        )
        self.engine.event_bus.subscribe(
            self._handle_arp_event,
            event_type="network.arp.new"
        )
    
    async def _main_loop(self) -> None:
        """Main discovery loop."""
        while self._running:
            try:
                now = datetime.utcnow()
                
                # Check if full scan needed
                if (
                    self._last_full_scan is None or
                    (now - self._last_full_scan).total_seconds() > self.full_scan_interval
                ):
                    await self._perform_full_scan()
                    self._last_full_scan = now
                
                # Quick scan (ARP only)
                elif (
                    self._last_quick_scan is None or
                    (now - self._last_quick_scan).total_seconds() > self.scan_interval
                ):
                    await self._perform_quick_scan()
                    self._last_quick_scan = now
                
                await asyncio.sleep(10)
                
            except Exception as e:
                logger.error(f"Discovery loop error: {e}")
                await asyncio.sleep(30)
    
    async def _perform_quick_scan(self) -> None:
        """Perform quick ARP scan."""
        logger.debug("Performing quick network scan")
        
        for network in self.networks_to_scan:
            devices = await self._arp_scan(network)
            await self._process_discovered_devices(devices, full_scan=False)
    
    async def _perform_full_scan(self) -> None:
        """Perform comprehensive network scan."""
        logger.info("Performing full network scan")
        
        for network in self.networks_to_scan:
            # ARP scan first
            devices = await self._arp_scan(network)
            
            # Then fingerprint each device
            for device in devices:
                await self._fingerprint_device(device)
            
            await self._process_discovered_devices(devices, full_scan=True)
        
        # Update topology
        await self._update_topology()
    
    async def _arp_scan(self, network: str) -> list[Device]:
        """Perform ARP scan of network."""
        devices = []
        
        # Use integration if available
        router = self.engine.get_integration("router")
        if router:
            arp_table = await router.get_arp_table()
            for entry in arp_table:
                device = Device(
                    interfaces=[NetworkInterface(
                        mac_address=entry["mac"],
                        ip_addresses=[entry["ip"]],
                        is_primary=True
                    )]
                )
                # Quick vendor lookup
                device.fingerprint.vendor = self._lookup_vendor(entry["mac"])
                devices.append(device)
        else:
            # Fallback to direct scanning (requires root/admin)
            # Implementation would use scapy or similar
            pass
        
        return devices
    
    async def _fingerprint_device(self, device: Device) -> None:
        """Perform detailed device fingerprinting."""
        ip = device.primary_ip
        if not ip:
            return
        
        # Port scan
        open_ports = await self._scan_ports(ip)
        device.fingerprint.open_ports = open_ports
        
        # Service detection
        services = await self._detect_services(ip, open_ports)
        device.fingerprint.services = services
        
        # OS detection (passive)
        os_info = await self._detect_os(ip)
        if os_info:
            device.fingerprint.os_family = os_info.get("family")
            device.fingerprint.os_version = os_info.get("version")
        
        # Classify device type
        device.device_type = self._classify_device(device.fingerprint)
        
        # Calculate confidence
        device.fingerprint.confidence = self._calculate_confidence(device.fingerprint)
    
    async def _scan_ports(self, ip: str, ports: list[int] = None) -> list[int]:
        """Scan common ports on a device."""
        if ports is None:
            ports = [22, 80, 443, 445, 3389, 5900, 8080, 8443, 9090]
        
        open_ports = []
        for port in ports:
            try:
                _, writer = await asyncio.wait_for(
                    asyncio.open_connection(ip, port),
                    timeout=1.0
                )
                writer.close()
                await writer.wait_closed()
                open_ports.append(port)
            except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
                pass
        
        return open_ports
    
    async def _detect_services(self, ip: str, ports: list[int]) -> list[str]:
        """Detect services running on open ports."""
        services = []
        
        port_service_map = {
            22: "ssh",
            80: "http",
            443: "https",
            445: "smb",
            3389: "rdp",
            5900: "vnc",
            8080: "http-alt",
            9090: "prometheus"
        }
        
        for port in ports:
            if port in port_service_map:
                services.append(port_service_map[port])
        
        return services
    
    async def _detect_os(self, ip: str) -> Optional[dict]:
        """Passive OS detection."""
        # Would use TCP/IP fingerprinting in real implementation
        return None
    
    def _lookup_vendor(self, mac: str) -> Optional[str]:
        """Look up vendor from MAC address OUI."""
        prefix = mac[:8].upper()
        return FINGERPRINT_PATTERNS["vendor_mac_prefixes"].get(prefix)
    
    def _classify_device(self, fingerprint: DeviceFingerprint) -> DeviceType:
        """Classify device type based on fingerprint."""
        # Check for IoT signatures
        iot_sigs = FINGERPRINT_PATTERNS["service_signatures"]["iot"]
        if any(p in fingerprint.open_ports for p in iot_sigs["ports"]):
            if fingerprint.vendor and any(
                kw in fingerprint.vendor.lower()
                for kw in iot_sigs["keywords"]
            ):
                return DeviceType.IOT
        
        # Check for server signatures
        server_sigs = FINGERPRINT_PATTERNS["service_signatures"]["server"]
        if len([p for p in fingerprint.open_ports if p in server_sigs["ports"]]) >= 3:
            return DeviceType.SERVER
        
        # Check for workstation
        if 3389 in fingerprint.open_ports or 5900 in fingerprint.open_ports:
            return DeviceType.WORKSTATION
        
        # Check vendor hints
        if fingerprint.vendor:
            vendor_lower = fingerprint.vendor.lower()
            if "raspberry" in vendor_lower:
                return DeviceType.SERVER
            if "apple" in vendor_lower:
                return DeviceType.WORKSTATION
        
        return DeviceType.UNKNOWN
    
    def _calculate_confidence(self, fingerprint: DeviceFingerprint) -> float:
        """Calculate confidence score for classification."""
        score = 0.0
        
        if fingerprint.vendor:
            score += 0.3
        if fingerprint.os_family:
            score += 0.3
        if fingerprint.services:
            score += 0.2
        if fingerprint.open_ports:
            score += 0.2
        
        return min(score, 1.0)
    
    async def _process_discovered_devices(
        self,
        devices: list[Device],
        full_scan: bool
    ) -> None:
        """Process discovered devices and emit events."""
        for device in devices:
            mac = device.primary_mac
            if not mac:
                continue
            
            if mac not in self._known_devices:
                # New device
                self._known_devices[mac] = device
                
                await self.engine.event_bus.publish(Event(
                    category=EventCategory.DEVICE,
                    event_type="device.discovered",
                    severity=EventSeverity.INFO,
                    source=f"sentinel.agents.{self.agent_name}",
                    source_device_id=device.id,
                    title=f"New device discovered: {device.primary_ip}",
                    description=(
                        f"Type: {device.device_type.value}, "
                        f"Vendor: {device.fingerprint.vendor or 'Unknown'}"
                    ),
                    data=device.model_dump()
                ))
                
                # Analyze for auto-segmentation
                await self.analyze(Event(
                    category=EventCategory.DEVICE,
                    event_type="device.discovered",
                    severity=EventSeverity.INFO,
                    source="internal",
                    title="New device",
                    data=device.model_dump()
                ))
            else:
                # Update existing device
                existing = self._known_devices[mac]
                existing.last_seen = datetime.utcnow()
                existing.status = DeviceStatus.ONLINE
                
                if full_scan:
                    # Update fingerprint on full scan
                    existing.fingerprint = device.fingerprint
                    existing.device_type = device.device_type
    
    async def _update_topology(self) -> None:
        """Update network topology graph."""
        topology = NetworkTopology(name="primary")
        
        # Get LLDP/CDP data from switches if available
        switch = self.engine.get_integration("switch")
        if switch:
            lldp_data = await switch.get_lldp_neighbors()
            # Build topology from LLDP data...
        
        # Save topology to state
        await self.engine.state.set("topology", topology.model_dump())
    
    async def _handle_dhcp_event(self, event: Event) -> None:
        """Handle DHCP lease events from router."""
        data = event.data
        mac = data.get("mac")
        ip = data.get("ip")
        
        if mac and ip:
            if mac not in self._known_devices:
                # Trigger discovery for new DHCP lease
                device = Device(
                    interfaces=[NetworkInterface(
                        mac_address=mac,
                        ip_addresses=[ip],
                        is_primary=True
                    )]
                )
                device.fingerprint.vendor = self._lookup_vendor(mac)
                
                await self._fingerprint_device(device)
                await self._process_discovered_devices([device], full_scan=False)
    
    async def _handle_arp_event(self, event: Event) -> None:
        """Handle new ARP entries."""
        # Similar to DHCP handling
        pass
    
    async def analyze(self, event: Event) -> Optional[AgentDecision]:
        """Analyze device discovery event and propose segmentation."""
        if event.event_type != "device.discovered":
            return None
        
        device_data = event.data
        device = Device(**device_data)
        
        # Determine recommended VLAN
        recommended_vlan = self._recommend_vlan(device)
        
        # Build decision
        decision = AgentDecision(
            agent_name=self.agent_name,
            decision_type="device_segmentation",
            input_events=[event.id],
            input_state={"device": device_data},
            analysis=f"Device classified as {device.device_type.value} with "
                     f"{device.fingerprint.confidence:.0%} confidence",
            options_considered=[
                {
                    "vlan": recommended_vlan,
                    "reason": f"Standard VLAN for {device.device_type.value}"
                }
            ],
            selected_option={"vlan": recommended_vlan},
            confidence=device.fingerprint.confidence
        )
        
        # If confidence is high enough, propose action
        if decision.confidence >= self.confirm_threshold:
            await self.execute_action(
                action_type="assign_vlan",
                target_type="device",
                target_id=str(device.id),
                parameters={"vlan_id": recommended_vlan},
                reasoning=decision.analysis,
                confidence=decision.confidence,
                trigger_event=event
            )
        
        return decision
    
    def _recommend_vlan(self, device: Device) -> int:
        """Recommend VLAN based on device classification."""
        vlan_map = {
            DeviceType.WORKSTATION: 10,
            DeviceType.SERVER: 20,
            DeviceType.STORAGE: 30,
            DeviceType.IOT: 100,
            DeviceType.CAMERA: 100,
            DeviceType.MOBILE: 50,
            DeviceType.UNKNOWN: 200,  # Guest/quarantine
        }
        return vlan_map.get(device.device_type, 200)
    
    async def _do_execute(self, action: AgentAction) -> dict:
        """Execute VLAN assignment action."""
        if action.action_type == "assign_vlan":
            device_id = action.target_id
            vlan_id = action.parameters["vlan_id"]
            
            # Get device
            device = None
            for d in self._known_devices.values():
                if str(d.id) == device_id:
                    device = d
                    break
            
            if not device:
                raise ValueError(f"Device {device_id} not found")
            
            # Execute via switch integration
            switch = self.engine.get_integration("switch")
            if switch:
                await switch.set_port_vlan(
                    mac=device.primary_mac,
                    vlan_id=vlan_id
                )
            
            # Update device state
            device.assigned_vlan = vlan_id
            
            return {"assigned_vlan": vlan_id, "device_mac": device.primary_mac}
        
        raise ValueError(f"Unknown action type: {action.action_type}")
    
    async def _capture_rollback_data(self, action: AgentAction) -> Optional[dict]:
        """Capture current VLAN assignment for rollback."""
        if action.action_type == "assign_vlan":
            device_id = action.target_id
            for device in self._known_devices.values():
                if str(device.id) == device_id:
                    return {"previous_vlan": device.assigned_vlan}
        return None
    
    async def _do_rollback(self, action: AgentAction) -> None:
        """Rollback VLAN assignment."""
        if action.action_type == "assign_vlan" and action.rollback_data:
            previous_vlan = action.rollback_data.get("previous_vlan")
            if previous_vlan is not None:
                action.parameters["vlan_id"] = previous_vlan
                await self._do_execute(action)

Part 7: Configuration Schema
File: config/homelab.yaml
yaml# Sentinel Configuration for Homelab Deployment
# =============================================

sentinel:
  name: "home-sentinel"
  environment: "homelab"
  log_level: "INFO"

# State management
state:
  backend: "sqlite"  # sqlite, postgresql, redis
  path: "/var/lib/sentinel/state.db"
  backup_interval_hours: 24

# Network integrations
integrations:
  router:
    type: "opnsense"  # opnsense, pfsense, mikrotik
    host: "192.168.1.1"
    api_key: "${ROUTER_API_KEY}"
    verify_ssl: false
    
  switch:
    type: "ubiquiti"  # ubiquiti, cisco, netgear
    controller_url: "https://192.168.1.2:8443"
    username: "${UNIFI_USERNAME}"
    password: "${UNIFI_PASSWORD}"
    site: "default"
    
  hypervisor:
    type: "proxmox"
    host: "192.168.1.10"
    api_token: "${PROXMOX_TOKEN}"
    verify_ssl: false
    
  storage:
    type: "truenas"
    host: "192.168.1.20"
    api_key: "${TRUENAS_API_KEY}"
    
  kubernetes:
    type: "k3s"
    kubeconfig: "/etc/sentinel/kubeconfig.yaml"
    
  llm:
    primary:
      type: "ollama"
      host: "http://localhost:11434"
      model: "llama3.1:8b"
    fallback:
      type: "anthropic"
      api_key: "${ANTHROPIC_API_KEY}"
      model: "claude-3-5-sonnet-20241022"

# Agent configuration
agents:
  discovery:
    enabled: true
    scan_interval_seconds: 300
    full_scan_interval_seconds: 3600
    networks:
      - "192.168.1.0/24"
      - "192.168.10.0/24"
      - "192.168.20.0/24"
      - "192.168.100.0/24"
    auto_execute_threshold: 0.95
    log_execute_threshold: 0.80
    confirm_threshold: 0.60
    llm_enabled: true
    llm_model: "llama3.1:8b"
    
  optimizer:
    enabled: true
    analysis_interval_seconds: 60
    qos_enabled: true
    auto_execute_threshold: 0.90
    priorities:
      - application: "zoom"
        priority: "high"
        bandwidth_guarantee_mbps: 10
      - application: "teams"
        priority: "high"
        bandwidth_guarantee_mbps: 10
      - application: "backup"
        priority: "low"
        bandwidth_limit_mbps: 100
        
  planner:
    enabled: true
    auto_execute_threshold: 0.85
    default_vlans:
      management: 1
      workstations: 10
      servers: 20
      storage: 30
      ai_compute: 50
      iot: 100
      guest: 200
      quarantine: 666
      
  healer:
    enabled: true
    auto_execute_threshold: 0.95
    health_check_interval_seconds: 30
    auto_restart_services: true
    auto_failover: true
    # Security actions always require confirmation
    security_actions_require_confirmation: true

# VLAN definitions
vlans:
  - id: 1
    name: "Management"
    purpose: "management"
    subnet: "192.168.1.0/24"
    gateway: "192.168.1.1"
    dns_zone: "mgmt.home.lan"
    
  - id: 10
    name: "Workstations"
    purpose: "workstations"
    subnet: "192.168.10.0/24"
    gateway: "192.168.10.1"
    dns_zone: "ws.home.lan"
    
  - id: 20
    name: "Servers"
    purpose: "servers"
    subnet: "192.168.20.0/24"
    gateway: "192.168.20.1"
    dns_zone: "srv.home.lan"
    
  - id: 30
    name: "Storage"
    purpose: "storage"
    subnet: "192.168.30.0/24"
    gateway: "192.168.30.1"
    dns_zone: "stor.home.lan"
    isolated: true
    allowed_destinations: [20]  # Only servers can access storage
    
  - id: 50
    name: "AI Compute"
    purpose: "ai_compute"
    subnet: "192.168.50.0/24"
    gateway: "192.168.50.1"
    dns_zone: "ai.home.lan"
    
  - id: 100
    name: "IoT"
    purpose: "iot"
    subnet: "192.168.100.0/24"
    gateway: "192.168.100.1"
    dns_zone: "iot.home.lan"
    isolated: true
    allowed_destinations: []  # Internet only
    
  - id: 200
    name: "Guest"
    purpose: "guest"
    subnet: "192.168.200.0/24"
    gateway: "192.168.200.1"
    isolated: true
    allowed_destinations: []

# Security policies
policies:
  segmentation:
    - name: "IoT Isolation"
      source_vlan: 100
      destination_vlan: 10
      default_action: "deny"
      
    - name: "Workstation to Server"
      source_vlan: 10
      destination_vlan: 20
      allowed_services: ["ssh", "http", "https", "smb"]
      default_action: "deny"
      
    - name: "Server to Storage"
      source_vlan: 20
      destination_vlan: 30
      allowed_services: ["nfs", "smb", "iscsi"]
      default_action: "deny"

# API configuration
api:
  host: "0.0.0.0"
  port: 8080
  cors_origins:
    - "http://localhost:3000"
    - "https://sentinel.home.lan"
  auth:
    type: "jwt"
    secret: "${JWT_SECRET}"
    token_expiry_hours: 24

# Alerting
alerting:
  enabled: true
  channels:
    - type: "pushover"
      api_key: "${PUSHOVER_API_KEY}"
      user_key: "${PUSHOVER_USER_KEY}"
      priorities:
        critical: 2
        warning: 0
        info: -1
```

---

## Part 8: Implementation Phases

### Phase 1: Foundation (Weeks 1-4)

**Goals:**
- Repository setup with CI/CD
- Core data models implemented
- Basic engine with event bus
- Configuration system

**Tasks:**
```
Week 1:
- [ ] Initialize repository with structure
- [ ] Set up pyproject.toml with dependencies
- [ ] Implement core data models (device, network, policy, event)
- [ ] Create basic configuration loader

Week 2:
- [ ] Implement EventBus with pub/sub
- [ ] Create StateManager with SQLite backend
- [ ] Build Scheduler for periodic tasks
- [ ] Write unit tests for core components

Week 3:
- [ ] Implement SentinelEngine orchestration
- [ ] Create integration base classes
- [ ] Implement Ollama LLM integration
- [ ] Set up logging and telemetry

Week 4:
- [ ] Create Docker development environment
- [ ] Implement basic CLI for testing
- [ ] Write integration tests
- [ ] Documentation for Phase 1
```

### Phase 2: Network Discovery (Weeks 5-8)

**Goals:**
- Discovery agent fully functional
- Router/switch integrations
- Device fingerprinting
- Topology visualization

**Tasks:**
```
Week 5:
- [ ] Implement Discovery agent base
- [ ] ARP scanning implementation
- [ ] Vendor MAC lookup database
- [ ] Basic device classification

Week 6:
- [ ] Port scanning implementation
- [ ] Service detection
- [ ] OS fingerprinting (passive)
- [ ] Confidence scoring

Week 7:
- [ ] OPNsense/pfSense router integration
- [ ] UniFi switch integration
- [ ] LLDP/CDP topology discovery
- [ ] Network topology graph

Week 8:
- [ ] TrueNAS storage integration
- [ ] Proxmox hypervisor integration
- [ ] Device auto-classification tuning
- [ ] Testing with real hardware
```

### Phase 3: Intelligent Segmentation (Weeks 9-12)

**Goals:**
- Planner agent operational
- Automatic VLAN assignment
- Firewall rule generation
- DNS zone automation

**Tasks:**
```
Week 9:
- [ ] Implement Planner agent
- [ ] VLAN recommendation logic
- [ ] Segmentation policy engine
- [ ] Device-to-VLAN mapping

Week 10:
- [ ] Router firewall rule API
- [ ] Switch VLAN configuration API
- [ ] Automated rule generation
- [ ] Policy validation

Week 11:
- [ ] DNS zone management
- [ ] DHCP scope automation
- [ ] Inter-VLAN routing policies
- [ ] Rollback mechanism

Week 12:
- [ ] End-to-end segmentation testing
- [ ] Performance optimization
- [ ] Documentation update
- [ ] Homelab deployment
```

### Phase 4: Traffic Optimization (Weeks 13-16)

**Goals:**
- Optimizer agent operational
- QoS policy automation
- Traffic analysis
- Bandwidth management

**Tasks:**
```
Week 13:
- [ ] Implement Optimizer agent
- [ ] NetFlow/sFlow collection
- [ ] Traffic classification
- [ ] Application detection

Week 14:
- [ ] QoS policy engine
- [ ] Bandwidth allocation
- [ ] Priority queue management
- [ ] Real-time metrics

Week 15:
- [ ] Forecaster integration
- [ ] Predictive bandwidth allocation
- [ ] Multi-WAN load balancing
- [ ] Congestion detection

Week 16:
- [ ] Automated QoS tuning
- [ ] Performance dashboards
- [ ] Integration testing
- [ ] Documentation
```

### Phase 5: Self-Healing & Response (Weeks 17-20)

**Goals:**
- Healer agent operational
- Automated failover
- Incident response
- Human-in-the-loop workflows

**Tasks:**
```
Week 17:
- [ ] Implement Healer agent
- [ ] Health check framework
- [ ] Service restart automation
- [ ] Link failover

Week 18:
- [ ] Guardian agent (security)
- [ ] Anomaly detection
- [ ] Quarantine actions
- [ ] Alert correlation

Week 19:
- [ ] Confirmation workflow system
- [ ] Mobile notifications
- [ ] Action approval API
- [ ] Rollback automation

Week 20:
- [ ] Full system testing
- [ ] Chaos engineering tests
- [ ] Performance tuning
- [ ] Production deployment

Part 9: Testing Strategy
File: tests/conftest.py
python"""
Pytest configuration and fixtures.
"""
import asyncio
import pytest
from typing import AsyncGenerator
from unittest.mock import AsyncMock, MagicMock

from sentinel.core.engine import SentinelEngine
from sentinel.core.event_bus import EventBus
from sentinel.core.state import StateManager


@pytest.fixture(scope="session")
def event_loop():
    """Create event loop for async tests."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


@pytest.fixture
async def event_bus() -> AsyncGenerator[EventBus, None]:
    """Create test event bus."""
    bus = EventBus(persist_events=False)
    await bus.start()
    yield bus
    await bus.stop()


@pytest.fixture
def mock_config() -> dict:
    """Create mock configuration."""
    return {
        "state": {"backend": "memory"},
        "agents": {
            "discovery": {"enabled": True, "networks": ["192.168.1.0/24"]},
            "optimizer": {"enabled": False},
            "planner": {"enabled": False},
            "healer": {"enabled": False},
        },
        "integrations": {}
    }


@pytest.fixture
async def engine(mock_config) -> AsyncGenerator[SentinelEngine, None]:
    """Create test engine."""
    eng = SentinelEngine(mock_config)
    # Don't start integrations in tests
    eng._load_integrations = AsyncMock()
    await eng.start()
    yield eng
    await eng.stop()


@pytest.fixture
def mock_router():
    """Create mock router integration."""
    router = MagicMock()
    router.get_arp_table = AsyncMock(return_value=[
        {"mac": "00:1A:2B:3C:4D:5E", "ip": "192.168.1.100"},
        {"mac": "B8:27:EB:11:22:33", "ip": "192.168.1.101"},
    ])
    router.get_firewall_rules = AsyncMock(return_value=[])
    return router


@pytest.fixture
def mock_switch():
    """Create mock switch integration."""
    switch = MagicMock()
    switch.get_lldp_neighbors = AsyncMock(return_value=[])
    switch.set_port_vlan = AsyncMock()
    return switch
File: tests/unit/test_agents.py
python"""
Unit tests for AI agents.
"""
import pytest
from uuid import uuid4

from sentinel.agents.discovery import DiscoveryAgent
from sentinel.core.models.device import Device, DeviceType, NetworkInterface, DeviceFingerprint
from sentinel.core.models.event import Event, EventCategory, EventSeverity


class TestDiscoveryAgent:
    """Tests for Discovery agent."""
    
    @pytest.fixture
    async def discovery_agent(self, engine, mock_router, mock_switch):
        """Create discovery agent with mocked integrations."""
        engine._integrations["router"] = mock_router
        engine._integrations["switch"] = mock_switch
        
        agent = DiscoveryAgent(
            engine=engine,
            config={"networks": ["192.168.1.0/24"]}
        )
        await agent.start()
        yield agent
        await agent.stop()
    
    def test_vendor_lookup(self, discovery_agent):
        """Test MAC vendor lookup."""
        # Apple
        assert discovery_agent._lookup_vendor("00:1A:2B:3C:4D:5E") is None
        # Raspberry Pi
        assert discovery_agent._lookup_vendor("B8:27:EB:11:22:33") == "Raspberry Pi"
    
    def test_classify_device_iot(self, discovery_agent):
        """Test IoT device classification."""
        fingerprint = DeviceFingerprint(
            vendor="Ring",
            open_ports=[80, 443],
            services=["http", "https"]
        )
        assert discovery_agent._classify_device(fingerprint) == DeviceType.IOT
    
    def test_classify_device_server(self, discovery_agent):
        """Test server classification."""
        fingerprint = DeviceFingerprint(
            open_ports=[22, 80, 443, 3306],
            services=["ssh", "http", "https", "mysql"]
        )
        assert discovery_agent._classify_device(fingerprint) == DeviceType.SERVER
    
    def test_recommend_vlan(self, discovery_agent):
        """Test VLAN recommendation."""
        iot_device = Device(
            device_type=DeviceType.IOT,
            interfaces=[NetworkInterface(mac_address="00:11:22:33:44:55")]
        )
        assert discovery_agent._recommend_vlan(iot_device) == 100
        
        server = Device(
            device_type=DeviceType.SERVER,
            interfaces=[NetworkInterface(mac_address="00:11:22:33:44:56")]
        )
        assert discovery_agent._recommend_vlan(server) == 20
    
    def test_confidence_calculation(self, discovery_agent):
        """Test confidence score calculation."""
        # Full fingerprint
        full_fp = DeviceFingerprint(
            vendor="Dell",
            os_family="Linux",
            services=["ssh", "http"],
            open_ports=[22, 80]
        )
        assert discovery_agent._calculate_confidence(full_fp) == 1.0
        
        # Partial fingerprint
        partial_fp = DeviceFingerprint(
            vendor="Unknown"
        )
        assert discovery_agent._calculate_confidence(partial_fp) == 0.3
    
    @pytest.mark.asyncio
    async def test_analyze_new_device(self, discovery_agent, event_bus):
        """Test analysis of new device event."""
        device = Device(
            device_type=DeviceType.IOT,
            interfaces=[NetworkInterface(
                mac_address="00:11:22:33:44:55",
                ip_addresses=["192.168.1.100"]
            )],
            fingerprint=DeviceFingerprint(
                vendor="SmartThings",
                confidence=0.85
            )
        )
        
        event = Event(
            category=EventCategory.DEVICE,
            event_type="device.discovered",
            severity=EventSeverity.INFO,
            source="test",
            title="Test device",
            data=device.model_dump()
        )
        
        decision = await discovery_agent.analyze(event)
        
        assert decision is not None
        assert decision.decision_type == "device_segmentation"
        assert decision.confidence == 0.85

Part 10: Deployment
File: deploy/docker/Dockerfile
dockerfile# Sentinel Security Platform
# Multi-stage build for optimized image

# Stage 1: Builder
FROM python:3.11-slim as builder

WORKDIR /build

# Install build dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    libffi-dev \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY pyproject.toml .
RUN pip install --no-cache-dir build && \
    pip wheel --no-cache-dir --wheel-dir /wheels .

# Stage 2: Runtime
FROM python:3.11-slim

WORKDIR /app

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    libffi8 \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy wheels and install
COPY --from=builder /wheels /wheels
RUN pip install --no-cache-dir /wheels/*.whl && \
    rm -rf /wheels

# Copy application code
COPY src/sentinel /app/sentinel
COPY config /app/config

# Create non-root user
RUN useradd -m -u 1000 sentinel && \
    mkdir -p /var/lib/sentinel && \
    chown -R sentinel:sentinel /app /var/lib/sentinel

USER sentinel

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

# Expose API port
EXPOSE 8080

# Default command
CMD ["python", "-m", "sentinel.main", "--config", "/app/config/homelab.yaml"]
File: deploy/docker/docker-compose.prod.yml
yamlversion: "3.8"

services:
  sentinel:
    build:
      context: ../..
      dockerfile: deploy/docker/Dockerfile
    container_name: sentinel
    restart: unless-stopped
    ports:
      - "8080:8080"
    volumes:
      - sentinel-data:/var/lib/sentinel
      - ./config:/app/config:ro
    environment:
      - SENTINEL_CONFIG=/app/config/homelab.yaml
      - ROUTER_API_KEY=${ROUTER_API_KEY}
      - UNIFI_USERNAME=${UNIFI_USERNAME}
      - UNIFI_PASSWORD=${UNIFI_PASSWORD}
      - PROXMOX_TOKEN=${PROXMOX_TOKEN}
      - TRUENAS_API_KEY=${TRUENAS_API_KEY}
      - ANTHROPIC_API_KEY=${ANTHROPIC_API_KEY}
      - JWT_SECRET=${JWT_SECRET}
      - PUSHOVER_API_KEY=${PUSHOVER_API_KEY}
      - PUSHOVER_USER_KEY=${PUSHOVER_USER_KEY}
    networks:
      - sentinel-net
    depends_on:
      - ollama

  ollama:
    image: ollama/ollama:latest
    container_name: sentinel-ollama
    restart: unless-stopped
    ports:
      - "11434:11434"
    volumes:
      - ollama-models:/root/.ollama
    deploy:
      resources:
        reservations:
          devices:
            - driver: nvidia
              count: 1
              capabilities: [gpu]
    networks:
      - sentinel-net

  # Optional: Grafana for dashboards
  grafana:
    image: grafana/grafana:latest
    container_name: sentinel-grafana
    restart: unless-stopped
    ports:
      - "3000:3000"
    volumes:
      - grafana-data:/var/lib/grafana
    environment:
      - GF_SECURITY_ADMIN_PASSWORD=${GRAFANA_PASSWORD}
    networks:
      - sentinel-net

volumes:
  sentinel-data:
  ollama-models:
  grafana-data:

networks:
  sentinel-net:
    driver: bridge

Summary
This design provides a complete, production-ready architecture for Sentinel with:

Intuitive naming - All modules have clear, descriptive names
Modular architecture - Each component is independent and testable
AI-native design - Agents are first-class citizens with reasoning capabilities
Local-first AI - Ollama integration reduces API costs
Human-in-the-loop - Confidence thresholds ensure safety
Homelab-ready - Integrations for your specific hardware
Production patterns - Proper logging, testing, deployment