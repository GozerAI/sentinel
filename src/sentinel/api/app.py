"""
Sentinel API - FastAPI application for the Sentinel platform.

Provides REST API endpoints for:
- Status and health
- Device management
- Agent control
- Event streaming
- Configuration
"""
import logging
import os
from contextlib import asynccontextmanager
from datetime import datetime
from typing import Optional
from uuid import UUID

import httpx
from fastapi import FastAPI, HTTPException, Depends, Query, Request

from sentinel.core.utils import utc_now
from sentinel.core.metrics import get_metrics_collector, configure_metrics
from fastapi.middleware.cors import CORSMiddleware
from starlette.responses import Response
from pydantic import BaseModel, Field

from sentinel.api.auth import (
    configure_auth,
    get_current_user,
    require_scope,
    AuthMiddleware,
)
from sentinel.core.models.device import DeviceStatus

logger = logging.getLogger(__name__)

ZUULTIMATE_BASE_URL = os.environ.get("ZUULTIMATE_BASE_URL", "http://localhost:8000")

# Global engine reference (set during startup)
_engine = None

# CORS configuration - secure defaults
# Only allow localhost origins by default for development
# Configure explicitly for production deployments
_cors_origins: list[str] = [
    "http://localhost:3000",
    "http://localhost:8080",
    "http://127.0.0.1:3000",
    "http://127.0.0.1:8080",
]


def get_engine():
    """Dependency to get the engine instance."""
    if _engine is None:
        raise HTTPException(status_code=503, detail="Engine not initialized")
    return _engine


def configure_cors(origins: list[str]) -> None:
    """
    Configure allowed CORS origins.

    This should be called during application startup with the configured origins.

    Args:
        origins: List of allowed origin URLs (e.g., ["https://admin.example.com"])
    """
    global _cors_origins

    if not origins:
        logger.warning(
            "No CORS origins configured - using secure localhost-only defaults. "
            "Configure 'api.cors_origins' for production deployments."
        )
        return

    # Validate and warn about wildcard usage
    if "*" in origins:
        logger.warning(
            "CORS configured with wildcard '*' - this allows ALL origins and is "
            "INSECURE for production! Only use for local development."
        )

    _cors_origins = origins
    logger.info(f"CORS configured with {len(origins)} allowed origins")


# ── Zuultimate tenant auth ─────────────────────────────────────────────────

async def get_tenant(request: Request) -> dict:
    """Validate bearer token against Zuultimate and return tenant context."""
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing or invalid Authorization header")

    token = auth[7:]
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.get(
                f"{ZUULTIMATE_BASE_URL}/v1/identity/auth/validate",
                headers={"Authorization": f"Bearer {token}"},
            )
    except httpx.RequestError as e:
        logger.error("Zuultimate unreachable: %s", e)
        raise HTTPException(status_code=503, detail="Auth service unavailable")

    if resp.status_code == 401:
        raise HTTPException(status_code=401, detail="Invalid or expired credentials")
    if resp.status_code != 200:
        raise HTTPException(status_code=502, detail="Auth service error")

    return resp.json()


def require_entitlement(entitlement: str):
    """Dependency factory: blocks if tenant lacks the required entitlement."""
    async def _check(tenant: dict = Depends(get_tenant)) -> dict:
        if entitlement not in tenant.get("entitlements", []):
            raise HTTPException(
                status_code=403,
                detail=f"Your plan does not include '{entitlement}'. Upgrade to access this feature.",
            )
        return tenant
    return _check


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager."""
    # Configure auth from engine config if available
    if _engine and hasattr(_engine, 'config'):
        configure_auth(_engine.config)

        # Configure CORS from config
        api_config = _engine.config.get("api", {})
        cors_origins = api_config.get("cors_origins", [])
        configure_cors(cors_origins)

    yield


app = FastAPI(
    title="Sentinel API",
    description="AI-Native Security Platform API",
    version="0.1.0",
    lifespan=lifespan
)

# CORS middleware - uses secure defaults, configured via lifespan
# Note: allow_origins uses a callable to support dynamic configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins,  # Secure localhost-only defaults
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "X-API-Key", "Content-Type", "Accept"],
)

# Auth middleware for logging (optional)
app.add_middleware(AuthMiddleware)


# =============================================================================
# Schemas
# =============================================================================

class StatusResponse(BaseModel):
    """Engine status response."""
    status: str
    uptime_seconds: float
    agents: dict[str, dict]
    integrations: dict[str, bool]


class DeviceResponse(BaseModel):
    """Device information response."""
    id: str
    mac: str
    hostname: Optional[str] = None
    device_type: str
    vendor: Optional[str] = None
    ip_addresses: list[str] = []
    vlan: Optional[int] = None
    trust_level: str = "unknown"
    last_seen: Optional[datetime] = None
    online: bool = True


class DeviceListResponse(BaseModel):
    """List of devices response."""
    devices: list[DeviceResponse]
    total: int


class VLANResponse(BaseModel):
    """VLAN information response."""
    id: int
    name: str
    subnet: Optional[str] = None
    gateway: Optional[str] = None
    purpose: Optional[str] = None
    device_count: int = 0
    isolated: bool = False


class AgentResponse(BaseModel):
    """Agent information response."""
    name: str
    enabled: bool
    actions_taken: int
    last_action: Optional[datetime] = None
    stats: dict


class EventResponse(BaseModel):
    """Event information response."""
    id: str
    category: str
    event_type: str
    severity: str
    title: str
    description: Optional[str] = None
    created_at: datetime
    source: str
    acknowledged: bool = False


class ActionRequest(BaseModel):
    """Request to perform an action."""
    action_type: str
    target_type: str
    target_id: str
    parameters: dict = Field(default_factory=dict)
    confirm: bool = False


class ActionResponse(BaseModel):
    """Action result response."""
    id: str
    status: str
    message: str
    requires_confirmation: bool = False


# =============================================================================
# Routes - Status
# =============================================================================

@app.get("/", tags=["Status"])
async def root():
    """API root - basic info."""
    return {
        "name": "Sentinel API",
        "version": "0.1.0",
        "status": "running"
    }


@app.get("/health", tags=["Status"])
async def health():
    """Health check endpoint."""
    return {"status": "healthy", "timestamp": utc_now().isoformat()}


@app.get("/status", response_model=StatusResponse, tags=["Status"])
async def get_status(
    engine=Depends(get_engine),
    tenant: dict = Depends(require_entitlement("sentinel:basic")),
):
    """Get engine status. Requires sentinel:basic entitlement."""
    status = await engine.get_status()
    return StatusResponse(
        status=status["status"],
        uptime_seconds=status["uptime_seconds"],
        agents=status["agents"],
        integrations=status["integrations"]
    )


# =============================================================================
# Routes - Devices
# =============================================================================

@app.get("/devices", response_model=DeviceListResponse, tags=["Devices"])
async def list_devices(
    device_type: Optional[str] = Query(None, description="Filter by device type"),
    vlan: Optional[int] = Query(None, description="Filter by VLAN"),
    online: Optional[bool] = Query(None, description="Filter by online status"),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    engine=Depends(get_engine),
    tenant: dict = Depends(require_entitlement("sentinel:basic")),
):
    """List all discovered devices."""
    # Get devices from discovery agent
    discovery = engine.agents.get("discovery")
    if not discovery:
        raise HTTPException(status_code=503, detail="Discovery agent not available")

    # Use inventory.devices from Discovery agent
    devices = list(discovery._inventory.devices.values())

    # Apply filters
    if device_type:
        devices = [d for d in devices if d.device_type.value == device_type]
    if vlan is not None:
        devices = [d for d in devices if d.assigned_vlan == vlan]
    if online is not None:
        devices = [d for d in devices if (d.status == DeviceStatus.ONLINE) == online]

    total = len(devices)
    devices = devices[offset:offset + limit]

    return DeviceListResponse(
        devices=[
            DeviceResponse(
                id=str(d.id),
                mac=d.primary_mac or "",
                hostname=d.hostname,
                device_type=d.device_type.value,
                vendor=d.fingerprint.vendor if d.fingerprint else None,
                ip_addresses=[str(ip) for iface in d.interfaces for ip in iface.ip_addresses],
                vlan=d.assigned_vlan,
                trust_level=d.trust_level.value if hasattr(d.trust_level, 'value') else d.trust_level,
                last_seen=d.last_seen,
                online=d.status == DeviceStatus.ONLINE if hasattr(d, 'status') else True
            )
            for d in devices
        ],
        total=total
    )


@app.get("/devices/{device_id}", response_model=DeviceResponse, tags=["Devices"])
async def get_device(device_id: str, engine=Depends(get_engine), tenant: dict = Depends(require_entitlement("sentinel:basic"))):
    """Get device by ID."""
    from uuid import UUID

    discovery = engine.agents.get("discovery")
    if not discovery:
        raise HTTPException(status_code=503, detail="Discovery agent not available")

    # Look up device by ID
    device = None
    try:
        device_uuid = UUID(device_id)
        device = discovery._inventory.devices.get(device_uuid)
    except ValueError:
        # Not a valid UUID, try looking up by MAC
        device = discovery._inventory.get_by_mac(device_id)

    if not device:
        raise HTTPException(status_code=404, detail="Device not found")

    return DeviceResponse(
        id=str(device.id),
        mac=device.primary_mac or "",
        hostname=device.hostname,
        device_type=device.device_type.value,
        vendor=device.fingerprint.vendor if device.fingerprint else None,
        ip_addresses=[str(ip) for iface in device.interfaces for ip in iface.ip_addresses],
        vlan=device.assigned_vlan,
        trust_level=device.trust_level.value if hasattr(device.trust_level, 'value') else device.trust_level,
        last_seen=device.last_seen,
        online=device.status == DeviceStatus.ONLINE if hasattr(device, 'status') else True
    )


@app.post("/devices/{device_id}/scan", tags=["Devices"])
async def scan_device(device_id: str, engine=Depends(get_engine), tenant: dict = Depends(require_entitlement("sentinel:basic"))):
    """Trigger rescan of a specific device."""
    from uuid import UUID

    discovery = engine.agents.get("discovery")
    if not discovery:
        raise HTTPException(status_code=503, detail="Discovery agent not available")

    # Look up device
    device = None
    try:
        device_uuid = UUID(device_id)
        device = discovery._inventory.devices.get(device_uuid)
    except ValueError:
        device = discovery._inventory.get_by_mac(device_id)

    if not device:
        raise HTTPException(status_code=404, detail="Device not found")

    # Get device IP and fingerprint it
    ip = device.primary_ip
    if ip:
        await discovery._fingerprint_device(device)

    return {"status": "scan_initiated", "device_id": device_id}


# =============================================================================
# Routes - VLANs
# =============================================================================

@app.get("/vlans", response_model=list[VLANResponse], tags=["VLANs"])
async def list_vlans(engine=Depends(get_engine), tenant: dict = Depends(require_entitlement("sentinel:full"))):
    """List all configured VLANs."""
    planner = engine.agents.get("planner")
    if not planner:
        raise HTTPException(status_code=503, detail="Planner agent not available")

    vlans = []
    for vlan_id, vlan in planner._vlans.items():
        # Count devices in VLAN
        discovery = engine.agents.get("discovery")
        device_count = 0
        if discovery:
            device_count = sum(
                1 for d in discovery._inventory.devices.values()
                if d.assigned_vlan == vlan_id
            )

        vlans.append(VLANResponse(
            id=vlan_id,
            name=vlan.get("name", f"VLAN {vlan_id}"),
            subnet=vlan.get("subnet"),
            gateway=vlan.get("gateway"),
            purpose=vlan.get("purpose"),
            device_count=device_count,
            isolated=vlan.get("isolated", False)
        ))

    return vlans


@app.get("/vlans/{vlan_id}", response_model=VLANResponse, tags=["VLANs"])
async def get_vlan(vlan_id: int, engine=Depends(get_engine), tenant: dict = Depends(require_entitlement("sentinel:full"))):
    """Get VLAN by ID."""
    planner = engine.agents.get("planner")
    if not planner:
        raise HTTPException(status_code=503, detail="Planner agent not available")

    vlan = planner._vlans.get(vlan_id)
    if not vlan:
        raise HTTPException(status_code=404, detail="VLAN not found")

    discovery = engine.agents.get("discovery")
    device_count = 0
    if discovery:
        device_count = sum(
            1 for d in discovery._inventory.devices.values()
            if d.assigned_vlan == vlan_id
        )

    return VLANResponse(
        id=vlan_id,
        name=vlan.get("name", f"VLAN {vlan_id}"),
        subnet=vlan.get("subnet"),
        gateway=vlan.get("gateway"),
        purpose=vlan.get("purpose"),
        device_count=device_count,
        isolated=vlan.get("isolated", False)
    )


class VLANCreateRequest(BaseModel):
    """Request to create a VLAN."""
    id: int
    name: str
    subnet: Optional[str] = None
    gateway: Optional[str] = None
    purpose: Optional[str] = None
    isolated: bool = False


@app.post("/vlans", response_model=VLANResponse, tags=["VLANs"])
async def create_vlan(request: VLANCreateRequest, engine=Depends(get_engine), tenant: dict = Depends(require_entitlement("sentinel:full"))):
    """Create a new VLAN."""
    planner = engine.agents.get("planner")
    if not planner:
        raise HTTPException(status_code=503, detail="Planner agent not available")

    if request.id in planner._vlans:
        raise HTTPException(status_code=409, detail="VLAN already exists")

    vlan_data = {
        "id": request.id,
        "name": request.name,
        "subnet": request.subnet,
        "gateway": request.gateway,
        "purpose": request.purpose,
        "isolated": request.isolated,
    }
    planner._vlans[request.id] = vlan_data

    return VLANResponse(
        id=request.id,
        name=request.name,
        subnet=request.subnet,
        gateway=request.gateway,
        purpose=request.purpose,
        device_count=0,
        isolated=request.isolated
    )


# =============================================================================
# Routes - Policies
# =============================================================================

class PolicyResponse(BaseModel):
    """Segmentation policy response."""
    id: str
    name: str
    source_vlan: int
    destination_vlan: int
    allowed_services: list[str] = []
    denied_services: list[str] = []
    default_action: str = "deny"


class FirewallRuleResponse(BaseModel):
    """Firewall rule response."""
    id: str
    name: str
    description: Optional[str] = None
    action: str
    source_zone: Optional[str] = None
    destination_zone: Optional[str] = None
    destination_port: Optional[int] = None
    protocol: Optional[str] = None
    auto_generated: bool = False
    priority: int = 500


@app.get("/policies", response_model=list[PolicyResponse], tags=["Policies"])
async def list_policies(engine=Depends(get_engine), tenant: dict = Depends(require_entitlement("sentinel:full"))):
    """List all segmentation policies."""
    planner = engine.agents.get("planner")
    if not planner:
        raise HTTPException(status_code=503, detail="Planner agent not available")

    return [
        PolicyResponse(
            id=p.get("id", policy_id),
            name=p.get("name", policy_id),
            source_vlan=p.get("source_vlan"),
            destination_vlan=p.get("destination_vlan"),
            allowed_services=p.get("allowed_services", []),
            denied_services=p.get("denied_services", []),
            default_action=p.get("default_action", "deny")
        )
        for policy_id, p in planner._segmentation_policies.items()
    ]


@app.get("/policies/{policy_id}", response_model=PolicyResponse, tags=["Policies"])
async def get_policy(policy_id: str, engine=Depends(get_engine), tenant: dict = Depends(require_entitlement("sentinel:full"))):
    """Get a specific segmentation policy."""
    planner = engine.agents.get("planner")
    if not planner:
        raise HTTPException(status_code=503, detail="Planner agent not available")

    policy = planner._segmentation_policies.get(policy_id)
    if not policy:
        raise HTTPException(status_code=404, detail="Policy not found")

    return PolicyResponse(
        id=policy.get("id", policy_id),
        name=policy.get("name", policy_id),
        source_vlan=policy.get("source_vlan"),
        destination_vlan=policy.get("destination_vlan"),
        allowed_services=policy.get("allowed_services", []),
        denied_services=policy.get("denied_services", []),
        default_action=policy.get("default_action", "deny")
    )


@app.get("/firewall-rules", response_model=list[FirewallRuleResponse], tags=["Policies"])
async def list_firewall_rules(engine=Depends(get_engine), tenant: dict = Depends(require_entitlement("sentinel:full"))):
    """List all firewall rules."""
    planner = engine.agents.get("planner")
    if not planner:
        raise HTTPException(status_code=503, detail="Planner agent not available")

    return [
        FirewallRuleResponse(
            id=r.get("id", rule_id),
            name=r.get("name", rule_id),
            description=r.get("description"),
            action=r.get("action", "allow"),
            source_zone=r.get("source_zone"),
            destination_zone=r.get("destination_zone"),
            destination_port=r.get("destination_port"),
            protocol=r.get("protocol"),
            auto_generated=r.get("auto_generated", False),
            priority=r.get("priority", 500)
        )
        for rule_id, r in planner._firewall_rules.items()
    ]


# =============================================================================
# Routes - Agents
# =============================================================================

@app.get("/agents", response_model=list[AgentResponse], tags=["Agents"])
async def list_agents(engine=Depends(get_engine), tenant: dict = Depends(require_entitlement("sentinel:full"))):
    """List all agents."""
    agents = []
    for name, agent in engine.agents.items():
        stats = agent.stats
        # Support both _enabled (mock) and _running (real agents)
        enabled = getattr(agent, '_enabled', None)
        if enabled is None:
            enabled = getattr(agent, '_running', True)
        agents.append(AgentResponse(
            name=name,
            enabled=enabled,
            actions_taken=stats.get("actions_taken", 0),
            last_action=None,
            stats=stats
        ))
    return agents


@app.get("/agents/{agent_name}", response_model=AgentResponse, tags=["Agents"])
async def get_agent(agent_name: str, engine=Depends(get_engine), tenant: dict = Depends(require_entitlement("sentinel:full"))):
    """Get agent by name."""
    agent = engine.agents.get(agent_name)
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")

    stats = agent.stats
    # Support both _enabled (mock) and _running (real agents)
    enabled = getattr(agent, '_enabled', None)
    if enabled is None:
        enabled = getattr(agent, '_running', True)
    return AgentResponse(
        name=agent_name,
        enabled=enabled,
        actions_taken=stats.get("actions_taken", 0),
        last_action=None,
        stats=stats
    )


@app.post("/agents/{agent_name}/enable", tags=["Agents"])
async def enable_agent(agent_name: str, engine=Depends(get_engine), tenant: dict = Depends(require_entitlement("sentinel:full"))):
    """Enable an agent."""
    agent = engine.agents.get(agent_name)
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    
    agent._enabled = True
    return {"status": "enabled", "agent": agent_name}


@app.post("/agents/{agent_name}/disable", tags=["Agents"])
async def disable_agent(agent_name: str, engine=Depends(get_engine), tenant: dict = Depends(require_entitlement("sentinel:full"))):
    """Disable an agent."""
    agent = engine.agents.get(agent_name)
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    
    agent._enabled = False
    return {"status": "disabled", "agent": agent_name}


# =============================================================================
# Routes - Events
# =============================================================================

@app.get("/events", response_model=list[EventResponse], tags=["Events"])
async def list_events(
    category: Optional[str] = Query(None, description="Filter by category"),
    severity: Optional[str] = Query(None, description="Filter by severity"),
    limit: int = Query(100, ge=1, le=1000),
    engine=Depends(get_engine),
    tenant: dict = Depends(require_entitlement("sentinel:full")),
):
    """List recent events."""
    events = engine.event_bus.get_recent_events(limit * 2)  # Get more for filtering
    
    if category:
        events = [e for e in events if e.category.value == category]
    if severity:
        events = [e for e in events if e.severity.value == severity]
    
    events = events[:limit]
    
    return [
        EventResponse(
            id=str(e.id),
            category=e.category.value,
            event_type=e.event_type,
            severity=e.severity.value,
            title=e.title,
            description=e.description,
            created_at=e.timestamp,
            source=e.source,
            acknowledged=e.acknowledged
        )
        for e in events
    ]


@app.post("/events/{event_id}/acknowledge", tags=["Events"])
async def acknowledge_event(event_id: str, engine=Depends(get_engine), tenant: dict = Depends(require_entitlement("sentinel:full"))):
    """Acknowledge an event."""
    # Find and acknowledge event
    for event in engine.event_bus._event_history:
        if str(event.id) == event_id:
            event.acknowledged = True
            event.acknowledged_at = utc_now()
            return {"status": "acknowledged", "event_id": event_id}
    
    raise HTTPException(status_code=404, detail="Event not found")


# =============================================================================
# Routes - Actions
# =============================================================================

@app.post("/actions", response_model=ActionResponse, tags=["Actions"])
async def execute_action(request: ActionRequest, engine=Depends(get_engine), tenant: dict = Depends(require_entitlement("sentinel:full"))):
    """Execute an action through an agent."""
    # Route to appropriate agent based on action type
    agent_mapping = {
        "scan_network": "discovery",
        "assign_vlan": "planner",
        "create_vlan": "planner",
        "apply_qos": "optimizer",
        "block_ip": "guardian",
        "quarantine": "guardian",
        "restart_service": "healer",
    }
    
    agent_name = agent_mapping.get(request.action_type)
    if not agent_name:
        raise HTTPException(
            status_code=400, 
            detail=f"Unknown action type: {request.action_type}"
        )
    
    agent = engine.agents.get(agent_name)
    if not agent:
        raise HTTPException(
            status_code=503, 
            detail=f"Agent {agent_name} not available"
        )
    
    # Create and execute action
    from sentinel.core.models.event import AgentAction
    from uuid import uuid4
    
    action = AgentAction(
        agent_name=agent_name,
        action_type=request.action_type,
        target_type=request.target_type,
        target_id=request.target_id,
        parameters=request.parameters,
        reasoning="Manual API request",
        confidence=1.0 if request.confirm else 0.5,
        required_confirmation=not request.confirm
    )

    if action.required_confirmation and not request.confirm:
        return ActionResponse(
            id=str(action.id),
            status="pending_confirmation",
            message="Action requires confirmation. Set confirm=true to execute.",
            requires_confirmation=True
        )

    success = await agent._execute_action(action)

    return ActionResponse(
        id=str(action.id),
        status="success" if success else "failed",
        message="Action executed" if success else "Action failed",
        requires_confirmation=False
    )


# =============================================================================
# Routes - Scan
# =============================================================================

@app.post("/scan/quick", tags=["Scan"])
async def quick_scan(engine=Depends(get_engine), tenant: dict = Depends(require_entitlement("sentinel:basic"))):
    """Trigger a quick network scan."""
    discovery = engine.agents.get("discovery")
    if not discovery:
        raise HTTPException(status_code=503, detail="Discovery agent not available")

    await discovery._perform_quick_scan()
    return {"status": "scan_initiated", "type": "quick"}


@app.post("/scan/full", tags=["Scan"])
async def full_scan(engine=Depends(get_engine), tenant: dict = Depends(require_entitlement("sentinel:basic"))):
    """Trigger a full network scan."""
    discovery = engine.agents.get("discovery")
    if not discovery:
        raise HTTPException(status_code=503, detail="Discovery agent not available")

    await discovery._perform_full_scan()
    return {"status": "scan_initiated", "type": "full"}


# =============================================================================
# Routes - Security
# =============================================================================

@app.get("/security/blocked", tags=["Security"])
async def list_blocked_ips(engine=Depends(get_engine), tenant: dict = Depends(require_entitlement("sentinel:basic"))):
    """List blocked IP addresses."""
    guardian = engine.agents.get("guardian")
    if not guardian:
        raise HTTPException(status_code=503, detail="Guardian agent not available")
    
    return {
        "blocked_ips": list(guardian._blocked_ips),
        "count": len(guardian._blocked_ips)
    }


@app.get("/security/quarantined", tags=["Security"])
async def list_quarantined(engine=Depends(get_engine), tenant: dict = Depends(require_entitlement("sentinel:basic"))):
    """List quarantined devices."""
    guardian = engine.agents.get("guardian")
    if not guardian:
        raise HTTPException(status_code=503, detail="Guardian agent not available")
    
    return {
        "quarantined": list(guardian._quarantined_devices),
        "count": len(guardian._quarantined_devices)
    }


@app.post("/security/unblock/{ip}", tags=["Security"])
async def unblock_ip(ip: str, engine=Depends(get_engine), tenant: dict = Depends(require_entitlement("sentinel:basic"))):
    """Unblock an IP address."""
    guardian = engine.agents.get("guardian")
    if not guardian:
        raise HTTPException(status_code=503, detail="Guardian agent not available")
    
    success = await guardian.unblock_ip(ip)
    return {"status": "unblocked" if success else "failed", "ip": ip}


# =============================================================================
# Routes - Visualization
# =============================================================================


class TopologyRequest(BaseModel):
    """Request for topology generation."""
    layout: str = "hierarchical"  # hierarchical, force_directed, circular, radial, grid
    include_offline: bool = True
    include_infrastructure: bool = True
    group_by_vlan: bool = True


class TopologyResponse(BaseModel):
    """Topology graph response."""
    name: str
    description: str
    generated_at: str
    layout: str
    node_count: int
    edge_count: int
    vlans: list[int]
    nodes: list[dict]
    edges: list[dict]


class ExportRequest(BaseModel):
    """Request for topology export."""
    format: str = "json"  # json, dot, d3, svg, mermaid, cytoscape
    layout: str = "hierarchical"
    include_positions: bool = True


@app.get("/topology", response_model=TopologyResponse, tags=["Visualization"])
async def get_topology(
    layout: str = Query("hierarchical", description="Layout algorithm"),
    include_offline: bool = Query(True, description="Include offline devices"),
    include_infrastructure: bool = Query(True, description="Include infrastructure"),
    group_by_vlan: bool = Query(True, description="Group nodes by VLAN"),
    engine=Depends(get_engine),
    tenant: dict = Depends(require_entitlement("sentinel:full")),
):
    """
    Get network topology graph.

    Returns a topology graph with nodes and edges representing
    the network structure. Supports multiple layout algorithms.
    """
    from sentinel.visualization.topology import TopologyVisualizer, GraphLayout

    discovery = engine.agents.get("discovery")
    if not discovery:
        raise HTTPException(status_code=503, detail="Discovery agent not available")

    # Create visualizer with config
    visualizer = TopologyVisualizer({
        "default_layout": layout,
        "include_offline": include_offline,
        "group_by_vlan": group_by_vlan,
    })

    # Build graph from discovery data
    graph = await visualizer.build_from_discovery(
        discovery,
        include_infrastructure=include_infrastructure
    )

    # Apply layout
    try:
        layout_enum = GraphLayout(layout)
        visualizer.apply_layout(graph, layout_enum)
    except ValueError:
        # Invalid layout, use default
        pass

    data = graph.to_dict()
    return TopologyResponse(
        name=data["name"],
        description=data["description"],
        generated_at=data["generated_at"],
        layout=data["layout"],
        node_count=data["stats"]["node_count"],
        edge_count=data["stats"]["edge_count"],
        vlans=data["stats"]["vlans"],
        nodes=data["nodes"],
        edges=data["edges"],
    )


@app.get("/topology/summary", tags=["Visualization"])
async def get_topology_summary(engine=Depends(get_engine), tenant: dict = Depends(require_entitlement("sentinel:full"))):
    """
    Get topology summary with VLAN breakdown.

    Returns summary statistics about the network topology
    without the full node/edge details.
    """
    from sentinel.visualization.topology import TopologyVisualizer

    discovery = engine.agents.get("discovery")
    if not discovery:
        raise HTTPException(status_code=503, detail="Discovery agent not available")

    visualizer = TopologyVisualizer()
    graph = await visualizer.build_from_discovery(discovery)

    return {
        "total_nodes": len(graph.nodes),
        "total_edges": len(graph.edges),
        "infrastructure_nodes": sum(1 for n in graph.nodes if n.is_infrastructure),
        "device_nodes": sum(1 for n in graph.nodes if not n.is_infrastructure),
        "vlans": visualizer.get_vlan_summary(graph),
        "node_types": _count_node_types(graph),
        "edge_types": _count_edge_types(graph),
    }


def _count_node_types(graph) -> dict:
    """Count nodes by type."""
    counts = {}
    for node in graph.nodes:
        node_type = node.node_type.value
        counts[node_type] = counts.get(node_type, 0) + 1
    return counts


def _count_edge_types(graph) -> dict:
    """Count edges by type."""
    counts = {}
    for edge in graph.edges:
        edge_type = edge.edge_type.value
        counts[edge_type] = counts.get(edge_type, 0) + 1
    return counts


@app.post("/topology/export", tags=["Visualization"])
async def export_topology(
    request: ExportRequest,
    engine=Depends(get_engine),
    tenant: dict = Depends(require_entitlement("sentinel:full")),
):
    """
    Export topology in various formats.

    Supported formats:
    - json: JSON for web frontends
    - dot: Graphviz DOT format
    - d3: D3.js compatible JSON
    - svg: SVG image
    - mermaid: Mermaid diagram
    - cytoscape: Cytoscape.js format
    """
    from sentinel.visualization import (
        TopologyVisualizer,
        GraphLayout,
        JSONExporter,
        DOTExporter,
        D3Exporter,
        SVGExporter,
        MermaidExporter,
        CytoscapeExporter,
    )

    discovery = engine.agents.get("discovery")
    if not discovery:
        raise HTTPException(status_code=503, detail="Discovery agent not available")

    visualizer = TopologyVisualizer({"default_layout": request.layout})
    graph = await visualizer.build_from_discovery(discovery)

    # Apply layout
    try:
        layout_enum = GraphLayout(request.layout)
        visualizer.apply_layout(graph, layout_enum)
    except ValueError:
        pass

    # Export based on format
    format_map = {
        "json": JSONExporter(include_positions=request.include_positions),
        "dot": DOTExporter(),
        "d3": D3Exporter(),
        "svg": SVGExporter(),
        "mermaid": MermaidExporter(),
        "cytoscape": CytoscapeExporter(),
    }

    exporter = format_map.get(request.format.lower())
    if not exporter:
        raise HTTPException(
            status_code=400,
            detail=f"Unknown format: {request.format}. Supported: {list(format_map.keys())}"
        )

    content = exporter.export(graph)

    # Set content type based on format
    content_types = {
        "json": "application/json",
        "dot": "text/plain",
        "d3": "application/json",
        "svg": "image/svg+xml",
        "mermaid": "text/plain",
        "cytoscape": "application/json",
    }

    return Response(
        content=content,
        media_type=content_types.get(request.format.lower(), "text/plain")
    )


@app.get("/topology/d3", tags=["Visualization"])
async def get_d3_visualization(engine=Depends(get_engine), tenant: dict = Depends(require_entitlement("sentinel:full"))):
    """
    Get complete D3.js HTML visualization.

    Returns a standalone HTML page with an interactive
    D3.js force-directed graph visualization.
    """
    from sentinel.visualization import TopologyVisualizer, D3Exporter

    discovery = engine.agents.get("discovery")
    if not discovery:
        raise HTTPException(status_code=503, detail="Discovery agent not available")

    visualizer = TopologyVisualizer()
    graph = await visualizer.build_from_discovery(discovery)

    exporter = D3Exporter()
    html_content = exporter.export_with_html(graph, title="Sentinel Network Topology")

    return Response(content=html_content, media_type="text/html")


@app.get("/topology/node/{node_id}", tags=["Visualization"])
async def get_node_connections(node_id: str, engine=Depends(get_engine), tenant: dict = Depends(require_entitlement("sentinel:full"))):
    """
    Get connection details for a specific node.

    Returns all connections (edges) involving the specified node,
    including both inbound and outbound connections.
    """
    from sentinel.visualization.topology import TopologyVisualizer

    discovery = engine.agents.get("discovery")
    if not discovery:
        raise HTTPException(status_code=503, detail="Discovery agent not available")

    visualizer = TopologyVisualizer()
    graph = await visualizer.build_from_discovery(discovery)

    # Check if node exists
    node = graph.get_node(node_id)
    if not node:
        raise HTTPException(status_code=404, detail="Node not found")

    connections = visualizer.get_node_connections(graph, node_id)
    connections["node"] = node.to_dict()

    return connections


# =============================================================================
# Routes - Metrics
# =============================================================================

@app.get("/metrics", tags=["Monitoring"])
async def metrics():
    """
    Prometheus metrics endpoint.

    Returns metrics in Prometheus text exposition format.
    This endpoint is typically scraped by Prometheus.
    """
    collector = get_metrics_collector()
    return Response(
        content=collector.generate_metrics(),
        media_type=collector.get_content_type()
    )


# =============================================================================
# Application Factory
# =============================================================================

def create_app(engine) -> FastAPI:
    """Create FastAPI app with engine reference."""
    global _engine
    _engine = engine

    # Configure metrics collection
    configure_metrics(engine)

    return app
