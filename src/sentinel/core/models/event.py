"""
Event models for the event bus and logging.

This module defines event structures used throughout the Sentinel platform
for inter-component communication, alerting, and audit logging.
"""

from datetime import datetime, timezone
from enum import Enum
from typing import Optional, Any
from pydantic import BaseModel, Field
from uuid import UUID, uuid4


def _utc_now() -> datetime:
    """Get current UTC time (timezone-aware)."""
    return datetime.now(timezone.utc)


class EventSeverity(str, Enum):
    """Event severity levels following syslog conventions."""

    DEBUG = "debug"
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


class EventCategory(str, Enum):
    """High-level event categories."""

    NETWORK = "network"
    SECURITY = "security"
    DEVICE = "device"
    AGENT = "agent"
    SYSTEM = "system"
    COMPLIANCE = "compliance"


class Event(BaseModel):
    """
    Base event model for all system events.

    Events are the primary communication mechanism between components
    in the Sentinel platform. They are published to the event bus and
    can be subscribed to by any component.

    Attributes:
        id: Unique event identifier
        timestamp: Event creation timestamp
        category: High-level event category
        event_type: Specific event type (e.g., "device.discovered")
        severity: Event severity level
        source: Component that generated the event
        source_device_id: Device associated with event (if applicable)
        title: Short event title
        description: Detailed event description
        data: Additional event-specific data
        correlation_id: ID for correlating related events
        parent_event_id: Parent event for event chains
        acknowledged: Whether event has been acknowledged
        acknowledged_by: Who acknowledged the event
        acknowledged_at: When event was acknowledged
    """

    id: UUID = Field(default_factory=uuid4)
    timestamp: datetime = Field(default_factory=_utc_now)

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

    def acknowledge(self, by: str) -> None:
        """Mark event as acknowledged."""
        self.acknowledged = True
        self.acknowledged_by = by
        self.acknowledged_at = _utc_now()

    def create_child(self, event_type: str, title: str, **kwargs) -> "Event":
        """Create a child event correlated to this one."""
        return Event(
            category=kwargs.get("category", self.category),
            event_type=event_type,
            severity=kwargs.get("severity", self.severity),
            source=kwargs.get("source", self.source),
            source_device_id=kwargs.get("source_device_id", self.source_device_id),
            title=title,
            description=kwargs.get("description"),
            data=kwargs.get("data", {}),
            correlation_id=self.correlation_id or self.id,
            parent_event_id=self.id,
        )


class SecurityAlert(Event):
    """
    Security-specific alert with additional threat context.

    Extends the base Event with fields specific to security events,
    including MITRE ATT&CK mapping and risk assessment.

    Attributes:
        threat_type: Type of threat detected
        mitre_tactic: MITRE ATT&CK tactic
        mitre_technique: MITRE ATT&CK technique
        risk_score: Calculated risk score (0-10)
        confidence: Detection confidence (0-1)
        affected_device_ids: Devices affected by this threat
        affected_user_ids: Users affected by this threat
        auto_response_taken: Whether automated response was triggered
        auto_response_action: Description of automated response
        requires_investigation: Whether manual investigation is needed
    """

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

    @property
    def is_high_risk(self) -> bool:
        """Check if this is a high-risk alert."""
        return self.risk_score >= 7.0

    @property
    def is_actionable(self) -> bool:
        """Check if alert requires action."""
        return self.requires_investigation and not self.acknowledged


class AgentAction(BaseModel):
    """
    Records an action taken by an AI agent.

    Critical for auditability, rollback capability, and understanding
    agent decision-making.

    Attributes:
        id: Unique action identifier
        timestamp: Action timestamp
        agent_name: Name of the agent taking action
        action_type: Type of action taken
        trigger_event_id: Event that triggered this action
        reasoning: Explanation of why action was taken
        confidence: Agent's confidence in this action
        target_type: Type of target (device, vlan, rule, etc.)
        target_id: Identifier of the target
        parameters: Action parameters
        status: Current status (pending, executed, failed, rolled_back)
        result: Execution result data
        error_message: Error message if action failed
        reversible: Whether action can be reversed
        rollback_data: Data needed to reverse the action
        rolled_back_at: Timestamp of rollback
        required_confirmation: Whether human approval was needed
        confirmed_by: Who approved the action
        confirmed_at: When action was approved
    """

    id: UUID = Field(default_factory=uuid4)
    timestamp: datetime = Field(default_factory=_utc_now)

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

    @property
    def is_complete(self) -> bool:
        """Check if action execution is complete."""
        return self.status in ("executed", "failed", "rolled_back")

    @property
    def can_rollback(self) -> bool:
        """Check if action can be rolled back."""
        return (
            self.reversible
            and self.rollback_data is not None
            and self.status == "executed"
            and self.rolled_back_at is None
        )

    def mark_executed(self, result: dict) -> None:
        """Mark action as successfully executed."""
        self.status = "executed"
        self.result = result

    def mark_failed(self, error: str) -> None:
        """Mark action as failed."""
        self.status = "failed"
        self.error_message = error

    def mark_rolled_back(self) -> None:
        """Mark action as rolled back."""
        self.status = "rolled_back"
        self.rolled_back_at = _utc_now()


class AgentDecision(BaseModel):
    """
    Records the decision-making process of an agent.

    Used for explainability, debugging, and improving agent performance.

    Attributes:
        id: Unique decision identifier
        timestamp: Decision timestamp
        agent_name: Name of the deciding agent
        decision_type: Type of decision being made
        input_events: Events that informed this decision
        input_state: State information used in decision
        analysis: Agent's analysis text
        options_considered: Options that were evaluated
        selected_option: The chosen option
        rejection_reasons: Why other options were rejected
        confidence: Confidence in the decision
        action_ids: Actions resulting from this decision
        llm_model: LLM model used (if any)
        llm_prompt_tokens: Tokens used in prompt
        llm_completion_tokens: Tokens in completion
    """

    id: UUID = Field(default_factory=uuid4)
    timestamp: datetime = Field(default_factory=_utc_now)

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

    @property
    def used_llm(self) -> bool:
        """Check if LLM was used for this decision."""
        return self.llm_model is not None

    @property
    def total_tokens(self) -> int:
        """Get total LLM tokens used."""
        return (self.llm_prompt_tokens or 0) + (self.llm_completion_tokens or 0)


class MetricEvent(Event):
    """
    Time-series metric event for monitoring.

    Attributes:
        metric_name: Name of the metric
        metric_value: Numeric value
        metric_unit: Unit of measurement
        tags: Metric tags for filtering
    """

    category: EventCategory = EventCategory.SYSTEM

    metric_name: str = ""
    metric_value: float = 0.0
    metric_unit: str = ""
    tags: dict[str, str] = Field(default_factory=dict)


class AuditLogEntry(BaseModel):
    """
    Audit log entry for compliance and forensics.

    Captures all significant actions and changes in the system.
    """

    id: UUID = Field(default_factory=uuid4)
    timestamp: datetime = Field(default_factory=_utc_now)

    # Who
    actor_type: str  # user, agent, system
    actor_id: str
    actor_name: str

    # What
    action: str
    resource_type: str
    resource_id: str

    # Details
    changes: dict = Field(default_factory=dict)  # before/after
    context: dict = Field(default_factory=dict)

    # Result
    success: bool = True
    error_message: Optional[str] = None

    # Source
    source_ip: Optional[str] = None
    user_agent: Optional[str] = None
