"""
Base agent class for all AI agents.

This module provides the foundation for all Sentinel AI agents,
including lifecycle management, decision framework, and action execution.
"""

import asyncio
import logging
from abc import ABC, abstractmethod
from datetime import datetime, timedelta
from typing import Optional, Any, TYPE_CHECKING
from uuid import UUID, uuid4

from sentinel.core.utils import utc_now
from sentinel.core.models.event import (
    Event,
    EventCategory,
    EventSeverity,
    AgentAction,
    AgentDecision,
)

if TYPE_CHECKING:
    from sentinel.core.engine import SentinelEngine
    from sentinel.core.learning import LearningSystem

logger = logging.getLogger(__name__)


class BaseAgent(ABC):
    """
    Base class for all Sentinel AI agents.

    Provides the foundation for building intelligent agents that can:
    - Subscribe to and process events
    - Make decisions with configurable confidence thresholds
    - Execute actions with full audit logging
    - Rollback actions when needed
    - Query LLMs for complex reasoning

    Subclasses must implement:
    - _subscribe_events(): Subscribe to relevant events
    - analyze(): Analyze events and propose actions
    - _do_execute(): Perform actual action execution

    Attributes:
        agent_name: Unique identifier for the agent
        agent_description: Human-readable description
        engine: Reference to the Sentinel engine
        config: Agent configuration

    Confidence Thresholds:
        - auto_execute_threshold (0.95): Execute without logging
        - log_execute_threshold (0.80): Execute with prominent logging
        - confirm_threshold (0.60): Request human confirmation with timeout
        - Below confirm_threshold: Escalate to LLM with autonomous fallback

    Autonomous Operation:
        When fully_autonomous=True (default), agents will:
        - Use learning system to adjust confidence based on past outcomes
        - Auto-approve pending actions after confirmation_timeout
        - Execute LLM-recommended actions without waiting for human input
        - Fall back to conservative auto-execution if LLM unavailable

    Example:
        ```python
        class MyAgent(BaseAgent):
            agent_name = "my_agent"
            agent_description = "Does something useful"

            async def _subscribe_events(self):
                self.engine.event_bus.subscribe(
                    self._handle_event,
                    category=EventCategory.NETWORK
                )

            async def analyze(self, event):
                # Analyze and return AgentDecision
                pass

            async def _do_execute(self, action):
                # Perform the action
                return {"result": "success"}
        ```
    """

    # Class attributes - override in subclasses
    agent_name: str = "base"
    agent_description: str = "Base agent"

    def __init__(self, engine: "SentinelEngine", config: dict):
        """
        Initialize the agent.

        Args:
            engine: Reference to the Sentinel engine
            config: Agent-specific configuration
        """
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

        # Autonomous operation settings
        self.fully_autonomous = config.get("fully_autonomous", True)
        self.confirmation_timeout = timedelta(
            seconds=config.get("confirmation_timeout_seconds", 30)
        )
        self.low_confidence_auto_execute = config.get("low_confidence_auto_execute", True)
        self.llm_decision_weight = config.get("llm_decision_weight", 0.3)

        # Learning integration
        self.use_learning = config.get("use_learning", True)

        # Pending confirmation tracking
        self._pending_confirmations: dict[UUID, asyncio.Task] = {}

        # Action history
        self._actions: list[AgentAction] = []
        self._decisions: list[AgentDecision] = []

    async def start(self) -> None:
        """Start the agent."""
        self._running = True

        # Subscribe to relevant events
        await self._subscribe_events()

        # Start main loop if agent has one
        if hasattr(self, "_main_loop"):
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
        """
        Subscribe to events this agent cares about.

        Subclasses must implement this to set up event subscriptions.
        """
        pass

    @abstractmethod
    async def analyze(self, event: Event) -> Optional[AgentDecision]:
        """
        Analyze an event and decide on action.

        Args:
            event: Event to analyze

        Returns:
            AgentDecision with confidence score and proposed actions,
            or None if no action needed.
        """
        pass

    def _get_learning_system(self) -> Optional["LearningSystem"]:
        """Get the learning system from the engine if available."""
        if hasattr(self.engine, "learning_system"):
            learning = self.engine.learning_system
            # Verify it's an actual LearningSystem, not a mock
            if learning is not None and hasattr(learning, "get_adjusted_confidence"):
                # Additional check: the method should be callable and not a MagicMock
                method = getattr(learning, "get_adjusted_confidence", None)
                if callable(method) and not hasattr(method, "_mock_name"):
                    return learning
        return None

    def _get_adjusted_confidence(self, action_type: str, base_confidence: float) -> float:
        """
        Get learning-adjusted confidence for an action.

        Args:
            action_type: Type of action
            base_confidence: Original confidence score

        Returns:
            Adjusted confidence incorporating learning outcomes
        """
        if not self.use_learning:
            return base_confidence

        learning = self._get_learning_system()
        if learning:
            adjusted = learning.get_adjusted_confidence(
                self.agent_name, action_type, base_confidence
            )
            if adjusted != base_confidence:
                logger.debug(
                    f"Confidence adjusted by learning: {base_confidence:.2f} -> {adjusted:.2f} "
                    f"for {action_type}"
                )
            return adjusted

        return base_confidence

    async def execute_action(
        self,
        action_type: str,
        target_type: str,
        target_id: str,
        parameters: dict,
        reasoning: str,
        confidence: float,
        trigger_event: Optional[Event] = None,
        reversible: bool = True,
    ) -> AgentAction:
        """
        Execute an action with full audit logging and autonomous operation.

        Handles:
        - Learning-adjusted confidence scoring
        - Confidence-based approval routing with autonomous fallback
        - Rate limiting
        - Audit logging
        - Rollback data capture

        Args:
            action_type: Type of action (e.g., "assign_vlan")
            target_type: Type of target (e.g., "device")
            target_id: Target identifier
            parameters: Action parameters
            reasoning: Explanation for the action
            confidence: Confidence score (0.0-1.0)
            trigger_event: Event that triggered this action
            reversible: Whether action can be rolled back

        Returns:
            AgentAction record with execution status

        Raises:
            RuntimeError: If rate limit exceeded
        """
        # Check rate limit
        if not self._check_rate_limit():
            raise RuntimeError(f"Agent '{self.agent_name}' rate limit exceeded")

        # Apply learning adjustments to confidence
        adjusted_confidence = self._get_adjusted_confidence(action_type, confidence)

        # Create action record
        action = AgentAction(
            agent_name=self.agent_name,
            action_type=action_type,
            trigger_event_id=trigger_event.id if trigger_event else None,
            reasoning=reasoning,
            confidence=adjusted_confidence,
            target_type=target_type,
            target_id=target_id,
            parameters=parameters,
            reversible=reversible,
            required_confirmation=adjusted_confidence < self.auto_execute_threshold,
        )

        # Determine execution path based on adjusted confidence
        if adjusted_confidence >= self.auto_execute_threshold:
            # Auto-execute - highest confidence
            action = await self._execute_action_internal(action)

        elif adjusted_confidence >= self.log_execute_threshold:
            # Execute with prominent logging
            logger.warning(
                f"Agent '{self.agent_name}' executing with confidence {adjusted_confidence:.2f}: "
                f"{action_type} on {target_type}/{target_id}"
            )
            action = await self._execute_action_internal(action)

        elif adjusted_confidence >= self.confirm_threshold:
            # Request confirmation with autonomous timeout fallback
            action.status = "pending_confirmation"
            if self.fully_autonomous:
                action = await self._request_confirmation_with_timeout(action)
            else:
                await self._request_confirmation(action)

        else:
            # Low confidence - escalate to LLM with autonomous fallback
            action.status = "escalated"
            if self.fully_autonomous and self.low_confidence_auto_execute:
                action = await self._escalate_to_llm_autonomous(action, trigger_event)
            else:
                await self._escalate_to_llm(action, trigger_event)

        # Store action
        self._actions.append(action)

        # Publish action event
        await self.engine.event_bus.publish(
            Event(
                category=EventCategory.AGENT,
                event_type=f"agent.action.{action.status}",
                severity=EventSeverity.INFO,
                source=f"sentinel.agents.{self.agent_name}",
                title=f"Agent Action: {action_type}",
                description=reasoning,
                data=action.model_dump(),
            )
        )

        return action

    async def _execute_action_internal(self, action: AgentAction) -> AgentAction:
        """
        Internal action execution with rollback support.

        Args:
            action: Action to execute

        Returns:
            Updated action with execution results
        """
        try:
            # Capture rollback data before execution
            if action.reversible:
                action.rollback_data = await self._capture_rollback_data(action)

            # Execute the action
            result = await self._do_execute(action)

            action.mark_executed(result)
            self._action_timestamps.append(utc_now())

            logger.info(
                f"Agent '{self.agent_name}' executed {action.action_type} "
                f"on {action.target_type}/{action.target_id}"
            )

        except Exception as e:
            action.mark_failed(str(e))
            logger.error(f"Action execution failed: {e}")

        return action

    @abstractmethod
    async def _do_execute(self, action: AgentAction) -> dict:
        """
        Perform the actual action execution.

        Subclasses must implement this with specific action logic.

        Args:
            action: Action to execute

        Returns:
            Dictionary with execution results
        """
        pass

    async def _capture_rollback_data(self, action: AgentAction) -> Optional[dict]:
        """
        Capture state needed to rollback an action.

        Override in subclasses to capture specific state.

        Args:
            action: Action about to be executed

        Returns:
            Dictionary with rollback data, or None
        """
        return None

    async def rollback_action(self, action: AgentAction) -> bool:
        """
        Rollback a previously executed action.

        Args:
            action: Action to rollback

        Returns:
            True if rollback succeeded
        """
        if not action.can_rollback:
            logger.warning(f"Action {action.id} cannot be rolled back")
            return False

        try:
            await self._do_rollback(action)
            action.mark_rolled_back()

            logger.info(f"Action {action.id} rolled back successfully")

            # Publish rollback event
            await self.engine.event_bus.publish(
                Event(
                    category=EventCategory.AGENT,
                    event_type="agent.action.rolled_back",
                    severity=EventSeverity.WARNING,
                    source=f"sentinel.agents.{self.agent_name}",
                    title=f"Action Rolled Back: {action.action_type}",
                    description=f"Action on {action.target_type}/{action.target_id} was rolled back",
                    data=action.model_dump(),
                )
            )

            return True

        except Exception as e:
            logger.error(f"Rollback failed for action {action.id}: {e}")
            return False

    async def _do_rollback(self, action: AgentAction) -> None:
        """
        Perform the actual rollback.

        Override in subclasses with specific rollback logic.

        Args:
            action: Action to rollback
        """
        pass

    async def _request_confirmation(self, action: AgentAction) -> None:
        """
        Request human confirmation for an action.

        Args:
            action: Action requiring confirmation
        """
        await self.engine.event_bus.publish(
            Event(
                category=EventCategory.AGENT,
                event_type="agent.confirmation_required",
                severity=EventSeverity.WARNING,
                source=f"sentinel.agents.{self.agent_name}",
                title=f"Confirmation Required: {action.action_type}",
                description=action.reasoning,
                data={
                    "action_id": str(action.id),
                    "action": action.model_dump(),
                    "confidence": action.confidence,
                    "agent": self.agent_name,
                },
            )
        )

        logger.info(
            f"Confirmation requested for {action.action_type} "
            f"(confidence: {action.confidence:.2f})"
        )

    async def _request_confirmation_with_timeout(self, action: AgentAction) -> AgentAction:
        """
        Request confirmation with autonomous timeout fallback.

        If no human confirmation is received within the timeout period,
        the action is auto-approved for autonomous operation.

        Args:
            action: Action requiring confirmation

        Returns:
            Updated action (executed or pending)
        """
        # First, publish the confirmation request
        await self._request_confirmation(action)

        # Set up timeout for autonomous approval
        timeout_seconds = self.confirmation_timeout.total_seconds()

        logger.info(
            f"Waiting {timeout_seconds}s for confirmation of {action.action_type} "
            f"before auto-approving"
        )

        # Create a task to wait for confirmation
        async def wait_for_confirmation():
            await asyncio.sleep(timeout_seconds)
            return None  # Timeout reached

        try:
            # Wait for either confirmation or timeout
            await asyncio.wait_for(
                self._wait_for_action_confirmation(action.id), timeout=timeout_seconds
            )
            # If we get here, action was confirmed by human
            return action

        except asyncio.TimeoutError:
            # Timeout reached - auto-approve if still pending
            if action.status == "pending_confirmation":
                logger.warning(
                    f"Auto-approving {action.action_type} after {timeout_seconds}s timeout "
                    f"(confidence: {action.confidence:.2f})"
                )
                action.confirmed_by = "autonomous_timeout"
                action.confirmed_at = utc_now()
                action = await self._execute_action_internal(action)

        return action

    async def _wait_for_action_confirmation(self, action_id: UUID) -> bool:
        """
        Wait indefinitely for an action to be confirmed.

        Args:
            action_id: ID of action to wait for

        Returns:
            True when confirmed
        """
        while True:
            # Check if action was confirmed
            for a in self._actions:
                if a.id == action_id and a.status != "pending_confirmation":
                    return True
            await asyncio.sleep(0.5)

    async def confirm_action(self, action_id: UUID, confirmed_by: str) -> bool:
        """
        Confirm and execute a pending action.

        Args:
            action_id: ID of action to confirm
            confirmed_by: Who confirmed the action

        Returns:
            True if action was confirmed and executed
        """
        # Find pending action
        action = None
        for a in self._actions:
            if a.id == action_id and a.status == "pending_confirmation":
                action = a
                break

        if not action:
            logger.warning(f"Action {action_id} not found or not pending")
            return False

        action.confirmed_by = confirmed_by
        action.confirmed_at = utc_now()

        # Execute the action
        await self._execute_action_internal(action)

        return action.status == "executed"

    async def _escalate_to_llm(self, action: AgentAction, trigger_event: Optional[Event]) -> None:
        """
        Escalate low-confidence decision to LLM for analysis (non-autonomous).

        Args:
            action: Action being considered
            trigger_event: Event that triggered the action
        """
        llm = self.engine.get_integration("llm")
        if not llm or not self.llm_enabled:
            logger.warning("No LLM integration available for escalation")
            return

        # Build context for LLM
        context = {
            "agent": self.agent_name,
            "action": action.model_dump(),
            "trigger_event": trigger_event.model_dump() if trigger_event else None,
            "current_state": await self._get_relevant_state(),
        }

        try:
            response = await llm.analyze_decision(context)
            logger.info(f"LLM escalation response: {response}")
            # Handle LLM response - could increase confidence or suggest changes
        except Exception as e:
            logger.error(f"LLM escalation failed: {e}")

    async def _escalate_to_llm_autonomous(
        self, action: AgentAction, trigger_event: Optional[Event]
    ) -> AgentAction:
        """
        Escalate to LLM with autonomous execution based on LLM recommendation.

        For fully autonomous operation, this method:
        1. Queries the LLM for a decision recommendation
        2. If LLM recommends execution, executes the action
        3. If LLM recommends rejection, marks action as rejected
        4. If LLM unavailable, applies conservative auto-execution for reversible actions

        Args:
            action: Action being considered
            trigger_event: Event that triggered the action

        Returns:
            Updated action with execution status
        """
        llm = self.engine.get_integration("llm")

        if not llm or not self.llm_enabled:
            # LLM unavailable - apply conservative fallback
            return await self._autonomous_fallback(action)

        # Build context for LLM decision
        context = {
            "agent": self.agent_name,
            "agent_description": self.agent_description,
            "action": action.model_dump(),
            "trigger_event": trigger_event.model_dump() if trigger_event else None,
            "current_state": await self._get_relevant_state(),
            "request": (
                "Analyze this action and provide a decision. "
                'Respond with JSON: {"decision": "execute"|"reject"|"modify", '
                '"confidence_boost": 0.0-0.3, "reasoning": "..."}'
            ),
        }

        try:
            response = await llm.analyze_decision(context)
            logger.info(f"LLM autonomous decision: {response}")

            # Parse LLM decision
            decision = self._parse_llm_decision(response)

            if decision.get("decision") == "execute":
                # LLM recommends execution
                confidence_boost = min(0.3, decision.get("confidence_boost", 0.1))
                boosted_confidence = min(1.0, action.confidence + confidence_boost)

                logger.info(
                    f"LLM approved {action.action_type} with boost {confidence_boost:.2f} "
                    f"(new confidence: {boosted_confidence:.2f})"
                )

                action.confidence = boosted_confidence
                action.confirmed_by = "llm_autonomous"
                action.confirmed_at = utc_now()
                action = await self._execute_action_internal(action)

            elif decision.get("decision") == "reject":
                # LLM recommends rejection
                logger.info(
                    f"LLM rejected {action.action_type}: {decision.get('reasoning', 'No reason')}"
                )
                action.status = "rejected"
                action.result = {"llm_rejection": decision.get("reasoning", "Rejected by LLM")}

            else:
                # LLM suggests modification or unclear response - apply fallback
                logger.warning(f"LLM decision unclear for {action.action_type}, applying fallback")
                action = await self._autonomous_fallback(action)

        except Exception as e:
            logger.error(f"LLM autonomous escalation failed: {e}")
            # Fall back to conservative auto-execution
            action = await self._autonomous_fallback(action)

        return action

    def _parse_llm_decision(self, response: Any) -> dict:
        """
        Parse LLM decision response.

        Args:
            response: LLM response (string or dict)

        Returns:
            Parsed decision dictionary
        """
        import json
        import re

        if isinstance(response, dict):
            return response

        if isinstance(response, str):
            # Try to extract JSON from response
            try:
                # Look for JSON in the response
                json_match = re.search(r"\{[^{}]*\}", response)
                if json_match:
                    return json.loads(json_match.group())
            except (json.JSONDecodeError, AttributeError):
                pass

            # Try to infer decision from text
            response_lower = response.lower()
            if any(word in response_lower for word in ["execute", "proceed", "approve", "yes"]):
                return {"decision": "execute", "confidence_boost": 0.1}
            elif any(word in response_lower for word in ["reject", "deny", "no", "don't"]):
                return {"decision": "reject", "reasoning": response}

        return {"decision": "unclear"}

    async def _autonomous_fallback(self, action: AgentAction) -> AgentAction:
        """
        Apply conservative autonomous fallback for low-confidence actions.

        Fallback rules:
        1. Reversible actions with confidence >= 0.40 are executed with warning
        2. Non-reversible actions or very low confidence are rejected
        3. All fallback decisions are logged prominently

        Args:
            action: Action to evaluate

        Returns:
            Updated action with execution status
        """
        min_fallback_confidence = 0.40

        if action.reversible and action.confidence >= min_fallback_confidence:
            # Execute with prominent warning
            logger.warning(
                f"AUTONOMOUS FALLBACK: Executing reversible action {action.action_type} "
                f"with low confidence {action.confidence:.2f} (LLM unavailable)"
            )
            action.confirmed_by = "autonomous_fallback"
            action.confirmed_at = utc_now()
            action = await self._execute_action_internal(action)

        else:
            # Reject action as too risky
            logger.warning(
                f"AUTONOMOUS FALLBACK: Rejecting {action.action_type} "
                f"(reversible={action.reversible}, confidence={action.confidence:.2f})"
            )
            action.status = "rejected"
            action.result = {
                "fallback_rejection": (
                    f"Action rejected by autonomous fallback: "
                    f"{'non-reversible' if not action.reversible else 'confidence too low'}"
                )
            }

        return action

    async def _get_relevant_state(self) -> dict:
        """
        Get state relevant to this agent's decisions.

        Override in subclasses to provide specific state.

        Returns:
            Dictionary with relevant state
        """
        return {}

    def _check_rate_limit(self) -> bool:
        """
        Check if agent is within rate limits.

        Returns:
            True if under rate limit
        """
        now = utc_now()
        # Remove timestamps older than 1 minute
        self._action_timestamps = [
            ts for ts in self._action_timestamps if (now - ts).total_seconds() < 60
        ]
        return len(self._action_timestamps) < self.max_actions_per_minute

    async def query_llm(
        self, prompt: str, system_prompt: Optional[str] = None, prefer_local: bool = True
    ) -> str:
        """
        Query LLM for reasoning assistance.

        Uses local Ollama by default, falls back to Claude for complex queries.

        Args:
            prompt: User prompt
            system_prompt: Optional system prompt
            prefer_local: Whether to prefer local LLM

        Returns:
            LLM response text

        Raises:
            RuntimeError: If no LLM integration available
        """
        llm = self.engine.get_integration("llm")
        if not llm:
            raise RuntimeError("No LLM integration available")

        return await llm.complete(
            prompt=prompt,
            system_prompt=system_prompt,
            model=self.llm_model if prefer_local else self.llm_fallback,
        )

    def get_recent_actions(self, count: int = 10) -> list[AgentAction]:
        """Get recent actions taken by this agent."""
        return self._actions[-count:]

    def get_recent_decisions(self, count: int = 10) -> list[AgentDecision]:
        """Get recent decisions made by this agent."""
        return self._decisions[-count:]

    @property
    def stats(self) -> dict:
        """Get agent statistics."""
        # Count actions by confirmation source
        auto_approved = sum(
            1
            for a in self._actions
            if a.confirmed_by in ("autonomous_timeout", "llm_autonomous", "autonomous_fallback")
        )
        human_approved = sum(
            1
            for a in self._actions
            if a.confirmed_by
            and a.confirmed_by
            not in ("autonomous_timeout", "llm_autonomous", "autonomous_fallback")
        )

        return {
            "name": self.agent_name,
            "running": self._running,
            "total_actions": len(self._actions),
            "total_decisions": len(self._decisions),
            "actions_this_minute": len(self._action_timestamps),
            "autonomy": {
                "fully_autonomous": self.fully_autonomous,
                "confirmation_timeout_seconds": self.confirmation_timeout.total_seconds(),
                "low_confidence_auto_execute": self.low_confidence_auto_execute,
                "use_learning": self.use_learning,
                "auto_approved_count": auto_approved,
                "human_approved_count": human_approved,
            },
            "thresholds": {
                "auto_execute": self.auto_execute_threshold,
                "log_execute": self.log_execute_threshold,
                "confirm": self.confirm_threshold,
            },
        }
