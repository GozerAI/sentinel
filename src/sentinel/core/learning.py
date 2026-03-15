"""
Learning System for Sentinel.

This module provides outcome-based learning capabilities that allow Sentinel
to improve its decision-making over time based on the results of actions taken.
"""
import asyncio
import json
import logging
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional, Any, TYPE_CHECKING
from uuid import UUID, uuid4

from sentinel.core.utils import utc_now
from sentinel.core.models.event import Event, EventCategory, EventSeverity

if TYPE_CHECKING:
    from sentinel.core.engine import SentinelEngine

logger = logging.getLogger(__name__)


class ActionOutcome:
    """
    Records the outcome of an action for learning purposes.

    Attributes:
        action_id: ID of the action
        agent_name: Agent that took the action
        action_type: Type of action taken
        parameters: Action parameters
        initial_confidence: Confidence when action was taken
        outcome: Result of the action (success, failure, partial)
        effectiveness: How effective the action was (0.0-1.0)
        side_effects: Any unexpected side effects
        feedback: Human feedback if provided
    """

    def __init__(
        self,
        action_id: UUID,
        agent_name: str,
        action_type: str,
        parameters: dict,
        initial_confidence: float,
        context: dict = None
    ):
        self.id = uuid4()
        self.action_id = action_id
        self.agent_name = agent_name
        self.action_type = action_type
        self.parameters = parameters
        self.initial_confidence = initial_confidence
        self.context = context or {}
        self.timestamp = utc_now()

        # Outcome tracking
        self.outcome: Optional[str] = None  # success, failure, partial, rolled_back
        self.effectiveness: float = 0.0
        self.side_effects: list[str] = []
        self.resolution_time: Optional[timedelta] = None
        self.required_followup: bool = False
        self.feedback: Optional[str] = None
        self.feedback_score: Optional[float] = None  # -1.0 to 1.0

    def record_outcome(
        self,
        outcome: str,
        effectiveness: float,
        side_effects: list[str] = None,
        resolution_time: timedelta = None
    ) -> None:
        """Record the outcome of the action."""
        self.outcome = outcome
        self.effectiveness = effectiveness
        self.side_effects = side_effects or []
        self.resolution_time = resolution_time

    def add_feedback(self, feedback: str, score: float) -> None:
        """Add human feedback to the outcome."""
        self.feedback = feedback
        self.feedback_score = max(-1.0, min(1.0, score))

    def to_dict(self) -> dict:
        return {
            "id": str(self.id),
            "action_id": str(self.action_id),
            "agent_name": self.agent_name,
            "action_type": self.action_type,
            "parameters": self.parameters,
            "initial_confidence": self.initial_confidence,
            "context": self.context,
            "timestamp": self.timestamp.isoformat(),
            "outcome": self.outcome,
            "effectiveness": self.effectiveness,
            "side_effects": self.side_effects,
            "resolution_time": str(self.resolution_time) if self.resolution_time else None,
            "required_followup": self.required_followup,
            "feedback": self.feedback,
            "feedback_score": self.feedback_score
        }


class Pattern:
    """
    Represents a learned pattern from action outcomes.

    Patterns capture:
    - What conditions lead to successful outcomes
    - What conditions lead to failures
    - Optimal confidence thresholds
    - Recommended parameter adjustments
    """

    def __init__(
        self,
        pattern_type: str,
        agent_name: str,
        action_type: str,
        conditions: dict,
        recommendation: str,
        confidence_adjustment: float = 0.0,
        sample_size: int = 0
    ):
        self.id = uuid4()
        self.pattern_type = pattern_type  # success, failure, optimization
        self.agent_name = agent_name
        self.action_type = action_type
        self.conditions = conditions
        self.recommendation = recommendation
        self.confidence_adjustment = confidence_adjustment
        self.sample_size = sample_size
        self.created_at = utc_now()
        self.last_applied = None
        self.application_count = 0

    def to_dict(self) -> dict:
        return {
            "id": str(self.id),
            "pattern_type": self.pattern_type,
            "agent_name": self.agent_name,
            "action_type": self.action_type,
            "conditions": self.conditions,
            "recommendation": self.recommendation,
            "confidence_adjustment": self.confidence_adjustment,
            "sample_size": self.sample_size,
            "created_at": self.created_at.isoformat(),
            "application_count": self.application_count
        }


class LearningSystem:
    """
    Outcome-based learning system for Sentinel.

    The Learning System:
    - Records outcomes of all agent actions
    - Analyzes patterns in successes and failures
    - Adjusts confidence thresholds based on actual results
    - Provides recommendations for improving agent behavior
    - Uses LLM for complex pattern analysis when needed

    Example:
        ```python
        learning = LearningSystem(engine)

        # Record an outcome
        outcome = ActionOutcome(
            action_id=action.id,
            agent_name="guardian",
            action_type="block_ip",
            parameters={"ip": "10.0.0.1"},
            initial_confidence=0.85
        )
        outcome.record_outcome("success", effectiveness=0.95)
        await learning.record_outcome(outcome)

        # Get recommendations
        recommendations = await learning.get_recommendations("guardian", "block_ip")
        ```
    """

    def __init__(self, engine: "SentinelEngine", config: dict = None):
        """
        Initialize the learning system.

        Args:
            engine: Reference to the Sentinel engine
            config: Learning system configuration
        """
        self.engine = engine
        self.config = config or {}

        # Configuration
        self.min_samples_for_pattern = self.config.get("min_samples", 10)
        self.learning_rate = self.config.get("learning_rate", 0.1)
        self.persistence_path = Path(self.config.get(
            "persistence_path",
            "/var/lib/sentinel/learning.json"
        ))
        self.auto_persist_interval = self.config.get("auto_persist_interval", 300)

        # Outcome storage
        self._outcomes: list[ActionOutcome] = []
        self._patterns: list[Pattern] = []

        # Aggregated statistics
        self._stats_by_agent: dict[str, dict] = defaultdict(lambda: {
            "total_actions": 0,
            "successes": 0,
            "failures": 0,
            "avg_effectiveness": 0.0,
            "avg_confidence": 0.0
        })

        self._stats_by_action: dict[str, dict] = defaultdict(lambda: {
            "total": 0,
            "successes": 0,
            "failures": 0,
            "avg_effectiveness": 0.0,
            "optimal_confidence": 0.85
        })

        # Confidence adjustments learned over time
        self._confidence_adjustments: dict[str, float] = {}

        self._running = False
        self._persist_task: Optional[asyncio.Task] = None

    async def start(self) -> None:
        """Start the learning system."""
        self._running = True

        # Load persisted data
        await self._load_persisted_data()

        # Subscribe to relevant events
        await self._subscribe_events()

        # Start persistence task
        self._persist_task = asyncio.create_task(self._auto_persist_loop())

        logger.info("Learning system started")

    async def stop(self) -> None:
        """Stop the learning system."""
        self._running = False

        if self._persist_task:
            self._persist_task.cancel()
            try:
                await self._persist_task
            except asyncio.CancelledError:
                pass

        # Final persistence
        await self._persist_data()

        logger.info("Learning system stopped")

    async def _subscribe_events(self) -> None:
        """Subscribe to events for learning."""
        self.engine.event_bus.subscribe(
            self._handle_action_event,
            category=EventCategory.AGENT
        )

    async def _handle_action_event(self, event: Event) -> None:
        """Handle agent action events for learning."""
        if event.event_type == "agent.action.executed":
            await self._record_action_success(event)

        elif event.event_type == "agent.action.failed":
            await self._record_action_failure(event)

        elif event.event_type == "agent.action.rolled_back":
            await self._record_action_rollback(event)

    async def _record_action_success(self, event: Event) -> None:
        """Record a successful action."""
        outcome = ActionOutcome(
            action_id=UUID(event.data.get("id", str(uuid4()))),
            agent_name=event.data.get("agent_name", "unknown"),
            action_type=event.data.get("action_type", "unknown"),
            parameters=event.data.get("parameters", {}),
            initial_confidence=event.data.get("confidence", 0.5),
            context={"event_id": str(event.id)}
        )
        outcome.record_outcome("success", effectiveness=1.0)

        await self.record_outcome(outcome)

    async def _record_action_failure(self, event: Event) -> None:
        """Record a failed action."""
        outcome = ActionOutcome(
            action_id=UUID(event.data.get("id", str(uuid4()))),
            agent_name=event.data.get("agent_name", "unknown"),
            action_type=event.data.get("action_type", "unknown"),
            parameters=event.data.get("parameters", {}),
            initial_confidence=event.data.get("confidence", 0.5),
            context={
                "event_id": str(event.id),
                "error": event.data.get("error")
            }
        )
        outcome.record_outcome("failure", effectiveness=0.0)

        await self.record_outcome(outcome)

    async def _record_action_rollback(self, event: Event) -> None:
        """Record a rolled back action."""
        outcome = ActionOutcome(
            action_id=UUID(event.data.get("id", str(uuid4()))),
            agent_name=event.data.get("agent_name", "unknown"),
            action_type=event.data.get("action_type", "unknown"),
            parameters=event.data.get("parameters", {}),
            initial_confidence=event.data.get("confidence", 0.5),
            context={"event_id": str(event.id)}
        )
        outcome.record_outcome("rolled_back", effectiveness=0.2)

        await self.record_outcome(outcome)

    async def record_outcome(self, outcome: ActionOutcome) -> None:
        """
        Record an action outcome for learning.

        Args:
            outcome: The action outcome to record
        """
        self._outcomes.append(outcome)

        # Update statistics
        self._update_statistics(outcome)

        # Check if we should analyze patterns
        agent_key = f"{outcome.agent_name}:{outcome.action_type}"
        if self._stats_by_action[agent_key]["total"] >= self.min_samples_for_pattern:
            await self._analyze_patterns(outcome.agent_name, outcome.action_type)

        # Keep outcomes bounded
        if len(self._outcomes) > 50000:
            self._outcomes = self._outcomes[-25000:]

        logger.debug(f"Recorded outcome for {outcome.agent_name}/{outcome.action_type}: {outcome.outcome}")

    def _update_statistics(self, outcome: ActionOutcome) -> None:
        """Update aggregated statistics from an outcome."""
        # Update agent stats
        agent_stats = self._stats_by_agent[outcome.agent_name]
        agent_stats["total_actions"] += 1
        if outcome.outcome == "success":
            agent_stats["successes"] += 1
        elif outcome.outcome == "failure":
            agent_stats["failures"] += 1

        # Update running averages
        n = agent_stats["total_actions"]
        agent_stats["avg_effectiveness"] = (
            (agent_stats["avg_effectiveness"] * (n - 1) + outcome.effectiveness) / n
        )
        agent_stats["avg_confidence"] = (
            (agent_stats["avg_confidence"] * (n - 1) + outcome.initial_confidence) / n
        )

        # Update action stats
        action_key = f"{outcome.agent_name}:{outcome.action_type}"
        action_stats = self._stats_by_action[action_key]
        action_stats["total"] += 1
        if outcome.outcome == "success":
            action_stats["successes"] += 1
        elif outcome.outcome == "failure":
            action_stats["failures"] += 1

        n = action_stats["total"]
        action_stats["avg_effectiveness"] = (
            (action_stats["avg_effectiveness"] * (n - 1) + outcome.effectiveness) / n
        )

    async def _analyze_patterns(self, agent_name: str, action_type: str) -> None:
        """Analyze outcomes to identify patterns."""
        # Get relevant outcomes
        relevant_outcomes = [
            o for o in self._outcomes
            if o.agent_name == agent_name and o.action_type == action_type
        ]

        if len(relevant_outcomes) < self.min_samples_for_pattern:
            return

        # Calculate success rate by confidence level
        confidence_buckets: dict[str, list] = defaultdict(list)
        for outcome in relevant_outcomes:
            bucket = self._get_confidence_bucket(outcome.initial_confidence)
            confidence_buckets[bucket].append(outcome)

        # Find optimal confidence threshold
        best_bucket = None
        best_success_rate = 0.0

        for bucket, outcomes in confidence_buckets.items():
            if len(outcomes) >= 5:
                success_rate = sum(1 for o in outcomes if o.outcome == "success") / len(outcomes)
                if success_rate > best_success_rate:
                    best_success_rate = success_rate
                    best_bucket = bucket

        if best_bucket:
            # Create or update pattern
            pattern = Pattern(
                pattern_type="optimization",
                agent_name=agent_name,
                action_type=action_type,
                conditions={"confidence_bucket": best_bucket},
                recommendation=f"Optimal confidence for {action_type} is in {best_bucket} range",
                confidence_adjustment=self._bucket_to_adjustment(best_bucket),
                sample_size=len(relevant_outcomes)
            )

            # Update or add pattern
            existing = self._find_pattern(agent_name, action_type)
            if existing:
                existing.conditions = pattern.conditions
                existing.recommendation = pattern.recommendation
                existing.confidence_adjustment = pattern.confidence_adjustment
                existing.sample_size = pattern.sample_size
            else:
                self._patterns.append(pattern)

            # Update confidence adjustment
            key = f"{agent_name}:{action_type}"
            self._confidence_adjustments[key] = pattern.confidence_adjustment

            logger.info(f"Updated pattern for {agent_name}/{action_type}: {pattern.recommendation}")

    def _get_confidence_bucket(self, confidence: float) -> str:
        """Get confidence bucket for a confidence value."""
        if confidence >= 0.95:
            return "very_high"
        elif confidence >= 0.85:
            return "high"
        elif confidence >= 0.70:
            return "medium"
        elif confidence >= 0.50:
            return "low"
        else:
            return "very_low"

    def _bucket_to_adjustment(self, bucket: str) -> float:
        """Convert bucket to confidence adjustment."""
        adjustments = {
            "very_high": 0.05,
            "high": 0.02,
            "medium": 0.0,
            "low": -0.05,
            "very_low": -0.10
        }
        return adjustments.get(bucket, 0.0)

    def _find_pattern(self, agent_name: str, action_type: str) -> Optional[Pattern]:
        """Find existing pattern for agent/action combination."""
        for pattern in self._patterns:
            if pattern.agent_name == agent_name and pattern.action_type == action_type:
                return pattern
        return None

    def get_confidence_adjustment(self, agent_name: str, action_type: str) -> float:
        """
        Get the learned confidence adjustment for an action.

        Args:
            agent_name: Name of the agent
            action_type: Type of action

        Returns:
            Confidence adjustment (-1.0 to 1.0)
        """
        key = f"{agent_name}:{action_type}"
        return self._confidence_adjustments.get(key, 0.0)

    def get_adjusted_confidence(
        self,
        agent_name: str,
        action_type: str,
        base_confidence: float
    ) -> float:
        """
        Get adjusted confidence based on learning.

        Args:
            agent_name: Name of the agent
            action_type: Type of action
            base_confidence: Original confidence value

        Returns:
            Adjusted confidence (0.0 to 1.0)
        """
        adjustment = self.get_confidence_adjustment(agent_name, action_type)
        adjusted = base_confidence + (adjustment * self.learning_rate)
        return max(0.0, min(1.0, adjusted))

    async def get_recommendations(
        self,
        agent_name: str,
        action_type: Optional[str] = None
    ) -> list[dict]:
        """
        Get recommendations based on learned patterns.

        Args:
            agent_name: Agent to get recommendations for
            action_type: Specific action type (optional)

        Returns:
            List of recommendation dictionaries
        """
        recommendations = []

        # Get relevant patterns
        for pattern in self._patterns:
            if pattern.agent_name == agent_name:
                if action_type is None or pattern.action_type == action_type:
                    recommendations.append({
                        "type": pattern.pattern_type,
                        "action_type": pattern.action_type,
                        "recommendation": pattern.recommendation,
                        "confidence_adjustment": pattern.confidence_adjustment,
                        "sample_size": pattern.sample_size
                    })

        # Add statistical recommendations
        agent_stats = self._stats_by_agent.get(agent_name)
        if agent_stats and agent_stats["total_actions"] > 0:
            success_rate = agent_stats["successes"] / agent_stats["total_actions"]
            if success_rate < 0.7:
                recommendations.append({
                    "type": "performance",
                    "recommendation": f"Agent success rate is low ({success_rate:.1%}). Consider reviewing action criteria.",
                    "success_rate": success_rate
                })

        return recommendations

    async def provide_feedback(
        self,
        action_id: UUID,
        feedback: str,
        score: float
    ) -> bool:
        """
        Provide human feedback on an action outcome.

        Args:
            action_id: ID of the action
            feedback: Feedback text
            score: Feedback score (-1.0 to 1.0)

        Returns:
            True if feedback was recorded
        """
        for outcome in reversed(self._outcomes):
            if outcome.action_id == action_id:
                outcome.add_feedback(feedback, score)

                # Trigger pattern reanalysis with feedback
                await self._analyze_patterns(outcome.agent_name, outcome.action_type)

                logger.info(f"Recorded feedback for action {action_id}: score={score}")
                return True

        return False

    async def analyze_with_llm(self, query: str) -> str:
        """
        Use LLM to analyze learning data.

        Args:
            query: Analysis query

        Returns:
            LLM analysis response
        """
        llm = self.engine.get_integration("llm")
        if not llm:
            return "LLM integration not available"

        # Prepare context
        context = {
            "agent_stats": dict(self._stats_by_agent),
            "action_stats": dict(self._stats_by_action),
            "patterns": [p.to_dict() for p in self._patterns],
            "recent_outcomes": [o.to_dict() for o in self._outcomes[-100:]]
        }

        prompt = f"""Analyze the following learning data from Sentinel's agents:

{json.dumps(context, indent=2)}

Question: {query}

Provide insights and recommendations based on the data."""

        return await llm.complete(prompt)

    async def _auto_persist_loop(self) -> None:
        """Periodically persist learning data."""
        while self._running:
            try:
                await asyncio.sleep(self.auto_persist_interval)
                await self._persist_data()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in persist loop: {e}")

    async def _persist_data(self) -> None:
        """Persist learning data to disk."""
        try:
            self.persistence_path.parent.mkdir(parents=True, exist_ok=True)

            data = {
                "patterns": [p.to_dict() for p in self._patterns],
                "confidence_adjustments": self._confidence_adjustments,
                "stats_by_agent": dict(self._stats_by_agent),
                "stats_by_action": dict(self._stats_by_action),
                "persisted_at": utc_now().isoformat()
            }

            with open(self.persistence_path, 'w') as f:
                json.dump(data, f, indent=2)

            logger.debug(f"Persisted learning data to {self.persistence_path}")

        except Exception as e:
            logger.error(f"Failed to persist learning data: {e}")

    async def _load_persisted_data(self) -> None:
        """Load persisted learning data."""
        try:
            if not self.persistence_path.exists():
                logger.debug("No persisted learning data found")
                return

            with open(self.persistence_path, 'r') as f:
                data = json.load(f)

            # Restore confidence adjustments
            self._confidence_adjustments = data.get("confidence_adjustments", {})

            # Restore statistics
            for agent, stats in data.get("stats_by_agent", {}).items():
                self._stats_by_agent[agent].update(stats)

            for action, stats in data.get("stats_by_action", {}).items():
                self._stats_by_action[action].update(stats)

            # Restore patterns
            for pattern_data in data.get("patterns", []):
                pattern = Pattern(
                    pattern_type=pattern_data["pattern_type"],
                    agent_name=pattern_data["agent_name"],
                    action_type=pattern_data["action_type"],
                    conditions=pattern_data["conditions"],
                    recommendation=pattern_data["recommendation"],
                    confidence_adjustment=pattern_data.get("confidence_adjustment", 0.0),
                    sample_size=pattern_data.get("sample_size", 0)
                )
                self._patterns.append(pattern)

            logger.info(f"Loaded learning data: {len(self._patterns)} patterns")

        except Exception as e:
            logger.error(f"Failed to load persisted learning data: {e}")

    def get_agent_stats(self, agent_name: str) -> dict:
        """Get learning statistics for an agent."""
        return dict(self._stats_by_agent.get(agent_name, {}))

    def get_action_stats(self, agent_name: str, action_type: str) -> dict:
        """Get learning statistics for an action."""
        key = f"{agent_name}:{action_type}"
        return dict(self._stats_by_action.get(key, {}))

    @property
    def stats(self) -> dict:
        """Get overall learning system statistics."""
        return {
            "total_outcomes": len(self._outcomes),
            "total_patterns": len(self._patterns),
            "agents_tracked": len(self._stats_by_agent),
            "actions_tracked": len(self._stats_by_action),
            "confidence_adjustments": len(self._confidence_adjustments)
        }
