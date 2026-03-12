"""
Integration tests for LLM-powered specialists.

These tests verify that the specialists work correctly with and without
LLM routing, using mock LLM responses for deterministic testing.
"""

import asyncio
import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from typing import Dict, Any, Optional

from sentinel.core.hierarchy.base import Task, TaskPriority, TaskResult


# ============================================================================
# MOCK LLM ROUTER
# ============================================================================


class MockCompletionResult:
    """Mock completion result from LLM."""

    def __init__(self, text: str):
        self.text = text
        self.model = "mock-model"
        self.tier = "fast"
        self.tokens_used = 100


class MockLLMRouter:
    """Mock LLM router for testing."""

    def __init__(self):
        self._model_pool = {"mock-model": {}}
        self._responses: Dict[str, str] = {}
        self.stats = {
            "total_requests": 0,
            "cache_hits": 0,
            "fallbacks": 0,
        }

    def set_response(self, task_category: str, response: str) -> None:
        """Pre-set a response for a task category."""
        self._responses[task_category] = response

    async def initialize(self) -> None:
        """Mock initialization."""
        pass

    async def complete(
        self,
        prompt: str,
        task_category: str = "general",
        system_prompt: Optional[str] = None,
        context: Dict[str, Any] = None,
    ) -> MockCompletionResult:
        """Return pre-set mock response."""
        self.stats["total_requests"] += 1
        response = self._responses.get(task_category, '{"result": "mock response"}')
        return MockCompletionResult(response)


# ============================================================================
# FIXTURES
# ============================================================================


@pytest.fixture
def mock_llm_router():
    """Create a mock LLM router."""
    return MockLLMRouter()


@pytest.fixture
def threat_detection_task():
    """Create a sample threat detection task."""
    return Task(
        task_type="security.intrusion_detection",
        description="Analyze potential intrusion",
        parameters={
            "event_data": {
                "source_ip": "192.168.1.100",
                "dest_ip": "10.0.0.1",
                "dest_port": 22,
                "protocol": "tcp",
                "payload": "SSH-2.0-OpenSSH_8.9",
                "timestamp": "2025-01-16T10:00:00Z",
            }
        },
        priority=TaskPriority.HIGH,
    )


@pytest.fixture
def firewall_task():
    """Create a sample firewall configuration task."""
    return Task(
        task_type="security.firewall_config",
        description="Generate firewall rules",
        parameters={
            "action": "generate",
            "requirements": {
                "block_ips": ["10.0.0.50"],
                "allow_ports": [80, 443],
                "default_policy": "deny",
            },
            "platform": "mikrotik",
        },
        priority=TaskPriority.MEDIUM,
    )


@pytest.fixture
def health_check_task():
    """Create a sample health check task."""
    return Task(
        task_type="health.check.http",
        description="Check service health",
        parameters={
            "check_type": "http",
            "target": "https://example.com",
            "timeout": 5.0,
        },
        priority=TaskPriority.LOW,
    )


@pytest.fixture
def log_analysis_task():
    """Create a sample log analysis task."""
    return Task(
        task_type="health.analyze_logs",
        description="Analyze system logs",
        parameters={
            "logs": """
Jan 16 10:00:01 server1 sshd[1234]: Failed password for root from 10.0.0.50 port 22
Jan 16 10:00:02 server1 sshd[1234]: Failed password for root from 10.0.0.50 port 22
Jan 16 10:00:03 server1 sshd[1234]: Failed password for root from 10.0.0.50 port 22
Jan 16 10:00:04 server1 kernel: [UFW BLOCK] IN=eth0 OUT= MAC=... SRC=10.0.0.50
Jan 16 10:00:05 server1 sshd[1234]: Connection closed by 10.0.0.50
            """,
            "log_type": "syslog",
            "focus": ["errors", "security"],
        },
        priority=TaskPriority.MEDIUM,
    )


# ============================================================================
# INTRUSION DETECTION SPECIALIST TESTS
# ============================================================================


class TestIntrusionDetectionSpecialist:
    """Tests for IntrusionDetectionSpecialist."""

    @pytest.mark.asyncio
    async def test_handles_correct_task_types(self):
        """Test that specialist handles correct task types."""
        from sentinel.agents.hierarchy.specialists.security import IntrusionDetectionSpecialist

        specialist = IntrusionDetectionSpecialist()
        capability = specialist.capability

        assert "security.intrusion_detection" in capability.task_types
        assert "security.analyze_threat" in capability.task_types
        assert capability.confidence >= 0.8

    @pytest.mark.asyncio
    async def test_signature_detection_without_llm(self, threat_detection_task):
        """Test signature-based detection works without LLM."""
        from sentinel.agents.hierarchy.specialists.security import IntrusionDetectionSpecialist

        specialist = IntrusionDetectionSpecialist()

        # SSH brute force patterns
        threat_detection_task.parameters["event_data"][
            "payload"
        ] = "Failed password for root from 10.0.0.50"

        result = await specialist.execute(threat_detection_task)

        assert result.success
        assert result.output is not None
        assert "quick_analysis" in result.output

    @pytest.mark.asyncio
    async def test_detection_with_llm_analysis(self, mock_llm_router, threat_detection_task):
        """Test detection with LLM enhancement."""
        from sentinel.agents.hierarchy.specialists.security import IntrusionDetectionSpecialist

        # Set up mock LLM response
        mock_llm_router.set_response(
            "threat_detection",
            """{
            "is_threat": true,
            "threat_type": "ssh_brute_force",
            "confidence": 0.95,
            "indicators": ["multiple failed logins", "same source IP"],
            "recommended_action": "block_ip",
            "severity": "high"
        }""",
        )

        specialist = IntrusionDetectionSpecialist(llm_router=mock_llm_router)
        result = await specialist.execute(threat_detection_task)

        assert result.success
        assert result.output is not None
        # LLM should have been called
        assert mock_llm_router.stats["total_requests"] >= 1

    @pytest.mark.asyncio
    async def test_graceful_llm_failure(self, threat_detection_task):
        """Test graceful handling when LLM fails."""
        from sentinel.agents.hierarchy.specialists.security import IntrusionDetectionSpecialist

        # Create a router that always fails
        failing_router = MockLLMRouter()
        failing_router.complete = AsyncMock(side_effect=Exception("LLM unavailable"))

        specialist = IntrusionDetectionSpecialist(llm_router=failing_router)
        result = await specialist.execute(threat_detection_task)

        # Should still succeed with signature-based detection
        assert result.success
        assert result.output is not None


# ============================================================================
# FIREWALL SPECIALIST TESTS
# ============================================================================


class TestFirewallSpecialist:
    """Tests for FirewallSpecialist."""

    @pytest.mark.asyncio
    async def test_handles_correct_task_types(self):
        """Test that specialist handles correct task types."""
        from sentinel.agents.hierarchy.specialists.security import FirewallSpecialist

        specialist = FirewallSpecialist()
        capability = specialist.capability

        assert "security.firewall_config" in capability.task_types
        assert "security.generate_rules" in capability.task_types

    @pytest.mark.asyncio
    async def test_mikrotik_rule_generation(self, firewall_task):
        """Test MikroTik firewall rule generation."""
        from sentinel.agents.hierarchy.specialists.security import FirewallSpecialist

        specialist = FirewallSpecialist()
        firewall_task.parameters["platform"] = "mikrotik"

        result = await specialist.execute(firewall_task)

        assert result.success
        assert result.output is not None
        assert "rules" in result.output or "config" in result.output

    @pytest.mark.asyncio
    async def test_iptables_rule_generation(self, firewall_task):
        """Test iptables rule generation."""
        from sentinel.agents.hierarchy.specialists.security import FirewallSpecialist

        specialist = FirewallSpecialist()
        firewall_task.parameters["platform"] = "iptables"

        result = await specialist.execute(firewall_task)

        assert result.success

    @pytest.mark.asyncio
    async def test_rule_validation_with_llm(self, mock_llm_router, firewall_task):
        """Test that generated rules are validated by LLM."""
        from sentinel.agents.hierarchy.specialists.security import FirewallSpecialist

        mock_llm_router.set_response(
            "config_generation",
            """{
            "valid": true,
            "issues": [],
            "suggestions": ["Consider rate limiting SSH"],
            "security_score": 0.85
        }""",
        )

        specialist = FirewallSpecialist(llm_router=mock_llm_router)
        result = await specialist.execute(firewall_task)

        assert result.success


# ============================================================================
# HEALTH CHECK SPECIALIST TESTS
# ============================================================================


class TestHealthCheckSpecialist:
    """Tests for HealthCheckSpecialist."""

    @pytest.mark.asyncio
    async def test_handles_correct_task_types(self):
        """Test that specialist handles correct task types."""
        from sentinel.agents.hierarchy.specialists.reliability import HealthCheckSpecialist

        specialist = HealthCheckSpecialist()
        capability = specialist.capability

        assert "health.check" in capability.task_types
        assert "health.check.http" in capability.task_types
        assert "health.check.tcp" in capability.task_types

    @pytest.mark.asyncio
    async def test_tcp_check(self):
        """Test TCP connectivity check."""
        from sentinel.agents.hierarchy.specialists.reliability import HealthCheckSpecialist

        specialist = HealthCheckSpecialist()
        task = Task(
            task_type="health.check.tcp",
            parameters={
                "check_type": "tcp",
                "target": "localhost:22",
                "timeout": 2.0,
            },
        )

        result = await specialist.execute(task)

        assert result.success
        assert result.output is not None
        assert "check_type" in result.output
        assert result.output["check_type"] == "tcp"

    @pytest.mark.asyncio
    async def test_dns_check(self):
        """Test DNS resolution check."""
        from sentinel.agents.hierarchy.specialists.reliability import HealthCheckSpecialist

        specialist = HealthCheckSpecialist()
        task = Task(
            task_type="health.check",
            parameters={
                "check_type": "dns",
                "target": "localhost",
                "timeout": 5.0,
            },
        )

        result = await specialist.execute(task)

        assert result.success
        assert result.output is not None
        assert "check_type" in result.output

    @pytest.mark.asyncio
    async def test_missing_target_returns_error(self):
        """Test that missing target returns error."""
        from sentinel.agents.hierarchy.specialists.reliability import HealthCheckSpecialist

        specialist = HealthCheckSpecialist()
        task = Task(task_type="health.check", parameters={"check_type": "http"})

        result = await specialist.execute(task)

        assert not result.success
        assert "Target required" in result.error


# ============================================================================
# LOG ANALYSIS SPECIALIST TESTS
# ============================================================================


class TestLogAnalysisSpecialist:
    """Tests for LogAnalysisSpecialist."""

    @pytest.mark.asyncio
    async def test_handles_correct_task_types(self):
        """Test that specialist handles correct task types."""
        from sentinel.agents.hierarchy.specialists.reliability import LogAnalysisSpecialist

        specialist = LogAnalysisSpecialist()
        capability = specialist.capability

        assert "health.analyze_logs" in capability.task_types
        assert "reliability.log_analysis" in capability.task_types

    @pytest.mark.asyncio
    async def test_quick_analysis_detects_errors(self, log_analysis_task):
        """Test that quick analysis detects errors in logs."""
        from sentinel.agents.hierarchy.specialists.reliability import LogAnalysisSpecialist

        specialist = LogAnalysisSpecialist()
        result = await specialist.execute(log_analysis_task)

        assert result.success
        assert result.output is not None
        assert "quick_analysis" in result.output

        quick = result.output["quick_analysis"]
        assert quick["error_count"] > 0 or quick["warning_count"] > 0

    @pytest.mark.asyncio
    async def test_llm_deep_analysis(self, mock_llm_router, log_analysis_task):
        """Test LLM-powered deep analysis."""
        from sentinel.agents.hierarchy.specialists.reliability import LogAnalysisSpecialist

        mock_llm_router.set_response(
            "log_analysis",
            """{
            "summary": "SSH brute force attack detected",
            "severity": "high",
            "errors": [{"description": "Multiple failed SSH logins", "likely_cause": "brute force attack"}],
            "warnings": [],
            "anomalies": [{"description": "5 failed logins in 5 seconds", "deviation": "unusual"}],
            "patterns": [{"pattern": "IP 10.0.0.50", "interpretation": "attacker source"}],
            "recommendations": ["Block IP 10.0.0.50", "Enable fail2ban"],
            "root_cause_hints": ["Possible credential stuffing attack"]
        }""",
        )

        specialist = LogAnalysisSpecialist(llm_router=mock_llm_router)
        result = await specialist.execute(log_analysis_task)

        assert result.success
        assert result.output is not None
        assert result.output.get("llm_analysis") is not None
        assert mock_llm_router.stats["total_requests"] >= 1

    @pytest.mark.asyncio
    async def test_empty_logs_returns_error(self):
        """Test that empty logs return error."""
        from sentinel.agents.hierarchy.specialists.reliability import LogAnalysisSpecialist

        specialist = LogAnalysisSpecialist()
        task = Task(task_type="health.analyze_logs", parameters={"logs": ""})

        result = await specialist.execute(task)

        assert not result.success
        assert "Log data required" in result.error


# ============================================================================
# DISCOVERY SPECIALIST TESTS
# ============================================================================


class TestARPScanSpecialist:
    """Tests for ARPScanSpecialist."""

    @pytest.mark.asyncio
    async def test_handles_correct_task_types(self):
        """Test that specialist handles correct task types."""
        from sentinel.agents.hierarchy.specialists.discovery import ARPScanSpecialist

        specialist = ARPScanSpecialist()
        capability = specialist.capability

        assert "discovery.arp_scan" in capability.task_types
        assert "discovery.network_scan" in capability.task_types

    @pytest.mark.asyncio
    async def test_missing_network_returns_error(self):
        """Test that missing network parameter returns error."""
        from sentinel.agents.hierarchy.specialists.discovery import ARPScanSpecialist

        specialist = ARPScanSpecialist()
        task = Task(task_type="discovery.arp_scan", parameters={})

        result = await specialist.execute(task)

        assert not result.success
        assert "Network" in result.error or "network" in result.error.lower()


class TestVendorIdentificationSpecialist:
    """Tests for VendorIdentificationSpecialist."""

    @pytest.mark.asyncio
    async def test_handles_correct_task_types(self):
        """Test that specialist handles correct task types."""
        from sentinel.agents.hierarchy.specialists.discovery import VendorIdentificationSpecialist

        specialist = VendorIdentificationSpecialist()
        capability = specialist.capability

        assert "discovery.vendor_lookup" in capability.task_types

    @pytest.mark.asyncio
    async def test_oui_lookup(self):
        """Test OUI-based vendor lookup."""
        from sentinel.agents.hierarchy.specialists.discovery import VendorIdentificationSpecialist

        specialist = VendorIdentificationSpecialist()
        task = Task(task_type="discovery.vendor_lookup", parameters={"mac": "00:11:22:33:44:55"})

        result = await specialist.execute(task)

        # Should succeed even if vendor unknown
        assert result.success
        assert result.output is not None


# ============================================================================
# SERVICE RECOVERY SPECIALIST TESTS
# ============================================================================


class TestServiceRecoverySpecialist:
    """Tests for ServiceRecoverySpecialist."""

    @pytest.mark.asyncio
    async def test_handles_correct_task_types(self):
        """Test that specialist handles correct task types."""
        from sentinel.agents.hierarchy.specialists.reliability import ServiceRecoverySpecialist

        specialist = ServiceRecoverySpecialist()
        capability = specialist.capability

        assert "healing.recovery" in capability.task_types
        assert "service.restart" in capability.task_types

    @pytest.mark.asyncio
    async def test_missing_service_returns_error(self):
        """Test that missing service name returns error."""
        from sentinel.agents.hierarchy.specialists.reliability import ServiceRecoverySpecialist

        specialist = ServiceRecoverySpecialist()
        task = Task(task_type="service.restart", parameters={"action": "restart"})

        result = await specialist.execute(task)

        assert not result.success
        assert "Service name required" in result.error

    @pytest.mark.asyncio
    async def test_service_whitelist_enforcement(self):
        """Test that service whitelist is enforced."""
        from sentinel.agents.hierarchy.specialists.reliability import ServiceRecoverySpecialist

        specialist = ServiceRecoverySpecialist(allowed_services=["nginx", "postgresql"])

        task = Task(
            task_type="service.restart",
            parameters={"action": "restart", "service": "malicious_service"},
        )

        result = await specialist.execute(task)

        assert not result.success
        assert "not in allowed list" in result.error

    @pytest.mark.asyncio
    async def test_llm_safety_check(self, mock_llm_router):
        """Test that LLM safety check is performed."""
        from sentinel.agents.hierarchy.specialists.reliability import ServiceRecoverySpecialist

        mock_llm_router.set_response(
            "incident_response",
            """{
            "proceed": false,
            "confidence": 0.9,
            "reasoning": "Service is critical, avoid restart during peak hours",
            "alternatives": ["Schedule for maintenance window"],
            "precautions": []
        }""",
        )

        specialist = ServiceRecoverySpecialist(llm_router=mock_llm_router)
        task = Task(
            task_type="service.restart",
            parameters={
                "action": "restart",
                "service": "critical_db",
                "analyze_first": True,
            },
        )

        result = await specialist.execute(task)

        # LLM recommended against, so should fail
        assert not result.success


# ============================================================================
# LLM ROUTER PROPAGATION TESTS
# ============================================================================


class TestLLMRouterPropagation:
    """Tests for LLM router propagation through the hierarchy."""

    @pytest.mark.asyncio
    async def test_agent_propagates_router_to_specialists(self, mock_llm_router):
        """Test that agent propagates LLM router to all specialists."""
        from sentinel.core.hierarchy.base import (
            SentinelAgentBase,
            Manager,
            Specialist,
            Task,
            TaskResult,
            SpecialistCapability,
        )

        # Create a simple test specialist
        class TestSpecialist(Specialist):
            @property
            def capability(self) -> SpecialistCapability:
                return SpecialistCapability(
                    name="Test Specialist",
                    task_types=["test.task"],
                    confidence=0.9,
                )

            async def _do_execute(self, task: Task) -> TaskResult:
                has_router = self._llm_router is not None
                return TaskResult(success=True, output={"has_router": has_router})

        # Create a test manager
        class TestManager(Manager):
            @property
            def name(self) -> str:
                return "Test Manager"

            @property
            def domain(self) -> str:
                return "test"

            @property
            def handled_task_types(self) -> list:
                return ["test.task"]

        # Create a test agent
        class TestAgent(SentinelAgentBase):
            @property
            def name(self) -> str:
                return "Test Agent"

            @property
            def domain(self) -> str:
                return "test"

            @property
            def handled_task_types(self) -> list:
                return ["test.task"]

            async def _setup_managers(self) -> None:
                manager = TestManager()
                specialist = TestSpecialist()
                manager.register_specialist(specialist)
                self.register_manager(manager)

        # Initialize agent and set router
        agent = TestAgent()
        await agent.initialize()
        agent.set_llm_router(mock_llm_router)

        # Execute a task and verify router was propagated
        task = Task(task_type="test.task", parameters={})
        result = await agent.execute(task)

        assert result.success
        assert result.output["has_router"] is True


# ============================================================================
# CIO ROUTER TESTS
# ============================================================================


class TestCIORouter:
    """Tests for CIO-specific LLM router."""

    @pytest.mark.asyncio
    async def test_cio_router_initialization(self):
        """Test CIO router initialization."""
        try:
            from nexus.core.llm import CIORouter

            router = CIORouter({})

            # Check default task mappings
            assert "threat_detection" in router._task_to_tier
            assert "log_analysis" in router._task_to_tier
            assert "incident_response" in router._task_to_tier
            assert "config_generation" in router._task_to_tier
        except ImportError:
            pytest.skip("nexus.core.llm not available")

    @pytest.mark.asyncio
    async def test_cio_router_task_mapping(self):
        """Test CIO router maps tasks to correct tiers."""
        try:
            from nexus.core.llm import CIORouter, ModelTier

            router = CIORouter({})

            # Threat detection should use FAST tier
            assert router._task_to_tier["threat_detection"] == ModelTier.FAST

            # Log analysis should use BALANCED tier
            assert router._task_to_tier["log_analysis"] == ModelTier.BALANCED

            # Incident response should use QUALITY tier
            assert router._task_to_tier["incident_response"] == ModelTier.QUALITY
        except ImportError:
            pytest.skip("nexus.core.llm not available")
