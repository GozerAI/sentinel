"""
Tests for the Configuration module.

Tests cover configuration models, environment variable substitution,
loading from files/dicts, and global configuration access.
"""

import os
import pytest
import tempfile
from pathlib import Path
from unittest.mock import patch

import yaml

from sentinel.core.config import (
    # Models
    StateConfig,
    RouterIntegrationConfig,
    SwitchIntegrationConfig,
    HypervisorIntegrationConfig,
    StorageIntegrationConfig,
    KubernetesIntegrationConfig,
    LLMProviderConfig,
    LLMConfig,
    IntegrationsConfig,
    AgentConfig,
    DiscoveryAgentConfig,
    OptimizerAgentConfig,
    PlannerAgentConfig,
    HealerAgentConfig,
    GuardianAgentConfig,
    AgentsConfig,
    VLANConfig,
    SegmentationPolicyConfig,
    AuthConfig,
    RateLimitConfig,
    APIConfig,
    PushoverConfig,
    WebhookConfig,
    AlertingConfig,
    LogFileConfig,
    StructuredLogConfig,
    LoggingConfig,
    SentinelConfig,
    # Functions
    substitute_env_vars,
    load_config,
    load_config_from_dict,
    get_config,
    set_config,
    reload_config,
)


# =============================================================================
# Configuration Model Tests
# =============================================================================


class TestStateConfig:
    """Tests for StateConfig model."""

    def test_default_values(self):
        """Test default values."""
        config = StateConfig()
        assert config.backend == "sqlite"
        assert config.path == "/var/lib/sentinel/state.db"
        assert config.postgresql is None
        assert config.redis is None

    def test_custom_values(self):
        """Test custom values."""
        config = StateConfig(backend="memory", path="/tmp/state.db")
        assert config.backend == "memory"
        assert config.path == "/tmp/state.db"


class TestRouterIntegrationConfig:
    """Tests for RouterIntegrationConfig model."""

    def test_default_values(self):
        """Test default values."""
        config = RouterIntegrationConfig()
        assert config.type == "opnsense"
        assert config.host == "192.168.1.1"
        assert config.port == 443
        assert config.verify_ssl is False
        assert config.timeout == 30

    def test_custom_values(self):
        """Test custom values."""
        config = RouterIntegrationConfig(
            type="pfsense", host="10.0.0.1", api_key="test_key", api_secret="test_secret"
        )
        assert config.type == "pfsense"
        assert config.host == "10.0.0.1"
        assert config.api_key == "test_key"


class TestSwitchIntegrationConfig:
    """Tests for SwitchIntegrationConfig model."""

    def test_default_values(self):
        """Test default values."""
        config = SwitchIntegrationConfig()
        assert config.type == "ubiquiti"
        assert config.site == "default"
        assert config.verify_ssl is False


class TestHypervisorIntegrationConfig:
    """Tests for HypervisorIntegrationConfig model."""

    def test_default_values(self):
        """Test default values."""
        config = HypervisorIntegrationConfig()
        assert config.type == "proxmox"
        assert config.port == 8006
        assert config.user == "root@pam"


class TestStorageIntegrationConfig:
    """Tests for StorageIntegrationConfig model."""

    def test_default_values(self):
        """Test default values."""
        config = StorageIntegrationConfig()
        assert config.type == "truenas"
        assert config.verify_ssl is False


class TestKubernetesIntegrationConfig:
    """Tests for KubernetesIntegrationConfig model."""

    def test_default_values(self):
        """Test default values."""
        config = KubernetesIntegrationConfig()
        assert config.type == "k3s"
        assert config.context == "default"


class TestLLMConfig:
    """Tests for LLM configuration models."""

    def test_llm_provider_defaults(self):
        """Test LLMProviderConfig defaults."""
        config = LLMProviderConfig()
        assert config.type == "ollama"
        assert config.host == "http://localhost:11434"
        assert config.model == "llama3.1:8b"
        assert config.max_tokens == 4096

    def test_llm_config_defaults(self):
        """Test LLMConfig defaults."""
        config = LLMConfig()
        assert config.primary is not None
        assert config.fallback is None

    def test_llm_config_with_fallback(self):
        """Test LLMConfig with fallback."""
        fallback = LLMProviderConfig(type="openai", api_key="test_key")
        config = LLMConfig(fallback=fallback)
        assert config.fallback is not None
        assert config.fallback.type == "openai"


class TestAgentConfigs:
    """Tests for agent configuration models."""

    def test_base_agent_config_defaults(self):
        """Test AgentConfig defaults."""
        config = AgentConfig()
        assert config.enabled is True
        assert config.auto_execute_threshold == 0.95
        assert config.log_execute_threshold == 0.80
        assert config.confirm_threshold == 0.60
        assert config.max_actions_per_minute == 20

    def test_discovery_agent_config_defaults(self):
        """Test DiscoveryAgentConfig defaults."""
        config = DiscoveryAgentConfig()
        assert config.scan_interval_seconds == 300
        assert config.full_scan_interval_seconds == 3600
        assert config.networks == []
        assert config.port_scan_enabled is True

    def test_optimizer_agent_config_defaults(self):
        """Test OptimizerAgentConfig defaults."""
        config = OptimizerAgentConfig()
        assert config.analysis_interval_seconds == 60
        assert config.netflow_enabled is False
        assert config.bandwidth_threshold_percent == 80

    def test_planner_agent_config_defaults(self):
        """Test PlannerAgentConfig defaults."""
        config = PlannerAgentConfig()
        assert "create_vlan" in config.require_confirmation_for
        assert "delete_vlan" in config.require_confirmation_for

    def test_healer_agent_config_defaults(self):
        """Test HealerAgentConfig defaults."""
        config = HealerAgentConfig()
        assert config.health_check_interval_seconds == 30
        assert config.auto_restart_services is True
        assert config.max_restart_attempts == 3
        assert config.auto_failover is True

    def test_guardian_agent_config_defaults(self):
        """Test GuardianAgentConfig defaults."""
        config = GuardianAgentConfig()
        assert config.auto_quarantine is True
        assert config.quarantine_vlan == 666
        assert config.threat_thresholds["port_scan"] == 100

    def test_agents_config_defaults(self):
        """Test AgentsConfig defaults."""
        config = AgentsConfig()
        assert config.discovery is not None
        assert config.optimizer is not None
        assert config.planner is not None
        assert config.healer is not None
        assert config.guardian is not None


class TestVLANConfig:
    """Tests for VLANConfig model."""

    def test_required_fields(self):
        """Test required fields."""
        config = VLANConfig(id=10, name="Test VLAN")
        assert config.id == 10
        assert config.name == "Test VLAN"

    def test_default_values(self):
        """Test default values."""
        config = VLANConfig(id=10, name="Test")
        assert config.purpose == "general"
        assert config.subnet == ""
        assert config.dhcp_enabled is False
        assert config.isolated is False
        assert config.allowed_destinations == []

    def test_custom_values(self):
        """Test custom values."""
        config = VLANConfig(
            id=20,
            name="Servers",
            purpose="infrastructure",
            subnet="192.168.20.0/24",
            dhcp_enabled=True,
            isolated=True,
            allowed_destinations=[10, 30],
        )
        assert config.subnet == "192.168.20.0/24"
        assert config.isolated is True
        assert config.allowed_destinations == [10, 30]


class TestSegmentationPolicyConfig:
    """Tests for SegmentationPolicyConfig model."""

    def test_required_fields(self):
        """Test required fields."""
        config = SegmentationPolicyConfig(name="Test Policy", source_vlan=10, destination_vlan=20)
        assert config.name == "Test Policy"
        assert config.source_vlan == 10
        assert config.destination_vlan == 20

    def test_default_values(self):
        """Test default values."""
        config = SegmentationPolicyConfig(name="Test", source_vlan=10, destination_vlan=20)
        assert config.allowed_services == []
        assert config.default_action == "deny"


class TestAPIConfig:
    """Tests for API configuration models."""

    def test_auth_config_defaults(self):
        """Test AuthConfig defaults."""
        config = AuthConfig()
        assert config.type == "jwt"
        assert config.algorithm == "HS256"
        assert config.access_token_expire_minutes == 60

    def test_rate_limit_config_defaults(self):
        """Test RateLimitConfig defaults."""
        config = RateLimitConfig()
        assert config.enabled is True
        assert config.requests_per_minute == 100

    def test_api_config_defaults(self):
        """Test APIConfig defaults."""
        config = APIConfig()
        assert config.enabled is True
        assert config.host == "0.0.0.0"
        assert config.port == 8080
        assert "http://localhost:3000" in config.cors_origins


class TestAlertingConfig:
    """Tests for alerting configuration models."""

    def test_pushover_config_defaults(self):
        """Test PushoverConfig defaults."""
        config = PushoverConfig()
        assert config.enabled is False
        assert config.priority_mapping["critical"] == 2

    def test_webhook_config_defaults(self):
        """Test WebhookConfig defaults."""
        config = WebhookConfig()
        assert config.enabled is False
        assert config.headers == {}

    def test_alerting_config_defaults(self):
        """Test AlertingConfig defaults."""
        config = AlertingConfig()
        assert config.enabled is True
        assert config.pushover is not None
        assert config.webhook is not None


class TestLoggingConfig:
    """Tests for logging configuration models."""

    def test_log_file_config_defaults(self):
        """Test LogFileConfig defaults."""
        config = LogFileConfig()
        assert config.enabled is True
        assert config.max_size_mb == 100
        assert config.backup_count == 5

    def test_structured_log_config_defaults(self):
        """Test StructuredLogConfig defaults."""
        config = StructuredLogConfig()
        assert config.enabled is True
        assert config.include_timestamp is True
        assert config.include_caller is False

    def test_logging_config_defaults(self):
        """Test LoggingConfig defaults."""
        config = LoggingConfig()
        assert config.level == "INFO"
        assert config.format == "json"


class TestSentinelConfig:
    """Tests for main SentinelConfig model."""

    def test_default_values(self):
        """Test all defaults."""
        config = SentinelConfig()
        assert config.state is not None
        assert config.integrations is not None
        assert config.agents is not None
        assert config.vlans == []
        assert config.segmentation_policies == []
        assert config.api is not None
        assert config.alerting is not None
        assert config.logging is not None

    def test_full_config(self):
        """Test full configuration."""
        config = SentinelConfig(
            state=StateConfig(backend="memory"),
            vlans=[VLANConfig(id=10, name="Test")],
            segmentation_policies=[
                SegmentationPolicyConfig(name="Policy1", source_vlan=10, destination_vlan=20)
            ],
        )
        assert config.state.backend == "memory"
        assert len(config.vlans) == 1
        assert len(config.segmentation_policies) == 1


# =============================================================================
# Environment Variable Substitution Tests
# =============================================================================


class TestSubstituteEnvVars:
    """Tests for environment variable substitution."""

    def test_simple_substitution(self):
        """Test simple variable substitution."""
        with patch.dict(os.environ, {"TEST_VAR": "test_value"}):
            result = substitute_env_vars("${TEST_VAR}")
            assert result == "test_value"

    def test_with_default_value(self):
        """Test substitution with default value."""
        # Remove variable if it exists
        os.environ.pop("MISSING_VAR", None)
        result = substitute_env_vars("${MISSING_VAR:-default_value}")
        assert result == "default_value"

    def test_env_var_overrides_default(self):
        """Test that env var overrides default."""
        with patch.dict(os.environ, {"EXISTING_VAR": "real_value"}):
            result = substitute_env_vars("${EXISTING_VAR:-default}")
            assert result == "real_value"

    def test_missing_var_returns_empty(self):
        """Test missing var without default returns empty."""
        os.environ.pop("NONEXISTENT_VAR", None)
        result = substitute_env_vars("${NONEXISTENT_VAR}")
        assert result == ""

    def test_multiple_vars_in_string(self):
        """Test multiple variables in one string."""
        with patch.dict(os.environ, {"HOST": "localhost", "PORT": "8080"}):
            result = substitute_env_vars("http://${HOST}:${PORT}")
            assert result == "http://localhost:8080"

    def test_dict_substitution(self):
        """Test substitution in dictionary."""
        with patch.dict(os.environ, {"API_KEY": "secret123"}):
            result = substitute_env_vars({"key": "${API_KEY}", "nested": {"inner": "${API_KEY}"}})
            assert result["key"] == "secret123"
            assert result["nested"]["inner"] == "secret123"

    def test_list_substitution(self):
        """Test substitution in list."""
        with patch.dict(os.environ, {"ITEM": "value"}):
            result = substitute_env_vars(["${ITEM}", "literal"])
            assert result[0] == "value"
            assert result[1] == "literal"

    def test_non_string_passthrough(self):
        """Test non-string values pass through unchanged."""
        assert substitute_env_vars(123) == 123
        assert substitute_env_vars(True) is True
        assert substitute_env_vars(None) is None


# =============================================================================
# Configuration Loading Tests
# =============================================================================


class TestLoadConfig:
    """Tests for load_config function."""

    def test_load_default_when_no_file(self):
        """Test loading default config when no file exists."""
        with patch.dict(os.environ, {}, clear=True):
            os.environ.pop("SENTINEL_CONFIG", None)
            config = load_config("/nonexistent/path/config.yaml")
            assert config is not None
            assert isinstance(config, SentinelConfig)

    def test_load_from_file(self):
        """Test loading config from file."""
        config_data = {"state": {"backend": "memory"}, "agents": {"discovery": {"enabled": False}}}

        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            yaml.dump(config_data, f)
            temp_path = f.name

        try:
            config = load_config(temp_path)
            assert config.state.backend == "memory"
            assert config.agents.discovery.enabled is False
        finally:
            os.unlink(temp_path)

    def test_load_empty_file(self):
        """Test loading empty config file."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write("")  # Empty file
            temp_path = f.name

        try:
            config = load_config(temp_path)
            assert config is not None
            # Should use defaults
            assert config.state.backend == "sqlite"
        finally:
            os.unlink(temp_path)

    def test_load_with_env_vars(self):
        """Test loading config with environment variable substitution."""
        config_data = {"api": {"auth": {"secret_key": "${API_SECRET:-default_secret}"}}}

        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            yaml.dump(config_data, f)
            temp_path = f.name

        try:
            with patch.dict(os.environ, {"API_SECRET": "real_secret"}):
                config = load_config(temp_path)
                assert config.api.auth.secret_key == "real_secret"
        finally:
            os.unlink(temp_path)


class TestLoadConfigFromDict:
    """Tests for load_config_from_dict function."""

    def test_basic_dict(self):
        """Test loading from basic dict."""
        config = load_config_from_dict({"state": {"backend": "memory"}})
        assert config.state.backend == "memory"

    def test_empty_dict(self):
        """Test loading from empty dict."""
        config = load_config_from_dict({})
        assert config is not None
        assert config.state.backend == "sqlite"  # Default

    def test_with_env_substitution(self):
        """Test dict loading with env var substitution."""
        with patch.dict(os.environ, {"TEST_HOST": "10.0.0.1"}):
            config = load_config_from_dict({"integrations": {"router": {"host": "${TEST_HOST}"}}})
            assert config.integrations.router.host == "10.0.0.1"


# =============================================================================
# Global Configuration Access Tests
# =============================================================================


class TestGlobalConfig:
    """Tests for global configuration access functions."""

    def test_get_config_returns_instance(self):
        """Test get_config returns a config instance."""
        # Reset global config
        import sentinel.core.config as config_module

        config_module._config = None

        config = get_config()
        assert config is not None
        assert isinstance(config, SentinelConfig)

    def test_set_config(self):
        """Test set_config sets the global config."""
        import sentinel.core.config as config_module

        custom_config = SentinelConfig(state=StateConfig(backend="memory"))
        set_config(custom_config)

        assert config_module._config is custom_config
        assert get_config().state.backend == "memory"

    def test_reload_config(self):
        """Test reload_config reloads from file."""
        import sentinel.core.config as config_module

        # Set initial config
        initial = SentinelConfig(state=StateConfig(backend="initial"))
        set_config(initial)

        # Reload (will use default since no file)
        reloaded = reload_config()
        assert reloaded is not None
        # Should have been reloaded
        assert config_module._config is reloaded

    def test_reload_config_with_file(self):
        """Test reload_config with specific file."""
        config_data = {"state": {"backend": "reloaded"}}

        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            yaml.dump(config_data, f)
            temp_path = f.name

        try:
            reloaded = reload_config(temp_path)
            assert reloaded.state.backend == "reloaded"
        finally:
            os.unlink(temp_path)


# =============================================================================
# Integration Tests
# =============================================================================


class TestConfigIntegration:
    """Integration tests for configuration system."""

    def test_full_config_file(self):
        """Test loading a complete configuration file."""
        config_data = {
            "state": {"backend": "sqlite", "path": "/data/sentinel.db"},
            "integrations": {
                "router": {"type": "opnsense", "host": "192.168.1.1"},
                "llm": {"primary": {"type": "ollama", "model": "llama3.1:8b"}},
            },
            "agents": {
                "discovery": {"enabled": True, "networks": ["192.168.1.0/24", "10.0.0.0/8"]},
                "guardian": {"auto_quarantine": True, "quarantine_vlan": 999},
            },
            "vlans": [
                {"id": 10, "name": "Workstations"},
                {"id": 20, "name": "Servers", "isolated": True},
            ],
            "api": {"port": 8080, "cors_origins": ["http://localhost:3000"]},
        }

        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            yaml.dump(config_data, f)
            temp_path = f.name

        try:
            config = load_config(temp_path)

            # Verify all sections loaded correctly
            assert config.state.backend == "sqlite"
            assert config.state.path == "/data/sentinel.db"
            assert config.integrations.router.host == "192.168.1.1"
            assert config.integrations.llm.primary.model == "llama3.1:8b"
            assert len(config.agents.discovery.networks) == 2
            assert config.agents.guardian.quarantine_vlan == 999
            assert len(config.vlans) == 2
            assert config.vlans[1].isolated is True
            assert config.api.port == 8080
        finally:
            os.unlink(temp_path)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
