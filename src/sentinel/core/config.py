"""
Configuration management for Sentinel.

This module provides configuration loading, validation, and access
for the Sentinel security platform.
"""

import os
import re
from pathlib import Path
from typing import Any, Optional

import yaml
from pydantic import BaseModel, Field, field_validator
from pydantic_settings import BaseSettings


# =============================================================================
# Configuration Models
# =============================================================================


class StateConfig(BaseModel):
    """State backend configuration."""

    backend: str = "sqlite"  # memory, sqlite, postgresql, redis
    path: str = "/var/lib/sentinel/state.db"

    # PostgreSQL options
    postgresql: Optional[dict] = None

    # Redis options
    redis: Optional[dict] = None


class RouterIntegrationConfig(BaseModel):
    """Router integration configuration."""

    type: str = "opnsense"
    host: str = "192.168.1.1"
    port: int = 443
    api_key: str = ""
    api_secret: str = ""
    verify_ssl: bool = False
    timeout: int = 30


class SwitchIntegrationConfig(BaseModel):
    """Switch integration configuration."""

    type: str = "ubiquiti"
    controller_url: str = ""
    username: str = ""
    password: str = ""
    site: str = "default"
    verify_ssl: bool = False


class HypervisorIntegrationConfig(BaseModel):
    """Hypervisor integration configuration."""

    type: str = "proxmox"
    host: str = ""
    port: int = 8006
    user: str = "root@pam"
    token_name: str = ""
    token_value: str = ""
    verify_ssl: bool = False


class StorageIntegrationConfig(BaseModel):
    """Storage integration configuration."""

    type: str = "truenas"
    host: str = ""
    api_key: str = ""
    verify_ssl: bool = False


class KubernetesIntegrationConfig(BaseModel):
    """Kubernetes integration configuration."""

    type: str = "k3s"
    kubeconfig: str = ""
    context: str = "default"


class LLMProviderConfig(BaseModel):
    """LLM provider configuration."""

    type: str = "ollama"
    host: str = "http://localhost:11434"
    model: str = "llama3.1:8b"
    api_key: str = ""
    max_tokens: int = 4096


class LLMConfig(BaseModel):
    """LLM configuration with primary and fallback."""

    primary: LLMProviderConfig = Field(default_factory=LLMProviderConfig)
    fallback: Optional[LLMProviderConfig] = None


class IntegrationsConfig(BaseModel):
    """All integrations configuration."""

    router: Optional[RouterIntegrationConfig] = None
    switch: Optional[SwitchIntegrationConfig] = None
    hypervisor: Optional[HypervisorIntegrationConfig] = None
    storage: Optional[StorageIntegrationConfig] = None
    kubernetes: Optional[KubernetesIntegrationConfig] = None
    llm: LLMConfig = Field(default_factory=LLMConfig)


class AgentConfig(BaseModel):
    """Base agent configuration."""

    enabled: bool = True
    auto_execute_threshold: float = 0.95
    log_execute_threshold: float = 0.80
    confirm_threshold: float = 0.60
    max_actions_per_minute: int = 20


class DiscoveryAgentConfig(AgentConfig):
    """Discovery agent configuration."""

    scan_interval_seconds: int = 300
    full_scan_interval_seconds: int = 3600
    networks: list[str] = Field(default_factory=list)
    port_scan_enabled: bool = True
    service_detection_enabled: bool = True


class OptimizerAgentConfig(AgentConfig):
    """Optimizer agent configuration."""

    analysis_interval_seconds: int = 60
    netflow_enabled: bool = False
    netflow_port: int = 2055
    bandwidth_threshold_percent: int = 80


class PlannerAgentConfig(AgentConfig):
    """Planner agent configuration."""

    require_confirmation_for: list[str] = Field(
        default_factory=lambda: ["create_vlan", "delete_vlan", "modify_firewall"]
    )


class HealerAgentConfig(AgentConfig):
    """Healer agent configuration."""

    health_check_interval_seconds: int = 30
    auto_restart_services: bool = True
    max_restart_attempts: int = 3
    auto_failover: bool = True


class GuardianAgentConfig(AgentConfig):
    """Guardian agent configuration."""

    auto_quarantine: bool = True
    quarantine_vlan: int = 666
    threat_thresholds: dict = Field(
        default_factory=lambda: {"port_scan": 100, "failed_auth": 10, "bandwidth_spike": 500}
    )


class AgentsConfig(BaseModel):
    """All agents configuration."""

    discovery: DiscoveryAgentConfig = Field(default_factory=DiscoveryAgentConfig)
    optimizer: OptimizerAgentConfig = Field(default_factory=OptimizerAgentConfig)
    planner: PlannerAgentConfig = Field(default_factory=PlannerAgentConfig)
    healer: HealerAgentConfig = Field(default_factory=HealerAgentConfig)
    guardian: GuardianAgentConfig = Field(default_factory=GuardianAgentConfig)


class VLANConfig(BaseModel):
    """VLAN definition configuration."""

    id: int
    name: str
    purpose: str = "general"
    subnet: str = ""
    gateway: str = ""
    dns_zone: str = ""
    dhcp_enabled: bool = False
    dhcp_range_start: str = ""
    dhcp_range_end: str = ""
    isolated: bool = False
    allowed_destinations: list[int] = Field(default_factory=list)


class SegmentationPolicyConfig(BaseModel):
    """Segmentation policy configuration."""

    name: str
    source_vlan: int
    destination_vlan: int
    allowed_services: list[str] = Field(default_factory=list)
    default_action: str = "deny"


class APIKeyConfig(BaseModel):
    """API key configuration."""

    key_hash: str = ""  # SHA-256 hash of the API key
    name: str = ""
    scopes: list[str] = Field(default_factory=lambda: ["read"])


class AuthConfig(BaseModel):
    """API authentication configuration.

    Supports both API key and JWT authentication methods.
    When enabled=False, all endpoints are public (use for development only).
    """

    enabled: bool = True
    # API key authentication
    api_keys: dict[str, APIKeyConfig] = Field(default_factory=dict)
    # JWT authentication
    jwt_secret: str = (
        ""  # Required for JWT - generate with: python -c "import secrets; print(secrets.token_urlsafe(32))"
    )
    jwt_algorithm: str = "HS256"
    token_expire_minutes: int = 60

    @field_validator("jwt_secret")
    @classmethod
    def validate_jwt_secret(cls, v: str, info) -> str:
        """Warn if JWT secret is empty when auth is enabled."""
        # Access 'enabled' from the values dict if available
        if not v and info.data.get("enabled", True):
            import logging

            logging.getLogger(__name__).warning(
                "JWT secret is empty - JWT authentication will not work. "
                'Generate a secret with: python -c "import secrets; print(secrets.token_urlsafe(32))"'
            )
        return v


class RateLimitConfig(BaseModel):
    """Rate limiting configuration."""

    enabled: bool = True
    requests_per_minute: int = 100


class APIConfig(BaseModel):
    """API server configuration."""

    enabled: bool = True
    host: str = "0.0.0.0"
    port: int = 8080
    cors_origins: list[str] = Field(default_factory=lambda: ["http://localhost:3000"])
    auth: AuthConfig = Field(default_factory=AuthConfig)
    rate_limit: RateLimitConfig = Field(default_factory=RateLimitConfig)


class PushoverConfig(BaseModel):
    """Pushover notification configuration."""

    enabled: bool = False
    user_key: str = ""
    api_token: str = ""
    priority_mapping: dict = Field(
        default_factory=lambda: {"critical": 2, "error": 1, "warning": 0, "info": -1}
    )


class WebhookConfig(BaseModel):
    """Webhook notification configuration."""

    enabled: bool = False
    url: str = ""
    headers: dict = Field(default_factory=dict)


class AlertingConfig(BaseModel):
    """Alerting configuration."""

    enabled: bool = True
    pushover: PushoverConfig = Field(default_factory=PushoverConfig)
    webhook: WebhookConfig = Field(default_factory=WebhookConfig)


class LogFileConfig(BaseModel):
    """Log file configuration."""

    enabled: bool = True
    path: str = "/var/log/sentinel/sentinel.log"
    max_size_mb: int = 100
    backup_count: int = 5


class StructuredLogConfig(BaseModel):
    """Structured logging configuration."""

    enabled: bool = True
    include_timestamp: bool = True
    include_caller: bool = False


class LoggingConfig(BaseModel):
    """Logging configuration."""

    level: str = "INFO"
    format: str = "json"  # json or text
    file: LogFileConfig = Field(default_factory=LogFileConfig)
    structured: StructuredLogConfig = Field(default_factory=StructuredLogConfig)


class SentinelConfig(BaseModel):
    """Main Sentinel configuration."""

    state: StateConfig = Field(default_factory=StateConfig)
    integrations: IntegrationsConfig = Field(default_factory=IntegrationsConfig)
    agents: AgentsConfig = Field(default_factory=AgentsConfig)
    vlans: list[VLANConfig] = Field(default_factory=list)
    segmentation_policies: list[SegmentationPolicyConfig] = Field(default_factory=list)
    api: APIConfig = Field(default_factory=APIConfig)
    alerting: AlertingConfig = Field(default_factory=AlertingConfig)
    logging: LoggingConfig = Field(default_factory=LoggingConfig)


# =============================================================================
# Environment Variable Substitution
# =============================================================================


def substitute_env_vars(value: Any) -> Any:
    """
    Recursively substitute environment variables in configuration values.

    Supports:
    - ${VAR_NAME} - Required variable, raises if not set
    - ${VAR_NAME:-default} - Variable with default value
    - ${HOME} - Standard environment variables
    """
    if isinstance(value, str):
        # Pattern to match ${VAR} or ${VAR:-default}
        pattern = r"\$\{([^}:]+)(?::-([^}]*))?\}"

        def replace_var(match):
            var_name = match.group(1)
            default_value = match.group(2)

            env_value = os.environ.get(var_name)

            if env_value is not None:
                return env_value
            elif default_value is not None:
                return default_value
            else:
                # Return empty string for missing optional vars
                return ""

        return re.sub(pattern, replace_var, value)

    elif isinstance(value, dict):
        return {k: substitute_env_vars(v) for k, v in value.items()}

    elif isinstance(value, list):
        return [substitute_env_vars(item) for item in value]

    return value


# =============================================================================
# Configuration Loading
# =============================================================================


def load_config(config_path: Optional[str] = None) -> SentinelConfig:
    """
    Load Sentinel configuration from a YAML file.

    Args:
        config_path: Path to configuration file. If not provided, will look in:
            1. SENTINEL_CONFIG environment variable
            2. ./sentinel.yaml
            3. ./config/sentinel.yaml
            4. /etc/sentinel/sentinel.yaml

    Returns:
        Validated SentinelConfig object

    Raises:
        FileNotFoundError: If no configuration file found
        ValidationError: If configuration is invalid
    """
    search_paths = [
        config_path,
        os.environ.get("SENTINEL_CONFIG"),
        "sentinel.yaml",
        "config/sentinel.yaml",
        "config/homelab.yaml",
        "/etc/sentinel/sentinel.yaml",
    ]

    config_file = None
    for path in search_paths:
        if path and Path(path).exists():
            config_file = Path(path)
            break

    if config_file is None:
        # Return default config if no file found
        return SentinelConfig()

    with open(config_file, "r") as f:
        raw_config = yaml.safe_load(f)

    if raw_config is None:
        raw_config = {}

    # Substitute environment variables
    config_data = substitute_env_vars(raw_config)

    # Parse into config model
    return SentinelConfig(**config_data)


def load_config_from_dict(config_dict: dict) -> SentinelConfig:
    """
    Load Sentinel configuration from a dictionary.

    Useful for testing or programmatic configuration.

    Args:
        config_dict: Configuration dictionary

    Returns:
        Validated SentinelConfig object
    """
    config_data = substitute_env_vars(config_dict)
    return SentinelConfig(**config_data)


# =============================================================================
# Global Configuration Access
# =============================================================================

_config: Optional[SentinelConfig] = None


def get_config() -> SentinelConfig:
    """
    Get the global configuration instance.

    Loads configuration on first access.
    """
    global _config
    if _config is None:
        _config = load_config()
    return _config


def set_config(config: SentinelConfig) -> None:
    """
    Set the global configuration instance.

    Useful for testing or when configuration is loaded elsewhere.
    """
    global _config
    _config = config


def reload_config(config_path: Optional[str] = None) -> SentinelConfig:
    """
    Reload configuration from file.

    Args:
        config_path: Optional path to configuration file

    Returns:
        New configuration instance
    """
    global _config
    _config = load_config(config_path)
    return _config
