"""Sentinel API package."""
from sentinel.api.app import app, create_app
from sentinel.api.auth import (
    configure_auth,
    get_current_user,
    require_scope,
    generate_api_key,
    AuthConfig,
)

__all__ = [
    "app",
    "create_app",
    "configure_auth",
    "get_current_user",
    "require_scope",
    "generate_api_key",
    "AuthConfig",
]
