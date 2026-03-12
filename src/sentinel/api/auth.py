"""
Sentinel API Authentication Module.

Provides API key and JWT-based authentication for the Sentinel API.
JWT and API-key crypto are delegated to the shared auth_core library.
"""

import logging
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import Depends, HTTPException, Security, status
from fastapi.security import APIKeyHeader, HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel

from auth_core import verify_key as _verify_key
from auth_core import generate_key as _generate_key
from auth_core.jwt import create_token as _create_token, verify_token as _verify_token

logger = logging.getLogger(__name__)

# Security schemes
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)
bearer_scheme = HTTPBearer(auto_error=False)


class TokenData(BaseModel):
    """Token payload data."""

    sub: str  # Subject (user/client ID)
    exp: datetime  # Expiration
    iat: datetime  # Issued at
    scopes: list[str] = []  # Permissions


class AuthConfig(BaseModel):
    """Authentication configuration."""

    enabled: bool = True
    api_keys: dict[str, dict] = {}  # key_id -> {key_hash, name, scopes}
    jwt_secret: Optional[str] = None
    jwt_algorithm: str = "HS256"
    token_expire_minutes: int = 60


# Global auth config (set during app startup)
_auth_config: Optional[AuthConfig] = None


def configure_auth(config) -> None:
    """
    Configure authentication from config.

    Accepts either:
    - A SentinelConfig pydantic model
    - A full config dict with 'api.auth' section
    - A dict matching AuthConfig fields directly

    The config should have the following structure:
    {
        "api": {
            "auth": {
                "enabled": True,
                "api_keys": {
                    "key_id": {
                        "key_hash": "sha256_hash_of_api_key",
                        "name": "My API Key",
                        "scopes": ["read", "write"]
                    }
                },
                "jwt_secret": "your-secret-key",
                "jwt_algorithm": "HS256",
                "token_expire_minutes": 60
            }
        }
    }
    """
    global _auth_config

    # Handle different input types
    auth_settings = {}

    if hasattr(config, "api") and hasattr(config.api, "auth"):
        # SentinelConfig object from pydantic
        auth_obj = config.api.auth
        auth_settings = {
            "enabled": auth_obj.enabled,
            "api_keys": (
                {
                    k: {"key_hash": v.key_hash, "name": v.name, "scopes": v.scopes}
                    for k, v in auth_obj.api_keys.items()
                }
                if hasattr(auth_obj, "api_keys") and auth_obj.api_keys
                else {}
            ),
            "jwt_secret": auth_obj.jwt_secret,
            "jwt_algorithm": auth_obj.jwt_algorithm,
            "token_expire_minutes": auth_obj.token_expire_minutes,
        }
    elif isinstance(config, dict):
        # Dict config - navigate to auth section
        auth_settings = config.get("api", {}).get("auth", {})
        if not auth_settings and "enabled" in config:
            # Direct auth config dict
            auth_settings = config

    _auth_config = AuthConfig(
        enabled=auth_settings.get("enabled", True),
        api_keys=auth_settings.get("api_keys", {}),
        jwt_secret=auth_settings.get("jwt_secret") or "",
        jwt_algorithm=auth_settings.get("jwt_algorithm", "HS256"),
        token_expire_minutes=auth_settings.get("token_expire_minutes", 60),
    )

    if not _auth_config.enabled:
        logger.warning("API authentication is DISABLED - all endpoints are public")
    elif not _auth_config.jwt_secret and not _auth_config.api_keys:
        logger.warning(
            "API authentication enabled but no JWT secret or API keys configured. "
            "All authenticated endpoints will reject requests."
        )
    else:
        key_count = len(_auth_config.api_keys)
        has_jwt = bool(_auth_config.jwt_secret)
        logger.info(
            f"API authentication enabled: {key_count} API key(s), "
            f"JWT {'enabled' if has_jwt else 'disabled'}"
        )


def generate_api_key() -> tuple[str, str]:
    """Generate a new API key. Returns (key, key_hash) — store only the hash."""
    return _generate_key()


def verify_api_key(key: str, key_hash: str) -> bool:
    """Verify an API key against its hash."""
    return _verify_key(key, key_hash)


def get_api_key_info(key: str) -> Optional[dict]:
    """Look up API key and return its info if valid."""
    if not _auth_config:
        return None

    for key_id, key_data in _auth_config.api_keys.items():
        if verify_api_key(key, key_data.get("key_hash", "")):
            return {
                "key_id": key_id,
                "name": key_data.get("name", "Unknown"),
                "scopes": key_data.get("scopes", []),
            }

    return None


async def get_current_user(
    api_key: Optional[str] = Security(api_key_header),
    bearer: Optional[HTTPAuthorizationCredentials] = Security(bearer_scheme),
) -> dict:
    """
    Dependency to get the current authenticated user/client.

    Supports both API key (X-API-Key header) and Bearer token authentication.

    Returns:
        Dict with user/client info and scopes

    Raises:
        HTTPException: If authentication fails
    """
    # Check if auth is disabled
    if _auth_config is None or not _auth_config.enabled:
        return {
            "type": "anonymous",
            "id": "anonymous",
            "name": "Anonymous",
            "scopes": ["*"],  # Full access when auth disabled
        }

    # Try API key first
    if api_key:
        key_info = get_api_key_info(api_key)
        if key_info:
            return {
                "type": "api_key",
                "id": key_info["key_id"],
                "name": key_info["name"],
                "scopes": key_info["scopes"],
            }
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key",
            headers={"WWW-Authenticate": "ApiKey"},
        )

    # Try Bearer token
    if bearer:
        try:
            token_data = verify_jwt_token(bearer.credentials)
            return {
                "type": "jwt",
                "id": token_data.sub,
                "name": token_data.sub,
                "scopes": token_data.scopes,
            }
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=f"Invalid token: {e}",
                headers={"WWW-Authenticate": "Bearer"},
            )

    # No credentials provided
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Authentication required",
        headers={"WWW-Authenticate": "ApiKey, Bearer"},
    )


def verify_jwt_token(token: str) -> TokenData:
    """Verify and decode a JWT token, returning structured TokenData."""
    if not _auth_config or not _auth_config.jwt_secret:
        raise ValueError("JWT authentication not configured")

    payload = _verify_token(
        token,
        _auth_config.jwt_secret,
        algorithms=[_auth_config.jwt_algorithm],
    )

    exp_timestamp = payload.get("exp", 0)
    iat_timestamp = payload.get("iat", 0)

    return TokenData(
        sub=payload.get("sub", ""),
        exp=datetime.fromtimestamp(exp_timestamp, tz=timezone.utc),
        iat=datetime.fromtimestamp(iat_timestamp, tz=timezone.utc),
        scopes=payload.get("scopes", []),
    )


def create_jwt_token(
    subject: str,
    scopes: list[str] = None,
    expires_delta: timedelta = None,
) -> str:
    """Create a new signed JWT token."""
    if not _auth_config or not _auth_config.jwt_secret:
        raise ValueError("JWT authentication not configured")

    return _create_token(
        subject=subject,
        secret=_auth_config.jwt_secret,
        algorithm=_auth_config.jwt_algorithm,
        expires_delta=expires_delta,
        expire_minutes=_auth_config.token_expire_minutes,
        extra_claims={"scopes": scopes or []},
    )


def require_scope(required_scope: str):
    """
    Dependency factory for scope-based authorization.

    Usage:
        @app.get("/admin/users", dependencies=[Depends(require_scope("admin"))])
        async def list_users():
            ...
    """

    async def scope_checker(user: dict = Depends(get_current_user)):
        if "*" in user.get("scopes", []):
            return user
        if required_scope not in user.get("scopes", []):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN, detail=f"Scope '{required_scope}' required"
            )
        return user

    return scope_checker


# Predefined scope dependencies
require_read = Depends(require_scope("read"))
require_write = Depends(require_scope("write"))
require_admin = Depends(require_scope("admin"))


class AuthMiddleware:
    """
    ASGI middleware for authentication logging and metrics.

    This is optional - the main auth logic is in the get_current_user dependency.
    """

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] == "http":
            # Extract path for logging
            path = scope.get("path", "/")

            # Check for public endpoints that don't require auth
            public_paths = ["/", "/health", "/docs", "/openapi.json", "/redoc"]
            if path in public_paths:
                await self.app(scope, receive, send)
                return

            # Log auth attempt (actual auth is handled by dependencies)
            headers = dict(scope.get("headers", []))
            has_api_key = b"x-api-key" in headers
            has_bearer = b"authorization" in headers

            logger.debug(f"Auth check for {path}: api_key={has_api_key}, bearer={has_bearer}")

        await self.app(scope, receive, send)
