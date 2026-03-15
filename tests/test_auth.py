"""
Tests for the API Authentication module.

Tests cover API key generation/verification, JWT handling, auth configuration,
and the current user dependency.
"""
import base64
import hashlib
import json
import pytest
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, patch

from fastapi import HTTPException
from fastapi.security import HTTPAuthorizationCredentials

from sentinel.api.auth import (
    TokenData,
    AuthConfig,
    configure_auth,
    generate_api_key,
    verify_api_key,
    get_api_key_info,
    get_current_user,
    verify_jwt_token,
    create_jwt_token,
    require_scope,
    AuthMiddleware,
    _auth_config,
)
import sentinel.api.auth as auth_module


class TestTokenData:
    """Tests for TokenData model."""

    def test_token_data_creation(self):
        """Test creating TokenData."""
        now = datetime.now(timezone.utc)
        exp = now + timedelta(hours=1)

        token = TokenData(
            sub="user123",
            exp=exp,
            iat=now,
            scopes=["read", "write"]
        )

        assert token.sub == "user123"
        assert token.exp == exp
        assert token.iat == now
        assert token.scopes == ["read", "write"]

    def test_token_data_default_scopes(self):
        """Test TokenData with default scopes."""
        now = datetime.now(timezone.utc)
        token = TokenData(
            sub="user",
            exp=now,
            iat=now
        )
        assert token.scopes == []


class TestAuthConfig:
    """Tests for AuthConfig model."""

    def test_default_values(self):
        """Test default values."""
        config = AuthConfig()
        assert config.enabled is True
        assert config.api_keys == {}
        assert config.jwt_secret is None
        assert config.jwt_algorithm == "HS256"
        assert config.token_expire_minutes == 60

    def test_custom_values(self):
        """Test custom values."""
        config = AuthConfig(
            enabled=False,
            api_keys={"key1": {"key_hash": "abc", "name": "Test"}},
            jwt_secret="secret",
            token_expire_minutes=120
        )
        assert config.enabled is False
        assert "key1" in config.api_keys
        assert config.jwt_secret == "secret"
        assert config.token_expire_minutes == 120


class TestConfigureAuth:
    """Tests for configure_auth function."""

    def teardown_method(self):
        """Reset auth config after each test."""
        auth_module._auth_config = None

    def test_configure_auth_enabled(self):
        """Test configuring auth when enabled."""
        config = {
            "api": {
                "auth": {
                    "enabled": True,
                    "api_keys": {"key1": {"key_hash": "abc"}},
                    "jwt_secret": "test_secret",
                    "token_expire_minutes": 30
                }
            }
        }
        configure_auth(config)

        assert auth_module._auth_config is not None
        assert auth_module._auth_config.enabled is True
        assert "key1" in auth_module._auth_config.api_keys
        assert auth_module._auth_config.jwt_secret == "test_secret"
        assert auth_module._auth_config.token_expire_minutes == 30

    def test_configure_auth_disabled(self):
        """Test configuring auth when disabled."""
        config = {
            "api": {
                "auth": {
                    "enabled": False
                }
            }
        }
        configure_auth(config)

        assert auth_module._auth_config is not None
        assert auth_module._auth_config.enabled is False

    def test_configure_auth_empty_config(self):
        """Test configuring auth with empty config."""
        configure_auth({})

        assert auth_module._auth_config is not None
        assert auth_module._auth_config.enabled is True  # Default


class TestGenerateApiKey:
    """Tests for generate_api_key function."""

    def test_generate_api_key_returns_tuple(self):
        """Test generate_api_key returns (key, hash) tuple."""
        key, key_hash = generate_api_key()

        assert isinstance(key, str)
        assert isinstance(key_hash, str)
        assert key != key_hash

    def test_generate_api_key_hash_is_valid(self):
        """Test that hash is SHA256 of key."""
        key, key_hash = generate_api_key()

        expected_hash = hashlib.sha256(key.encode()).hexdigest()
        assert key_hash == expected_hash

    def test_generate_api_key_unique(self):
        """Test that generated keys are unique."""
        keys = set()
        for _ in range(100):
            key, _ = generate_api_key()
            assert key not in keys
            keys.add(key)


class TestVerifyApiKey:
    """Tests for verify_api_key function."""

    def test_verify_valid_key(self):
        """Test verifying a valid key."""
        key, key_hash = generate_api_key()

        assert verify_api_key(key, key_hash) is True

    def test_verify_invalid_key(self):
        """Test verifying an invalid key."""
        _, key_hash = generate_api_key()

        assert verify_api_key("wrong_key", key_hash) is False

    def test_verify_wrong_hash(self):
        """Test verifying with wrong hash."""
        key, _ = generate_api_key()

        assert verify_api_key(key, "wrong_hash") is False


class TestGetApiKeyInfo:
    """Tests for get_api_key_info function."""

    def teardown_method(self):
        """Reset auth config after each test."""
        auth_module._auth_config = None

    def test_get_api_key_info_no_config(self):
        """Test getting key info when config not set."""
        auth_module._auth_config = None
        result = get_api_key_info("any_key")
        assert result is None

    def test_get_api_key_info_valid_key(self):
        """Test getting key info for valid key."""
        key, key_hash = generate_api_key()

        auth_module._auth_config = AuthConfig(
            api_keys={
                "test_key": {
                    "key_hash": key_hash,
                    "name": "Test Key",
                    "scopes": ["read", "write"]
                }
            }
        )

        result = get_api_key_info(key)

        assert result is not None
        assert result["key_id"] == "test_key"
        assert result["name"] == "Test Key"
        assert result["scopes"] == ["read", "write"]

    def test_get_api_key_info_invalid_key(self):
        """Test getting key info for invalid key."""
        _, key_hash = generate_api_key()

        auth_module._auth_config = AuthConfig(
            api_keys={
                "test_key": {"key_hash": key_hash}
            }
        )

        result = get_api_key_info("wrong_key")
        assert result is None


class TestGetCurrentUser:
    """Tests for get_current_user dependency."""

    def teardown_method(self):
        """Reset auth config after each test."""
        auth_module._auth_config = None

    @pytest.mark.asyncio
    async def test_get_current_user_auth_disabled(self):
        """Test get_current_user when auth is disabled."""
        auth_module._auth_config = AuthConfig(enabled=False)

        user = await get_current_user(api_key=None, bearer=None)

        assert user["type"] == "anonymous"
        assert "*" in user["scopes"]

    @pytest.mark.asyncio
    async def test_get_current_user_no_config(self):
        """Test get_current_user when config is None."""
        auth_module._auth_config = None

        user = await get_current_user(api_key=None, bearer=None)

        assert user["type"] == "anonymous"

    @pytest.mark.asyncio
    async def test_get_current_user_valid_api_key(self):
        """Test get_current_user with valid API key."""
        key, key_hash = generate_api_key()

        auth_module._auth_config = AuthConfig(
            enabled=True,
            api_keys={
                "my_key": {
                    "key_hash": key_hash,
                    "name": "My API Key",
                    "scopes": ["read"]
                }
            }
        )

        user = await get_current_user(api_key=key, bearer=None)

        assert user["type"] == "api_key"
        assert user["id"] == "my_key"
        assert user["name"] == "My API Key"
        assert user["scopes"] == ["read"]

    @pytest.mark.asyncio
    async def test_get_current_user_invalid_api_key(self):
        """Test get_current_user with invalid API key."""
        auth_module._auth_config = AuthConfig(
            enabled=True,
            api_keys={}
        )

        with pytest.raises(HTTPException) as exc_info:
            await get_current_user(api_key="invalid_key", bearer=None)

        assert exc_info.value.status_code == 401
        assert "Invalid API key" in exc_info.value.detail

    @pytest.mark.asyncio
    async def test_get_current_user_no_credentials(self):
        """Test get_current_user with no credentials."""
        auth_module._auth_config = AuthConfig(enabled=True)

        with pytest.raises(HTTPException) as exc_info:
            await get_current_user(api_key=None, bearer=None)

        assert exc_info.value.status_code == 401
        assert "Authentication required" in exc_info.value.detail

    @pytest.mark.asyncio
    async def test_get_current_user_valid_bearer(self):
        """Test get_current_user with valid bearer token."""
        # Configure auth first so we can create a proper token
        auth_module._auth_config = AuthConfig(
            enabled=True,
            jwt_secret="test_secret"
        )

        # Create a properly signed JWT token using the new function
        token = create_jwt_token(
            subject="user123",
            scopes=["read", "write"],
            expires_delta=timedelta(hours=1)
        )

        bearer = HTTPAuthorizationCredentials(scheme="Bearer", credentials=token)
        user = await get_current_user(api_key=None, bearer=bearer)

        assert user["type"] == "jwt"
        assert user["id"] == "user123"
        assert "read" in user["scopes"]

    @pytest.mark.asyncio
    async def test_get_current_user_invalid_bearer(self):
        """Test get_current_user with invalid bearer token."""
        auth_module._auth_config = AuthConfig(
            enabled=True,
            jwt_secret="test_secret"
        )

        bearer = HTTPAuthorizationCredentials(
            scheme="Bearer",
            credentials="invalid.token"
        )

        with pytest.raises(HTTPException) as exc_info:
            await get_current_user(api_key=None, bearer=bearer)

        assert exc_info.value.status_code == 401


class TestVerifyJwtToken:
    """Tests for verify_jwt_token function."""

    def teardown_method(self):
        """Reset auth config after each test."""
        auth_module._auth_config = None

    def test_verify_jwt_no_config(self):
        """Test verifying JWT when config is None."""
        auth_module._auth_config = None

        with pytest.raises(ValueError) as exc_info:
            verify_jwt_token("any.token.here")

        assert "not configured" in str(exc_info.value)

    def test_verify_jwt_no_secret(self):
        """Test verifying JWT when secret is None."""
        auth_module._auth_config = AuthConfig(jwt_secret=None)

        with pytest.raises(ValueError) as exc_info:
            verify_jwt_token("any.token.here")

        assert "not configured" in str(exc_info.value)

    def test_verify_jwt_invalid_format(self):
        """Test verifying JWT with invalid format."""
        auth_module._auth_config = AuthConfig(jwt_secret="secret")

        with pytest.raises(ValueError) as exc_info:
            verify_jwt_token("not.a.valid.token.format")

        # python-jose raises JWTError for invalid tokens
        assert "verification failed" in str(exc_info.value).lower()

    def test_verify_jwt_expired_token(self):
        """Test verifying expired JWT."""
        auth_module._auth_config = AuthConfig(jwt_secret="secret")

        # Create a properly signed but expired token using python-jose directly
        from jose import jwt as jose_jwt
        past = datetime.now(timezone.utc) - timedelta(hours=1)
        payload = {
            "sub": "user",
            "exp": past,
            "iat": past - timedelta(hours=1)
        }
        token = jose_jwt.encode(payload, "secret", algorithm="HS256")

        with pytest.raises(ValueError) as exc_info:
            verify_jwt_token(token)

        assert "expired" in str(exc_info.value).lower()

    def test_verify_jwt_valid_token(self):
        """Test verifying valid JWT."""
        auth_module._auth_config = AuthConfig(jwt_secret="secret")

        # Create a properly signed token using create_jwt_token
        token = create_jwt_token(
            subject="user123",
            scopes=["admin"],
            expires_delta=timedelta(hours=1)
        )

        result = verify_jwt_token(token)

        assert result.sub == "user123"
        assert result.scopes == ["admin"]


class TestRequireScope:
    """Tests for require_scope dependency factory."""

    def teardown_method(self):
        """Reset auth config after each test."""
        auth_module._auth_config = None

    @pytest.mark.asyncio
    async def test_require_scope_with_wildcard(self):
        """Test require_scope when user has wildcard scope."""
        checker = require_scope("admin")

        user = {"scopes": ["*"]}
        result = await checker(user=user)

        assert result == user

    @pytest.mark.asyncio
    async def test_require_scope_has_scope(self):
        """Test require_scope when user has required scope."""
        checker = require_scope("read")

        user = {"scopes": ["read", "write"]}
        result = await checker(user=user)

        assert result == user

    @pytest.mark.asyncio
    async def test_require_scope_missing_scope(self):
        """Test require_scope when user lacks required scope."""
        checker = require_scope("admin")

        user = {"scopes": ["read", "write"]}

        with pytest.raises(HTTPException) as exc_info:
            await checker(user=user)

        assert exc_info.value.status_code == 403
        assert "admin" in exc_info.value.detail

    @pytest.mark.asyncio
    async def test_require_scope_empty_scopes(self):
        """Test require_scope when user has no scopes."""
        checker = require_scope("read")

        user = {"scopes": []}

        with pytest.raises(HTTPException) as exc_info:
            await checker(user=user)

        assert exc_info.value.status_code == 403


class TestAuthMiddleware:
    """Tests for AuthMiddleware class."""

    @pytest.mark.asyncio
    async def test_middleware_passes_through_http(self):
        """Test middleware passes through HTTP requests."""
        app_called = []

        async def mock_app(scope, receive, send):
            app_called.append(True)

        middleware = AuthMiddleware(mock_app)

        scope = {
            "type": "http",
            "path": "/test",
            "headers": []
        }

        await middleware(scope, None, None)

        assert len(app_called) == 1

    @pytest.mark.asyncio
    async def test_middleware_public_paths(self):
        """Test middleware handles public paths."""
        app_called = []

        async def mock_app(scope, receive, send):
            app_called.append(scope["path"])

        middleware = AuthMiddleware(mock_app)

        public_paths = ["/", "/health", "/docs", "/openapi.json", "/redoc"]

        for path in public_paths:
            app_called.clear()
            scope = {"type": "http", "path": path, "headers": []}
            await middleware(scope, None, None)
            assert path in app_called

    @pytest.mark.asyncio
    async def test_middleware_non_http(self):
        """Test middleware handles non-HTTP scopes."""
        app_called = []

        async def mock_app(scope, receive, send):
            app_called.append(True)

        middleware = AuthMiddleware(mock_app)

        scope = {"type": "websocket"}

        await middleware(scope, None, None)

        assert len(app_called) == 1

    @pytest.mark.asyncio
    async def test_middleware_logs_auth_headers(self):
        """Test middleware detects auth headers."""
        app_called = []

        async def mock_app(scope, receive, send):
            app_called.append(True)

        middleware = AuthMiddleware(mock_app)

        scope = {
            "type": "http",
            "path": "/api/test",
            "headers": [
                (b"x-api-key", b"test-key"),
                (b"authorization", b"Bearer token")
            ]
        }

        await middleware(scope, None, None)

        assert len(app_called) == 1


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
