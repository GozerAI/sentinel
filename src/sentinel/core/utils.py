"""
Utility functions for the Sentinel platform.

Provides common helpers used across the codebase:
- Time utilities
- Retry logic with exponential backoff
- Input validation
- Security helpers
"""
import asyncio
import functools
import ipaddress
import logging
import random
import re
from datetime import datetime, timezone
from typing import Any, Callable, Optional, TypeVar, Union

logger = logging.getLogger(__name__)

T = TypeVar("T")


# =============================================================================
# Time Utilities
# =============================================================================


def utc_now() -> datetime:
    """
    Get the current UTC time as a timezone-aware datetime.

    This replaces deprecated datetime.utcnow() calls.

    Returns:
        Timezone-aware datetime in UTC
    """
    return datetime.now(timezone.utc)


def utc_now_iso() -> str:
    """
    Get the current UTC time as an ISO format string.

    Returns:
        ISO 8601 formatted UTC timestamp
    """
    return utc_now().isoformat()


# =============================================================================
# Retry Logic with Exponential Backoff
# =============================================================================


class RetryError(Exception):
    """Raised when all retry attempts are exhausted."""

    def __init__(self, message: str, last_exception: Optional[Exception] = None):
        super().__init__(message)
        self.last_exception = last_exception


async def retry_async(
    func: Callable[..., T],
    *args,
    max_attempts: int = 3,
    base_delay: float = 1.0,
    max_delay: float = 60.0,
    exponential_base: float = 2.0,
    jitter: bool = True,
    retryable_exceptions: tuple = (Exception,),
    on_retry: Optional[Callable[[int, Exception, float], None]] = None,
    **kwargs
) -> T:
    """
    Retry an async function with exponential backoff.

    Args:
        func: Async function to retry
        *args: Arguments to pass to func
        max_attempts: Maximum number of attempts (default: 3)
        base_delay: Initial delay in seconds (default: 1.0)
        max_delay: Maximum delay cap in seconds (default: 60.0)
        exponential_base: Base for exponential backoff (default: 2.0)
        jitter: Add random jitter to delay (default: True)
        retryable_exceptions: Tuple of exceptions to retry on (default: (Exception,))
        on_retry: Optional callback(attempt, exception, delay) called before retry
        **kwargs: Keyword arguments to pass to func

    Returns:
        Result from func

    Raises:
        RetryError: If all attempts are exhausted

    Example:
        ```python
        result = await retry_async(
            fetch_data,
            url,
            max_attempts=5,
            retryable_exceptions=(ConnectionError, TimeoutError)
        )
        ```
    """
    last_exception = None

    for attempt in range(1, max_attempts + 1):
        try:
            return await func(*args, **kwargs)
        except retryable_exceptions as e:
            last_exception = e

            if attempt == max_attempts:
                logger.warning(
                    f"Retry exhausted after {max_attempts} attempts: {e}"
                )
                break

            # Calculate delay with exponential backoff
            delay = min(base_delay * (exponential_base ** (attempt - 1)), max_delay)

            # Add jitter (±25% of delay)
            if jitter:
                delay = delay * (0.75 + random.random() * 0.5)

            logger.debug(
                f"Attempt {attempt}/{max_attempts} failed: {e}. "
                f"Retrying in {delay:.2f}s..."
            )

            if on_retry:
                on_retry(attempt, e, delay)

            await asyncio.sleep(delay)

    raise RetryError(
        f"All {max_attempts} attempts failed",
        last_exception=last_exception
    )


def retry(
    max_attempts: int = 3,
    base_delay: float = 1.0,
    max_delay: float = 60.0,
    exponential_base: float = 2.0,
    jitter: bool = True,
    retryable_exceptions: tuple = (Exception,),
):
    """
    Decorator for retry with exponential backoff.

    Args:
        max_attempts: Maximum number of attempts
        base_delay: Initial delay in seconds
        max_delay: Maximum delay cap in seconds
        exponential_base: Base for exponential backoff
        jitter: Add random jitter to delay
        retryable_exceptions: Tuple of exceptions to retry on

    Example:
        ```python
        @retry(max_attempts=3, retryable_exceptions=(ConnectionError,))
        async def fetch_data(url):
            ...
        ```
    """
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        async def wrapper(*args, **kwargs):
            return await retry_async(
                func,
                *args,
                max_attempts=max_attempts,
                base_delay=base_delay,
                max_delay=max_delay,
                exponential_base=exponential_base,
                jitter=jitter,
                retryable_exceptions=retryable_exceptions,
                **kwargs
            )
        return wrapper
    return decorator


# =============================================================================
# Input Validation
# =============================================================================


def validate_ip_address(ip: str) -> bool:
    """
    Validate an IP address (IPv4 or IPv6).

    Args:
        ip: IP address string to validate

    Returns:
        True if valid, False otherwise
    """
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def validate_cidr(cidr: str) -> bool:
    """
    Validate a CIDR notation network.

    Args:
        cidr: CIDR notation string (e.g., "192.168.1.0/24")

    Returns:
        True if valid, False otherwise
    """
    try:
        ipaddress.ip_network(cidr, strict=False)
        return True
    except ValueError:
        return False


def validate_port(port: int) -> bool:
    """
    Validate a port number.

    Args:
        port: Port number to validate

    Returns:
        True if valid (1-65535), False otherwise
    """
    return isinstance(port, int) and 1 <= port <= 65535


def validate_vlan_id(vlan_id: int) -> bool:
    """
    Validate a VLAN ID.

    Args:
        vlan_id: VLAN ID to validate

    Returns:
        True if valid (1-4094), False otherwise
    """
    return isinstance(vlan_id, int) and 1 <= vlan_id <= 4094


def validate_mac_address(mac: str) -> bool:
    """
    Validate a MAC address.

    Args:
        mac: MAC address string to validate

    Returns:
        True if valid, False otherwise
    """
    # Accept formats: AA:BB:CC:DD:EE:FF, AA-BB-CC-DD-EE-FF, AABBCCDDEEFF
    mac_patterns = [
        r'^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$',  # Colon separated
        r'^([0-9A-Fa-f]{2}-){5}[0-9A-Fa-f]{2}$',  # Hyphen separated
        r'^[0-9A-Fa-f]{12}$',  # No separator
    ]
    return any(re.match(pattern, mac) for pattern in mac_patterns)


def validate_hostname(hostname: str) -> bool:
    """
    Validate a hostname.

    Args:
        hostname: Hostname string to validate

    Returns:
        True if valid, False otherwise
    """
    if not hostname or len(hostname) > 253:
        return False

    # Remove trailing dot if present (FQDN)
    if hostname.endswith('.'):
        hostname = hostname[:-1]

    # Each label must be 1-63 characters
    labels = hostname.split('.')
    label_pattern = re.compile(r'^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$')

    return all(label_pattern.match(label) for label in labels)


def validate_url(url: str) -> bool:
    """
    Validate a URL.

    Args:
        url: URL string to validate

    Returns:
        True if valid, False otherwise
    """
    url_pattern = re.compile(
        r'^https?://'  # http:// or https://
        r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,6}\.?|'  # domain
        r'localhost|'  # localhost
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'  # or ip
        r'(?::\d+)?'  # optional port
        r'(?:/?|[/?]\S+)$', re.IGNORECASE
    )
    return bool(url_pattern.match(url))


# =============================================================================
# Security Helpers
# =============================================================================


def mask_sensitive(value: str, show_chars: int = 4) -> str:
    """
    Mask a sensitive string, showing only the last few characters.

    Args:
        value: String to mask
        show_chars: Number of characters to show at the end (default: 4)

    Returns:
        Masked string (e.g., "****1234")
    """
    if not value:
        return ""
    if len(value) <= show_chars:
        return "*" * len(value)
    return "*" * (len(value) - show_chars) + value[-show_chars:]


def mask_password(password: str) -> str:
    """
    Mask a password for logging.

    Args:
        password: Password to mask

    Returns:
        Masked string (e.g., "********")
    """
    if not password:
        return ""
    return "*" * min(len(password), 8)


def safe_log_dict(data: dict, sensitive_keys: set = None) -> dict:
    """
    Create a safe copy of a dict for logging, masking sensitive values.

    Args:
        data: Dictionary to sanitize
        sensitive_keys: Set of key names to mask (default: common sensitive keys)

    Returns:
        Sanitized copy of the dictionary
    """
    if sensitive_keys is None:
        sensitive_keys = {
            "password", "api_key", "token", "secret", "credential",
            "private_key", "ssh_key", "auth", "authorization",
            "token_value", "api_secret", "client_secret",
        }

    def _sanitize(obj: Any, depth: int = 0) -> Any:
        if depth > 10:  # Prevent infinite recursion
            return "..."

        if isinstance(obj, dict):
            return {
                k: (mask_sensitive(str(v)) if k.lower() in sensitive_keys else _sanitize(v, depth + 1))
                for k, v in obj.items()
            }
        elif isinstance(obj, (list, tuple)):
            return type(obj)(_sanitize(item, depth + 1) for item in obj)
        else:
            return obj

    return _sanitize(data)


# =============================================================================
# Connection/Integration Helpers
# =============================================================================


class ConnectionState:
    """Track connection state with backoff for reconnection attempts."""

    def __init__(
        self,
        name: str,
        max_failures: int = 5,
        backoff_base: float = 5.0,
        backoff_max: float = 300.0
    ):
        """
        Initialize connection state tracker.

        Args:
            name: Connection name for logging
            max_failures: Max failures before marking unhealthy
            backoff_base: Base delay for reconnection backoff
            backoff_max: Maximum backoff delay
        """
        self.name = name
        self.max_failures = max_failures
        self.backoff_base = backoff_base
        self.backoff_max = backoff_max

        self._connected = False
        self._consecutive_failures = 0
        self._last_failure: Optional[datetime] = None
        self._last_success: Optional[datetime] = None

    @property
    def connected(self) -> bool:
        return self._connected

    @property
    def healthy(self) -> bool:
        return self._consecutive_failures < self.max_failures

    @property
    def next_retry_delay(self) -> float:
        """Calculate next retry delay with exponential backoff."""
        if self._consecutive_failures == 0:
            return 0
        delay = min(
            self.backoff_base * (2 ** (self._consecutive_failures - 1)),
            self.backoff_max
        )
        # Add jitter
        return delay * (0.75 + random.random() * 0.5)

    def record_success(self) -> None:
        """Record a successful connection/operation."""
        self._connected = True
        self._consecutive_failures = 0
        self._last_success = utc_now()
        logger.debug(f"{self.name}: Connection successful")

    def record_failure(self, error: Optional[Exception] = None) -> None:
        """Record a connection/operation failure."""
        self._connected = False
        self._consecutive_failures += 1
        self._last_failure = utc_now()

        if error:
            logger.warning(
                f"{self.name}: Connection failure #{self._consecutive_failures}: {error}"
            )
        else:
            logger.warning(
                f"{self.name}: Connection failure #{self._consecutive_failures}"
            )

        if not self.healthy:
            logger.error(
                f"{self.name}: Marked unhealthy after {self._consecutive_failures} failures"
            )

    def to_dict(self) -> dict:
        """Get state as dictionary."""
        return {
            "name": self.name,
            "connected": self._connected,
            "healthy": self.healthy,
            "consecutive_failures": self._consecutive_failures,
            "last_success": self._last_success.isoformat() if self._last_success else None,
            "last_failure": self._last_failure.isoformat() if self._last_failure else None,
            "next_retry_delay": self.next_retry_delay,
        }
