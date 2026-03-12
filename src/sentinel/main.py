"""
Sentinel Security Platform - Main Entry Point.

This module provides the main entry point for running the Sentinel platform.
It handles configuration loading, signal handling, and graceful shutdown.
"""

import asyncio
import logging
import signal
import sys
from pathlib import Path
from typing import Optional

import structlog

from sentinel.core.config import load_config, SentinelConfig
from sentinel.core.engine import SentinelEngine


# =============================================================================
# Logging Setup
# =============================================================================


def setup_logging(config: SentinelConfig) -> None:
    """
    Configure logging based on configuration.

    Args:
        config: Sentinel configuration
    """
    log_config = config.logging

    # Determine log level
    level = getattr(logging, log_config.level.upper(), logging.INFO)

    # Configure structlog for structured logging
    if log_config.structured.enabled:
        processors = [
            structlog.contextvars.merge_contextvars,
            structlog.processors.add_log_level,
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
        ]

        if log_config.structured.include_timestamp:
            processors.insert(0, structlog.processors.TimeStamper(fmt="iso"))

        if log_config.format == "json":
            processors.append(structlog.processors.JSONRenderer())
        else:
            processors.append(structlog.dev.ConsoleRenderer())

        structlog.configure(
            processors=processors,
            wrapper_class=structlog.make_filtering_bound_logger(level),
            context_class=dict,
            logger_factory=structlog.PrintLoggerFactory(),
            cache_logger_on_first_use=True,
        )

    # Configure standard logging
    logging.basicConfig(
        level=level,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    # Set up file logging if enabled
    if log_config.file.enabled:
        log_path = Path(log_config.file.path)
        log_path.parent.mkdir(parents=True, exist_ok=True)

        file_handler = logging.handlers.RotatingFileHandler(
            log_path,
            maxBytes=log_config.file.max_size_mb * 1024 * 1024,
            backupCount=log_config.file.backup_count,
        )
        file_handler.setLevel(level)
        file_handler.setFormatter(
            logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
        )
        logging.getLogger().addHandler(file_handler)

    # Reduce noise from third-party libraries
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("asyncio").setLevel(logging.WARNING)


# =============================================================================
# Main Application
# =============================================================================


class SentinelApplication:
    """
    Main Sentinel application class.

    Handles initialization, signal handling, and lifecycle management.
    """

    def __init__(self, config_path: Optional[str] = None):
        """
        Initialize the Sentinel application.

        Args:
            config_path: Optional path to configuration file
        """
        self.config_path = config_path
        self.config: Optional[SentinelConfig] = None
        self.engine: Optional[SentinelEngine] = None
        self._shutdown_event = asyncio.Event()
        self._logger = logging.getLogger(__name__)

    async def start(self) -> None:
        """Start the Sentinel application."""
        # Load configuration
        self.config = load_config(self.config_path)

        # Setup logging
        setup_logging(self.config)

        self._logger.info("=" * 60)
        self._logger.info("Sentinel Security Platform")
        self._logger.info("=" * 60)
        self._logger.info(f"Configuration loaded from: {self.config_path or 'default'}")

        # Create engine with config dict
        config_dict = self.config.model_dump()
        self.engine = SentinelEngine(config_dict)

        # Setup signal handlers
        self._setup_signal_handlers()

        # Start engine
        await self.engine.start()

        self._logger.info("Sentinel is now running. Press Ctrl+C to stop.")

        # Wait for shutdown signal
        await self._shutdown_event.wait()

    async def stop(self) -> None:
        """Stop the Sentinel application gracefully."""
        self._logger.info("Initiating shutdown...")

        if self.engine:
            await self.engine.stop()

        self._logger.info("Sentinel has stopped.")

    def _setup_signal_handlers(self) -> None:
        """Setup signal handlers for graceful shutdown."""
        loop = asyncio.get_running_loop()

        def signal_handler(sig: signal.Signals) -> None:
            self._logger.info(f"Received signal {sig.name}, shutting down...")
            self._shutdown_event.set()

        # Handle SIGINT (Ctrl+C) and SIGTERM
        for sig in (signal.SIGINT, signal.SIGTERM):
            try:
                loop.add_signal_handler(sig, lambda s=sig: signal_handler(s))
            except NotImplementedError:
                # Windows doesn't support add_signal_handler
                signal.signal(sig, lambda s, f, sig=sig: signal_handler(sig))

    async def run(self) -> None:
        """Run the application with proper lifecycle management."""
        try:
            await self.start()
        except KeyboardInterrupt:
            self._logger.info("Received keyboard interrupt")
        except Exception as e:
            self._logger.error(f"Fatal error: {e}")
            raise
        finally:
            await self.stop()


# =============================================================================
# Entry Points
# =============================================================================


async def run_sentinel(config_path: Optional[str] = None) -> None:
    """
    Run Sentinel with the specified configuration.

    Args:
        config_path: Optional path to configuration file
    """
    app = SentinelApplication(config_path)
    await app.run()


def main() -> None:
    """Main entry point for the Sentinel application."""
    import argparse

    parser = argparse.ArgumentParser(
        description="Sentinel Security Platform - AI-Native Zero-Trust Security"
    )
    parser.add_argument("-c", "--config", type=str, help="Path to configuration file", default=None)
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    parser.add_argument("--version", action="version", version="Sentinel 0.1.0")

    args = parser.parse_args()

    if args.verbose:
        logging.basicConfig(level=logging.DEBUG)

    try:
        asyncio.run(run_sentinel(args.config))
    except KeyboardInterrupt:
        print("\nShutdown complete.")
        sys.exit(0)
    except Exception as e:
        print(f"Fatal error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
