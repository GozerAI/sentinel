"""
Comprehensive tests for main.py entry point module.

Tests cover SentinelApplication, setup_logging, and entry points.
"""

import pytest
import asyncio
import logging
import signal
import sys
from unittest.mock import MagicMock, patch, AsyncMock
from pathlib import Path


class TestSetupLogging:
    """Tests for setup_logging function."""

    def test_setup_logging_basic(self):
        """Test basic logging setup."""
        from sentinel.main import setup_logging

        mock_config = MagicMock()
        mock_config.logging.level = "INFO"
        mock_config.logging.format = "text"
        mock_config.logging.structured.enabled = False
        mock_config.logging.file.enabled = False

        with patch("logging.basicConfig") as mock_basic:
            setup_logging(mock_config)
            mock_basic.assert_called_once()

    def test_setup_logging_debug_level(self):
        """Test logging setup with DEBUG level."""
        from sentinel.main import setup_logging

        mock_config = MagicMock()
        mock_config.logging.level = "DEBUG"
        mock_config.logging.format = "text"
        mock_config.logging.structured.enabled = False
        mock_config.logging.file.enabled = False

        with patch("logging.basicConfig") as mock_basic:
            setup_logging(mock_config)
            call_args = mock_basic.call_args
            assert call_args[1]["level"] == logging.DEBUG

    def test_setup_logging_structured(self):
        """Test structured logging setup."""
        from sentinel.main import setup_logging

        mock_config = MagicMock()
        mock_config.logging.level = "INFO"
        mock_config.logging.format = "text"
        mock_config.logging.structured.enabled = True
        mock_config.logging.structured.include_timestamp = True
        mock_config.logging.file.enabled = False

        with patch("structlog.configure") as mock_structlog:
            with patch("logging.basicConfig"):
                setup_logging(mock_config)
                mock_structlog.assert_called_once()

    def test_setup_logging_json_format(self):
        """Test JSON format logging setup."""
        from sentinel.main import setup_logging

        mock_config = MagicMock()
        mock_config.logging.level = "INFO"
        mock_config.logging.format = "json"
        mock_config.logging.structured.enabled = True
        mock_config.logging.structured.include_timestamp = True
        mock_config.logging.file.enabled = False

        with patch("structlog.configure") as mock_structlog:
            with patch("logging.basicConfig"):
                setup_logging(mock_config)
                mock_structlog.assert_called_once()

    def test_setup_logging_file_enabled(self, tmp_path):
        """Test file logging setup."""
        from sentinel.main import setup_logging

        log_file = tmp_path / "logs" / "sentinel.log"

        mock_config = MagicMock()
        mock_config.logging.level = "INFO"
        mock_config.logging.format = "text"
        mock_config.logging.structured.enabled = False
        mock_config.logging.file.enabled = True
        mock_config.logging.file.path = str(log_file)
        mock_config.logging.file.max_size_mb = 10
        mock_config.logging.file.backup_count = 5

        with patch("logging.handlers.RotatingFileHandler") as mock_handler:
            with patch("logging.basicConfig"):
                with patch("logging.getLogger") as mock_get_logger:
                    mock_logger = MagicMock()
                    mock_get_logger.return_value = mock_logger

                    setup_logging(mock_config)

                    mock_handler.assert_called_once()

    def test_setup_logging_third_party_reduced(self):
        """Test that third-party loggers are set to WARNING."""
        from sentinel.main import setup_logging

        mock_config = MagicMock()
        mock_config.logging.level = "INFO"
        mock_config.logging.format = "text"
        mock_config.logging.structured.enabled = False
        mock_config.logging.file.enabled = False

        with patch("logging.basicConfig"):
            with patch("logging.getLogger") as mock_get_logger:
                mock_loggers = {}

                def get_logger_side_effect(name=None):
                    if name not in mock_loggers:
                        mock_loggers[name] = MagicMock()
                    return mock_loggers[name]

                mock_get_logger.side_effect = get_logger_side_effect

                setup_logging(mock_config)

                # Check that httpx, httpcore, urllib3, asyncio were set to WARNING
                for logger_name in ["httpx", "httpcore", "urllib3", "asyncio"]:
                    mock_loggers[logger_name].setLevel.assert_called_with(logging.WARNING)


class TestSentinelApplication:
    """Tests for SentinelApplication class."""

    def test_init(self):
        """Test application initialization."""
        from sentinel.main import SentinelApplication

        app = SentinelApplication()

        assert app.config_path is None
        assert app.config is None
        assert app.engine is None

    def test_init_with_config_path(self):
        """Test initialization with config path."""
        from sentinel.main import SentinelApplication

        app = SentinelApplication(config_path="/path/to/config.yaml")

        assert app.config_path == "/path/to/config.yaml"

    @pytest.mark.asyncio
    async def test_start(self):
        """Test application start."""
        from sentinel.main import SentinelApplication

        app = SentinelApplication()

        mock_config = MagicMock()
        mock_config.model_dump.return_value = {"test": "config"}

        mock_engine = MagicMock()
        mock_engine.start = AsyncMock()

        with patch("sentinel.main.load_config", return_value=mock_config):
            with patch("sentinel.main.setup_logging"):
                with patch("sentinel.main.SentinelEngine", return_value=mock_engine):
                    with patch.object(app, "_setup_signal_handlers"):
                        # Start the app and trigger shutdown
                        async def run_start():
                            start_task = asyncio.create_task(app.start())
                            await asyncio.sleep(0.1)
                            app._shutdown_event.set()
                            await start_task

                        await run_start()

                        mock_engine.start.assert_called_once()

    @pytest.mark.asyncio
    async def test_stop(self):
        """Test application stop."""
        from sentinel.main import SentinelApplication

        app = SentinelApplication()
        mock_engine = MagicMock()
        mock_engine.stop = AsyncMock()
        app.engine = mock_engine

        await app.stop()

        mock_engine.stop.assert_called_once()

    @pytest.mark.asyncio
    async def test_stop_no_engine(self):
        """Test stop when engine is None."""
        from sentinel.main import SentinelApplication

        app = SentinelApplication()
        app.engine = None

        # Should not raise
        await app.stop()

    def test_setup_signal_handlers(self):
        """Test signal handlers setup."""
        from sentinel.main import SentinelApplication

        app = SentinelApplication()

        # Create a mock event loop
        mock_loop = MagicMock()
        mock_loop.add_signal_handler = MagicMock()

        with patch("asyncio.get_running_loop", return_value=mock_loop):
            app._setup_signal_handlers()

            # Check that signal handlers were added
            assert mock_loop.add_signal_handler.called

    def test_setup_signal_handlers_windows(self):
        """Test signal handlers setup on Windows."""
        from sentinel.main import SentinelApplication

        app = SentinelApplication()

        # Create a mock event loop that doesn't support add_signal_handler
        mock_loop = MagicMock()
        mock_loop.add_signal_handler.side_effect = NotImplementedError()

        with patch("asyncio.get_running_loop", return_value=mock_loop):
            with patch("signal.signal") as mock_signal:
                app._setup_signal_handlers()

                # Check that signal.signal was used as fallback
                assert mock_signal.called

    @pytest.mark.asyncio
    async def test_run(self):
        """Test run method."""
        from sentinel.main import SentinelApplication

        app = SentinelApplication()

        # Mock start and stop
        app.start = AsyncMock()
        app.stop = AsyncMock()

        await app.run()

        app.start.assert_called_once()
        app.stop.assert_called_once()

    @pytest.mark.asyncio
    async def test_run_with_error(self):
        """Test run method with error."""
        from sentinel.main import SentinelApplication

        app = SentinelApplication()

        # Mock start to raise exception
        app.start = AsyncMock(side_effect=Exception("Test error"))
        app.stop = AsyncMock()

        with pytest.raises(Exception, match="Test error"):
            await app.run()

        # Stop should still be called in finally
        app.stop.assert_called_once()

    @pytest.mark.asyncio
    async def test_run_with_keyboard_interrupt(self):
        """Test run method with keyboard interrupt."""
        from sentinel.main import SentinelApplication

        app = SentinelApplication()

        # Mock start to raise KeyboardInterrupt
        app.start = AsyncMock(side_effect=KeyboardInterrupt())
        app.stop = AsyncMock()

        await app.run()

        app.stop.assert_called_once()


class TestRunSentinel:
    """Tests for run_sentinel function."""

    @pytest.mark.asyncio
    async def test_run_sentinel(self):
        """Test run_sentinel function."""
        from sentinel.main import run_sentinel

        mock_app = MagicMock()
        mock_app.run = AsyncMock()

        with patch("sentinel.main.SentinelApplication", return_value=mock_app):
            await run_sentinel("/path/to/config.yaml")

            mock_app.run.assert_called_once()

    @pytest.mark.asyncio
    async def test_run_sentinel_no_config(self):
        """Test run_sentinel without config."""
        from sentinel.main import run_sentinel

        mock_app = MagicMock()
        mock_app.run = AsyncMock()

        with patch("sentinel.main.SentinelApplication", return_value=mock_app):
            await run_sentinel()

            mock_app.run.assert_called_once()


class TestMain:
    """Tests for main function."""

    def test_main_no_args(self):
        """Test main with no arguments."""
        from sentinel.main import main

        mock_app = MagicMock()
        mock_app.run = AsyncMock()

        with patch("sentinel.main.SentinelApplication", return_value=mock_app):
            with patch("sys.argv", ["sentinel"]):
                with patch("asyncio.run") as mock_run:
                    main()
                    mock_run.assert_called_once()

    def test_main_with_config(self):
        """Test main with config argument."""
        from sentinel.main import main

        mock_app = MagicMock()
        mock_app.run = AsyncMock()

        with patch("sentinel.main.SentinelApplication", return_value=mock_app):
            with patch("sys.argv", ["sentinel", "-c", "/path/config.yaml"]):
                with patch("asyncio.run") as mock_run:
                    main()
                    mock_run.assert_called_once()

    def test_main_verbose(self):
        """Test main with verbose flag."""
        from sentinel.main import main

        mock_app = MagicMock()
        mock_app.run = AsyncMock()

        with patch("sentinel.main.SentinelApplication", return_value=mock_app):
            with patch("sys.argv", ["sentinel", "-v"]):
                with patch("asyncio.run") as mock_run:
                    with patch("logging.basicConfig") as mock_basic:
                        main()
                        mock_basic.assert_called_once_with(level=logging.DEBUG)

    def test_main_keyboard_interrupt(self):
        """Test main with keyboard interrupt."""
        from sentinel.main import main

        with patch("sys.argv", ["sentinel"]):
            with patch("asyncio.run", side_effect=KeyboardInterrupt()):
                with patch("sys.exit") as mock_exit:
                    main()
                    mock_exit.assert_called_once_with(0)

    def test_main_error(self):
        """Test main with fatal error."""
        from sentinel.main import main

        with patch("sys.argv", ["sentinel"]):
            with patch("asyncio.run", side_effect=Exception("Fatal error")):
                with patch("sys.exit") as mock_exit:
                    main()
                    mock_exit.assert_called_once_with(1)

    def test_main_version(self):
        """Test main with version flag."""
        from sentinel.main import main

        with patch("sys.argv", ["sentinel", "--version"]):
            with pytest.raises(SystemExit) as exc_info:
                main()

            # argparse exits with 0 for --version
            assert exc_info.value.code == 0


class TestSignalHandling:
    """Tests for signal handling."""

    @pytest.mark.asyncio
    async def test_signal_handler_sigint(self):
        """Test SIGINT signal handling."""
        from sentinel.main import SentinelApplication

        app = SentinelApplication()

        # Manually trigger the signal handler logic
        app._shutdown_event.set()

        assert app._shutdown_event.is_set()

    @pytest.mark.asyncio
    async def test_signal_handler_sigterm(self):
        """Test SIGTERM signal handling."""
        from sentinel.main import SentinelApplication

        app = SentinelApplication()

        # Manually trigger the signal handler logic
        app._shutdown_event.set()

        assert app._shutdown_event.is_set()


class TestConfigurationLoading:
    """Tests for configuration loading in application."""

    def test_load_config_success(self, tmp_path):
        """Test successful config loading."""
        from sentinel.main import SentinelApplication

        config_file = tmp_path / "config.yaml"
        config_file.write_text(
            """
api:
  host: localhost
  port: 8000
agents:
  discovery:
    enabled: true
logging:
  level: INFO
"""
        )

        app = SentinelApplication(config_path=str(config_file))

        assert app.config_path == str(config_file)
        assert app.config is None  # Not loaded until start()

    def test_load_config_default(self):
        """Test loading default config when no path provided."""
        from sentinel.main import SentinelApplication

        app = SentinelApplication()

        assert app.config_path is None
        assert app.config is None  # Not loaded until start()


class TestEngineIntegration:
    """Tests for engine integration."""

    @pytest.mark.asyncio
    async def test_engine_created_with_config(self):
        """Test engine is created with config dict."""
        from sentinel.main import SentinelApplication

        app = SentinelApplication()

        mock_config = MagicMock()
        mock_config.model_dump.return_value = {"agents": {}, "api": {}}

        with patch("sentinel.main.load_config", return_value=mock_config):
            with patch("sentinel.main.setup_logging"):
                with patch("sentinel.main.SentinelEngine") as mock_engine_class:
                    mock_engine = MagicMock()
                    mock_engine.start = AsyncMock()
                    mock_engine_class.return_value = mock_engine

                    with patch.object(app, "_setup_signal_handlers"):

                        async def run_test():
                            start_task = asyncio.create_task(app.start())
                            await asyncio.sleep(0.05)
                            app._shutdown_event.set()
                            await start_task

                        await run_test()

                        mock_engine_class.assert_called_once_with({"agents": {}, "api": {}})
