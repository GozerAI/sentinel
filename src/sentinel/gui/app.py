"""
Sentinel Desktop Application Entry Point.

This module provides the main application class and entry point for the
Sentinel desktop GUI.
"""
import sys
import asyncio
import logging
import threading
from typing import Optional
from pathlib import Path

from PySide6.QtWidgets import QApplication, QMessageBox
from PySide6.QtCore import QTimer, QThread, Signal, QObject
from PySide6.QtGui import QIcon

from sentinel.gui.main_window import MainWindow
from sentinel.core.config import load_config
from sentinel.core.engine import SentinelEngine

logger = logging.getLogger(__name__)


class EngineWorker(QObject):
    """Worker to run the Sentinel engine in a separate thread."""

    started = Signal()
    stopped = Signal()
    error = Signal(str)
    status_update = Signal(str)

    def __init__(self, engine: SentinelEngine):
        super().__init__()
        self.engine = engine
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._running = False

    def start_engine(self) -> None:
        """Start the engine in this thread's event loop."""
        try:
            self._loop = asyncio.new_event_loop()
            asyncio.set_event_loop(self._loop)
            self._running = True

            self.status_update.emit("Starting engine...")

            # Run the engine
            self._loop.run_until_complete(self._run_engine())

        except Exception as e:
            logger.error(f"Engine worker error: {e}")
            self.error.emit(str(e))
        finally:
            if self._loop:
                self._loop.close()

    async def _run_engine(self) -> None:
        """Run the engine until stopped."""
        try:
            await self.engine.start()
            self.started.emit()
            self.status_update.emit("Engine running")

            # Keep running until stopped
            while self._running and self.engine.is_running:
                await asyncio.sleep(0.5)

        except Exception as e:
            logger.error(f"Engine run error: {e}")
            self.error.emit(str(e))
        finally:
            try:
                await self.engine.stop()
            except Exception as e:
                logger.error(f"Engine stop error: {e}")
            self.stopped.emit()

    def stop_engine(self) -> None:
        """Signal the engine to stop."""
        self._running = False


class SentinelApp:
    """
    Main Sentinel desktop application.

    This class manages the Qt application lifecycle and integrates
    with the Sentinel engine for real-time monitoring.

    Example:
        ```python
        app = SentinelApp()
        sys.exit(app.run())
        ```
    """

    def __init__(self, config_path: Optional[str] = None):
        """
        Initialize the Sentinel application.

        Args:
            config_path: Optional path to configuration file
        """
        self.config_path = config_path
        self.config: Optional[dict] = None
        self.engine: Optional[SentinelEngine] = None
        self.qt_app: Optional[QApplication] = None
        self.main_window: Optional[MainWindow] = None
        self._update_timer: Optional[QTimer] = None
        self._engine_thread: Optional[QThread] = None
        self._engine_worker: Optional[EngineWorker] = None

    def _setup_logging(self) -> None:
        """Configure logging for the application."""
        log_level = self.config.get("logging", {}).get("level", "INFO")
        logging.basicConfig(
            level=getattr(logging, log_level.upper(), logging.INFO),
            format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
        )

    def _load_config(self) -> None:
        """Load configuration from file or defaults."""
        if self.config_path and Path(self.config_path).exists():
            self.config = load_config(self.config_path)
        else:
            # Use default configuration for GUI mode
            self.config = {
                "agents": {
                    "discovery": {"enabled": True},
                    "guardian": {"enabled": True},
                    "planner": {"enabled": True},
                    "optimizer": {"enabled": True},
                    "healer": {"enabled": True},
                },
                "api": {
                    "enabled": True,
                    "host": "127.0.0.1",
                    "port": 8080,
                },
                "logging": {
                    "level": "INFO"
                }
            }

    def _create_engine(self) -> None:
        """Create the Sentinel engine."""
        self.engine = SentinelEngine(self.config)

    def _create_qt_app(self) -> None:
        """Create the Qt application."""
        self.qt_app = QApplication(sys.argv)
        self.qt_app.setApplicationName("Sentinel Network Assistant")
        self.qt_app.setApplicationVersion("0.1.0")
        self.qt_app.setOrganizationName("Sentinel")

        # Set application style
        self.qt_app.setStyle("Fusion")

        # Set application icon
        icon_path = Path(__file__).parent.parent / "assets" / "sentinel.ico"
        if icon_path.exists():
            self.qt_app.setWindowIcon(QIcon(str(icon_path)))

    def _create_main_window(self) -> None:
        """Create the main application window."""
        self.main_window = MainWindow(self.engine, self.config)
        self.main_window.show()

    def _setup_update_timer(self) -> None:
        """Set up periodic UI updates."""
        self._update_timer = QTimer()
        self._update_timer.timeout.connect(self._update_ui)
        self._update_timer.start(1000)  # Update every second

    def _update_ui(self) -> None:
        """Update UI with latest data."""
        if self.main_window:
            self.main_window.refresh_data()

    def _start_engine_thread(self) -> None:
        """Start the engine in a background thread."""
        if not self.engine:
            return

        # Create worker and thread
        self._engine_thread = QThread()
        self._engine_worker = EngineWorker(self.engine)
        self._engine_worker.moveToThread(self._engine_thread)

        # Connect signals
        self._engine_thread.started.connect(self._engine_worker.start_engine)
        self._engine_worker.started.connect(self._on_engine_started)
        self._engine_worker.stopped.connect(self._on_engine_stopped)
        self._engine_worker.error.connect(self._on_engine_error)
        self._engine_worker.status_update.connect(self._on_status_update)

        # Start the thread
        self._engine_thread.start()
        logger.info("Engine thread started")

    def _stop_engine_thread(self) -> None:
        """Stop the engine thread gracefully."""
        if self._engine_worker:
            self._engine_worker.stop_engine()

        if self._engine_thread:
            self._engine_thread.quit()
            self._engine_thread.wait(5000)  # Wait up to 5 seconds
            logger.info("Engine thread stopped")

    def _on_engine_started(self) -> None:
        """Handle engine started signal."""
        logger.info("Sentinel engine started successfully")
        if self.main_window:
            self.main_window.status_bar.showMessage("Engine running")
            self.main_window.refresh_data()

    def _on_engine_stopped(self) -> None:
        """Handle engine stopped signal."""
        logger.info("Sentinel engine stopped")
        if self.main_window:
            self.main_window.status_bar.showMessage("Engine stopped")

    def _on_engine_error(self, error: str) -> None:
        """Handle engine error signal."""
        logger.error(f"Engine error: {error}")
        if self.main_window:
            self.main_window.status_bar.showMessage(f"Engine error: {error}")
            QMessageBox.warning(
                self.main_window,
                "Engine Error",
                f"The Sentinel engine encountered an error:\n{error}"
            )

    def _on_status_update(self, status: str) -> None:
        """Handle engine status update signal."""
        if self.main_window:
            self.main_window.status_bar.showMessage(status)

    def run(self) -> int:
        """
        Run the application.

        Returns:
            Exit code
        """
        try:
            # Initialize
            self._load_config()
            self._setup_logging()
            self._create_engine()
            self._create_qt_app()
            self._create_main_window()
            self._setup_update_timer()

            # Start engine in background thread
            QTimer.singleShot(100, self._start_engine_thread)

            # Run Qt event loop
            result = self.qt_app.exec()

            # Cleanup
            self._update_timer.stop()
            self._stop_engine_thread()

            return result

        except Exception as e:
            logger.error(f"Application error: {e}")
            return 1


def main():
    """Entry point for the desktop application."""
    import argparse

    parser = argparse.ArgumentParser(description="Sentinel Desktop Application")
    parser.add_argument(
        "-c", "--config",
        help="Path to configuration file",
        default=None
    )
    args = parser.parse_args()

    app = SentinelApp(config_path=args.config)
    sys.exit(app.run())


if __name__ == "__main__":
    main()
