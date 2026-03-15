"""
Sentinel Main Window.

This module provides the main application window with dashboard,
device management, security monitoring, and settings panels.
"""
import logging
from typing import Optional, TYPE_CHECKING

from PySide6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QStackedWidget, QListWidget, QListWidgetItem,
    QLabel, QFrame, QPushButton, QStatusBar,
    QSplitter, QTreeWidget, QTreeWidgetItem,
    QTableWidget, QTableWidgetItem, QHeaderView,
    QGroupBox, QProgressBar, QSizePolicy,
    QSystemTrayIcon, QMenu, QMessageBox,
)
from PySide6.QtCore import Qt, QSize, Signal, Slot
from PySide6.QtGui import QIcon, QAction, QFont, QColor

if TYPE_CHECKING:
    from sentinel.core.engine import SentinelEngine

logger = logging.getLogger(__name__)


class SidebarButton(QPushButton):
    """Custom sidebar navigation button."""

    def __init__(self, text: str, icon_char: str = "", parent=None):
        super().__init__(text, parent)
        self.setCheckable(True)
        self.setMinimumHeight(50)
        self.setStyleSheet("""
            QPushButton {
                text-align: left;
                padding-left: 20px;
                border: none;
                background-color: #2d2d2d;
                color: #ffffff;
                font-size: 14px;
            }
            QPushButton:hover {
                background-color: #3d3d3d;
            }
            QPushButton:checked {
                background-color: #0078d4;
            }
        """)


class StatsCard(QFrame):
    """Card widget for displaying statistics."""

    def __init__(self, title: str, value: str = "0", parent=None):
        super().__init__(parent)
        self.setFrameStyle(QFrame.Shape.StyledPanel)
        self.setStyleSheet("""
            StatsCard {
                background-color: #2d2d2d;
                border-radius: 8px;
                padding: 15px;
            }
        """)

        layout = QVBoxLayout(self)

        self.title_label = QLabel(title)
        self.title_label.setStyleSheet("color: #888888; font-size: 12px;")
        layout.addWidget(self.title_label)

        self.value_label = QLabel(value)
        self.value_label.setStyleSheet("color: #ffffff; font-size: 28px; font-weight: bold;")
        layout.addWidget(self.value_label)

    def set_value(self, value: str) -> None:
        """Update the displayed value."""
        self.value_label.setText(value)


class DashboardPage(QWidget):
    """Dashboard overview page."""

    def __init__(self, engine: "SentinelEngine", parent=None):
        super().__init__(parent)
        self.engine = engine
        self._last_event_count = 0
        self._setup_ui()

    def _setup_ui(self) -> None:
        """Set up the dashboard UI."""
        layout = QVBoxLayout(self)
        layout.setSpacing(20)

        # Header
        header = QLabel("Dashboard")
        header.setStyleSheet("font-size: 24px; font-weight: bold; color: #ffffff;")
        layout.addWidget(header)

        # Stats cards row
        cards_layout = QHBoxLayout()

        self.devices_card = StatsCard("Devices Online", "0")
        cards_layout.addWidget(self.devices_card)

        self.agents_card = StatsCard("Active Agents", "0")
        cards_layout.addWidget(self.agents_card)

        self.alerts_card = StatsCard("Security Alerts", "0")
        cards_layout.addWidget(self.alerts_card)

        self.uptime_card = StatsCard("Uptime", "0s")
        cards_layout.addWidget(self.uptime_card)

        layout.addLayout(cards_layout)

        # Status section
        status_group = QGroupBox("System Status")
        status_group.setStyleSheet("""
            QGroupBox {
                color: #ffffff;
                font-weight: bold;
                border: 1px solid #3d3d3d;
                border-radius: 5px;
                margin-top: 10px;
                padding-top: 10px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px;
            }
        """)
        status_layout = QVBoxLayout(status_group)

        # Create a grid for status items
        status_grid = QHBoxLayout()

        # Left column - engine status
        left_status = QVBoxLayout()
        self.engine_status = QLabel("Engine: Starting...")
        self.engine_status.setStyleSheet("color: #ffa500;")
        left_status.addWidget(self.engine_status)

        self.cto_status = QLabel("CTO Mode: Checking...")
        self.cto_status.setStyleSheet("color: #888888;")
        left_status.addWidget(self.cto_status)

        self.api_status = QLabel("API: Not Started")
        self.api_status.setStyleSheet("color: #888888;")
        left_status.addWidget(self.api_status)

        status_grid.addLayout(left_status)

        # Right column - component status
        right_status = QVBoxLayout()

        self.event_bus_status = QLabel("Event Bus: Starting...")
        self.event_bus_status.setStyleSheet("color: #888888;")
        right_status.addWidget(self.event_bus_status)

        self.learning_status = QLabel("Learning System: Starting...")
        self.learning_status.setStyleSheet("color: #888888;")
        right_status.addWidget(self.learning_status)

        self.integrations_status = QLabel("Integrations: 0 connected")
        self.integrations_status.setStyleSheet("color: #888888;")
        right_status.addWidget(self.integrations_status)

        status_grid.addLayout(right_status)
        status_layout.addLayout(status_grid)

        layout.addWidget(status_group)

        # Recent events
        events_group = QGroupBox("Recent Events")
        events_group.setStyleSheet("""
            QGroupBox {
                color: #ffffff;
                font-weight: bold;
                border: 1px solid #3d3d3d;
                border-radius: 5px;
                margin-top: 10px;
                padding-top: 10px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px;
            }
        """)
        events_layout = QVBoxLayout(events_group)

        self.events_table = QTableWidget(0, 4)
        self.events_table.setHorizontalHeaderLabels(["Time", "Type", "Source", "Message"])
        self.events_table.horizontalHeader().setStretchLastSection(True)
        self.events_table.setStyleSheet("""
            QTableWidget {
                background-color: #2d2d2d;
                color: #ffffff;
                gridline-color: #3d3d3d;
            }
            QHeaderView::section {
                background-color: #1d1d1d;
                color: #ffffff;
                padding: 5px;
                border: none;
            }
        """)
        events_layout.addWidget(self.events_table)

        layout.addWidget(events_group)
        layout.addStretch()

    def refresh(self) -> None:
        """Refresh dashboard data."""
        if not self.engine:
            return

        # Update stats
        try:
            discovery = self.engine.get_agent("discovery")
            if discovery and hasattr(discovery, '_inventory'):
                device_count = len(discovery._inventory.devices)
                self.devices_card.set_value(str(device_count))

            agent_count = len(self.engine._agents)
            self.agents_card.set_value(str(agent_count))

            # Uptime
            uptime = int(self.engine.uptime_seconds)
            if uptime < 60:
                uptime_str = f"{uptime}s"
            elif uptime < 3600:
                uptime_str = f"{uptime // 60}m {uptime % 60}s"
            else:
                hours = uptime // 3600
                mins = (uptime % 3600) // 60
                uptime_str = f"{hours}h {mins}m"
            self.uptime_card.set_value(uptime_str)

            # Engine status
            if self.engine.is_running:
                self.engine_status.setText("Engine: Running")
                self.engine_status.setStyleSheet("color: #00ff00;")
            else:
                self.engine_status.setText("Engine: Stopped")
                self.engine_status.setStyleSheet("color: #ff0000;")

            # CTO mode status
            if hasattr(self.engine, 'is_cto_mode') and self.engine.is_cto_mode:
                self.cto_status.setText("CTO Mode: Active")
                self.cto_status.setStyleSheet("color: #00ff00;")
            else:
                self.cto_status.setText("CTO Mode: Disabled")
                self.cto_status.setStyleSheet("color: #888888;")

            # Event bus status
            if hasattr(self.engine, 'event_bus'):
                stats = self.engine.event_bus.stats
                processed = stats.get('events_processed', 0)
                self.event_bus_status.setText(f"Event Bus: {processed} events processed")
                self.event_bus_status.setStyleSheet("color: #00ff00;")

            # Learning system status
            if hasattr(self.engine, 'learning_system') and self.engine.learning_system:
                ls_stats = self.engine.learning_system.stats
                patterns = ls_stats.get('patterns_stored', 0)
                self.learning_status.setText(f"Learning System: {patterns} patterns")
                self.learning_status.setStyleSheet("color: #00ff00;")
            else:
                self.learning_status.setText("Learning System: Not available")
                self.learning_status.setStyleSheet("color: #888888;")

            # Integrations status
            integration_count = len(self.engine.integration_names)
            if integration_count > 0:
                self.integrations_status.setText(f"Integrations: {integration_count} connected")
                self.integrations_status.setStyleSheet("color: #00ff00;")
            else:
                self.integrations_status.setText("Integrations: None connected")
                self.integrations_status.setStyleSheet("color: #ffa500;")

            # Update recent events from event bus
            self._update_events()

        except Exception as e:
            logger.error(f"Error refreshing dashboard: {e}")

    def _update_events(self) -> None:
        """Update the events table with recent events from the event bus."""
        try:
            if not self.engine or not hasattr(self.engine, 'event_bus'):
                return

            # Get recent events
            events = self.engine.event_bus.get_recent_events(count=20)

            # Check if events changed (avoid flickering on no change)
            current_count = len(events)
            if current_count == self._last_event_count and current_count > 0:
                # Only skip if we have events and count hasn't changed
                # This is a simple heuristic; could be improved
                return
            self._last_event_count = current_count

            # Update table
            self.events_table.setRowCount(len(events))

            # Display events in reverse order (newest first)
            for row, event in enumerate(reversed(events)):
                # Time
                time_str = event.timestamp.strftime("%H:%M:%S")
                time_item = QTableWidgetItem(time_str)
                time_item.setForeground(QColor("#888888"))
                self.events_table.setItem(row, 0, time_item)

                # Type
                type_item = QTableWidgetItem(event.event_type)
                self.events_table.setItem(row, 1, type_item)

                # Source
                source_item = QTableWidgetItem(event.source)
                source_item.setForeground(QColor("#0078d4"))
                self.events_table.setItem(row, 2, source_item)

                # Message/Title
                message = event.title or event.description or ""
                message_item = QTableWidgetItem(message[:100])  # Truncate long messages

                # Color by severity
                severity_colors = {
                    "critical": "#ff4444",
                    "high": "#ff8844",
                    "medium": "#ffaa00",
                    "low": "#44ff44",
                    "info": "#ffffff",
                }
                color = severity_colors.get(event.severity.value, "#ffffff")
                message_item.setForeground(QColor(color))
                self.events_table.setItem(row, 3, message_item)

            # Update alerts count based on security events
            security_events = [e for e in events if e.category.value == "security"]
            self.alerts_card.set_value(str(len(security_events)))

        except Exception as e:
            logger.error(f"Error updating events: {e}")


class DevicesPage(QWidget):
    """Devices management page."""

    # Signal emitted when scan is requested
    scan_requested = Signal()

    def __init__(self, engine: "SentinelEngine", parent=None):
        super().__init__(parent)
        self.engine = engine
        self._scan_in_progress = False
        self._setup_ui()

    def _setup_ui(self) -> None:
        """Set up the devices UI."""
        layout = QVBoxLayout(self)
        layout.setSpacing(15)

        # Header with actions
        header_layout = QHBoxLayout()
        header = QLabel("Devices")
        header.setStyleSheet("font-size: 24px; font-weight: bold; color: #ffffff;")
        header_layout.addWidget(header)

        header_layout.addStretch()

        self.scan_btn = QPushButton("Scan Network")
        self.scan_btn.setStyleSheet("""
            QPushButton {
                background-color: #0078d4;
                color: white;
                border: none;
                padding: 8px 16px;
                border-radius: 4px;
            }
            QPushButton:hover {
                background-color: #1084d8;
            }
            QPushButton:disabled {
                background-color: #555555;
                color: #888888;
            }
        """)
        self.scan_btn.clicked.connect(self._on_scan_clicked)
        header_layout.addWidget(self.scan_btn)

        layout.addLayout(header_layout)

        # Devices table
        self.devices_table = QTableWidget(0, 6)
        self.devices_table.setHorizontalHeaderLabels([
            "Hostname", "IP Address", "MAC Address", "Type", "VLAN", "Status"
        ])
        self.devices_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.devices_table.setStyleSheet("""
            QTableWidget {
                background-color: #2d2d2d;
                color: #ffffff;
                gridline-color: #3d3d3d;
                border: none;
            }
            QHeaderView::section {
                background-color: #1d1d1d;
                color: #ffffff;
                padding: 8px;
                border: none;
                font-weight: bold;
            }
            QTableWidget::item {
                padding: 5px;
            }
            QTableWidget::item:selected {
                background-color: #0078d4;
            }
        """)
        layout.addWidget(self.devices_table)

    def refresh(self) -> None:
        """Refresh devices list."""
        if not self.engine:
            return

        try:
            discovery = self.engine.get_agent("discovery")
            if not discovery or not hasattr(discovery, '_inventory'):
                return

            devices = list(discovery._inventory.devices.values())
            self.devices_table.setRowCount(len(devices))

            for row, device in enumerate(devices):
                hostname = device.hostname or "Unknown"
                ip = device.primary_ip or "N/A"
                mac = device.primary_mac or "N/A"
                dtype = device.device_type.value
                vlan = str(device.assigned_vlan) if device.assigned_vlan else "N/A"
                status = device.status.value

                self.devices_table.setItem(row, 0, QTableWidgetItem(hostname))
                self.devices_table.setItem(row, 1, QTableWidgetItem(ip))
                self.devices_table.setItem(row, 2, QTableWidgetItem(mac))
                self.devices_table.setItem(row, 3, QTableWidgetItem(dtype))
                self.devices_table.setItem(row, 4, QTableWidgetItem(vlan))

                status_item = QTableWidgetItem(status)
                if status == "online":
                    status_item.setForeground(QColor("#00ff00"))
                elif status == "offline":
                    status_item.setForeground(QColor("#ff0000"))
                self.devices_table.setItem(row, 5, status_item)

        except Exception as e:
            logger.error(f"Error refreshing devices: {e}")

    def _on_scan_clicked(self) -> None:
        """Handle scan button click."""
        if self._scan_in_progress:
            return

        self._scan_in_progress = True
        self.scan_btn.setEnabled(False)
        self.scan_btn.setText("Scanning...")

        # Emit signal for external handling if needed
        self.scan_requested.emit()

        # Trigger scan via the discovery agent
        self._trigger_scan()

    def _trigger_scan(self) -> None:
        """Trigger a network scan via the discovery agent."""
        try:
            if not self.engine:
                self._scan_complete()
                return

            discovery = self.engine.get_agent("discovery")
            if not discovery:
                logger.warning("Discovery agent not available for scan")
                self._scan_complete()
                return

            # The discovery agent has an async full_scan method
            # We need to run it in the engine's event loop
            # For now, we'll mark scan as complete and rely on the agent's internal scanning
            # The actual scan is triggered by publishing an event

            from sentinel.core.models.event import Event, EventCategory, EventSeverity

            # Publish a scan request event
            event = Event(
                category=EventCategory.SYSTEM,
                event_type="discovery.scan_requested",
                severity=EventSeverity.INFO,
                source="sentinel.gui",
                title="Network Scan Requested",
                description="User requested a full network scan from GUI"
            )

            # Use sync publish since we're in Qt context
            if hasattr(self.engine, 'event_bus'):
                self.engine.event_bus.publish_sync(event)
                logger.info("Network scan requested via GUI")

            # Reset button after a delay (scan happens async)
            from PySide6.QtCore import QTimer
            QTimer.singleShot(2000, self._scan_complete)

        except Exception as e:
            logger.error(f"Error triggering scan: {e}")
            self._scan_complete()

    def _scan_complete(self) -> None:
        """Reset scan button state."""
        self._scan_in_progress = False
        self.scan_btn.setEnabled(True)
        self.scan_btn.setText("Scan Network")
        # Refresh the device list
        self.refresh()


class SecurityPage(QWidget):
    """Security monitoring page."""

    def __init__(self, engine: "SentinelEngine", parent=None):
        super().__init__(parent)
        self.engine = engine
        self._setup_ui()

    def _setup_ui(self) -> None:
        """Set up the security UI."""
        layout = QVBoxLayout(self)
        layout.setSpacing(15)

        # Header
        header = QLabel("Security")
        header.setStyleSheet("font-size: 24px; font-weight: bold; color: #ffffff;")
        layout.addWidget(header)

        # Security stats
        stats_layout = QHBoxLayout()

        self.blocked_card = StatsCard("Blocked IPs", "0")
        stats_layout.addWidget(self.blocked_card)

        self.quarantined_card = StatsCard("Quarantined", "0")
        stats_layout.addWidget(self.quarantined_card)

        self.threats_card = StatsCard("Threats Today", "0")
        stats_layout.addWidget(self.threats_card)

        layout.addLayout(stats_layout)

        # Blocked IPs list
        blocked_group = QGroupBox("Blocked IP Addresses")
        blocked_group.setStyleSheet("""
            QGroupBox {
                color: #ffffff;
                font-weight: bold;
                border: 1px solid #3d3d3d;
                border-radius: 5px;
                margin-top: 10px;
                padding-top: 10px;
            }
        """)
        blocked_layout = QVBoxLayout(blocked_group)

        self.blocked_list = QListWidget()
        self.blocked_list.setStyleSheet("""
            QListWidget {
                background-color: #2d2d2d;
                color: #ffffff;
                border: none;
            }
            QListWidget::item {
                padding: 8px;
                border-bottom: 1px solid #3d3d3d;
            }
            QListWidget::item:selected {
                background-color: #0078d4;
            }
        """)
        blocked_layout.addWidget(self.blocked_list)

        layout.addWidget(blocked_group)
        layout.addStretch()

    def refresh(self) -> None:
        """Refresh security data."""
        if not self.engine:
            return

        try:
            guardian = self.engine.get_agent("guardian")
            if guardian:
                blocked = getattr(guardian, '_blocked_ips', set())
                quarantined = getattr(guardian, '_quarantined_devices', set())

                self.blocked_card.set_value(str(len(blocked)))
                self.quarantined_card.set_value(str(len(quarantined)))

                # Update blocked list
                self.blocked_list.clear()
                for ip in sorted(blocked):
                    self.blocked_list.addItem(ip)

        except Exception as e:
            logger.error(f"Error refreshing security: {e}")


class AgentsPage(QWidget):
    """Agents management page."""

    def __init__(self, engine: "SentinelEngine", parent=None):
        super().__init__(parent)
        self.engine = engine
        self._setup_ui()

    def _setup_ui(self) -> None:
        """Set up the agents UI."""
        layout = QVBoxLayout(self)
        layout.setSpacing(15)

        # Header
        header = QLabel("AI Agents")
        header.setStyleSheet("font-size: 24px; font-weight: bold; color: #ffffff;")
        layout.addWidget(header)

        # Agents table
        self.agents_table = QTableWidget(0, 4)
        self.agents_table.setHorizontalHeaderLabels([
            "Agent", "Status", "Actions", "Decisions"
        ])
        self.agents_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.agents_table.setStyleSheet("""
            QTableWidget {
                background-color: #2d2d2d;
                color: #ffffff;
                gridline-color: #3d3d3d;
                border: none;
            }
            QHeaderView::section {
                background-color: #1d1d1d;
                color: #ffffff;
                padding: 8px;
                border: none;
                font-weight: bold;
            }
        """)
        layout.addWidget(self.agents_table)

        layout.addStretch()

    def refresh(self) -> None:
        """Refresh agents data."""
        if not self.engine:
            return

        try:
            agents = list(self.engine._agents.items())
            self.agents_table.setRowCount(len(agents))

            for row, (name, agent) in enumerate(agents):
                self.agents_table.setItem(row, 0, QTableWidgetItem(name.title()))

                running = getattr(agent, '_running', False)
                status_item = QTableWidgetItem("Running" if running else "Stopped")
                status_item.setForeground(QColor("#00ff00" if running else "#ff0000"))
                self.agents_table.setItem(row, 1, status_item)

                stats = agent.stats if hasattr(agent, 'stats') else {}
                actions = stats.get('total_actions', 0)
                decisions = stats.get('total_decisions', 0)

                self.agents_table.setItem(row, 2, QTableWidgetItem(str(actions)))
                self.agents_table.setItem(row, 3, QTableWidgetItem(str(decisions)))

        except Exception as e:
            logger.error(f"Error refreshing agents: {e}")


class SettingsPage(QWidget):
    """Settings page."""

    def __init__(self, engine: "SentinelEngine", config: dict, parent=None):
        super().__init__(parent)
        self.engine = engine
        self.config = config
        self._setup_ui()

    def _setup_ui(self) -> None:
        """Set up the settings UI."""
        layout = QVBoxLayout(self)
        layout.setSpacing(15)

        # Header
        header = QLabel("Settings")
        header.setStyleSheet("font-size: 24px; font-weight: bold; color: #ffffff;")
        layout.addWidget(header)

        # API Settings group
        api_group = QGroupBox("API Configuration")
        api_group.setStyleSheet("""
            QGroupBox {
                color: #ffffff;
                font-weight: bold;
                border: 1px solid #3d3d3d;
                border-radius: 5px;
                margin-top: 10px;
                padding: 15px;
            }
        """)
        api_layout = QVBoxLayout(api_group)

        api_info = QLabel(
            f"API Host: {self.config.get('api', {}).get('host', '127.0.0.1')}\n"
            f"API Port: {self.config.get('api', {}).get('port', 8080)}"
        )
        api_info.setStyleSheet("color: #cccccc;")
        api_layout.addWidget(api_info)

        layout.addWidget(api_group)

        # About
        about_group = QGroupBox("About")
        about_group.setStyleSheet("""
            QGroupBox {
                color: #ffffff;
                font-weight: bold;
                border: 1px solid #3d3d3d;
                border-radius: 5px;
                margin-top: 10px;
                padding: 15px;
            }
        """)
        about_layout = QVBoxLayout(about_group)

        about_text = QLabel(
            "Sentinel - AI-Native Security Platform\n"
            "Version 0.1.0\n\n"
            "An intelligent platform for network security,\n"
            "device management, and automation."
        )
        about_text.setStyleSheet("color: #cccccc;")
        about_layout.addWidget(about_text)

        layout.addWidget(about_group)
        layout.addStretch()

    def refresh(self) -> None:
        """Refresh settings (no-op for now)."""
        pass


class MainWindow(QMainWindow):
    """
    Main application window for Sentinel.

    Provides a modern dashboard interface with sidebar navigation
    and multiple pages for different functions.
    """

    def __init__(self, engine: "SentinelEngine", config: dict, parent=None):
        super().__init__(parent)
        self.engine = engine
        self.config = config

        self._setup_window()
        self._setup_ui()
        self._setup_tray()

    def _setup_window(self) -> None:
        """Configure the main window."""
        self.setWindowTitle("Sentinel")
        self.setMinimumSize(1200, 800)

        # Dark theme
        self.setStyleSheet("""
            QMainWindow {
                background-color: #1d1d1d;
            }
            QWidget {
                background-color: #1d1d1d;
                color: #ffffff;
            }
        """)

    def _setup_ui(self) -> None:
        """Set up the main UI layout."""
        central_widget = QWidget()
        self.setCentralWidget(central_widget)

        main_layout = QHBoxLayout(central_widget)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)

        # Sidebar
        sidebar = QWidget()
        sidebar.setFixedWidth(220)
        sidebar.setStyleSheet("background-color: #2d2d2d;")
        sidebar_layout = QVBoxLayout(sidebar)
        sidebar_layout.setContentsMargins(0, 0, 0, 0)
        sidebar_layout.setSpacing(0)

        # Logo/title
        title = QLabel("SENTINEL")
        title.setStyleSheet("""
            font-size: 20px;
            font-weight: bold;
            color: #0078d4;
            padding: 20px;
        """)
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        sidebar_layout.addWidget(title)

        # Navigation buttons
        self.nav_buttons = []

        self.dashboard_btn = SidebarButton("Dashboard")
        self.dashboard_btn.setChecked(True)
        self.dashboard_btn.clicked.connect(lambda: self._switch_page(0))
        sidebar_layout.addWidget(self.dashboard_btn)
        self.nav_buttons.append(self.dashboard_btn)

        self.devices_btn = SidebarButton("Devices")
        self.devices_btn.clicked.connect(lambda: self._switch_page(1))
        sidebar_layout.addWidget(self.devices_btn)
        self.nav_buttons.append(self.devices_btn)

        self.security_btn = SidebarButton("Security")
        self.security_btn.clicked.connect(lambda: self._switch_page(2))
        sidebar_layout.addWidget(self.security_btn)
        self.nav_buttons.append(self.security_btn)

        self.agents_btn = SidebarButton("Agents")
        self.agents_btn.clicked.connect(lambda: self._switch_page(3))
        sidebar_layout.addWidget(self.agents_btn)
        self.nav_buttons.append(self.agents_btn)

        self.settings_btn = SidebarButton("Settings")
        self.settings_btn.clicked.connect(lambda: self._switch_page(4))
        sidebar_layout.addWidget(self.settings_btn)
        self.nav_buttons.append(self.settings_btn)

        sidebar_layout.addStretch()

        main_layout.addWidget(sidebar)

        # Content area
        content = QWidget()
        content.setStyleSheet("background-color: #1d1d1d;")
        content_layout = QVBoxLayout(content)
        content_layout.setContentsMargins(20, 20, 20, 20)

        # Stacked widget for pages
        self.pages = QStackedWidget()

        self.dashboard_page = DashboardPage(self.engine)
        self.pages.addWidget(self.dashboard_page)

        self.devices_page = DevicesPage(self.engine)
        self.pages.addWidget(self.devices_page)

        self.security_page = SecurityPage(self.engine)
        self.pages.addWidget(self.security_page)

        self.agents_page = AgentsPage(self.engine)
        self.pages.addWidget(self.agents_page)

        self.settings_page = SettingsPage(self.engine, self.config)
        self.pages.addWidget(self.settings_page)

        content_layout.addWidget(self.pages)

        main_layout.addWidget(content)

        # Status bar
        self.status_bar = QStatusBar()
        self.status_bar.setStyleSheet("""
            QStatusBar {
                background-color: #2d2d2d;
                color: #888888;
            }
        """)
        self.setStatusBar(self.status_bar)
        self.status_bar.showMessage("Ready")

    def _setup_tray(self) -> None:
        """Set up system tray icon."""
        self.tray_icon = QSystemTrayIcon(self)

        # Create tray menu
        tray_menu = QMenu()

        show_action = QAction("Show", self)
        show_action.triggered.connect(self.show)
        tray_menu.addAction(show_action)

        tray_menu.addSeparator()

        quit_action = QAction("Quit", self)
        quit_action.triggered.connect(self._quit_app)
        tray_menu.addAction(quit_action)

        self.tray_icon.setContextMenu(tray_menu)
        self.tray_icon.activated.connect(self._tray_activated)
        self.tray_icon.show()

    def _switch_page(self, index: int) -> None:
        """Switch to a different page."""
        # Update button states
        for i, btn in enumerate(self.nav_buttons):
            btn.setChecked(i == index)

        # Switch page
        self.pages.setCurrentIndex(index)

        # Refresh the page
        self.refresh_data()

    def _tray_activated(self, reason: QSystemTrayIcon.ActivationReason) -> None:
        """Handle tray icon activation."""
        if reason == QSystemTrayIcon.ActivationReason.DoubleClick:
            self.show()
            self.activateWindow()

    def _quit_app(self) -> None:
        """Quit the application."""
        self.tray_icon.hide()
        self.close()

    def refresh_data(self) -> None:
        """Refresh data on the current page."""
        current_index = self.pages.currentIndex()
        current_page = self.pages.widget(current_index)

        if hasattr(current_page, 'refresh'):
            current_page.refresh()

        # Update status bar
        if self.engine and self.engine.is_running:
            self.status_bar.showMessage(
                f"Engine running | Uptime: {int(self.engine.uptime_seconds)}s"
            )

    def closeEvent(self, event) -> None:
        """Handle window close event."""
        # Minimize to tray instead of closing
        event.ignore()
        self.hide()
        self.tray_icon.showMessage(
            "Sentinel",
            "Application minimized to tray",
            QSystemTrayIcon.MessageIcon.Information,
            2000
        )
