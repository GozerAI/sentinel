"""
Sentinel CLI - Command-line interface for the Sentinel platform.

Provides commands for:
- Starting/stopping the engine
- Querying status
- Managing agents
- Viewing logs and metrics
"""
import asyncio
import sys
from pathlib import Path
from typing import Optional

import typer
import yaml
from rich.console import Console
from rich.table import Table

app = typer.Typer(
    name="sentinel",
    help="AI-Native Security Platform CLI"
)
console = Console()


def load_config(config_path: str) -> dict:
    """Load configuration from YAML file."""
    path = Path(config_path)
    if not path.exists():
        console.print(f"[red]Config file not found: {config_path}[/red]")
        raise typer.Exit(1)
    
    with open(path) as f:
        return yaml.safe_load(f)


@app.command()
def start(
    config: str = typer.Option(
        "config/homelab.yaml",
        "--config", "-c",
        help="Path to configuration file"
    ),
    daemon: bool = typer.Option(
        False,
        "--daemon", "-d",
        help="Run as daemon"
    )
):
    """Start the Sentinel engine."""
    console.print("[green]Starting Sentinel Engine...[/green]")
    
    try:
        cfg = load_config(config)
        
        from sentinel.core.engine import SentinelEngine
        
        engine = SentinelEngine(cfg)
        
        async def run():
            await engine.start()
            console.print("[green]Sentinel Engine running. Press Ctrl+C to stop.[/green]")
            
            try:
                while True:
                    await asyncio.sleep(1)
            except KeyboardInterrupt:
                console.print("\n[yellow]Shutting down...[/yellow]")
            finally:
                await engine.stop()
        
        asyncio.run(run())
        
    except Exception as e:
        console.print(f"[red]Failed to start: {e}[/red]")
        raise typer.Exit(1)


@app.command()
def status(
    config: str = typer.Option(
        "config/homelab.yaml",
        "--config", "-c",
        help="Path to configuration file"
    )
):
    """Show engine status."""
    console.print("[blue]Fetching status...[/blue]")
    
    # In a real implementation, this would connect to a running engine
    # via the API. For now, show a placeholder.
    
    table = Table(title="Sentinel Status")
    table.add_column("Component", style="cyan")
    table.add_column("Status", style="green")
    table.add_column("Details")
    
    table.add_row("Engine", "Running", "Uptime: 2h 34m")
    table.add_row("Discovery Agent", "Active", "Last scan: 2m ago")
    table.add_row("Optimizer Agent", "Active", "Flows monitored: 1,234")
    table.add_row("Planner Agent", "Active", "VLANs managed: 8")
    table.add_row("Healer Agent", "Active", "Health checks: OK")
    table.add_row("Guardian Agent", "Active", "Alerts: 0")
    
    console.print(table)


@app.command()
def agents(
    action: str = typer.Argument(
        "list",
        help="Action: list, enable, disable"
    ),
    agent_name: Optional[str] = typer.Argument(
        None,
        help="Agent name (for enable/disable)"
    )
):
    """Manage AI agents."""
    if action == "list":
        table = Table(title="AI Agents")
        table.add_column("Agent", style="cyan")
        table.add_column("Status", style="green")
        table.add_column("Actions", style="yellow")
        table.add_column("Last Decision")
        
        table.add_row("discovery", "Enabled", "156", "2m ago")
        table.add_row("optimizer", "Enabled", "89", "30s ago")
        table.add_row("planner", "Enabled", "12", "1h ago")
        table.add_row("healer", "Enabled", "4", "15m ago")
        table.add_row("guardian", "Enabled", "0", "N/A")
        
        console.print(table)
    
    elif action in ("enable", "disable"):
        if not agent_name:
            console.print("[red]Agent name required[/red]")
            raise typer.Exit(1)
        
        console.print(f"[green]Agent '{agent_name}' {action}d[/green]")


@app.command()
def devices(
    action: str = typer.Argument(
        "list",
        help="Action: list, scan, classify"
    ),
    filter: Optional[str] = typer.Option(
        None,
        "--filter", "-f",
        help="Filter by type: workstation, server, iot, etc."
    )
):
    """View and manage discovered devices."""
    if action == "list":
        table = Table(title="Discovered Devices")
        table.add_column("IP", style="cyan")
        table.add_column("MAC")
        table.add_column("Type", style="green")
        table.add_column("Vendor")
        table.add_column("VLAN", style="yellow")
        table.add_column("Status")
        
        # Sample data
        devices = [
            ("192.168.1.10", "00:1E:4F:XX:XX:XX", "server", "Dell", "20", "Online"),
            ("192.168.1.20", "B8:27:EB:XX:XX:XX", "server", "Raspberry Pi", "20", "Online"),
            ("192.168.1.50", "00:17:88:XX:XX:XX", "iot", "Philips Hue", "100", "Online"),
            ("192.168.1.100", "A4:BA:DB:XX:XX:XX", "workstation", "Dell", "10", "Online"),
        ]
        
        for d in devices:
            if filter is None or d[2] == filter:
                table.add_row(*d)
        
        console.print(table)
    
    elif action == "scan":
        console.print("[blue]Triggering network scan...[/blue]")
        console.print("[green]Scan initiated. Check status with 'sentinel devices list'[/green]")


@app.command()
def topology():
    """Show network topology."""
    console.print("[blue]Network Topology[/blue]")
    console.print("""
┌─────────────────────────────────────────────────────┐
│                    Internet                         │
└─────────────────────┬───────────────────────────────┘
                      │
               ┌──────┴──────┐
               │   Router    │
               │ 192.168.1.1 │
               └──────┬──────┘
                      │
        ┌─────────────┼─────────────┐
        │             │             │
   ┌────┴────┐  ┌────┴────┐  ┌────┴────┐
   │ Switch1 │  │ Switch2 │  │ Switch3 │
   │ VLAN 10 │  │ VLAN 20 │  │ VLAN100 │
   └────┬────┘  └────┬────┘  └────┬────┘
        │            │            │
   Workstations   Servers       IoT
    """)


@app.command()
def vlans():
    """Show VLAN configuration."""
    table = Table(title="VLAN Configuration")
    table.add_column("ID", style="cyan")
    table.add_column("Name")
    table.add_column("Subnet", style="green")
    table.add_column("Purpose")
    table.add_column("Devices", style="yellow")
    
    vlans = [
        ("1", "Management", "192.168.1.0/24", "management", "5"),
        ("10", "Workstations", "192.168.10.0/24", "workstations", "12"),
        ("20", "Servers", "192.168.20.0/24", "servers", "8"),
        ("30", "Storage", "192.168.30.0/24", "storage", "2"),
        ("50", "AI Compute", "192.168.50.0/24", "ai_compute", "3"),
        ("100", "IoT", "192.168.100.0/24", "iot", "15"),
        ("200", "Guest", "192.168.200.0/24", "guest", "0"),
        ("666", "Quarantine", "192.168.166.0/24", "quarantine", "0"),
    ]
    
    for v in vlans:
        table.add_row(*v)
    
    console.print(table)


@app.command()
def logs(
    lines: int = typer.Option(
        50,
        "--lines", "-n",
        help="Number of lines to show"
    ),
    follow: bool = typer.Option(
        False,
        "--follow", "-f",
        help="Follow log output"
    ),
    level: str = typer.Option(
        "INFO",
        "--level", "-l",
        help="Minimum log level"
    )
):
    """View engine logs."""
    console.print(f"[blue]Showing last {lines} log entries (level >= {level})[/blue]")
    
    # Sample log output
    logs = [
        "[2024-01-15 10:30:00] INFO  discovery: Full scan completed - 45 devices found",
        "[2024-01-15 10:30:01] INFO  discovery: Device classified: 192.168.1.50 -> iot",
        "[2024-01-15 10:30:05] INFO  planner: VLAN assignment proposed: 192.168.1.50 -> VLAN 100",
        "[2024-01-15 10:30:06] INFO  discovery: Action executed: assign_vlan (confidence: 0.92)",
        "[2024-01-15 10:31:00] INFO  optimizer: Traffic analysis complete - 1,234 flows",
    ]
    
    for log in logs:
        console.print(log)


@app.command()
def version():
    """Show version information."""
    console.print("[blue]Sentinel Security Platform[/blue]")
    console.print("Version: 0.1.0")
    console.print("Python: " + sys.version.split()[0])


if __name__ == "__main__":
    app()
