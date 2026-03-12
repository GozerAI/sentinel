"""
Sentinel CLI - Command-line interface for the Sentinel platform.

Provides commands for:
- Starting/stopping the engine
- Managing devices and VLANs
- Viewing events and alerts
- Agent control
- Configuration management
"""

import asyncio
import logging
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn

app = typer.Typer(
    name="sentinel",
    help="Sentinel AI-Native Security Platform CLI",
    add_completion=False,
)
console = Console()

# Sub-command groups
devices_app = typer.Typer(help="Device management commands")
vlans_app = typer.Typer(help="VLAN management commands")
agents_app = typer.Typer(help="Agent management commands")
events_app = typer.Typer(help="Event and alert commands")
scan_app = typer.Typer(help="Network scanning commands")
config_app = typer.Typer(help="Configuration commands")

app.add_typer(devices_app, name="devices")
app.add_typer(vlans_app, name="vlans")
app.add_typer(agents_app, name="agents")
app.add_typer(events_app, name="events")
app.add_typer(scan_app, name="scan")
app.add_typer(config_app, name="config")


def get_api_client(base_url: str = "http://localhost:8000", api_key: Optional[str] = None):
    """Get an HTTP client for the API."""
    import httpx

    headers = {}
    if api_key:
        headers["X-API-Key"] = api_key

    return httpx.Client(base_url=base_url, headers=headers, timeout=30.0)


# =============================================================================
# Main Commands
# =============================================================================


@app.command()
def start(
    config: Path = typer.Option(None, "--config", "-c", help="Path to configuration file"),
    host: str = typer.Option("0.0.0.0", "--host", "-h", help="API server host"),
    port: int = typer.Option(8000, "--port", "-p", help="API server port"),
    workers: int = typer.Option(1, "--workers", "-w", help="Number of worker processes"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Enable verbose logging"),
):
    """Start the Sentinel engine and API server."""
    import uvicorn
    from sentinel.core.config import load_config

    console.print(
        Panel.fit("[bold blue]Sentinel[/] AI-Native Security Platform", subtitle="Starting...")
    )

    # Load configuration
    config_path = config or Path("config/sentinel.yaml")
    if config_path.exists():
        console.print(f"Loading config from: {config_path}")
    else:
        console.print(f"[yellow]Config not found at {config_path}, using defaults[/]")

    log_level = "debug" if verbose else "info"

    console.print(f"Starting API server on {host}:{port}")

    uvicorn.run(
        "sentinel.api:app",
        host=host,
        port=port,
        workers=workers,
        log_level=log_level,
        reload=verbose,  # Enable reload in verbose/dev mode
    )


@app.command()
def status(
    url: str = typer.Option("http://localhost:8000", "--url", "-u", help="API URL"),
    api_key: Optional[str] = typer.Option(None, "--api-key", "-k", help="API key"),
):
    """Show engine status."""
    try:
        client = get_api_client(url, api_key)
        response = client.get("/status")
        response.raise_for_status()
        data = response.json()

        # Status panel
        status_color = "green" if data["status"] == "running" else "red"
        uptime = data.get("uptime_seconds", 0)
        uptime_str = f"{uptime // 3600:.0f}h {(uptime % 3600) // 60:.0f}m"

        console.print(
            Panel(
                f"[{status_color}]Status: {data['status'].upper()}[/]\n" f"Uptime: {uptime_str}",
                title="Sentinel Engine",
            )
        )

        # Agents table
        agents_table = Table(title="Agents")
        agents_table.add_column("Name", style="cyan")
        agents_table.add_column("Enabled", style="green")
        agents_table.add_column("Actions", justify="right")

        for name, agent in data.get("agents", {}).items():
            enabled = "[green]Yes[/]" if agent.get("enabled") else "[red]No[/]"
            agents_table.add_row(name, enabled, str(agent.get("actions_taken", 0)))

        console.print(agents_table)

        # Integrations table
        int_table = Table(title="Integrations")
        int_table.add_column("Name", style="cyan")
        int_table.add_column("Status")

        for name, connected in data.get("integrations", {}).items():
            status_str = "[green]Connected[/]" if connected else "[red]Disconnected[/]"
            int_table.add_row(name, status_str)

        console.print(int_table)

    except Exception as e:
        console.print(f"[red]Error connecting to Sentinel API: {e}[/]")
        raise typer.Exit(1)


@app.command()
def version():
    """Show version information."""
    from sentinel import __version__

    console.print(f"Sentinel version: [bold]{__version__}[/]")


# =============================================================================
# Device Commands
# =============================================================================


@devices_app.command("list")
def devices_list(
    device_type: Optional[str] = typer.Option(None, "--type", "-t", help="Filter by type"),
    vlan: Optional[int] = typer.Option(None, "--vlan", "-v", help="Filter by VLAN"),
    online: Optional[bool] = typer.Option(None, "--online", help="Filter by online status"),
    url: str = typer.Option("http://localhost:8000", "--url", "-u"),
    api_key: Optional[str] = typer.Option(None, "--api-key", "-k"),
):
    """List discovered devices."""
    try:
        client = get_api_client(url, api_key)

        params = {}
        if device_type:
            params["device_type"] = device_type
        if vlan is not None:
            params["vlan"] = vlan
        if online is not None:
            params["online"] = online

        response = client.get("/devices", params=params)
        response.raise_for_status()
        data = response.json()

        table = Table(title=f"Devices ({data['total']} total)")
        table.add_column("MAC", style="cyan")
        table.add_column("IP")
        table.add_column("Hostname")
        table.add_column("Type")
        table.add_column("VLAN", justify="right")
        table.add_column("Status")
        table.add_column("Vendor")

        for device in data["devices"]:
            status = "[green]Online[/]" if device.get("online") else "[red]Offline[/]"
            ips = ", ".join(device.get("ip_addresses", [])[:2])
            table.add_row(
                device.get("mac", ""),
                ips,
                device.get("hostname") or "-",
                device.get("device_type", "unknown"),
                str(device.get("vlan") or "-"),
                status,
                device.get("vendor") or "-",
            )

        console.print(table)

    except Exception as e:
        console.print(f"[red]Error: {e}[/]")
        raise typer.Exit(1)


@devices_app.command("show")
def devices_show(
    device_id: str = typer.Argument(..., help="Device ID or MAC address"),
    url: str = typer.Option("http://localhost:8000", "--url", "-u"),
    api_key: Optional[str] = typer.Option(None, "--api-key", "-k"),
):
    """Show device details."""
    try:
        client = get_api_client(url, api_key)
        response = client.get(f"/devices/{device_id}")
        response.raise_for_status()
        device = response.json()

        console.print(
            Panel(
                f"[bold]MAC:[/] {device.get('mac')}\n"
                f"[bold]Hostname:[/] {device.get('hostname') or 'Unknown'}\n"
                f"[bold]Type:[/] {device.get('device_type')}\n"
                f"[bold]Vendor:[/] {device.get('vendor') or 'Unknown'}\n"
                f"[bold]IPs:[/] {', '.join(device.get('ip_addresses', []))}\n"
                f"[bold]VLAN:[/] {device.get('vlan') or 'Unassigned'}\n"
                f"[bold]Trust Level:[/] {device.get('trust_level', 0):.0%}\n"
                f"[bold]Status:[/] {'Online' if device.get('online') else 'Offline'}\n"
                f"[bold]Last Seen:[/] {device.get('last_seen') or 'Never'}",
                title=f"Device: {device.get('id')}",
            )
        )

    except Exception as e:
        console.print(f"[red]Error: {e}[/]")
        raise typer.Exit(1)


@devices_app.command("scan")
def devices_scan(
    device_id: str = typer.Argument(..., help="Device ID or MAC to rescan"),
    url: str = typer.Option("http://localhost:8000", "--url", "-u"),
    api_key: Optional[str] = typer.Option(None, "--api-key", "-k"),
):
    """Trigger a rescan of a specific device."""
    try:
        client = get_api_client(url, api_key)
        response = client.post(f"/devices/{device_id}/scan")
        response.raise_for_status()
        console.print(f"[green]Scan initiated for device {device_id}[/]")
    except Exception as e:
        console.print(f"[red]Error: {e}[/]")
        raise typer.Exit(1)


# =============================================================================
# VLAN Commands
# =============================================================================


@vlans_app.command("list")
def vlans_list(
    url: str = typer.Option("http://localhost:8000", "--url", "-u"),
    api_key: Optional[str] = typer.Option(None, "--api-key", "-k"),
):
    """List configured VLANs."""
    try:
        client = get_api_client(url, api_key)
        response = client.get("/vlans")
        response.raise_for_status()
        vlans = response.json()

        table = Table(title="VLANs")
        table.add_column("ID", style="cyan", justify="right")
        table.add_column("Name")
        table.add_column("Subnet")
        table.add_column("Purpose")
        table.add_column("Devices", justify="right")
        table.add_column("Isolated")

        for vlan in vlans:
            isolated = "[yellow]Yes[/]" if vlan.get("isolated") else "No"
            table.add_row(
                str(vlan.get("id")),
                vlan.get("name", ""),
                vlan.get("subnet") or "-",
                vlan.get("purpose") or "-",
                str(vlan.get("device_count", 0)),
                isolated,
            )

        console.print(table)

    except Exception as e:
        console.print(f"[red]Error: {e}[/]")
        raise typer.Exit(1)


@vlans_app.command("create")
def vlans_create(
    vlan_id: int = typer.Argument(..., help="VLAN ID"),
    name: str = typer.Argument(..., help="VLAN name"),
    subnet: Optional[str] = typer.Option(
        None, "--subnet", "-s", help="Subnet (e.g., 192.168.10.0/24)"
    ),
    purpose: Optional[str] = typer.Option(None, "--purpose", "-p", help="VLAN purpose"),
    isolated: bool = typer.Option(False, "--isolated", "-i", help="Isolate this VLAN"),
    url: str = typer.Option("http://localhost:8000", "--url", "-u"),
    api_key: Optional[str] = typer.Option(None, "--api-key", "-k"),
):
    """Create a new VLAN."""
    try:
        client = get_api_client(url, api_key)
        response = client.post(
            "/vlans",
            json={
                "id": vlan_id,
                "name": name,
                "subnet": subnet,
                "purpose": purpose,
                "isolated": isolated,
            },
        )
        response.raise_for_status()
        console.print(f"[green]Created VLAN {vlan_id}: {name}[/]")
    except Exception as e:
        console.print(f"[red]Error: {e}[/]")
        raise typer.Exit(1)


# =============================================================================
# Agent Commands
# =============================================================================


@agents_app.command("list")
def agents_list(
    url: str = typer.Option("http://localhost:8000", "--url", "-u"),
    api_key: Optional[str] = typer.Option(None, "--api-key", "-k"),
):
    """List all agents."""
    try:
        client = get_api_client(url, api_key)
        response = client.get("/agents")
        response.raise_for_status()
        agents = response.json()

        table = Table(title="Agents")
        table.add_column("Name", style="cyan")
        table.add_column("Enabled")
        table.add_column("Actions Taken", justify="right")
        table.add_column("Events Processed", justify="right")
        table.add_column("Decisions Made", justify="right")

        for agent in agents:
            enabled = "[green]Yes[/]" if agent.get("enabled") else "[red]No[/]"
            stats = agent.get("stats", {})
            table.add_row(
                agent.get("name"),
                enabled,
                str(agent.get("actions_taken", 0)),
                str(stats.get("events_processed", 0)),
                str(stats.get("decisions_made", 0)),
            )

        console.print(table)

    except Exception as e:
        console.print(f"[red]Error: {e}[/]")
        raise typer.Exit(1)


@agents_app.command("enable")
def agents_enable(
    agent_name: str = typer.Argument(..., help="Agent name"),
    url: str = typer.Option("http://localhost:8000", "--url", "-u"),
    api_key: Optional[str] = typer.Option(None, "--api-key", "-k"),
):
    """Enable an agent."""
    try:
        client = get_api_client(url, api_key)
        response = client.post(f"/agents/{agent_name}/enable")
        response.raise_for_status()
        console.print(f"[green]Agent '{agent_name}' enabled[/]")
    except Exception as e:
        console.print(f"[red]Error: {e}[/]")
        raise typer.Exit(1)


@agents_app.command("disable")
def agents_disable(
    agent_name: str = typer.Argument(..., help="Agent name"),
    url: str = typer.Option("http://localhost:8000", "--url", "-u"),
    api_key: Optional[str] = typer.Option(None, "--api-key", "-k"),
):
    """Disable an agent."""
    try:
        client = get_api_client(url, api_key)
        response = client.post(f"/agents/{agent_name}/disable")
        response.raise_for_status()
        console.print(f"[yellow]Agent '{agent_name}' disabled[/]")
    except Exception as e:
        console.print(f"[red]Error: {e}[/]")
        raise typer.Exit(1)


# =============================================================================
# Event Commands
# =============================================================================


@events_app.command("list")
def events_list(
    category: Optional[str] = typer.Option(None, "--category", "-c", help="Filter by category"),
    severity: Optional[str] = typer.Option(None, "--severity", "-s", help="Filter by severity"),
    limit: int = typer.Option(20, "--limit", "-l", help="Maximum events to show"),
    url: str = typer.Option("http://localhost:8000", "--url", "-u"),
    api_key: Optional[str] = typer.Option(None, "--api-key", "-k"),
):
    """List recent events."""
    try:
        client = get_api_client(url, api_key)

        params = {"limit": limit}
        if category:
            params["category"] = category
        if severity:
            params["severity"] = severity

        response = client.get("/events", params=params)
        response.raise_for_status()
        events = response.json()

        table = Table(title=f"Events (showing {len(events)})")
        table.add_column("Time", style="dim")
        table.add_column("Severity")
        table.add_column("Category")
        table.add_column("Title")
        table.add_column("Source")

        severity_colors = {
            "critical": "red bold",
            "high": "red",
            "warning": "yellow",
            "info": "blue",
            "low": "dim",
        }

        for event in events:
            sev = event.get("severity", "info")
            sev_style = severity_colors.get(sev, "")
            created = event.get("created_at", "")[:19]  # Trim to datetime

            table.add_row(
                created,
                f"[{sev_style}]{sev.upper()}[/]",
                event.get("category", ""),
                event.get("title", "")[:50],
                event.get("source", "")[:30],
            )

        console.print(table)

    except Exception as e:
        console.print(f"[red]Error: {e}[/]")
        raise typer.Exit(1)


@events_app.command("acknowledge")
def events_ack(
    event_id: str = typer.Argument(..., help="Event ID to acknowledge"),
    url: str = typer.Option("http://localhost:8000", "--url", "-u"),
    api_key: Optional[str] = typer.Option(None, "--api-key", "-k"),
):
    """Acknowledge an event."""
    try:
        client = get_api_client(url, api_key)
        response = client.post(f"/events/{event_id}/acknowledge")
        response.raise_for_status()
        console.print(f"[green]Event {event_id} acknowledged[/]")
    except Exception as e:
        console.print(f"[red]Error: {e}[/]")
        raise typer.Exit(1)


# =============================================================================
# Scan Commands
# =============================================================================


@scan_app.command("quick")
def scan_quick(
    url: str = typer.Option("http://localhost:8000", "--url", "-u"),
    api_key: Optional[str] = typer.Option(None, "--api-key", "-k"),
):
    """Run a quick network scan (ARP only)."""
    try:
        client = get_api_client(url, api_key)

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            progress.add_task("Running quick scan...", total=None)
            response = client.post("/scan/quick")
            response.raise_for_status()

        console.print("[green]Quick scan initiated[/]")

    except Exception as e:
        console.print(f"[red]Error: {e}[/]")
        raise typer.Exit(1)


@scan_app.command("full")
def scan_full(
    url: str = typer.Option("http://localhost:8000", "--url", "-u"),
    api_key: Optional[str] = typer.Option(None, "--api-key", "-k"),
):
    """Run a full network scan with fingerprinting."""
    try:
        client = get_api_client(url, api_key)

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            progress.add_task("Running full scan (this may take a while)...", total=None)
            response = client.post("/scan/full")
            response.raise_for_status()

        console.print("[green]Full scan initiated[/]")

    except Exception as e:
        console.print(f"[red]Error: {e}[/]")
        raise typer.Exit(1)


# =============================================================================
# Config Commands
# =============================================================================


@config_app.command("show")
def config_show(
    config_path: Path = typer.Option(
        Path("config/sentinel.yaml"), "--config", "-c", help="Path to config file"
    ),
):
    """Show current configuration."""
    try:
        if not config_path.exists():
            console.print(f"[yellow]Config file not found: {config_path}[/]")
            return

        import yaml

        with open(config_path) as f:
            config = yaml.safe_load(f)

        from rich.syntax import Syntax

        yaml_str = yaml.dump(config, default_flow_style=False)
        syntax = Syntax(yaml_str, "yaml", theme="monokai", line_numbers=True)
        console.print(syntax)

    except Exception as e:
        console.print(f"[red]Error: {e}[/]")
        raise typer.Exit(1)


@config_app.command("validate")
def config_validate(
    config_path: Path = typer.Option(
        Path("config/sentinel.yaml"), "--config", "-c", help="Path to config file"
    ),
):
    """Validate configuration file."""
    try:
        from sentinel.core.config import load_config

        config = load_config(config_path)
        console.print(f"[green]Configuration is valid![/]")
        console.print(f"  Agents: {len(config.agents)} configured")
        console.print(f"  VLANs: {len(config.vlans) if hasattr(config, 'vlans') else 0} configured")

    except Exception as e:
        console.print(f"[red]Configuration error: {e}[/]")
        raise typer.Exit(1)


@config_app.command("generate-api-key")
def config_generate_api_key(
    name: str = typer.Argument(..., help="Name for the API key"),
):
    """Generate a new API key."""
    from sentinel.api.auth import generate_api_key

    key, key_hash = generate_api_key()

    console.print(
        Panel(
            f"[bold]API Key:[/] {key}\n\n"
            f"[bold]Key Hash (for config):[/] {key_hash}\n\n"
            "[yellow]Save this key now - it cannot be recovered![/]\n\n"
            "Add to config/sentinel.yaml:\n"
            f"  api:\n"
            f"    auth:\n"
            f"      api_keys:\n"
            f"        {name}:\n"
            f'          key_hash: "{key_hash}"\n'
            f'          name: "{name}"\n'
            f"          scopes:\n"
            f'            - "read"\n'
            f'            - "write"',
            title=f"New API Key: {name}",
        )
    )


def main():
    """Main entry point for CLI."""
    app()


if __name__ == "__main__":
    main()
