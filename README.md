# Sentinel

[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

AI-powered security monitoring and threat detection platform. Uses autonomous agents to scan networks, discover devices, manage VLANs, detect threats, and enforce security policies.

Part of the [GozerAI](https://gozerai.com) ecosystem.

## Features

- **Network discovery** with automatic device classification and topology mapping
- **Threat detection** with SOC operations, IP blocking, and device quarantine
- **VLAN management** with segmentation policies and firewall rules
- **Self-healing** with automated failover and health monitoring
- **Traffic optimization** with QoS management and NetFlow analysis
- **REST API** with API key and JWT authentication

## Feature Tiers

| Feature | Community | Pro | Enterprise |
|---------|:---------:|:---:|:----------:|
| Network & discovery agents | x | x | x |
| REST API & core engine | x | x | x |
| Native integrations | x | x | x |
| GUI dashboard | | x | x |
| Orchestration engine | | x | x |
| IoT device management | | x | x |
| Visualization & reporting | | x | x |
| Nexus integration | | | x |

## Agents

| Agent | Role | Description |
|-------|------|-------------|
| **Guardian** | Security | SOC operations, threat detection, IP blocking, quarantine |
| **Healer** | Reliability | SRE operations, self-repair, health monitoring, failover |
| **Discovery** | Asset Management | Network scanning, device classification, topology |
| **Optimizer** | Network Ops | Traffic engineering, QoS, NetFlow analysis |
| **Planner** | Architecture | VLAN design, segmentation policies, firewall rules |
| **Strategy** | Executive | Agent coordination, decision approval, oversight |

## Quick Start

```bash
git clone https://github.com/GozerAI/sentinel.git
cd sentinel
pip install -e ".[dev]"

# Copy and edit configuration
cp config.example.yaml config/config.yaml
# Edit config.yaml — set network ranges, credentials, auth settings

# Start the server
python -m sentinel.main
```

## Configuration

Sentinel uses a YAML configuration file (`config/config.yaml`). Key sections:

```yaml
api:
  host: 0.0.0.0
  port: 8010
  auth:
    enabled: true
    jwt_secret: "your-secret"
    api_keys:
      my-key:
        name: "My API Key"
        scopes: ["read", "write"]

state:
  backend: sqlite           # memory, sqlite, postgresql, redis
  path: /var/lib/sentinel/state.db

network:
  scan_range: "192.168.1.0/24"
  scan_interval: 300         # seconds

integrations:
  router:
    type: opnsense
    host: 192.168.1.1
    api_key: ""
    api_secret: ""
```

## API Reference

Authentication: `X-API-Key: <key>` or `Authorization: Bearer <jwt_token>`.

### Network & Discovery

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/devices` | List discovered devices |
| GET | `/api/v1/devices/:id` | Device details |
| POST | `/api/v1/scan` | Trigger network scan |
| GET | `/api/v1/topology` | Network topology map |

### Security

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/events` | Security events |
| GET | `/api/v1/threats` | Active threats |
| POST | `/api/v1/quarantine/:device_id` | Quarantine a device |
| POST | `/api/v1/block/:ip` | Block an IP address |

### VLANs & Segmentation

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/vlans` | List VLANs |
| POST | `/api/v1/vlans` | Create a VLAN |
| GET | `/api/v1/policies` | Segmentation policies |
| POST | `/api/v1/policies` | Create a policy |

### System

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/agents` | Agent statuses |
| GET | `/api/v1/health` | System health |
| GET | `/api/v1/metrics` | Metrics and statistics |

## Docker

```bash
docker compose up -d
```

See `docker-compose.yml` for configuration options and `deploy/` for production deployment scripts.

## License

MIT — see [LICENSE](LICENSE) for details. Learn more at [gozerai.com](https://gozerai.com).
