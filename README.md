# Sentinel - AI-Native Chief Information Officer (CIO)

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

**AI-Native Infrastructure Management with Autonomous Operations**

Sentinel is an autonomous CIO platform that uses AI agents to manage, monitor, secure, and optimize internal IT operations. It provides real-time network discovery, automatic segmentation, traffic optimization, security enforcement, and self-healing capabilities.

## CIO vs CTO Function

Sentinel serves as the **CIO function** - managing internal infrastructure and operations:

| CIO (Sentinel) | CTO (Coming Soon) |
|----------------|-------------------|
| Internal infrastructure | External products |
| IT operations | Product development |
| Security & compliance | Technical strategy |
| Network management | Customer solutions |
| Asset inventory | Innovation R&D |

## Agent Council (CIO Team)

| Agent | Role | Function |
|-------|------|----------|
| **Guardian** | Chief Security Officer | SOC operations, threat detection, IP blocking, device quarantine |
| **Healer** | VP of Reliability | SRE operations, self-repair, health monitoring, automated failover |
| **Discovery** | IT Asset Manager | Network scanning, device classification, topology mapping |
| **Optimizer** | Network Operations | Traffic engineering, QoS management, NetFlow analysis |
| **Planner** | Infrastructure Architect | VLAN design, segmentation policies, firewall rules |
| **Strategy** | CIO Executive | Strategic oversight, agent coordination, decision approval |

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    SENTINEL CIO CONTROL PLANE                    │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│                     ┌──────────────────┐                        │
│                     │  Strategy Agent  │                        │
│                     │  (CIO Executive) │                        │
│                     └────────┬─────────┘                        │
│                              │                                   │
│    ┌─────────────────────────┼─────────────────────────┐        │
│    │                         │                          │        │
│    ▼                         ▼                          ▼        │
│ ┌──────────┐          ┌──────────┐              ┌──────────┐    │
│ │ Guardian │          │  Healer  │              │ Discovery│    │
│ │ (SecOps) │          │  (SRE)   │              │(AssetMgr)│    │
│ └────┬─────┘          └────┬─────┘              └────┬─────┘    │
│      │                     │                          │          │
│      └─────────────────────┼──────────────────────────┘          │
│                            │                                     │
│    ┌───────────────────────┼───────────────────────┐            │
│    │                       │                        │            │
│    ▼                       ▼                        ▼            │
│ ┌──────────┐         ┌──────────┐            ┌──────────┐       │
│ │Optimizer │         │ Planner  │            │Event Bus │       │
│ │(NetOps)  │         │(InfrArch)│            │(Comms)   │       │
│ └──────────┘         └──────────┘            └──────────┘       │
│                                                                  │
├─────────────────────────────────────────────────────────────────┤
│                      INTEGRATIONS LAYER                          │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐        │
│  │ OPNsense │  │  UniFi   │  │ Proxmox  │  │ TrueNAS  │        │
│  │ (Router) │  │ (Switch) │  │(Compute) │  │(Storage) │        │
│  └──────────┘  └──────────┘  └──────────┘  └──────────┘        │
└─────────────────────────────────────────────────────────────────┘
```

## Key Capabilities

### Security (Guardian)
- Real-time threat detection and response
- Automated IP blocking with router integration
- Device quarantine via VLAN isolation
- Failed authentication tracking
- Security event correlation

### Reliability (Healer)
- Infrastructure health monitoring
- Automated failover and recovery
- Predictive failure detection
- Self-healing workflows

### Asset Management (Discovery)
- Continuous network scanning
- Device fingerprinting and classification
- LLDP-based topology mapping
- Infrastructure auto-detection (MikroTik, RPi, NAS)
- IoT device classification

### Network Operations (Optimizer)
- NetFlow/IPFIX traffic analysis
- Automatic QoS policy application
- Bandwidth optimization
- Application classification

### Infrastructure Architecture (Planner)
- Automated VLAN design
- Firewall rule management
- Network segmentation policies
- Security zone enforcement

## Quick Start

### Prerequisites

- Python 3.11+
- Network equipment with API access (OPNsense, UniFi, etc.)

### Installation

```bash
# Clone the repository
git clone https://github.com/chrisarseno/sentinel.git
cd sentinel

# Create virtual environment
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install dependencies
pip install -e ".[dev]"

# Copy and configure settings
cp config/default.yaml config/local.yaml
# Edit config/local.yaml with your settings
```

### Running

```bash
# Start GUI application
python -m sentinel.gui

# Or start the engine directly
python -m sentinel.main --config config/local.yaml
```

### Configuration

```yaml
# Enable network scanning (disabled by default for safety)
agents:
  discovery:
    enable_scanning: true
    networks:
      - "192.168.1.0/24"

# Configure integrations
integrations:
  router:
    type: "opnsense"
    host: "192.168.1.1"
    api_key: "${ROUTER_API_KEY}"
    api_secret: "${ROUTER_API_SECRET}"

  switch:
    type: "ubiquiti"
    controller_url: "https://192.168.1.2:8443"
    username: "${UNIFI_USER}"
    password: "${UNIFI_PASS}"

# Enable NetFlow collection
agents:
  optimizer:
    netflow_enabled: true
    netflow_port: 2055
```

## Project Structure

```
sentinel/
├── src/sentinel/
│   ├── core/           # Engine, event bus, state management
│   ├── agents/         # AI agents (Guardian, Healer, etc.)
│   ├── integrations/   # Router, switch, compute, storage
│   ├── gui/            # Desktop application
│   ├── api/            # REST API
│   └── iot/            # IoT classifier and segmenter
├── tests/              # Test suite
├── config/             # Configuration files
├── deploy/             # Deployment configurations
└── docs/               # Documentation
```

## Development

```bash
# Install dev dependencies
pip install -e ".[dev]"

# Run tests
pytest

# Format code
black src tests

# Type checking
mypy src
```

## Roadmap

### Phase 1: CIO Foundation (Current)
- [x] Agent architecture with event bus
- [x] Router integration (OPNsense)
- [x] Switch integration (UniFi)
- [x] Network discovery and topology
- [x] Security enforcement (Guardian)
- [x] NetFlow traffic analysis
- [x] QoS policy application

### Phase 2: CIO Enhancement
- [ ] LLM-assisted decision making
- [ ] Predictive failure analysis
- [ ] Advanced threat correlation
- [ ] Multi-site support

### Phase 3: CTO System
- [ ] Product Architect Agent
- [ ] Tech Debt Tracker Agent
- [ ] Developer Experience Agent
- [ ] Innovation Scout Agent

### Phase 4: Executive Coordination
- [ ] CIO-CTO communication layer
- [ ] Unified dashboards
- [ ] Cross-domain insights

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- Part of the GozerAI ecosystem
- Built with [Pydantic](https://pydantic.dev/), [PySide6](https://wiki.qt.io/Qt_for_Python), and [asyncio](https://docs.python.org/3/library/asyncio.html)

---

**Documentation**: [https://sentinel.gozerai.com/docs](https://sentinel.gozerai.com/docs)
**Issues**: [https://github.com/chrisarseno/sentinel/issues](https://github.com/chrisarseno/sentinel/issues)
