# Sentinel Security Platform

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

**AI-Native Security Platform with Zero-Trust Architecture and Autonomous Network Management**

Sentinel is a comprehensive security platform that combines zero-trust architecture, intelligent network management, and AI-driven automation. It provides real-time network discovery, automatic segmentation, traffic optimization, and self-healing capabilities.

## Features

- **Zero-Trust Identity (Gatekeeper)**: Continuous authentication and authorization
- **Credential Management (Keymaster)**: Certificate lifecycle and secrets management
- **Network Fabric (NetMesh)**: Software-defined networking with automatic VLAN management
- **Firewall (Shield)**: L3-L7 inspection with WAF capabilities
- **Detection (Observer)**: SIEM/XDR with event correlation
- **AI Agents**: Autonomous network management with human-in-the-loop controls

## AI Agents

| Agent | Purpose |
|-------|---------|
| Discovery | Network scanning and device classification |
| Optimizer | Traffic engineering and QoS management |
| Planner | Segmentation and VLAN automation |
| Orchestrator | Workload placement and scaling |
| Forecaster | Predictive analytics and capacity planning |
| Healer | Self-repair and automated failover |
| Guardian | Security policy enforcement |

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    SENTINEL CONTROL PLANE                    │
├─────────────────────────────────────────────────────────────┤
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────┐  │
│  │  Gatekeeper  │  │   Keymaster  │  │  Policy Engine   │  │
│  │  (Identity)  │  │ (Credentials)│  │  (Zero-Trust)    │  │
│  └──────────────┘  └──────────────┘  └──────────────────┘  │
│                           │                                  │
│                    ┌──────┴──────┐                          │
│                    │   AI Agents  │                          │
│                    │   Council    │                          │
│                    └──────┬──────┘                          │
│                           │                                  │
│  ┌──────────────┐  ┌──────┴──────┐  ┌──────────────────┐  │
│  │   NetMesh    │  │   Shield    │  │    Observer      │  │
│  │  (Network)   │  │ (Firewall)  │  │    (SIEM)        │  │
│  └──────────────┘  └─────────────┘  └──────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

## Quick Start

### Prerequisites

- Python 3.11+
- Docker and Docker Compose (for deployment)
- Network equipment with API access (OPNsense, UniFi, etc.)
- Ollama (for local AI inference)

### Installation

```bash
# Clone the repository
git clone https://github.com/1450enterprises/sentinel.git
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
# Start with local configuration
sentinel --config config/local.yaml

# Or run directly with Python
python -m sentinel.main --config config/local.yaml

# Run with Docker
docker-compose -f deploy/docker/docker-compose.prod.yml up -d
```

### Configuration

See `config/homelab.yaml` for a complete configuration example. Key settings:

```yaml
integrations:
  router:
    type: "opnsense"
    host: "192.168.1.1"
    api_key: "${ROUTER_API_KEY}"
    
  switch:
    type: "ubiquiti"
    controller_url: "https://192.168.1.2:8443"
    
  llm:
    primary:
      type: "ollama"
      host: "http://localhost:11434"
      model: "llama3.1:8b"
```

## Project Structure

```
sentinel/
├── src/sentinel/
│   ├── core/           # Core engine and models
│   ├── agents/         # AI agents
│   ├── integrations/   # External system integrations
│   ├── api/            # REST API
│   └── cli/            # Command-line interface
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

# Run tests with coverage
pytest --cov=sentinel --cov-report=html

# Format code
black src tests

# Lint code
ruff check src tests

# Type checking
mypy src
```

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- Part of the GozerAI ecosystem by 1450 Enterprises LLC
- Built with [Pydantic](https://pydantic.dev/), [FastAPI](https://fastapi.tiangolo.com/), and [Ollama](https://ollama.ai/)

---

**Documentation**: [https://sentinel.1450enterprises.com/docs](https://sentinel.1450enterprises.com/docs)  
**Issues**: [https://github.com/1450enterprises/sentinel/issues](https://github.com/1450enterprises/sentinel/issues)
