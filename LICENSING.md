# Commercial Licensing — Sentinel

This project is dual-licensed:

- **AGPL-3.0** — Free for open-source use with copyleft obligations
- **Commercial License** — Proprietary use without AGPL requirements

## Tiers

| Feature | Community (Free) | Pro ($149/mo) | Enterprise ($499/mo) |
|---------|:---:|:---:|:---:|
| Device discovery & scans | Yes | Yes | Yes |
| Blocked IPs & quarantine status | Yes | Yes | Yes |
| Quick & full network scans | Yes | Yes | Yes |
| AI agents (Guardian, Optimizer, Healer) | — | Yes | Yes |
| Policy & VLAN management | — | Yes | Yes |
| Autonomous response | — | — | Yes |
| Network topology & visualization | — | — | Yes |
| Fleet-wide security orchestration | — | — | Yes |
| Support SLA | Community | 48h email | 4h priority |

## Getting a License

Visit **https://1450enterprises.com/pricing** or contact sales@1450enterprises.com.

```bash
export SENTINEL_LICENSE_KEY="your-key-here"
export SENTINEL_SERVER="https://api.1450enterprises.com"
```

## Feature Flags

| Flag | Tier |
|------|------|
| `std.sentinel.discovery` | Pro |
| `std.sentinel.autonomous` | Enterprise |
| `std.sentinel.topology` | Enterprise |
