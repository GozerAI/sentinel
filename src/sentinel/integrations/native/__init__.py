"""
Native integrations for Sentinel.

These integrations allow Sentinel to function as infrastructure directly,
rather than requiring external systems like OPNsense or UniFi.

Native capabilities:
- Firewall: nftables/iptables based packet filtering
- Network: Interface management and discovery
- DHCP: Built-in DHCP server
- DNS: Built-in DNS with filtering
"""

from sentinel.integrations.native.firewall import NativeFirewall
from sentinel.integrations.native.network import NetworkManager
from sentinel.integrations.native.dhcp import DHCPServer

__all__ = [
    "NativeFirewall",
    "NetworkManager",
    "DHCPServer",
]
