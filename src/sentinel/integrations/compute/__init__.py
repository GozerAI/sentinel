"""
Compute cluster integrations for Sentinel.

Provides management of distributed compute resources including:
- Raspberry Pi clusters
- Docker/container orchestration
- Kubernetes (k3s) clusters
"""
from sentinel.integrations.compute.cluster import ComputeClusterManager
from sentinel.integrations.compute.node import ComputeNode

__all__ = [
    "ComputeClusterManager",
    "ComputeNode",
]
