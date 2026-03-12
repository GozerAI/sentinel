"""
Nexus - Autonomous Operations Platform.

Nexus coordinates the C-level executive agents:
- COO (Chief Operating Officer): Orchestrates operations across CIO and CTO
- CIO (Sentinel): Infrastructure and security operations
- CTO (Forge): Software development and product operations

Usage:
    from nexus import COOOrchestrator
    from sentinel.nexus_agent import SentinelAgent

    # Initialize COO with CIO
    coo = COOOrchestrator()
    cio = SentinelAgent(config_path="config/sentinel.yaml")
    await coo.initialize(cio=cio)

    # Execute infrastructure task
    result = await coo.execute({
        "task_type": "security.block_ip",
        "parameters": {"ip": "10.0.0.50"},
    })
"""

__version__ = "0.1.0"

from nexus.coo import (
    COOOrchestrator,
    COOTask,
    COOConfig,
    TaskDomain,
    TaskPriority,
)

__all__ = [
    "COOOrchestrator",
    "COOTask",
    "COOConfig",
    "TaskDomain",
    "TaskPriority",
]
