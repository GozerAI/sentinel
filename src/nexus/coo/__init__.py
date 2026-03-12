"""
Nexus COO Module - Chief Operating Officer orchestration.

The COO orchestrates operations across C-level executives:
- CIO (Sentinel): Infrastructure and security operations
- CTO (Forge): Software development and product operations

Usage:
    from nexus.coo import COOOrchestrator, COOTask, TaskDomain

    # Initialize COO
    coo = COOOrchestrator()
    await coo.initialize(cio=sentinel_agent, cto=forge_agent)

    # Execute task
    result = await coo.execute({
        "task_type": "security.block_ip",
        "parameters": {"ip": "10.0.0.50"},
    })

    # Execute workflow
    result = await coo.execute_workflow([
        {"task_type": "security.scan", "parameters": {}},
        {"task_type": "reliability.health_check", "parameters": {}},
    ])
"""

from nexus.coo.orchestrator import (
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
