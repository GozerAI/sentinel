"""
Nexus LLM Module - Domain-specific LLM routing for C-level executives.

Each C-level executive (CIO, CTO, COO) has their own LLM router with a
model pool optimized for their domain. This prevents bottlenecks and
allows fine-grained control over model selection per task type.

Architecture:
    ┌─────────────────────────────────────────────────────────────────┐
    │                         COO (Nexus)                             │
    │                              │                                  │
    │              ┌───────────────┼───────────────┐                  │
    │              ▼               ▼               ▼                  │
    │       ┌──────────┐    ┌──────────┐    ┌──────────┐             │
    │       │CIORouter │    │CTORouter │    │COORouter │             │
    │       │(Sentinel)│    │ (Forge)  │    │ (Nexus)  │             │
    │       └────┬─────┘    └────┬─────┘    └────┬─────┘             │
    │            │               │               │                    │
    │       ┌────▼────┐     ┌────▼────┐     ┌────▼────┐              │
    │       │Infra    │     │Dev      │     │Business │              │
    │       │Models   │     │Models   │     │Models   │              │
    │       └─────────┘     └─────────┘     └─────────┘              │
    └─────────────────────────────────────────────────────────────────┘

Model Tiers:
    - FAST: Low latency, smaller models (7B) for real-time tasks
    - BALANCED: Good quality/speed trade-off (13B-33B)
    - QUALITY: Best output quality (70B+ or cloud APIs)
    - SPECIALIZED: Domain-specific models (code, config, etc.)

Usage:
    from nexus.core.llm import CIORouter, CTORouter

    # Initialize CIO router for infrastructure tasks
    cio_router = CIORouter(config)
    await cio_router.initialize()

    # Analyze a threat (uses FAST tier)
    result = await cio_router.analyze_threat(threat_data)

    # Initialize CTO router for development tasks
    cto_router = CTORouter(config)
    await cto_router.initialize()

    # Generate code (uses QUALITY tier)
    result = await cto_router.generate_code(spec, language="python")
"""

from nexus.core.llm.router import (
    LLMRouter,
    ModelConfig,
    ModelTier,
    ModelProvider,
    RoutingResult,
    CompletionResult,
)

from nexus.core.llm.cio_router import CIORouter
from nexus.core.llm.cto_router import CTORouter

__all__ = [
    # Base classes
    "LLMRouter",
    "ModelConfig",
    "ModelTier",
    "ModelProvider",
    "RoutingResult",
    "CompletionResult",
    # Domain routers
    "CIORouter",
    "CTORouter",
]
