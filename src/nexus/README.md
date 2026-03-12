# Vendored Nexus Module

This is a **vendored (bundled) copy** of the minimal Nexus components required for Sentinel to operate standalone.

## Purpose

Sentinel needs to communicate with the COO (Chief Operating Officer) orchestration layer. Rather than requiring the full Nexus installation, this vendored copy contains only:

- `coo/` - COO Orchestrator for task routing
- `core/llm/` - LLM routing for CIO/CTO specialized models

## When to Use

**Use this vendored copy when:**
- Running Sentinel in isolation
- Deploying Sentinel on a dedicated security machine
- Testing Sentinel without full C-Suite installation

**Use the main Nexus (`src/nexus/`) when:**
- Running the full C-Suite platform
- Need access to all Nexus features (RAG, memory, experts, etc.)
- Running in the control plane deployment

## Updating

If you need to update this vendored copy:

1. Copy the required files from `src/nexus/`
2. Update imports to be relative within this package
3. Test Sentinel in isolation mode
4. Document any changes made

## Contents

```
nexus/
├── __init__.py          # Exports COOOrchestrator
├── coo/
│   ├── __init__.py
│   └── orchestrator.py  # Main COO orchestration logic
└── core/
    ├── __init__.py
    └── llm/
        ├── __init__.py
        ├── router.py      # Base LLM routing
        ├── cio_router.py  # Security-focused model selection
        └── cto_router.py  # Development-focused model selection
```

## Version

This vendored copy corresponds to Nexus v0.1.0.
Last updated: 2026-01-17
