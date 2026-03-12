#!/usr/bin/env bash
# export_public.sh — Creates a clean public export of Sentinel for GozerAI/sentinel.
# Usage: bash scripts/export_public.sh [target_dir]
#
# Strips proprietary modules (GUI, IoT, Nexus integration, orchestration bridges)
# and C-Suite references, leaving community-tier security monitoring code.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TARGET="${1:-${REPO_ROOT}/../sentinel-public-export}"

echo "=== Sentinel Public Export ==="
echo "Source: ${REPO_ROOT}"
echo "Target: ${TARGET}"

# Clean target
rm -rf "${TARGET}"
mkdir -p "${TARGET}"

# Use git archive to get a clean copy (respects .gitignore, excludes .git)
cd "${REPO_ROOT}"
git archive HEAD | tar -x -C "${TARGET}"

# ===== STRIP PROPRIETARY MODULES =====

# Pro tier — GUI visualization
rm -rf "${TARGET}/src/sentinel/gui/"
rm -rf "${TARGET}/J:devSentinelsrcsentinelgui/"
rm -f "${TARGET}/sentinel_gui.bat"

# Pro tier — orchestration bridges (C-Suite integration)
rm -rf "${TARGET}/src/sentinel/orchestration/"

# Pro tier — IoT classifier
rm -rf "${TARGET}/src/sentinel/iot/"

# Pro tier — visualization
rm -rf "${TARGET}/src/sentinel/visualization/"

# Enterprise tier — Nexus integration (C-Suite/ag3ntwerk bridge)
rm -f "${TARGET}/src/sentinel/nexus_agent.py"
rm -f "${TARGET}/src/sentinel/nexus_integration.py"

# ===== STRIP TESTS FOR PROPRIETARY MODULES =====
rm -f "${TARGET}/tests/test_gui.py"
rm -f "${TARGET}/tests/test_orchestration_bridges.py"
rm -f "${TARGET}/tests/test_iot_classifier.py"
rm -f "${TARGET}/tests/test_visualization.py"
rm -f "${TARGET}/tests/test_cto_architecture.py"

# ===== STRIP INTERNAL FILES =====
rm -rf "${TARGET}/.github/"
rm -f "${TARGET}/CLAUDE.md"
rm -f "${TARGET}/.env.example"
rm -f "${TARGET}/Sentinel_plan.md"
rm -f "${TARGET}/gozer_ai_apparatus.md"
rm -f "${TARGET}/gozer_core.md"
rm -rf "${TARGET}/docs/"

# Remove tmpclaude temp files
find "${TARGET}" -name "tmpclaude-*" -delete 2>/dev/null || true

# ===== FIX __init__.py — Remove Nexus imports =====
cat > "${TARGET}/src/sentinel/__init__.py" << 'PYEOF'
"""
Sentinel - AI Security Monitoring and Threat Detection

An autonomous infrastructure management platform that uses AI agents
to manage, monitor, secure, and optimize IT operations.

Part of the GozerAI ecosystem.
"""

__version__ = "0.2.0"
__author__ = "GozerAI"

from sentinel.core.engine import SentinelEngine
from sentinel.core.event_bus import EventBus
from sentinel.core.state import StateManager
from sentinel.core.scheduler import Scheduler
from sentinel.core.config import load_config, SentinelConfig

__all__ = [
    "__version__",
    "SentinelEngine",
    "EventBus",
    "StateManager",
    "Scheduler",
    "load_config",
    "SentinelConfig",
]
PYEOF

# ===== CREATE STUB __init__.py FOR STRIPPED PACKAGES =====

STUB_CONTENT='"""This module requires a commercial license.

Visit https://gozerai.com/pricing for Pro and Enterprise tier details.
Set VINZY_LICENSE_KEY to unlock licensed features.
"""

raise ImportError(
    f"{__name__} requires a commercial license. "
    "Visit https://gozerai.com/pricing for details."
)'

for pkg in gui orchestration iot visualization; do
    mkdir -p "${TARGET}/src/sentinel/${pkg}"
    echo "${STUB_CONTENT}" > "${TARGET}/src/sentinel/${pkg}/__init__.py"
done

# ===== SANITIZE REFERENCES =====
find "${TARGET}" -type f \( -name "*.py" -o -name "*.md" -o -name "*.yml" -o -name "*.yaml" -o -name "*.toml" -o -name "*.txt" -o -name "*.cfg" -o -name "*.sh" -o -name "Dockerfile" -o -name "*.bat" \) -exec sed -i \
    -e 's|1450enterprises\.com|gozerai.com|g' \
    -e 's|chrisarseno/sentinel|GozerAI/sentinel|g' \
    -e 's|chrisarseno@[a-zA-Z.]*|dev@gozerai.com|g' \
    {} +

# Warn about remaining C-Suite references
for f in $(grep -rl "c-suite\|csuite\|c_suite\|1450" "${TARGET}/src/sentinel/" 2>/dev/null || true); do
    echo "WARNING: Internal reference found in kept file: ${f}"
    echo "  Review and manually clean if needed."
done

echo ""
echo "=== Sentinel Public Export ==="
echo ""
echo "Community-tier modules included:"
echo "  core/ (engine, event bus, state, scheduler, config)"
echo "  agents/ (guardian, healer, discovery, optimizer, planner, strategy)"
echo "  api/ (REST endpoints)"
echo "  cli/ (command-line interface)"
echo "  integrations/ (network integrations — routers, switches, etc.)"
echo "  assets/ (static assets)"
echo "  main.py (entry point)"
echo ""
echo "Stripped (Pro/Enterprise/Private):"
echo "  gui/ (Pro), orchestration/ (Pro — C-Suite bridges),"
echo "  iot/ (Pro), visualization/ (Pro),"
echo "  nexus_agent.py (Enterprise), nexus_integration.py (Enterprise)"
echo ""
echo "Next steps:"
echo "  cd ${TARGET}"
echo "  git init && git add -A && git commit -m 'Initial public release'"
echo "  gh repo create GozerAI/sentinel --public --description 'AI security monitoring and threat detection — Part of the GozerAI ecosystem'"
echo "  git remote add origin https://github.com/GozerAI/sentinel.git"
echo "  git push -u origin main"
echo "  gh release create v1.0.0 --title 'v1.0.0' --notes 'Initial public release under GozerAI organization. Community-tier features included. Pro/Enterprise features require a commercial license — visit https://gozerai.com/pricing'"
