"""
Reliability Specialists - Real implementations for infrastructure reliability.

These specialists perform actual reliability operations:
- Health checking with real probes
- Log analysis with LLM
- Service management
- Automated healing actions
"""

import asyncio
import json
import logging
import re
import socket
from datetime import datetime
from typing import Dict, List, Any, Optional, TYPE_CHECKING
import aiohttp

from sentinel.core.hierarchy.base import (
    Specialist,
    Task,
    TaskResult,
    SpecialistCapability,
)

if TYPE_CHECKING:
    from nexus.core.llm import LLMRouter

logger = logging.getLogger(__name__)


# ============================================================================
# HEALTH CHECK SPECIALIST
# ============================================================================


class HealthCheckSpecialist(Specialist):
    """
    Health check specialist for service and infrastructure monitoring.

    Capabilities:
    - HTTP/HTTPS endpoint health checks
    - TCP port connectivity checks
    - Ping/ICMP reachability
    - DNS resolution checks
    - Custom health endpoint parsing
    """

    def __init__(
        self,
        specialist_id: Optional[str] = None,
        llm_router: Optional["LLMRouter"] = None,
        default_timeout: float = 10.0,
    ):
        super().__init__(specialist_id, llm_router)
        self._default_timeout = default_timeout

    @property
    def capability(self) -> SpecialistCapability:
        return SpecialistCapability(
            name="Health Check Specialist",
            task_types=[
                "health.check",
                "health.check.service",
                "health.check.http",
                "health.check.tcp",
                "reliability.health_check",
            ],
            confidence=0.95,
            max_concurrent=20,
            description="Performs health checks on services and infrastructure",
        )

    async def _do_execute(self, task: Task) -> TaskResult:
        """Execute health check."""
        check_type = task.parameters.get("check_type", "http")
        target = task.parameters.get("target")
        timeout = task.parameters.get("timeout", self._default_timeout)

        if not target:
            return TaskResult(
                success=False,
                error="Target required for health check",
            )

        if check_type == "http" or check_type == "https":
            return await self._check_http(target, timeout, task.parameters)
        elif check_type == "tcp":
            return await self._check_tcp(target, timeout, task.parameters)
        elif check_type == "ping":
            return await self._check_ping(target, timeout)
        elif check_type == "dns":
            return await self._check_dns(target, timeout)
        else:
            return TaskResult(
                success=False,
                error=f"Unknown check type: {check_type}",
            )

    async def _check_http(self, target: str, timeout: float, params: Dict[str, Any]) -> TaskResult:
        """Perform HTTP health check."""
        url = target if target.startswith("http") else f"https://{target}"
        expected_status = params.get("expected_status", [200, 201, 204])
        expected_body = params.get("expected_body")
        headers = params.get("headers", {})

        start_time = datetime.now()

        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    url,
                    timeout=aiohttp.ClientTimeout(total=timeout),
                    headers=headers,
                    ssl=False,  # For self-signed certs
                ) as response:
                    status = response.status
                    body = await response.text()
                    response_time = (datetime.now() - start_time).total_seconds() * 1000

                    # Check status
                    if isinstance(expected_status, list):
                        status_ok = status in expected_status
                    else:
                        status_ok = status == expected_status

                    # Check body if specified
                    body_ok = True
                    if expected_body:
                        body_ok = expected_body in body

                    healthy = status_ok and body_ok

                    return TaskResult(
                        success=True,
                        output={
                            "check_type": "http",
                            "target": url,
                            "healthy": healthy,
                            "status_code": status,
                            "response_time_ms": round(response_time, 2),
                            "status_ok": status_ok,
                            "body_ok": body_ok,
                            "body_preview": body[:200] if body else None,
                        },
                        confidence=0.95,
                        metadata={"check_type": "http"},
                    )

        except asyncio.TimeoutError:
            return TaskResult(
                success=True,
                output={
                    "check_type": "http",
                    "target": url,
                    "healthy": False,
                    "error": "timeout",
                    "response_time_ms": timeout * 1000,
                },
                confidence=0.95,
                metadata={"check_type": "http"},
            )
        except Exception as e:
            return TaskResult(
                success=True,
                output={
                    "check_type": "http",
                    "target": url,
                    "healthy": False,
                    "error": str(e),
                },
                confidence=0.95,
                metadata={"check_type": "http"},
            )

    async def _check_tcp(self, target: str, timeout: float, params: Dict[str, Any]) -> TaskResult:
        """Perform TCP connectivity check."""
        # Parse target as host:port
        if ":" in target:
            host, port_str = target.rsplit(":", 1)
            port = int(port_str)
        else:
            host = target
            port = params.get("port", 80)

        start_time = datetime.now()

        try:
            # Use asyncio for non-blocking socket
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=timeout
            )
            writer.close()
            await writer.wait_closed()

            response_time = (datetime.now() - start_time).total_seconds() * 1000

            return TaskResult(
                success=True,
                output={
                    "check_type": "tcp",
                    "target": f"{host}:{port}",
                    "healthy": True,
                    "response_time_ms": round(response_time, 2),
                },
                confidence=0.95,
                metadata={"check_type": "tcp"},
            )

        except asyncio.TimeoutError:
            return TaskResult(
                success=True,
                output={
                    "check_type": "tcp",
                    "target": f"{host}:{port}",
                    "healthy": False,
                    "error": "connection_timeout",
                },
                confidence=0.95,
                metadata={"check_type": "tcp"},
            )
        except Exception as e:
            return TaskResult(
                success=True,
                output={
                    "check_type": "tcp",
                    "target": f"{host}:{port}",
                    "healthy": False,
                    "error": str(e),
                },
                confidence=0.95,
                metadata={"check_type": "tcp"},
            )

    async def _check_ping(self, target: str, timeout: float) -> TaskResult:
        """Perform ICMP ping check."""
        start_time = datetime.now()

        try:
            proc = await asyncio.create_subprocess_exec(
                "ping",
                "-c",
                "3",
                "-W",
                str(int(timeout)),
                target,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout + 5)

            output = stdout.decode()
            healthy = proc.returncode == 0

            # Parse ping output for stats
            stats = {}
            if healthy:
                # Extract packet loss
                loss_match = re.search(r"(\d+)% packet loss", output)
                if loss_match:
                    stats["packet_loss"] = int(loss_match.group(1))

                # Extract RTT
                rtt_match = re.search(r"min/avg/max.*= ([\d.]+)/([\d.]+)/([\d.]+)", output)
                if rtt_match:
                    stats["rtt_min"] = float(rtt_match.group(1))
                    stats["rtt_avg"] = float(rtt_match.group(2))
                    stats["rtt_max"] = float(rtt_match.group(3))

            return TaskResult(
                success=True,
                output={
                    "check_type": "ping",
                    "target": target,
                    "healthy": healthy,
                    "stats": stats,
                    "response_time_ms": (datetime.now() - start_time).total_seconds() * 1000,
                },
                confidence=0.95,
                metadata={"check_type": "ping"},
            )

        except Exception as e:
            return TaskResult(
                success=True,
                output={
                    "check_type": "ping",
                    "target": target,
                    "healthy": False,
                    "error": str(e),
                },
                confidence=0.95,
                metadata={"check_type": "ping"},
            )

    async def _check_dns(self, target: str, timeout: float) -> TaskResult:
        """Perform DNS resolution check."""
        start_time = datetime.now()

        try:
            loop = asyncio.get_event_loop()

            def resolve():
                return socket.gethostbyname(target)

            ip = await asyncio.wait_for(loop.run_in_executor(None, resolve), timeout=timeout)

            return TaskResult(
                success=True,
                output={
                    "check_type": "dns",
                    "target": target,
                    "healthy": True,
                    "resolved_ip": ip,
                    "response_time_ms": (datetime.now() - start_time).total_seconds() * 1000,
                },
                confidence=0.95,
                metadata={"check_type": "dns"},
            )

        except Exception as e:
            return TaskResult(
                success=True,
                output={
                    "check_type": "dns",
                    "target": target,
                    "healthy": False,
                    "error": str(e),
                },
                confidence=0.95,
                metadata={"check_type": "dns"},
            )


# ============================================================================
# LOG ANALYSIS SPECIALIST
# ============================================================================


class LogAnalysisSpecialist(Specialist):
    """
    Log analysis specialist with LLM-powered insights.

    Capabilities:
    - Parses and analyzes log data
    - Identifies errors, warnings, and anomalies
    - Extracts patterns and trends
    - Provides root cause suggestions
    """

    def __init__(
        self,
        specialist_id: Optional[str] = None,
        llm_router: Optional["LLMRouter"] = None,
    ):
        super().__init__(specialist_id, llm_router)

    @property
    def capability(self) -> SpecialistCapability:
        return SpecialistCapability(
            name="Log Analysis Specialist",
            task_types=[
                "health.analyze_logs",
                "reliability.log_analysis",
                "healing.analyze",
            ],
            confidence=0.85,
            max_concurrent=5,
            description="Analyzes logs for errors and anomalies",
        )

    async def _do_execute(self, task: Task) -> TaskResult:
        """Analyze logs."""
        logs = task.parameters.get("logs", "")
        log_type = task.parameters.get("log_type", "syslog")
        analysis_focus = task.parameters.get("focus", ["errors", "warnings", "patterns"])

        if not logs:
            return TaskResult(
                success=False,
                error="Log data required for analysis",
            )

        # Quick pattern-based analysis
        quick_analysis = self._quick_analyze(logs, log_type)

        # LLM deep analysis if available
        llm_analysis = None
        if self._llm_router:
            llm_analysis = await self._llm_analyze(logs, log_type, analysis_focus)

        # Merge analyses
        merged = self._merge_analyses(quick_analysis, llm_analysis)

        return TaskResult(
            success=True,
            output={
                "log_type": log_type,
                "log_lines": len(logs.split("\n")),
                "summary": merged.get("summary"),
                "errors": merged.get("errors", []),
                "warnings": merged.get("warnings", []),
                "patterns": merged.get("patterns", []),
                "anomalies": merged.get("anomalies", []),
                "recommendations": merged.get("recommendations", []),
                "severity": merged.get("severity", "info"),
                "quick_analysis": quick_analysis,
                "llm_analysis": llm_analysis,
            },
            confidence=0.85 if llm_analysis else 0.7,
            metadata={"log_type": log_type},
        )

    def _quick_analyze(self, logs: str, log_type: str) -> Dict[str, Any]:
        """Quick pattern-based log analysis."""
        lines = logs.split("\n")
        errors = []
        warnings = []
        patterns = {}

        error_patterns = [
            r"error",
            r"fail(ed|ure)?",
            r"exception",
            r"critical",
            r"fatal",
        ]

        warning_patterns = [
            r"warn(ing)?",
            r"deprecated",
            r"timeout",
            r"retry",
        ]

        for i, line in enumerate(lines):
            line_lower = line.lower()

            # Check for errors
            for pattern in error_patterns:
                if re.search(pattern, line_lower):
                    errors.append(
                        {
                            "line_number": i + 1,
                            "content": line[:200],
                            "pattern": pattern,
                        }
                    )
                    break

            # Check for warnings
            for pattern in warning_patterns:
                if re.search(pattern, line_lower):
                    warnings.append(
                        {
                            "line_number": i + 1,
                            "content": line[:200],
                            "pattern": pattern,
                        }
                    )
                    break

            # Extract common patterns (IPs, timestamps, etc.)
            ip_matches = re.findall(r"\d+\.\d+\.\d+\.\d+", line)
            for ip in ip_matches:
                patterns[ip] = patterns.get(ip, 0) + 1

        # Get top patterns
        top_patterns = sorted(patterns.items(), key=lambda x: -x[1])[:10]

        return {
            "error_count": len(errors),
            "warning_count": len(warnings),
            "errors": errors[:20],  # Limit to first 20
            "warnings": warnings[:20],
            "top_patterns": top_patterns,
            "total_lines": len(lines),
        }

    async def _llm_analyze(
        self, logs: str, log_type: str, focus: List[str]
    ) -> Optional[Dict[str, Any]]:
        """Deep log analysis using LLM."""
        system_prompt = """You are a systems engineer analyzing logs.
Analyze the logs for errors, warnings, anomalies, and patterns.
Respond with JSON:
{
    "summary": "brief summary of log health",
    "severity": "critical/high/medium/low/info",
    "errors": [{"description": "...", "likely_cause": "...", "line_hint": "..."}],
    "warnings": [{"description": "...", "potential_impact": "..."}],
    "anomalies": [{"description": "...", "deviation": "..."}],
    "patterns": [{"pattern": "...", "interpretation": "..."}],
    "recommendations": ["list of actionable recommendations"],
    "root_cause_hints": ["potential root causes if issues found"]
}"""

        # Truncate logs for LLM
        max_chars = 6000
        if len(logs) > max_chars:
            logs = logs[:max_chars] + "\n...[truncated]..."

        focus_text = ", ".join(focus)
        prompt = f"""Analyze these {log_type} logs, focusing on: {focus_text}

```
{logs}
```

Provide detailed analysis as JSON:"""

        try:
            response = await self.llm_complete(
                prompt=prompt,
                task_category="log_analysis",
                system_prompt=system_prompt,
            )

            if response:
                json_match = re.search(r"\{[\s\S]*\}", response)
                if json_match:
                    return json.loads(json_match.group())
        except Exception as e:
            logger.warning(f"LLM log analysis failed: {e}")

        return None

    def _merge_analyses(
        self, quick: Dict[str, Any], llm: Optional[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Merge quick and LLM analyses."""
        if not llm:
            return {
                "summary": f"Found {quick['error_count']} errors and {quick['warning_count']} warnings",
                "severity": (
                    "high"
                    if quick["error_count"] > 10
                    else "medium" if quick["error_count"] > 0 else "info"
                ),
                "errors": quick["errors"],
                "warnings": quick["warnings"],
                "patterns": [{"pattern": p[0], "count": p[1]} for p in quick["top_patterns"]],
            }

        # Prefer LLM analysis but include quick stats
        result = llm.copy()
        result["quick_stats"] = {
            "error_count": quick["error_count"],
            "warning_count": quick["warning_count"],
            "total_lines": quick["total_lines"],
        }

        return result


# ============================================================================
# SERVICE RECOVERY SPECIALIST
# ============================================================================


class ServiceRecoverySpecialist(Specialist):
    """
    Service recovery specialist for automated healing.

    Capabilities:
    - Restarts services via systemd or docker
    - Clears caches and temporary files
    - Performs basic recovery actions
    - Coordinates with LLM for complex recovery decisions
    """

    def __init__(
        self,
        specialist_id: Optional[str] = None,
        llm_router: Optional["LLMRouter"] = None,
        allowed_services: Optional[List[str]] = None,
    ):
        super().__init__(specialist_id, llm_router)
        self._allowed_services = allowed_services or []

    @property
    def capability(self) -> SpecialistCapability:
        return SpecialistCapability(
            name="Service Recovery Specialist",
            task_types=[
                "healing.recovery",
                "healing.restart",
                "service.restart",
                "reliability.restart_service",
            ],
            confidence=0.9,
            max_concurrent=3,
            description="Performs automated service recovery",
        )

    async def _do_execute(self, task: Task) -> TaskResult:
        """Execute recovery action."""
        action = task.parameters.get("action", "restart")
        service = task.parameters.get("service")
        service_type = task.parameters.get("service_type", "systemd")

        if not service:
            return TaskResult(
                success=False,
                error="Service name required for recovery",
            )

        # Safety check - only allow whitelisted services if configured
        if self._allowed_services and service not in self._allowed_services:
            return TaskResult(
                success=False,
                error=f"Service '{service}' not in allowed list",
                output={"allowed_services": self._allowed_services},
            )

        # Get LLM recommendation if available
        llm_recommendation = None
        if self._llm_router and task.parameters.get("analyze_first", True):
            llm_recommendation = await self._get_recovery_recommendation(
                service, action, task.parameters
            )

            if llm_recommendation and not llm_recommendation.get("proceed", True):
                return TaskResult(
                    success=False,
                    error="LLM recommended against this action",
                    output={"recommendation": llm_recommendation},
                )

        # Execute recovery
        if action == "restart":
            result = await self._restart_service(service, service_type)
        elif action == "stop":
            result = await self._stop_service(service, service_type)
        elif action == "start":
            result = await self._start_service(service, service_type)
        elif action == "clear_cache":
            result = await self._clear_cache(task.parameters)
        else:
            return TaskResult(
                success=False,
                error=f"Unknown recovery action: {action}",
            )

        result["llm_recommendation"] = llm_recommendation
        return TaskResult(
            success=result.get("success", False),
            output=result,
            confidence=0.9,
            metadata={"service": service, "action": action},
        )

    async def _restart_service(self, service: str, service_type: str) -> Dict[str, Any]:
        """Restart a service."""
        try:
            if service_type == "systemd":
                cmd = ["systemctl", "restart", service]
            elif service_type == "docker":
                cmd = ["docker", "restart", service]
            else:
                return {"success": False, "error": f"Unknown service type: {service_type}"}

            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=60)

            return {
                "success": proc.returncode == 0,
                "action": "restart",
                "service": service,
                "service_type": service_type,
                "stdout": stdout.decode()[:500],
                "stderr": stderr.decode()[:500],
                "return_code": proc.returncode,
            }

        except asyncio.TimeoutError:
            return {"success": False, "error": "Restart timed out"}
        except Exception as e:
            return {"success": False, "error": str(e)}

    async def _stop_service(self, service: str, service_type: str) -> Dict[str, Any]:
        """Stop a service."""
        try:
            if service_type == "systemd":
                cmd = ["systemctl", "stop", service]
            elif service_type == "docker":
                cmd = ["docker", "stop", service]
            else:
                return {"success": False, "error": f"Unknown service type: {service_type}"}

            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=30)

            return {
                "success": proc.returncode == 0,
                "action": "stop",
                "service": service,
                "stdout": stdout.decode()[:500],
                "stderr": stderr.decode()[:500],
            }

        except Exception as e:
            return {"success": False, "error": str(e)}

    async def _start_service(self, service: str, service_type: str) -> Dict[str, Any]:
        """Start a service."""
        try:
            if service_type == "systemd":
                cmd = ["systemctl", "start", service]
            elif service_type == "docker":
                cmd = ["docker", "start", service]
            else:
                return {"success": False, "error": f"Unknown service type: {service_type}"}

            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=30)

            return {
                "success": proc.returncode == 0,
                "action": "start",
                "service": service,
                "stdout": stdout.decode()[:500],
                "stderr": stderr.decode()[:500],
            }

        except Exception as e:
            return {"success": False, "error": str(e)}

    async def _clear_cache(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Clear cache for a service or system."""
        cache_type = params.get("cache_type", "system")
        target = params.get("target")

        try:
            if cache_type == "system":
                # Clear Linux page cache (requires root)
                proc = await asyncio.create_subprocess_exec(
                    "sh",
                    "-c",
                    "sync; echo 3 > /proc/sys/vm/drop_caches",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                await proc.communicate()
                return {"success": True, "action": "clear_cache", "cache_type": "system"}

            elif cache_type == "docker":
                proc = await asyncio.create_subprocess_exec(
                    "docker",
                    "system",
                    "prune",
                    "-f",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, _ = await proc.communicate()
                return {
                    "success": proc.returncode == 0,
                    "action": "clear_cache",
                    "cache_type": "docker",
                    "output": stdout.decode()[:500],
                }

            else:
                return {"success": False, "error": f"Unknown cache type: {cache_type}"}

        except Exception as e:
            return {"success": False, "error": str(e)}

    async def _get_recovery_recommendation(
        self, service: str, action: str, params: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        """Get LLM recommendation for recovery action."""
        system_prompt = """You are an SRE expert evaluating service recovery actions.
Analyze the proposed action and provide a recommendation.
Respond with JSON:
{
    "proceed": true/false,
    "confidence": 0.0-1.0,
    "reasoning": "explanation",
    "alternatives": ["alternative actions if not proceeding"],
    "precautions": ["precautions to take before proceeding"]
}"""

        context = params.get("context", {})
        prompt = f"""Evaluate this service recovery action:

Service: {service}
Action: {action}
Current Status: {context.get('status', 'unknown')}
Error: {context.get('error', 'N/A')}
Recent Events: {context.get('recent_events', [])}

Should this recovery action proceed?"""

        try:
            response = await self.llm_complete(
                prompt=prompt,
                task_category="incident_response",
                system_prompt=system_prompt,
            )

            if response:
                json_match = re.search(r"\{[\s\S]*\}", response)
                if json_match:
                    return json.loads(json_match.group())
        except Exception as e:
            logger.warning(f"LLM recovery recommendation failed: {e}")

        return None
