"""Host Kali execution backend for the Phase-1 executor boundary.

The replay executor owns planning and parsing. This backend does the one impure
job left in Phase 1: execute an already-validated ``ArgvPlan`` on this Kali
machine with ``shell=False`` and return stdout.

No Docker, Podman, virtualenv, shell string, or command construction happens
here. The argv list from ``argv.py`` is executed verbatim after a second
backend-local scope check.
"""
from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass, field
from typing import Dict, List, Mapping, Optional

from lotusmcp.engine.scope import Scope
from lotusmcp.executor.argv import ArgvPlan


class SandboxUnavailable(RuntimeError):
    """The requested execution backend is not available on this host."""


def _url_host_port(value: str) -> tuple[Optional[str], Optional[int]]:
    """Minimal URL host/port extraction for argv produced by ``argv.py``.

    The URL was already schema-validated before reaching this point. This helper
    exists only for a second, backend-local scope check.
    """
    scheme = "http"
    rest = value
    if "://" in value:
        scheme, _, rest = value.partition("://")
    hostport = rest.split("/", 1)[0]
    if hostport.startswith("[") and "]" in hostport:
        host, _, tail = hostport[1:].partition("]")
        port_s = tail[1:] if tail.startswith(":") else ""
    else:
        host, _, port_s = hostport.partition(":")
    if not host:
        return None, None
    if port_s.isdigit():
        return host, int(port_s)
    return host, 443 if scheme == "https" else 80


def plan_destinations(plan: ArgvPlan) -> List[tuple[str, Optional[int]]]:
    """Extract network destinations from a validated plan.

    Host-level scans have no port yet and are checked with ``host_in_scope``.
    Service-level probes/fuzzing include a concrete port and are checked with
    ``in_scope``.
    """
    if plan.tool == "nmap":
        return [(plan.argv[-1], None)]
    if plan.tool == "curl":
        host, port = _url_host_port(plan.argv[-1])
        return [(host, port)] if host else []
    if plan.tool == "ffuf":
        try:
            url = plan.argv[plan.argv.index("-u") + 1]
        except (ValueError, IndexError):
            return []
        host, port = _url_host_port(url)
        return [(host, port)] if host else []
    return []


def plan_in_scope(plan: ArgvPlan, scope: Optional[Scope]) -> bool:
    if scope is None:
        return True
    for host, port in plan_destinations(plan):
        if port is None:
            if not scope.host_in_scope(host):
                return False
        elif not scope.in_scope(host, port):
            return False
    return True


def _scrubbed_env(extra: Optional[Mapping[str, str]] = None) -> Dict[str, str]:
    env = {
        "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
    }
    if extra:
        env.update({str(k): str(v) for k, v in extra.items()})
    return env


@dataclass
class SubprocessBackend:
    """Run validated plans directly on this Kali host."""

    scope: Optional[Scope] = None
    timeout: float = 60.0
    max_stdout: int = 4 * 1024 * 1024
    env: Mapping[str, str] = field(default_factory=dict)

    def __call__(self, plan: ArgvPlan) -> Optional[str]:
        if not plan_in_scope(plan, self.scope):
            return None
        if shutil.which(plan.argv[0]) is None:
            return None
        try:
            r = subprocess.run(
                list(plan.argv),
                shell=False,
                check=False,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=self.timeout,
                env=_scrubbed_env(self.env),
            )
        except (OSError, subprocess.TimeoutExpired):
            return None
        if r.returncode != 0 and not r.stdout:
            return None
        return r.stdout[: self.max_stdout]


def backend_from_env(scope: Optional[Scope] = None) -> SubprocessBackend:
    """Build the host executor backend.

    ``LOTUS_EXEC_BACKEND`` is accepted only for compatibility. The only
    supported value is ``subprocess`` because this deployment uses the exact
    Kali machine, not containers or venvs.
    """
    kind = os.environ.get("LOTUS_EXEC_BACKEND", "subprocess").strip().lower()
    if kind not in ("", "subprocess", "host"):
        raise SandboxUnavailable(
            f"unsupported LOTUS_EXEC_BACKEND={kind!r}; use 'subprocess'/'host'"
        )
    return SubprocessBackend(scope=scope)
