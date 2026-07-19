"""Production launcher helpers.

Importing ``lotusmcp.server`` intentionally leaves EXEC tools fail-closed. A
real deployment imports this module before serving so the MCP-facing services
are wired to signed scope loading and the Linux executor backend.
"""
from __future__ import annotations

import json
from typing import Optional

from lotusmcp.engine.scope import ScopeError, ScopeVerifier
from lotusmcp.executor.replay import ReplayExecutor
from lotusmcp.executor.sandbox import backend_from_env
from lotusmcp.kernel.case import Case


def scope_for_case(case: Case, trusted_keys) -> Optional[object]:
    if not trusted_keys or not case.scope_path.exists():
        return None
    try:
        manifest = json.loads(case.scope_path.read_text(encoding="utf-8"))
        return ScopeVerifier(trusted_keys).load_scope(manifest)
    except (OSError, ValueError, ScopeError):
        return None


def configure_server(server_module) -> None:
    """Wire ``server.JOBS`` to the selected Linux executor backend.

    Scope still fails closed at the loop: no signed scope means no scope choke,
    but production operators should provide ``LOTUS_TRUSTED_OP_KEYS`` and a
    per-case ``scope.json`` before using FULL exec tools.
    """

    trusted = list(getattr(server_module.SESSIONS, "trusted_keys", []))

    def scope_factory(case: Case):
        return scope_for_case(case, trusted)

    def executor_factory(case: Case):
        return ReplayExecutor(backend_from_env(scope=scope_factory(case)))

    server_module.JOBS.configure(
        executor_factory=executor_factory,
        scope_factory=scope_factory,
    )


def main() -> None:
    from lotusmcp import server

    configure_server(server)
    server.mcp.run()


if __name__ == "__main__":
    main()
