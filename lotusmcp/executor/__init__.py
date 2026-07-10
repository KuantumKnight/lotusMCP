"""Executor boundary — the only layer that turns a decided action into a real
command line. Everything here is a *pure* argv builder + validator: no process
is ever spawned in this module, so it runs and is testable on Windows with no
Kali present. The sandboxed runner (Phase 1, Linux-only) consumes these argv
vectors; it never constructs a command itself.
"""
from lotusmcp.executor.argv import (
    ArgvPlan,
    ArgvRejected,
    NoAdapter,
    build_argv,
)
from lotusmcp.executor.plan import plan_action

__all__ = ["ArgvPlan", "ArgvRejected", "NoAdapter", "build_argv", "plan_action"]
