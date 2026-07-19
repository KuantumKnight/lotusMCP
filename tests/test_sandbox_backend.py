"""Host Kali executor backend tests.

These tests do not require live targets or network. They validate the impure
runner's destination extraction and second scope choke without spawning tools.

    PYTHONPATH=. PYTHONIOENCODING=utf-8 python tests/test_sandbox_backend.py
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from lotusmcp.engine.scope import Scope  # noqa: E402
from lotusmcp.executor.argv import ArgvPlan  # noqa: E402
from lotusmcp.executor.sandbox import backend_from_env, plan_destinations, plan_in_scope  # noqa: E402


def _plan(tool, argv):
    return ArgvPlan(tool=tool, argv=tuple(argv), capability=tool, target_id="T1")


def test_extracts_destinations_from_validated_plans():
    assert plan_destinations(_plan("nmap", ["nmap", "--", "10.10.11.53"])) == [
        ("10.10.11.53", None)
    ]
    assert plan_destinations(_plan("curl", ["curl", "--", "http://h.htb:8080/a"])) == [
        ("h.htb", 8080)
    ]
    ffuf = _plan("ffuf", ["ffuf", "-w", "w", "-u", "https://h.htb/FUZZ"])
    assert plan_destinations(ffuf) == [("h.htb", 443)]


def test_scope_refuses_out_of_scope_before_spawn():
    scope = Scope.from_payload({"hosts": ["10.10.11.0/24"], "ports": [80]})
    plan = _plan("curl", ["curl", "--", "http://9.9.9.9:80/"])
    assert plan_in_scope(plan, scope) is False


def test_backend_from_env_is_host_only():
    backend = backend_from_env()
    assert backend.__class__.__name__ == "SubprocessBackend"


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items())
           if k.startswith("test_") and callable(v)]
    failed = 0
    for fn in fns:
        try:
            fn()
            print(f"  ok  {fn.__name__}")
        except Exception as e:  # noqa: BLE001
            failed += 1
            print(f"FAIL  {fn.__name__}: {e}")
    print(f"\n{len(fns) - failed}/{len(fns)} passed")
    sys.exit(1 if failed else 0)
