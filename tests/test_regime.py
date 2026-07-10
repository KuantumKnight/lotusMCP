"""Regime routing: which phases/categories are interactive code-synthesis (§4.2).

    PYTHONPATH=. PYTHONIOENCODING=utf-8 python tests/test_regime.py
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from lotusmcp.engine.regime import INTERACTIVE, PLANNER, is_interactive, regime  # noqa: E402


def test_planner_phases_never_interactive():
    for phase in ("TRIAGE", "RECON", "ENUMERATE"):
        for cat in ("pwn", "web", "crypto", "rev", "forensics", None):
            assert regime(phase, cat) == PLANNER, (phase, cat)


def test_exploit_phases_interactive_for_code_synthesis_categories():
    for phase in ("EXPLOIT", "POST_EXPLOIT"):
        for cat in ("pwn", "rev", "crypto", "web"):
            assert regime(phase, cat) == INTERACTIVE, (phase, cat)


def test_exploit_phase_planner_for_checklist_categories():
    for cat in ("forensics", "osint", "misc", None, ""):
        assert regime("EXPLOIT", cat) == PLANNER, cat


def test_case_insensitive_and_whitespace():
    assert regime("EXPLOIT", "  PWN ") == INTERACTIVE
    assert regime("EXPLOIT", "Web") == INTERACTIVE


def test_terminal_phases_are_planner():
    for phase in ("SOLVED_PENDING_SUBMIT", "FLAG_FOUND", "EXHAUSTED", "ESCALATED"):
        assert regime(phase, "pwn") == PLANNER


def test_is_interactive_helper():
    assert is_interactive("EXPLOIT", "pwn")
    assert not is_interactive("RECON", "pwn")


if __name__ == "__main__":
    import traceback

    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    failed = 0
    for fn in fns:
        try:
            fn()
            print(f"ok   {fn.__name__}")
        except Exception:  # noqa: BLE001
            failed += 1
            print(f"FAIL {fn.__name__}")
            traceback.print_exc()
    print(f"\n{len(fns) - failed}/{len(fns)} passed")
    sys.exit(1 if failed else 0)
