"""repro.sh generation from the command trail (Phase 6).

The ReplayExecutor now records each validated argv as a command.requested
event; build_repro folds that trail into a deterministic, shell-quoted bash
script. This proves: the script reproduces the actual commands, is
byte-identical across rebuilds, shell-quotes every token, never echoes the
flag, and degrades gracefully when no command trail exists.

    PYTHONPATH=. PYTHONIOENCODING=utf-8 python tests/test_repro.py
"""
from __future__ import annotations

import shlex
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from lotusmcp.engine.loop import Loop
from lotusmcp.executor.replay import FixtureBackend, ReplayExecutor
from lotusmcp.kernel.case import Case
from lotusmcp.kernel.events import EventDraft
from lotusmcp.replay import build_repro
from tests.test_replay_executor import FIXTURES, HOST


def _solved_case(d):
    """Drive a real RECON→ENUMERATE→EXPLOIT walk through the argv boundary so
    the log carries a genuine command.requested trail."""
    case = Case.create(d, "repro", title="Titan", category="web",
                       flag_format=r"flag\{[^}]+\}", platform="HackTheBox")
    case.append(EventDraft("entity.asserted", {"kind": "executor", "name": "seed"},
                           {"kind": "host", "natural_key": {"addr": HOST}}))
    case.append(EventDraft("entity.asserted", {"kind": "executor", "name": "seed"},
                           {"kind": "service.http",
                            "natural_key": {"host": HOST, "proto": "tcp", "port": 80}}))
    loop = Loop(case, ReplayExecutor(FixtureBackend(FIXTURES)))
    for _ in range(12):
        if loop.step().halted:
            break
    return case


def test_repro_reproduces_recorded_commands():
    with tempfile.TemporaryDirectory() as d:
        case = _solved_case(d)
        script = build_repro(case)
        assert script.startswith("#!/usr/bin/env bash\n")
        assert "set -euo pipefail" in script
        # the real curl/nmap argv that ran must appear as runnable lines
        assert "curl" in script and "10.10.11.53" in script
        # phase section headers present, in walk order
        assert "# ── RECON ──" in script
        # steps are numbered
        assert "# [step 1]" in script
        print(script.splitlines()[1])
        print(f"repro.sh: {len(script.splitlines())} lines, "
              f"{script.count('# [step')} steps")


def test_repro_is_deterministic():
    with tempfile.TemporaryDirectory() as d:
        case = _solved_case(d)
        a = build_repro(case)
        b = build_repro(case)              # same log ⇒ byte-identical
        assert a == b, "repro.sh is not deterministic"
        print("repro.sh byte-identical across rebuilds")


def test_repro_shell_quotes_every_token():
    with tempfile.TemporaryDirectory() as d:
        case = _solved_case(d)
        script = build_repro(case)
        # every command line must parse as a shell word list without error, and
        # re-quoting its tokens must round-trip (i.e. it was already quoted).
        cmd_lines = [ln for ln in script.splitlines()
                     if ln and not ln.startswith("#") and ln != "set -euo pipefail"]
        assert cmd_lines, "no command lines emitted"
        for ln in cmd_lines:
            toks = shlex.split(ln)
            assert " ".join(shlex.quote(t) for t in toks) == ln, ln
        print(f"{len(cmd_lines)} command lines all safely shell-quoted")


def test_repro_never_echoes_the_flag():
    with tempfile.TemporaryDirectory() as d:
        case = _solved_case(d)
        # inject + verify a flag so flag.verified is in the log
        from lotusmcp.flag.facade import FlagEngine
        FLAG = "flag{repro_secret_1337}"
        eng = FlagEngine(case)
        eng.scan([f"note: {FLAG}"])
        dec = eng.decide()
        if dec.action == "SUBMIT":
            eng.submit(dec, lambda v: v == FLAG)
        script = build_repro(case)
        assert FLAG not in script, "repro.sh must not echo the raw flag"
        assert "FLAG_FOUND" in script or "flag.verified" in script
        print("flag value absent from repro.sh; outcome referenced by event")


def test_repro_graceful_without_command_trail():
    with tempfile.TemporaryDirectory() as d:
        # a scripted/no-exec case has no command.requested events
        case = Case.create(d, "empty", title="t", category="web")
        script = build_repro(case)
        assert script.startswith("#!/usr/bin/env bash\n")
        assert "No reproducible commands" in script
        # still a valid, non-crashing script body
        assert "set -euo pipefail" in script
        print("no-command case → valid script with honest note")


def test_repro_reflects_scope_when_present():
    with tempfile.TemporaryDirectory() as d:
        case = _solved_case(d)
        # simulate a loaded scope in meta (as rebuild surfaces it)
        import json
        (case.dir / "scope.json").write_text(
            json.dumps({"targets": [{"value": "10.10.11.53/32"}]}), encoding="utf-8")
        script = build_repro(case)
        assert "In-scope targets at capture: 10.10.11.53/32" in script
        print("scope targets surfaced in repro header")


TESTS = [v for k, v in sorted(globals().items()) if k.startswith("test_")]

if __name__ == "__main__":
    import traceback
    failed = 0
    for t in TESTS:
        try:
            t()
            print(f"ok   {t.__name__}")
        except Exception:  # noqa: BLE001
            failed += 1
            print(f"FAIL {t.__name__}")
            traceback.print_exc()
    print(f"\n{len(TESTS)-failed}/{len(TESTS)} passed")
    sys.exit(1 if failed else 0)
