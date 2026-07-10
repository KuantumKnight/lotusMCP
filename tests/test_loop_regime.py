"""The OODA loop routing an exploit phase to a Regime-B interactive session
instead of the planner (Phase 4).

    PYTHONPATH=. PYTHONIOENCODING=utf-8 python tests/test_loop_regime.py
"""
from __future__ import annotations

import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from lotusmcp.control_plane.keyring import SigningKey, sign_manifest  # noqa: E402
from lotusmcp.engine.loop import Loop  # noqa: E402
from lotusmcp.engine.scope import ScopeVerifier  # noqa: E402
from lotusmcp.kernel.case import Case  # noqa: E402
from lotusmcp.kernel.events import EventDraft  # noqa: E402
from lotusmcp.session import (  # noqa: E402
    DeterministicScriptAuthor,
    DeterministicScriptRunner,
    InteractiveSession,
    ScriptedTube,
)

FMT = r"flag\{[^}]+\}"
FLAG = "flag{f0rmat_str1ng_pwn_1337}"
HOST = "10.10.11.53"
PORT = 1337
OP = SigningKey.generate()
SCOPE = {"hosts": ["10.10.11.0/24"], "ports": [PORT], "auto_cap": 2}


def _scope():
    m = sign_manifest(OP, "scope", "c1", SCOPE)
    return ScopeVerifier(trusted_operator_keys={OP.public_hex}).load_scope(m)


def _win_tube():
    def responder(sent, _t):
        return f"leaked: {FLAG}\n" if sent.strip() == "%7$s" else "nope\n> "
    return ScriptedTube(responder, greeting="pwnme\n> ")


def _provider(strategies, tube_factory=_win_tube):
    def provider(*, case, sid, entity, goal, flag, budget, scope, phase):
        return InteractiveSession(
            case, sid, entity, goal, tube_factory(),
            DeterministicScriptAuthor(strategies), DeterministicScriptRunner(),
            flag, budget, scope=scope, phase=phase)
    return provider


class TrackingExecutor:
    """The planner ACT path — must never run while a session owns the step."""

    def __init__(self):
        self.calls = []

    def run(self, action, case):
        self.calls.append(action.capability)
        return [EventDraft("note.added", {"kind": "system", "name": "x"},
                           {"text": "nothing"})]


def _case(tmp, host=HOST):
    case = Case.create(tmp, "pwn", title="fmt-string pwn", category="pwn",
                       flag_format=FMT, platform="HackTheBox")
    nk = {"host": host, "proto": "tcp", "port": PORT}
    case.append(EventDraft("entity.asserted", {"kind": "executor", "name": "nmap@2"},
                           {"kind": "service.tcp", "natural_key": nk}))
    case.set_meta(phase="EXPLOIT")                # resume straight into exploit
    return case


def _events(case, etype):
    return [e for e in case.store.iter_events() if e["type"] == etype]


def test_exploit_routes_to_session_and_wins():
    with tempfile.TemporaryDirectory() as d:
        case = _case(d)
        ex = TrackingExecutor()
        loop = Loop(case, ex, scope=_scope(),
                    session_provider=_provider([["hello"], ["%7$s"]]),
                    submit_oracle=lambda v: v == FLAG)
        result = loop.run(max_steps=12)
        assert result.final_phase == "FLAG_FOUND", result.final_phase
        assert result.flag == FLAG
        assert not ex.calls, "planner ACT must not run while a session owns the step"
        assert _events(case, "session.opened")
        assert _events(case, "script.run")
        assert case.store.verify_chain() == -1


def test_no_provider_stays_on_planner():
    # backward compat: without a provider, an EXPLOIT pwn case never opens a session
    with tempfile.TemporaryDirectory() as d:
        case = _case(d)
        loop = Loop(case, TrackingExecutor(), scope=_scope())
        loop.run(max_steps=8)
        assert not _events(case, "session.opened")


def test_out_of_scope_session_target_refused():
    with tempfile.TemporaryDirectory() as d:
        case = _case(d, host="9.9.9.9")           # outside the scope CIDR
        loop = Loop(case, TrackingExecutor(), scope=_scope(),
                    session_provider=_provider([["%7$s"]]))
        loop.run(max_steps=8)
        assert not _events(case, "session.opened")
        refused = [e for e in _events(case, "note.added")
                   if e["payload"].get("kind") == "scope_refused"]
        assert refused, "an out-of-scope session write-in must be refused"


def test_session_charges_the_shared_budget():
    with tempfile.TemporaryDirectory() as d:
        case = _case(d)
        loop = Loop(case, TrackingExecutor(), scope=_scope(),
                    session_provider=_provider([["hello"], ["%7$s"]]),
                    submit_oracle=lambda v: v == FLAG)
        loop.run(max_steps=12)
        # each script.run + the submit charged the one ledger
        assert loop.budget.tool_invocations >= 2


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
