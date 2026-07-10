"""The client-driven session path: InteractiveSession.edit_run (caller supplies
the script) and the SessionManager registry the MCP tools wrap (Phase 4).

    PYTHONPATH=. PYTHONIOENCODING=utf-8 python tests/test_session_manager.py
"""
from __future__ import annotations

import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from lotusmcp.control_plane.keyring import SigningKey, sign_manifest  # noqa: E402
from lotusmcp.engine.budget import BudgetLedger  # noqa: E402
from lotusmcp.engine.scope import ScopeVerifier  # noqa: E402
from lotusmcp.flag.facade import FlagEngine  # noqa: E402
from lotusmcp.kernel.case import Case  # noqa: E402
from lotusmcp.session import (  # noqa: E402
    DeterministicScriptAuthor,
    DeterministicScriptRunner,
    InteractiveSession,
    ScriptedTube,
    SessionError,
    SessionManager,
)

FMT = r"flag\{[^}]+\}"
FLAG = "flag{cl1ent_dr1ven_pwn_1337}"
HOST, PORT = "10.10.11.53", 1337
OP = SigningKey.generate()


def _scope():
    m = sign_manifest(OP, "scope", "c1",
                      {"hosts": ["10.10.11.0/24"], "ports": [PORT], "auto_cap": 2})
    return ScopeVerifier(trusted_operator_keys={OP.public_hex}).load_scope(m)


def _case(tmp):
    return Case.create(tmp, "cli", title="pwn", category="pwn",
                       flag_format=FMT, platform="HackTheBox")


def _win_tube():
    def responder(sent, _t):
        return f"leak: {FLAG}\n" if sent.strip() == "%7$s" else "nope\n> "
    return ScriptedTube(responder, greeting="svc\n> ")


def _entity(host=HOST):
    return {"id": "svc-1", "display": f"{host}:{PORT}", "host": host, "port": PORT}


def _factory(tube_factory=_win_tube):
    def factory(*, case, sid, entity, goal, flag, budget, scope, phase):
        return InteractiveSession(
            case, sid, entity, goal, tube_factory(),
            DeterministicScriptAuthor([["noop"]]), DeterministicScriptRunner(),
            flag, budget, scope=scope, phase=phase)
    return factory


# ------------------------------------------------------------- edit_run (direct)


def test_edit_run_supplied_script_captures_flag():
    with tempfile.TemporaryDirectory() as d:
        case = _case(d)
        fe = FlagEngine(case)
        sess = InteractiveSession(
            case, "s1", _entity(), "flag", _win_tube(),
            DeterministicScriptAuthor([["unused"]]), DeterministicScriptRunner(),
            fe, BudgetLedger(), scope=_scope())
        assert sess.open()
        r0 = sess.edit_run(["AAAA"])                 # client tries something wrong
        assert r0.ran and not r0.flag_local_ok
        r1 = sess.edit_run(["%7$s"])                 # client patches to the winner
        assert r1.flag_local_ok and sess.closed
        assert any(FLAG == r.value for r in fe.ranked())


def test_edit_run_requires_open_session():
    with tempfile.TemporaryDirectory() as d:
        case = _case(d)
        sess = InteractiveSession(
            case, "s1", _entity(), "flag", _win_tube(),
            DeterministicScriptAuthor([["x"]]), DeterministicScriptRunner(),
            FlagEngine(case), BudgetLedger(), scope=_scope())
        r = sess.edit_run(["%7$s"])                  # never opened
        assert not r.ran and r.reason == "not open"


# ------------------------------------------------------------- SessionManager


def test_manager_open_edit_run_close_list():
    with tempfile.TemporaryDirectory() as d:
        case = _case(d)
        fe, budget = FlagEngine(case), BudgetLedger()
        mgr = SessionManager(_factory())
        opened = mgr.open(case=case, entity=_entity(), goal="flag",
                          flag=fe, budget=budget, scope=_scope())
        assert opened["opened"] and opened["sid"] == "s1"
        v = mgr.edit_run(case.case_id, "s1", ["%7$s"])
        assert v["flag_local_ok"] and v["closed"]
        listed = mgr.list(case.case_id)
        assert len(listed) == 1 and listed[0]["sid"] == "s1"


def test_manager_rejects_missing_or_closed_session():
    with tempfile.TemporaryDirectory() as d:
        case = _case(d)
        mgr = SessionManager(_factory())
        try:
            mgr.edit_run(case.case_id, "nope", ["%7$s"])
        except SessionError:
            pass
        else:
            raise AssertionError("edit_run on a missing session must raise")
        mgr.open(case=case, entity=_entity(), goal="flag",
                 flag=FlagEngine(case), budget=BudgetLedger(), scope=_scope())
        mgr.close(case.case_id, "s1")
        try:
            mgr.edit_run(case.case_id, "s1", ["%7$s"])
        except SessionError:
            return
        raise AssertionError("edit_run on a closed session must raise")


def test_manager_out_of_scope_open_refused():
    with tempfile.TemporaryDirectory() as d:
        case = _case(d)
        mgr = SessionManager(_factory())
        opened = mgr.open(case=case, entity=_entity(host="9.9.9.9"), goal="flag",
                          flag=FlagEngine(case), budget=BudgetLedger(), scope=_scope())
        assert opened["opened"] is False
        refused = [e for e in case.store.iter_events()
                   if e["type"] == "note.added"
                   and e["payload"].get("kind") == "scope_refused"]
        assert refused


def test_manager_sids_are_per_case_sequential():
    with tempfile.TemporaryDirectory() as d:
        case = _case(d)
        mgr = SessionManager(_factory())
        a = mgr.open(case=case, entity=_entity(), goal="g", flag=FlagEngine(case),
                     budget=BudgetLedger(), scope=_scope())
        b = mgr.open(case=case, entity=_entity(), goal="g", flag=FlagEngine(case),
                     budget=BudgetLedger(), scope=_scope())
        assert a["sid"] == "s1" and b["sid"] == "s2"


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
