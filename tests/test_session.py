"""Regime-B interactive session: author -> run vs tube -> fold, with scope,
budget, redaction, and flag capture (Phase 4).

    PYTHONPATH=. PYTHONIOENCODING=utf-8 python tests/test_session.py
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
)

FMT = r"flag\{[^}]+\}"
FLAG = "flag{f0rmat_str1ng_pwn_1337}"
HOST = "10.10.11.53"
OP = SigningKey.generate()
SCOPE = {"hosts": ["10.10.11.0/24"], "ports": [1337, 80], "auto_cap": 2}


def _scope():
    m = sign_manifest(OP, "scope", "c1", SCOPE)
    return ScopeVerifier(trusted_operator_keys={OP.public_hex}).load_scope(m)


def _case(tmp):
    return Case.create(tmp, "sess", title="format-string pwn", category="pwn",
                       flag_format=FMT, platform="HackTheBox")


def _win_tube():
    """A vuln service that leaks the flag only when fed the winning payload."""
    def responder(sent, _t):
        s = sent.strip()
        if s == "%7$s":
            return f"leaked: {FLAG}\n"
        return "nope, try again\n> "
    return ScriptedTube(responder, greeting="pwnme service\n> ")


def _entity(host=HOST, port=1337):
    return {"id": "svc-1", "display": f"{host}:{port}", "host": host, "port": port}


def _session(case, tube, strategies, scope=None, budget=None, max_revs=6):
    return InteractiveSession(
        case, "s1", _entity(), goal="capture the flag", tube=tube,
        author=DeterministicScriptAuthor(strategies),
        runner=DeterministicScriptRunner(),
        flag=FlagEngine(case), budget=budget or BudgetLedger(),
        scope=scope, max_revs=max_revs,
    )


def _events(case, etype):
    return [e for e in case.store.iter_events() if e["type"] == etype]


def test_session_converges_and_captures_flag():
    with tempfile.TemporaryDirectory() as d:
        case = _case(d)
        sess = _session(case, _win_tube(),
                        strategies=[["hello"], ["%7$s"]], scope=_scope())
        res = sess.run_to_completion()
        assert res.flag_local_ok, "the winning revision must surface the flag"
        assert sess.closed and res.reason == "flag candidate found"
        # exactly the revisions that ran are recorded, in order
        assert len(_events(case, "script.revised")) == 2
        assert len(_events(case, "script.run")) == 2
        assert len(_events(case, "session.opened")) == 1
        assert len(_events(case, "session.closed")) == 1
        assert case.store.verify_chain() == -1


def test_flag_is_ranked_after_capture():
    with tempfile.TemporaryDirectory() as d:
        case = _case(d)
        fe = FlagEngine(case)
        sess = InteractiveSession(
            case, "s1", _entity(), "flag", _win_tube(),
            DeterministicScriptAuthor([["hello"], ["%7$s"]]),
            DeterministicScriptRunner(), fe, BudgetLedger(), scope=_scope())
        sess.run_to_completion()
        ranked = fe.ranked()
        assert ranked and any(FLAG == r.value for r in ranked), [r.value for r in ranked]
        assert any(r.tier <= 2 for r in ranked)


def test_out_of_scope_target_refused():
    with tempfile.TemporaryDirectory() as d:
        case = _case(d)
        sess = InteractiveSession(
            case, "s1", {"id": "svc-x", "display": "9.9.9.9:1337",
                         "host": "9.9.9.9", "port": 1337},
            "flag", _win_tube(),
            DeterministicScriptAuthor([["%7$s"]]), DeterministicScriptRunner(),
            FlagEngine(case), BudgetLedger(), scope=_scope())
        assert sess.open() is False
        assert not _events(case, "session.opened")
        refused = [e for e in _events(case, "note.added")
                   if e["payload"].get("kind") == "scope_refused"]
        assert refused, "an out-of-scope write-in must be refused"


def test_budget_exhaustion_stops_session():
    with tempfile.TemporaryDirectory() as d:
        case = _case(d)
        # never-winning strategy, tiny budget: must stop without spinning
        budget = BudgetLedger(max_tool_invocations=2)
        sess = _session(case, _win_tube(), strategies=[["hello"]],
                        scope=_scope(), budget=budget, max_revs=50)
        sess.run_to_completion(max_iters=50)
        assert sess.closed
        assert budget.tool_invocations <= 3
        assert not sess.runs or not any(
            "flag" in r.stdout for r in sess.runs)


def test_captured_secret_is_redacted_in_the_log():
    with tempfile.TemporaryDirectory() as d:
        case = _case(d)
        leaky = ScriptedTube(
            {"creds": "admin password=SuperSecretPw99 logged in\n"},
            greeting="svc\n> ")
        sess = _session(case, leaky, strategies=[["creds"]], scope=_scope())
        sess.open()
        sess.iterate()
        runs = _events(case, "script.run")
        blob = runs[0]["payload"]["output"]
        assert "SuperSecretPw99" not in blob, "plaintext secret leaked into the log"
        assert "«SECRET:" in blob, "secret should be tokenized to a handle"
        # and the workspace transcript is redacted too
        tr = (Path(case.dir) / "sessions" / "s1" / "transcript.log").read_text(
            encoding="utf-8")
        assert "SuperSecretPw99" not in tr


def test_workspace_files_written():
    with tempfile.TemporaryDirectory() as d:
        case = _case(d)
        sess = _session(case, _win_tube(),
                        strategies=[["hello"], ["%7$s"]], scope=_scope())
        sess.run_to_completion()
        ws = Path(case.dir) / "sessions" / "s1"
        assert (ws / "script.rev0.py").exists()
        assert (ws / "transcript.log").exists()


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
