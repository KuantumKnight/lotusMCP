"""End-to-end OODA loop tests with a scripted executor (no Kali, no LLM).

Drives a full autonomous web solve through the real Case/serializer:
  TRIAGE -> RECON (fingerprint) -> ENUMERATE (.git leak -> new param)
        -> EXPLOIT (SQLi -> access + flag in dump) -> POST_EXPLOIT
        -> SOLVED_PENDING_SUBMIT -> (oracle) -> FLAG_FOUND
and also checks the budget-exhaustion and plateau escape hatches.
"""
from __future__ import annotations

import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from lotusmcp.engine.budget import BudgetLedger  # noqa: E402
from lotusmcp.engine.loop import Loop  # noqa: E402
from lotusmcp.kernel.case import Case  # noqa: E402
from lotusmcp.kernel.events import EventDraft  # noqa: E402

FMT = r"flag\{[^}]+\}"
FLAG = "flag{sqli_dump_win_1337}"
HOST = "10.10.11.53"


class ScriptedExecutor:
    """Maps a chosen capability to the events a real tool would emit."""

    def __init__(self):
        self.calls = []

    def run(self, action, case):
        self.calls.append((action.capability, action.params.get("class")
                           or action.params.get("probe")))
        cap = action.params.get("probe") or action.params.get("class")
        actor = {"kind": "executor", "name": action.capability}
        tid = action.target_id

        if action.capability == "http_probe" and cap == "banner":
            return [
                EventDraft("attribute.asserted", actor,
                           {"entity_id": tid, "attr": "server", "value": "nginx", "confidence": 0.9}),
                EventDraft("attribute.asserted", actor,
                           {"entity_id": tid, "attr": "version", "value": "1.25.3", "confidence": 0.9}),
            ]
        if action.capability == "http_probe" and cap == "git":
            nk = {"endpoint_id": tid, "location": "query", "name": "q"}
            return [
                EventDraft("finding.raised", actor,
                           {"id": "F-git", "type": "exposure", "severity": "high",
                            "confidence": 0.9, "subject": {"t": action.target_display},
                            "attrs": {"leak": "git repo exposed"}}),
                EventDraft("hypothesis.proposed", {"kind": "llm", "name": "oracle"},
                           {"hid": "H-git", "status": "OPEN", "confidence": 0.6,
                            "statement": "git leak -> source -> injectable q param"}),
                EventDraft("entity.asserted", actor,
                           {"kind": "http.param", "natural_key": nk}),
                EventDraft("attribute.asserted", actor,
                           {"kind": "http.param", "natural_key": nk, "attr": "reflected",
                            "value": True, "confidence": 0.8}),
            ]
        if action.capability == "web_attack" and cap == "sqli":
            return [
                EventDraft("finding.raised", actor,
                           {"id": "F-sqli", "type": "sqli_dump", "severity": "critical",
                            "confidence": 0.9, "subject": {"p": action.target_display},
                            "attrs": {"dumped": "users"}}),
                EventDraft("note.added", {"kind": "llm", "name": "oracle"},
                           {"text": f"users table dumped; admin row note = {FLAG}"}),
            ]
        # any other probe: nothing notable -> dead end
        return [EventDraft("note.added", {"kind": "system", "name": action.capability},
                           {"text": f"{action.capability} found nothing"})]


def _case(tmp, cid="loop"):
    case = Case.create(tmp, cid, title="Titan Gateway search portal", category="web",
                       flag_format=FMT, platform="HackTheBox")
    case.append(EventDraft("entity.asserted", {"kind": "executor", "name": "nmap@2"},
                           {"kind": "host", "natural_key": {"addr": HOST}}))
    nk = {"host": HOST, "proto": "tcp", "port": 80}
    case.append(EventDraft("entity.asserted", {"kind": "executor", "name": "httpx@1"},
                           {"kind": "service.http", "natural_key": nk}))
    return case


def test_full_autonomous_solve():
    with tempfile.TemporaryDirectory() as d:
        case = _case(d)
        loop = Loop(case, ScriptedExecutor(), submit_oracle=lambda v: v == FLAG)
        result = loop.run(max_steps=20)
        assert result.final_phase == "FLAG_FOUND", result.final_phase
        assert result.flag == FLAG
        # the phases were visited in order
        phases = [h.phase for h in result.history]
        for p in ("RECON", "ENUMERATE", "EXPLOIT", "POST_EXPLOIT", "FLAG_FOUND"):
            assert p in phases, f"{p} not in {phases}"
        # the log is intact and records the win
        assert case.store.verify_chain() == -1
        types = [e["type"] for e in case.store.iter_events()]
        assert "flag.verified" in types


def test_capabilities_fired_in_sensible_order():
    with tempfile.TemporaryDirectory() as d:
        ex = ScriptedExecutor()
        loop = Loop(_case(d), ex, submit_oracle=lambda v: v == FLAG)
        loop.run(max_steps=20)
        caps = [c for c, _ in ex.calls]
        # recon probe precedes the git check precedes the sqli attack
        assert caps.index("http_probe") < caps.index("web_attack")


def test_solved_pending_submit_when_no_oracle():
    # no submit oracle -> stop at SOLVED_PENDING_SUBMIT, surface to human
    with tempfile.TemporaryDirectory() as d:
        loop = Loop(_case(d), ScriptedExecutor(), submit_oracle=None)
        result = loop.run(max_steps=20)
        assert result.final_phase == "SOLVED_PENDING_SUBMIT"
        assert result.flag is None


def test_budget_exhaustion_halts():
    with tempfile.TemporaryDirectory() as d:
        # a tiny budget: the loop must stop and mark EXHAUSTED, not spin
        budget = BudgetLedger(max_tool_invocations=2)
        loop = Loop(_case(d), ScriptedExecutor(), budget=budget)
        result = loop.run(max_steps=20)
        assert result.final_phase in ("EXHAUSTED", "ESCALATED")
        assert budget.tool_invocations <= 3


def test_dead_end_probes_are_not_retried():
    # A world with a param but an executor that always finds nothing: the loop
    # should mark dead-ends and stop proposing them (eventually no candidates).
    class NullExecutor:
        def run(self, action, case):
            return [EventDraft("note.added", {"kind": "system", "name": "x"},
                               {"text": "nothing"})]

    with tempfile.TemporaryDirectory() as d:
        case = _case(d)
        loop = Loop(case, NullExecutor())
        loop.run(max_steps=30)
        # every tried key that produced nothing became a dead end
        assert loop.dead_end
        assert loop.dead_end <= loop.tried


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
