"""JobService — lotus_next / propose_and_run / lotus_submit (Phase 5).

lotus_next is read-only planning (always available, mutates nothing);
propose_and_run drives the OODA loop with a configured sandbox executor and
fails closed without one; lotus_submit submits to a configured platform oracle,
never auto-submits, and fails closed without one. All testable with the scripted
executor + mock oracle from test_loop — no Kali, no LLM.

    PYTHONPATH=. PYTHONIOENCODING=utf-8 python tests/test_jobs.py
"""
from __future__ import annotations

import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from lotusmcp.engine.jobs import JobError, JobService
from lotusmcp.kernel.case import Case
from lotusmcp.kernel.events import EventDraft
from tests.test_loop import FLAG, ScriptedExecutor, _case


def test_next_is_readonly_and_ranks():
    with tempfile.TemporaryDirectory() as d:
        case = _case(d)
        case.set_meta(phase="RECON")
        tip_before = case.store.tip
        js = JobService(d)
        out = js.next("loop")
        assert out["phase"] == "RECON" and out["category"] == "web"
        rec = out["recommended"]
        assert rec and rec["capability"] and "scores" in rec
        # ranked strictly by score desc (recommended is the top)
        s_all = [rec["scores"]["s"]] + [a["scores"]["s"] for a in out["alternatives"]]
        assert s_all == sorted(s_all, reverse=True), s_all
        # READ-ONLY: no events appended by planning
        assert case.store.tip == tip_before, "lotus_next must not mutate the log"
        print(f"next → {rec['capability']} @ {rec['target']} (s={rec['scores']['s']}), "
              f"{len(out['alternatives'])} alternatives, log untouched")


def test_next_no_candidate_in_triage():
    with tempfile.TemporaryDirectory() as d:
        _case(d)                       # fresh case stays in TRIAGE
        out = JobService(d).next("loop")
        assert out["recommended"] is None and out["alternatives"] == []
        assert "no live candidate" in out["reason"]
        print("next in TRIAGE → no candidate (escalate/regress)")


def test_propose_and_run_fails_closed_without_executor():
    with tempfile.TemporaryDirectory() as d:
        _case(d)
        out = JobService(d).propose_and_run("loop")
        assert out["ran"] is False and out["refused"] is True
        assert "fail closed" in out["reason"]
        print("propose_and_run without executor → fail closed")


def test_propose_and_run_drives_the_loop_to_the_flag():
    with tempfile.TemporaryDirectory() as d:
        case = _case(d)
        js = JobService(d)
        js.configure(executor_factory=lambda c: ScriptedExecutor(),
                     submit_oracle=lambda v: v == FLAG)
        out = js.propose_and_run("loop", max_steps=20)
        assert out["ran"] is True
        assert out["final_phase"] == "FLAG_FOUND", out["final_phase"]
        assert out["flag"] == FLAG
        # each step is reported with its phase/action/budget
        assert out["steps"] and all("phase" in s for s in out["steps"])
        # the win is in the log
        types = [e["type"] for e in case.store.iter_events()]
        assert "flag.verified" in types
        assert case.store.verify_chain() == -1
        print(f"propose_and_run drove {len(out['steps'])} steps → {out['flag']}")


def test_propose_and_run_bad_steps_rejected():
    with tempfile.TemporaryDirectory() as d:
        _case(d)
        js = JobService(d)
        js.configure(executor_factory=lambda c: ScriptedExecutor())
        try:
            js.propose_and_run("loop", max_steps=0)
            raise AssertionError("max_steps=0 should raise")
        except JobError:
            print("propose_and_run rejects max_steps < 1")


def test_submit_fails_closed_without_oracle():
    with tempfile.TemporaryDirectory() as d:
        _case(d)
        out = JobService(d).submit("loop")
        assert out["submitted"] is False and out["refused"] is True
        assert "never auto-submits" in out["reason"]
        print("submit without oracle → fail closed")


def test_submit_waits_when_no_candidate():
    with tempfile.TemporaryDirectory() as d:
        _case(d)
        js = JobService(d)
        js.configure(submit_oracle=lambda v: True)
        out = js.submit("loop")           # nothing scanned yet
        assert out["submitted"] is False and out.get("action") == "WAIT"
        print(f"submit with no candidate → {out['action']}")


def test_submit_verifies_a_scanned_flag():
    with tempfile.TemporaryDirectory() as d:
        case = _case(d)
        # get the flag into the registry via a flag.candidate the way scan would
        from lotusmcp.flag.facade import FlagEngine
        FlagEngine(case).scan([f"leak: {FLAG}"])
        js = JobService(d)
        js.configure(submit_oracle=lambda v: v == FLAG)
        out = js.submit("loop")
        assert out["submitted"] is True and out["verified"] is True, out
        assert out["flag"] == FLAG and out["status"] == "FLAG_FOUND"
        # idempotent terminal: a second submit is a no-op DONE
        again = js.submit("loop")
        assert again["submitted"] is False and again["action"] == "DONE"
        types = [e["type"] for e in case.store.iter_events()]
        assert "flag.verified" in types
        print(f"submit verified {out['flag']}; re-submit → DONE")


def test_submit_rejects_wrong_flag_then_allows_retry():
    with tempfile.TemporaryDirectory() as d:
        case = _case(d)
        from lotusmcp.flag.facade import FlagEngine
        FlagEngine(case).scan([f"decoy {FLAG}", "flag{another_real_looking_1337}"])
        js = JobService(d)
        # oracle only accepts the true FLAG
        js.configure(submit_oracle=lambda v: v == FLAG)
        # explicitly submit the wrong one first
        wrong = "flag{another_real_looking_1337}"
        r1 = js.submit("loop", value=wrong)
        assert r1["submitted"] is True and r1["verified"] is False, r1
        # re-submitting the same rejected value is refused
        r2 = js.submit("loop", value=wrong)
        assert r2["submitted"] is False, r2
        # unknown value is refused (must be scanned first)
        r3 = js.submit("loop", value="flag{never_seen}")
        assert r3["submitted"] is False and "known candidate" in r3["reason"]
        print("wrong flag rejected; re-submit blocked; unknown value refused")


def test_unknown_case_raises():
    with tempfile.TemporaryDirectory() as d:
        js = JobService(d)
        for fn in (lambda: js.next("nope"),
                   lambda: js.submit("nope")):
            try:
                js.configure(submit_oracle=lambda v: True)
                fn()
                raise AssertionError("unknown case should raise")
            except JobError:
                pass
        print("unknown case → JobError")


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
