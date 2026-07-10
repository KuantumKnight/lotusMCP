"""Tests for the BudgetLedger and the authoritative phase machine."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from lotusmcp.engine.budget import BudgetLedger  # noqa: E402
from lotusmcp.engine.phases import (  # noqa: E402
    PhaseSignals,
    check_transition,
    is_terminal,
    should_halt,
)


# ---------------- budget ----------------
def test_budget_charges_and_fractions():
    b = BudgetLedger(max_tool_invocations=10, max_llm_tokens=1000, max_wall_clock_s=100)
    b.charge(tool_invocations=5, phase="RECON")
    assert b.fraction_spent() == 0.5
    b.charge(llm_tokens=1000)
    assert b.fraction_spent() == 1.0 and b.exhausted()


def test_budget_high_water():
    b = BudgetLedger(max_tool_invocations=10)
    b.charge(tool_invocations=8)
    assert b.high_water() and not b.exhausted()


def test_per_phase_tool_cap():
    b = BudgetLedger(per_phase_tool_caps={"ENUMERATE": 3})
    b.charge(tool_invocations=3, phase="ENUMERATE")
    assert b.phase_cap_reached("ENUMERATE")
    assert not b.phase_cap_reached("EXPLOIT")


# ---------------- phase forward machine ----------------
def test_triage_to_recon_guard():
    s = PhaseSignals(scope_verified=True, reachable=True, flag_format_set=True)
    assert check_transition("TRIAGE", s).next == "RECON"
    # missing any precondition holds the phase
    assert not check_transition("TRIAGE", PhaseSignals(scope_verified=True,
                                                       reachable=True)).transition


def test_recon_to_enumerate_needs_fingerprint():
    assert not check_transition("RECON", PhaseSignals()).transition
    assert check_transition("RECON", PhaseSignals(fingerprinted_services=1)).next == "ENUMERATE"


def test_enumerate_to_exploit_gate():
    # conf below the gate holds
    assert not check_transition("ENUMERATE",
                                PhaseSignals(best_open_hyp_conf=0.3,
                                             best_open_hyp_payoff=0.8)).transition
    # payoff below the gate holds
    assert not check_transition("ENUMERATE",
                                PhaseSignals(best_open_hyp_conf=0.6,
                                             best_open_hyp_payoff=0.5)).transition
    # both satisfied advances
    assert check_transition("ENUMERATE",
                            PhaseSignals(best_open_hyp_conf=0.45,
                                         best_open_hyp_payoff=0.7)).next == "EXPLOIT"


def test_exploit_to_post_needs_hard_access():
    assert check_transition("EXPLOIT", PhaseSignals(access_gained=True)).next == "POST_EXPLOIT"


def test_exploit_regress_to_enumerate():
    s = PhaseSignals(all_exploit_dead_ended=True, new_surface=True)
    assert check_transition("EXPLOIT", s).next == "ENUMERATE"


def test_post_exploit_to_pending_submit():
    assert check_transition("POST_EXPLOIT",
                            PhaseSignals(flag_local_ok=True)).next == "SOLVED_PENDING_SUBMIT"


def test_pending_submit_to_flag_found():
    assert check_transition("SOLVED_PENDING_SUBMIT",
                            PhaseSignals(flag_verified=True)).next == "FLAG_FOUND"


# ---------------- any-phase escapes ----------------
def test_exhausted_when_budget_gone_and_no_lead():
    s = PhaseSignals(budget_exhausted=True, best_open_hyp_payoff=0.0)
    assert check_transition("ENUMERATE", s).next == "EXHAUSTED"


def test_budget_gone_but_open_lead_does_not_exhaust():
    # a strong open lead means keep going, not EXHAUSTED
    s = PhaseSignals(budget_exhausted=True, best_open_hyp_payoff=0.8)
    t = check_transition("ENUMERATE", s)
    assert t.next != "EXHAUSTED"


def test_scope_conflict_escalates_from_any_phase():
    assert check_transition("RECON", PhaseSignals(scope_conflict=True)).next == "ESCALATED"
    assert check_transition("EXPLOIT", PhaseSignals(scope_conflict=True)).next == "ESCALATED"


def test_high_budget_no_access_escalates():
    assert check_transition("EXPLOIT",
                            PhaseSignals(budget_high_no_access=True)).next == "ESCALATED"


def test_exhausted_wins_over_escalate():
    # both set: EXHAUSTED is checked first only when no lead; here escalate should
    # not preempt a genuine exhaustion with no lead
    s = PhaseSignals(budget_exhausted=True, plateaued=True, best_open_hyp_payoff=0.0)
    assert check_transition("EXPLOIT", s).next == "EXHAUSTED"


def test_terminal_helpers():
    assert is_terminal("FLAG_FOUND") and is_terminal("EXHAUSTED")
    assert not is_terminal("SOLVED_PENDING_SUBMIT")
    assert should_halt("SOLVED_PENDING_SUBMIT") and should_halt("ESCALATED")
    assert not should_halt("EXPLOIT")


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
