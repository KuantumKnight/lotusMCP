"""The authoritative phase machine (§4.3).

Phase transitions are a **server** decision, never the LLM's — a single
"the model says we have access" can update confidence but can never advance a
phase (the CONFIRM-requires-corroboration rule closes the LLM-said-yes cascade).
So this module is pure: given the current phase and a bundle of *derived
signals*, it returns the next phase (or none) and the reason.

`step()` computes the signals from the graph, the hypothesis set, the flag
engine, and the budget; keeping the guards separate makes them exhaustively
testable without any of that machinery.
"""
from __future__ import annotations

from dataclasses import dataclass

PHASES = ("TRIAGE", "RECON", "ENUMERATE", "EXPLOIT", "POST_EXPLOIT")
TERMINALS = ("SOLVED_PENDING_SUBMIT", "FLAG_FOUND", "EXHAUSTED", "ESCALATED")

EXPLOIT_GATE = 0.40      # min OPEN-hypothesis confidence to enter EXPLOIT
PAYOFF_GATE = 0.60       # min hypothesis payoff to justify EXPLOIT / keep hunting


@dataclass
class PhaseSignals:
    # TRIAGE -> RECON
    scope_verified: bool = False
    reachable: bool = False
    flag_format_set: bool = False
    # RECON -> ENUMERATE
    fingerprinted_services: int = 0
    # ENUMERATE -> EXPLOIT
    best_open_hyp_conf: float = 0.0
    best_open_hyp_payoff: float = 0.0
    # EXPLOIT -> POST_EXPLOIT (HARD, corroborated)
    access_gained: bool = False
    # POST_EXPLOIT -> SOLVED_PENDING_SUBMIT / FLAG_FOUND
    flag_local_ok: bool = False
    flag_verified: bool = False
    # EXPLOIT -> ENUMERATE (regress)
    all_exploit_dead_ended: bool = False
    new_surface: bool = False
    # any -> ESCALATED / EXHAUSTED
    budget_exhausted: bool = False
    budget_high_no_access: bool = False
    plateaued: bool = False
    scope_conflict: bool = False


@dataclass(frozen=True)
class Transition:
    transition: bool
    next: str = ""
    reason: str = ""


def _has_open_lead(s: PhaseSignals) -> bool:
    return s.best_open_hyp_payoff >= PAYOFF_GATE


def check_transition(phase: str, s: PhaseSignals) -> Transition:
    """Return the single authoritative next transition for `phase`, if any.

    Terminal/escape guards (EXHAUSTED, ESCALATED) are checked first because they
    apply from *any* phase and must win over normal forward progress.
    """
    # ---- any-phase escapes (order matters: exhausted beats escalate) ----
    if s.budget_exhausted and not _has_open_lead(s) and not s.flag_local_ok:
        return Transition(True, "EXHAUSTED", "budget exhausted, no open lead ≥ payoff gate")
    if s.scope_conflict:
        return Transition(True, "ESCALATED", "scope conflict — human required")
    if s.plateaued:
        return Transition(True, "ESCALATED", "plateau after self-escalation")
    if s.budget_high_no_access:
        return Transition(True, "ESCALATED", "budget ≥80% without access")

    # ---- forward machine ----
    if phase == "TRIAGE":
        if s.scope_verified and s.reachable and s.flag_format_set:
            return Transition(True, "RECON", "scope verified ∧ reachable ∧ flag_format set")

    elif phase == "RECON":
        if s.fingerprinted_services >= 1:
            return Transition(True, "ENUMERATE", "≥1 service fingerprinted with product/version")

    elif phase == "ENUMERATE":
        if s.best_open_hyp_conf >= EXPLOIT_GATE and s.best_open_hyp_payoff >= PAYOFF_GATE:
            return Transition(True, "EXPLOIT",
                              f"OPEN hypothesis conf≥{EXPLOIT_GATE} ∧ payoff≥{PAYOFF_GATE}")

    elif phase == "EXPLOIT":
        if s.access_gained:
            return Transition(True, "POST_EXPLOIT", "CONFIRMED access gained (HARD signal)")
        if s.all_exploit_dead_ended and s.new_surface:
            return Transition(True, "ENUMERATE", "all exploit candidates dead-ended ∧ new surface")

    elif phase == "POST_EXPLOIT":
        if s.flag_local_ok:
            return Transition(True, "SOLVED_PENDING_SUBMIT",
                              "flag matches format ∧ local check passes")

    elif phase == "SOLVED_PENDING_SUBMIT":
        if s.flag_verified:
            return Transition(True, "FLAG_FOUND", "platform oracle returned correct")

    return Transition(False)


def is_terminal(phase: str) -> bool:
    """Hard-done: the case is over, no human follow-up will change it."""
    return phase in ("FLAG_FOUND", "EXHAUSTED")


def should_halt(phase: str) -> bool:
    """Stop active spend — includes soft-terminals that surface to a human
    (SOLVED_PENDING_SUBMIT with no oracle, ESCALATED)."""
    return phase in TERMINALS
