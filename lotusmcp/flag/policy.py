"""The submit-policy state machine.

Platform submissions are scarce and often rate-limited or penalised, so the
policy is deliberately conservative. It decides *whether* to spend an oracle
attempt on a ranked flag, and it tracks the outcome so the same value is never
re-submitted and a verified flag is terminal.

The decision is a pure function of (ranked candidates, prior outcomes, config).
Recording a submit/result mutates state; deciding does not. This mirrors the
phase-machine terminals in ARCHITECTURE.md §4.3:

  - **SUBMIT**  -> caller emits `flag.submitted`, calls the oracle, then
                   `record_result(...)`.
  - **DONE**    -> a flag verified (T1/FLAG_FOUND). Terminal.
  - **BLOCKED** -> a strong candidate exists but we cannot submit (no signed
                   endpoint / budget spent). Soft-terminal SOLVED_PENDING_SUBMIT:
                   stop active spend, surface to the human.
  - **WAIT**    -> nothing worth submitting yet; keep hunting.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence

from lotusmcp.flag.ranker import RankedFlag, T2_STRONG

SUBMIT = "SUBMIT"
WAIT = "WAIT"
BLOCKED = "BLOCKED"
DONE = "DONE"


@dataclass(frozen=True)
class SubmitDecision:
    action: str                      # SUBMIT | WAIT | BLOCKED | DONE
    flag: Optional[RankedFlag] = None
    reason: str = ""


@dataclass
class SubmitPolicy:
    """Conservative, dedup-safe, budget-bounded submission gate."""

    has_signed_endpoint: bool = True     # operator-signed submit allowlist present
    max_submissions: int = 5             # hard cap on oracle attempts
    min_tier: int = T2_STRONG            # only submit at this tier or better
    require_local_check: bool = False    # if set, only *_locally_checked flags submit

    # ---- mutable outcome ledger (keyed by value_sha) ----
    submitted: set = field(default_factory=set)
    rejected: set = field(default_factory=set)
    verified: Optional[RankedFlag] = None
    attempts: int = 0

    def decide(
        self,
        ranked: Sequence[RankedFlag],
        locally_checked: Optional[Sequence[str]] = None,
    ) -> SubmitDecision:
        """Pick the best still-viable candidate to submit, or explain why not."""
        if self.verified is not None:
            return SubmitDecision(DONE, self.verified, "flag already verified")

        checked = set(locally_checked or [])
        # viable = right tier, not tried, not rejected, (optionally) locally checked
        viable = [
            f for f in ranked
            if f.tier <= self.min_tier
            and f.value_sha not in self.submitted
            and f.value_sha not in self.rejected
            and (not self.require_local_check or f.value in checked)
        ]
        # ranked is already best-first; keep that order
        if not viable:
            # Is there a decent candidate we simply *can't* pursue? -> BLOCKED.
            blocked_worthy = any(
                f.tier <= self.min_tier and f.value_sha not in self.rejected
                for f in ranked
            )
            if blocked_worthy and self.attempts >= self.max_submissions:
                return SubmitDecision(BLOCKED, None, "submission budget exhausted")
            return SubmitDecision(WAIT, None, "no submittable candidate yet")

        if self.attempts >= self.max_submissions:
            return SubmitDecision(BLOCKED, viable[0], "submission budget exhausted")
        if not self.has_signed_endpoint:
            return SubmitDecision(
                BLOCKED, viable[0],
                "no operator-signed submit endpoint (surface to human)",
            )
        return SubmitDecision(SUBMIT, viable[0], viable[0].reason)

    # ---- outcome recording (the only state mutations) ----
    def record_submit(self, flag: RankedFlag) -> None:
        self.submitted.add(flag.value_sha)
        self.attempts += 1

    def record_result(self, flag: RankedFlag, correct: bool) -> None:
        if correct:
            # promote to T1 CONFIRMED (terminal)
            self.verified = RankedFlag(
                value=flag.value, tier=1, confidence=1.0, is_decoy=False,
                reason="platform oracle confirmed", source=flag.source,
                decode_path=flag.decode_path,
            )
        else:
            self.rejected.add(flag.value_sha)

    @property
    def terminal(self) -> bool:
        return self.verified is not None
