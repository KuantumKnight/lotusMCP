"""EV + UCB action selection (§4.4).

The Playbook Engine proposes; the selector *chooses*. It folds three terms:

    EV(a) = info_gain(a) · payoff(phase) / cost(a)
    UCB(a)= c · sqrt(ln(T+1) / (n_class(a)+1))
    S(a)  = w_ev·EV(a) + w_ucb·UCB(a) + w_prior·U_playbook(a)

`U_playbook(a)` is the server prior already computed by the engine (the
proposal's score). `info_gain(a)` is the LLM's estimate of how much an action
tells us (defaulted to 1.0 here so the loop is exercisable with no gateway).
`n_class(a)` counts how often that action *class* has already run — the UCB term
is what makes the loop *explore* a neglected class instead of hammering one lead.

Exploration guard (§4.4): don't broaden while the current lead still has an
untested cheap test. If any proposal is on the `active_lead` class, UCB is
suppressed for *other* classes that round, so depth beats breadth until the lead
is spent.

Deterministic: tie-break is (higher S, lower cost, lex rule_id, lex target).
"""
from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional

from lotusmcp.engine.candidate import PHASE_PAYOFF, CandidateAction
from lotusmcp.playbooks.engine import Proposal

W_EV = 1.0
W_UCB = 0.4
W_PRIOR = 0.2
UCB_C = 1.4

# an action's "class" for UCB accounting and dead-end keys
def action_class(a: CandidateAction) -> str:
    return a.capability


InfoGainFn = Callable[[CandidateAction], float]


@dataclass
class Scored:
    proposal: Proposal
    ev: float
    ucb: float
    prior: float
    s: float

    @property
    def action(self) -> CandidateAction:
        return self.proposal.action


@dataclass
class Selection:
    chosen: Optional[Scored]
    ranked: List[Scored]

    @property
    def action(self) -> Optional[CandidateAction]:
        return self.chosen.action if self.chosen else None


def _default_info_gain(_: CandidateAction) -> float:
    return 1.0


def select(
    proposals: List[Proposal],
    phase: str,
    t: int = 0,
    n_class: Optional[Dict[str, int]] = None,
    info_gain: Optional[InfoGainFn] = None,
    active_lead: Optional[str] = None,
) -> Selection:
    """Score proposals with EV+UCB and pick the best. `t` is the global step
    count; `n_class` maps action-class -> times already run."""
    n_class = n_class or {}
    ig = info_gain or _default_info_gain
    payoff = PHASE_PAYOFF.get(phase, 0.4)

    # is the active lead still on the table with a proposal this round?
    lead_present = active_lead is not None and any(
        action_class(p.action) == active_lead for p in proposals
    )

    scored: List[Scored] = []
    for p in proposals:
        a = p.action
        cls = action_class(a)
        ev = ig(a) * payoff / (a.cost + 1e-9)
        ucb = UCB_C * math.sqrt(math.log(t + 1.0) / (n_class.get(cls, 0) + 1.0))
        # depth-before-breadth: mute exploration on classes other than the lead
        if lead_present and cls != active_lead:
            ucb = 0.0
        prior = p.score
        s = W_EV * ev + W_UCB * ucb + W_PRIOR * prior
        scored.append(Scored(p, round(ev, 6), round(ucb, 6),
                             round(prior, 6), round(s, 6)))

    scored.sort(key=lambda x: (-x.s, x.action.cost,
                               x.action.rule_id, x.action.target_id))
    return Selection(scored[0] if scored else None, scored)
