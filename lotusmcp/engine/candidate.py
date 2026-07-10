"""CandidateAction — the unit the Playbook Engine emits and the loop selects.

A candidate is a *proposed* action bound to an in-scope entity, carrying the
priors the OODA loop needs. The playbook score `U(A)` is the **server prior**;
the loop later folds in EV+UCB (ARCHITECTURE.md §4.4). Keeping `U(A)` here means
the generator and the selector agree on one formula.

    U(A) = categoryConf^1.5 · yield · priorityNorm · novelty · phaseGate
           / (cost + 10) · riskGate

Everything is a pure function of the candidate + a few caller-supplied scalars,
so proposal ordering is deterministic and replayable.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Tuple

# The phases a capability may run in (mirrors §4.3 phase machine names).
PHASES = ("TRIAGE", "RECON", "ENUMERATE", "EXPLOIT", "POST_EXPLOIT")

# payoff by phase, used later by EV; kept here so the two agree.
PHASE_PAYOFF = {"TRIAGE": 0.2, "RECON": 0.2, "ENUMERATE": 0.4,
                "EXPLOIT": 0.8, "POST_EXPLOIT": 1.0}


@dataclass(frozen=True)
class CandidateAction:
    capability: str                      # internal adapter name (never an MCP tool)
    category: str                        # web|crypto|pwn|rev|forensics|osint|recon
    target_id: str                       # entity_id this action binds to (in-scope)
    target_display: str
    params: Dict[str, Any]
    rule_id: str
    rationale: str
    phase_gate: Tuple[str, ...]          # phases in which this is allowed
    yield_: float = 0.5                  # expected usefulness of the output 0..1
    priority: float = 0.5                # rule author's hand priority 0..1
    cost: float = 1.0                    # relative spend (wall/tokens/attempts)
    risk: float = 1.0                    # risk GATE: 1.0 safe .. 0.0 forbidden

    def dedup_key(self) -> Tuple[str, str, str]:
        """(capability, target, param_class) — the dead-end / novelty key (§4.6)."""
        param_class = self.params.get("class") or self.params.get("probe") or "-"
        return (self.capability, self.target_id, str(param_class))

    def score(
        self,
        category_conf: float,
        phase: str,
        novelty: float = 1.0,
    ) -> float:
        """The playbook prior U(A). `novelty` decays as the dedup key repeats."""
        cat = max(0.0, min(1.0, category_conf))
        phase_gate = 1.0 if phase in self.phase_gate else 0.0
        priority_norm = max(0.0, min(1.0, self.priority))
        base = (cat ** 1.5) * self.yield_ * priority_norm * novelty * phase_gate
        return base / (self.cost + 10.0) * self.risk

    def to_dict(self) -> Dict[str, Any]:
        return {
            "capability": self.capability, "category": self.category,
            "target_id": self.target_id, "target": self.target_display,
            "params": self.params, "rule_id": self.rule_id,
            "rationale": self.rationale, "phase_gate": list(self.phase_gate),
            "yield": self.yield_, "priority": self.priority,
            "cost": self.cost, "risk": self.risk,
        }
