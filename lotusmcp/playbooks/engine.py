"""The Playbook Engine — the SOLE candidate generator (§4.4).

Forward-chains the rule set over the world, then ranks the emitted candidates by
the playbook prior `U(A)`. It is the only place actions are born; the OODA loop
never invents an action, it only *selects* among these and folds in EV+UCB.

Two filters keep the proposal set honest and bounded:

  - **Dead-end / novelty.** A candidate whose `(capability, target, param_class)`
    key was already tried gets its novelty (and thus score) decayed; a key on the
    dead-end set is dropped outright — we never re-propose a known failure (§4.6).
  - **Per-entity-class quota.** Before scoring, cap how many candidates any single
    entity *kind* contributes, so a 5000-endpoint case can't drown out a crypto
    lead. Silent truncation is logged in the result, never hidden.

Deterministic: stable sort on (−score, cost, rule_id, target_id).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Set, Tuple

from lotusmcp.engine.candidate import CandidateAction
from lotusmcp.playbooks.model import Rule, World
from lotusmcp.playbooks.rules import ALL_RULES

# novelty multiplier once a dedup key has been tried but not dead-ended
_RETRY_NOVELTY = 0.2
DEFAULT_QUOTA_PER_KIND = 25


@dataclass
class Proposal:
    action: CandidateAction
    score: float
    novelty: float


@dataclass
class ProposalSet:
    proposals: List[Proposal]
    dropped_dead_end: int = 0
    dropped_quota: int = 0

    @property
    def actions(self) -> List[CandidateAction]:
        return [p.action for p in self.proposals]

    def top(self, n: int) -> List[Proposal]:
        return self.proposals[:n]


class PlaybookEngine:
    def __init__(self, rules: Optional[List[Rule]] = None) -> None:
        self.rules = rules if rules is not None else ALL_RULES

    def propose(
        self,
        world: World,
        phase: str,
        category_conf: Optional[Dict[str, float]] = None,
        tried_keys: Optional[Set[Tuple[str, str, str]]] = None,
        dead_end_keys: Optional[Set[Tuple[str, str, str]]] = None,
        quota_per_kind: int = DEFAULT_QUOTA_PER_KIND,
    ) -> ProposalSet:
        """Fire every phase-eligible rule and return scored, ranked proposals."""
        category_conf = category_conf or {}
        tried = tried_keys or set()
        dead = dead_end_keys or set()

        raw: List[CandidateAction] = []
        for rule in self.rules:
            if phase not in rule.phase_gate:
                continue
            raw.extend(rule.fire(world))

        # per-entity-kind quota (by the rule's selected kind == target kind)
        kept, dropped_quota = self._apply_quota(world, raw, quota_per_kind)

        proposals: List[Proposal] = []
        dropped_dead = 0
        for act in kept:
            key = act.dedup_key()
            if key in dead:
                dropped_dead += 1
                continue
            novelty = _RETRY_NOVELTY if key in tried else 1.0
            conf = category_conf.get(act.category, 0.5)
            score = act.score(conf, phase, novelty)
            if score <= 0.0:
                continue  # phase-gated out or zero-yield
            proposals.append(Proposal(act, round(score, 6), novelty))

        proposals.sort(key=lambda p: (-p.score, p.action.cost,
                                      p.action.rule_id, p.action.target_id))
        return ProposalSet(proposals, dropped_dead, dropped_quota)

    @staticmethod
    def _apply_quota(
        world: World, actions: List[CandidateAction], quota: int
    ) -> Tuple[List[CandidateAction], int]:
        if quota <= 0:
            return actions, 0
        # kind of the target entity, resolved via the world
        seen: Dict[str, int] = {}
        kept: List[CandidateAction] = []
        dropped = 0
        for act in actions:
            ent = world.get(act.target_id)
            kind = ent.kind if ent else "?"
            n = seen.get(kind, 0)
            if n >= quota:
                dropped += 1
                continue
            seen[kind] = n + 1
            kept.append(act)
        return kept, dropped
