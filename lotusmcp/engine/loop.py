"""The OODA step() loop — Regime A, server-authoritative (§4.5).

One `step()` is OBSERVE → ORIENT → DECIDE → ACT:

  OBSERVE  rebuild the graph from the log tip; scan fresh output for flags.
  ORIENT   triage → derive phase signals → authoritative phase transition;
           halt on a terminal (surfacing to a human where the design says so).
  DECIDE   PlaybookEngine.propose (the SOLE generator) → EV+UCB select.
  ACT      the Executor runs the chosen action (sandboxed, in production) and
           returns the events it produced; the loop appends them through the ONE
           serializer, charges budget, and records progress / dead-ends.

The LLM and Kali are *injected* behind narrow interfaces. With the stub executor
and no gateway, the whole loop runs deterministically with neither — which is
exactly what makes it testable here. The loop never runs a command itself and
never mutates state except by appending events.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Protocol, Set, Tuple

from lotusmcp.engine.budget import BudgetLedger
from lotusmcp.engine.candidate import CandidateAction
from lotusmcp.engine.phases import (
    PhaseSignals,
    check_transition,
    should_halt,
)
from lotusmcp.engine.progress import ProgressTracker
from lotusmcp.engine.selector import action_class, select
from lotusmcp.flag.facade import FlagEngine
from lotusmcp.kernel.events import EventDraft
from lotusmcp.playbooks.engine import PlaybookEngine
from lotusmcp.playbooks.model import World
from lotusmcp.triage.classify import classify

# finding types that constitute a HARD "access gained" signal
_ACCESS_FTYPES = {"rce", "shell", "access", "authz_bypass", "auth_bypass", "sqli_dump"}
_SEVERITY_PAYOFF = {"critical": 1.0, "high": 0.8, "medium": 0.5, "low": 0.3, "info": 0.2}
_HARD_CONF = 0.8         # confidence proxy for a corroborated HARD signal (skeleton)
_LLM_TOKENS_PER_STEP = 800   # notional gateway spend charged each decision


class Executor(Protocol):
    """The only thing that touches Kali. Runs one action and returns the events
    it produced (already redacted). In production this is the sandboxed runner;
    in tests/demo it's scripted."""

    def run(self, action: CandidateAction, case) -> List[EventDraft]: ...


@dataclass
class StepResult:
    phase: str
    action: Optional[CandidateAction] = None
    halted: bool = False
    reason: str = ""
    progressed: bool = False
    budget: Dict = field(default_factory=dict)


@dataclass
class RunResult:
    final_phase: str
    steps: int
    flag: Optional[str] = None
    reason: str = ""
    history: List[StepResult] = field(default_factory=list)


class Loop:
    def __init__(
        self,
        case,
        executor: Executor,
        budget: Optional[BudgetLedger] = None,
        submit_oracle: Optional[Callable[[str], bool]] = None,
        scope_verified: bool = True,
        reachable: bool = True,
    ) -> None:
        self.case = case
        self.executor = executor
        self.budget = budget or BudgetLedger()
        self.submit_oracle = submit_oracle
        self.scope_verified = scope_verified
        self.reachable = reachable

        self.playbook = PlaybookEngine()
        self.flag = FlagEngine(case)
        self.progress = ProgressTracker()
        self.phase = case.meta.get("phase", "TRIAGE")

        self.turn = 0
        self.n_class: Dict[str, int] = {}
        self.tried: Set[Tuple[str, str, str]] = set()
        self.dead_end: Set[Tuple[str, str, str]] = set()
        self._last_entity_count = 0
        self._all_exploit_dead = False

    # ---------------------------------------------------------------- signals
    def _world(self) -> World:
        return World.from_graph_db(self.case.rebuild()["graph_db"])

    def _scan_for_flags(self, drafts: List[EventDraft]) -> None:
        texts: List[str] = []
        for d in drafts:
            for v in d.payload.values():
                if isinstance(v, str):
                    texts.append(v)
                elif isinstance(v, dict):
                    texts.extend(str(x) for x in v.values() if isinstance(x, str))
        if texts:
            self.flag.scan(texts)

    def _signals(self, world: World) -> PhaseSignals:
        fingerprinted = sum(
            1 for k in ("service.tcp", "service.http")
            for e in world.entities(k)
            if e.attr("product") or e.attr("version") or e.attr("server")
        )
        open_hyps = [h for h in world.hypotheses if h.status == "OPEN"]
        conf_candidates = [h.confidence for h in open_hyps] + \
                          [f.confidence for f in world.findings]
        payoff_candidates = [_SEVERITY_PAYOFF.get(f.severity, 0.2) for f in world.findings]
        best_conf = max(conf_candidates, default=0.0)
        best_payoff = max(payoff_candidates, default=0.0)

        access = any(
            f.ftype in _ACCESS_FTYPES and f.confidence >= _HARD_CONF
            for f in world.findings
        )

        ranked = self.flag.ranked()
        flag_local_ok = any(r.tier <= 2 for r in ranked)
        flag_verified = self.flag.policy.terminal

        return PhaseSignals(
            scope_verified=self.scope_verified,
            reachable=self.reachable,
            flag_format_set=bool(self.case.meta.get("flag_format")),
            fingerprinted_services=fingerprinted,
            best_open_hyp_conf=best_conf,
            best_open_hyp_payoff=best_payoff,
            access_gained=access,
            flag_local_ok=flag_local_ok,
            flag_verified=flag_verified,
            all_exploit_dead_ended=self._all_exploit_dead,
            new_surface=len(world) > self._last_entity_count,
            budget_exhausted=self.budget.exhausted(),
            budget_high_no_access=self.budget.high_water() and not access,
            plateaued=self.progress.plateaued(),
        )

    def _set_phase(self, new_phase: str, reason: str) -> None:
        if new_phase == self.phase:
            return
        self.phase = new_phase
        self.case.set_meta(phase=new_phase)
        self.case.append(EventDraft(
            type="case.status_changed",
            actor={"kind": "system", "name": "engine"},
            payload={"phase": new_phase, "reason": reason},
        ))

    def _maybe_submit(self, world: World) -> None:
        """On entering SOLVED_PENDING_SUBMIT with an oracle wired, try to verify."""
        if self.phase != "SOLVED_PENDING_SUBMIT" or not self.submit_oracle:
            return
        decision = self.flag.decide()
        if decision.action == "SUBMIT":
            self.budget.charge(tool_invocations=1, phase=self.phase)
            if self.flag.submit(decision, self.submit_oracle):
                self._set_phase("FLAG_FOUND", "platform oracle confirmed")

    # ---------------------------------------------------------------- step
    def step(self) -> StepResult:
        # ---- OBSERVE ----
        world = self._world()

        # ---- ORIENT ----
        tri = classify(self.case.meta, world)
        signals = self._signals(world)
        tr = check_transition(self.phase, signals)
        if tr.transition:
            self._set_phase(tr.next, tr.reason)
            self._maybe_submit(world)              # may promote to FLAG_FOUND

        if should_halt(self.phase):
            return StepResult(self.phase, halted=True, reason=tr.reason or "terminal",
                              budget=self.budget.snapshot())
        if self.budget.exhausted():
            self._set_phase("EXHAUSTED", "budget exhausted")
            return StepResult(self.phase, halted=True, reason="budget exhausted",
                              budget=self.budget.snapshot())

        # ---- DECIDE ----
        ps = self.playbook.propose(
            world, self.phase, category_conf=tri.category_conf,
            tried_keys=self.tried, dead_end_keys=self.dead_end,
        )
        if not ps.proposals:
            # no live candidate in this phase
            self._all_exploit_dead = (self.phase == "EXPLOIT")
            self.progress.record(False)
            return StepResult(self.phase, reason="no candidates (regress/escalate next)",
                              budget=self.budget.snapshot())
        sel = select(ps.proposals, self.phase, t=self.turn, n_class=self.n_class)
        action = sel.action

        # ---- ACT ----
        before_sig = world.signature()
        drafts = self.executor.run(action, self.case)
        for d in drafts:
            self.case.append(d)
        self._scan_for_flags(drafts)
        self.budget.charge(tool_invocations=1, llm_tokens=_LLM_TOKENS_PER_STEP,
                           phase=self.phase)
        key = action.dedup_key()
        self.tried.add(key)
        self.n_class[action_class(action)] = self.n_class.get(action_class(action), 0) + 1
        self.turn += 1

        # ---- progress / dead-end ----
        after_world = self._world()
        # progress = the graph actually learned something (§4.6)
        progressed = after_world.signature() != before_sig
        if not progressed:
            self.dead_end.add(key)   # produced no new knowledge -> never re-propose
        self.progress.record(progressed)
        self._last_entity_count = len(after_world)

        return StepResult(self.phase, action=action, progressed=progressed,
                          reason=action.rationale, budget=self.budget.snapshot())

    def run(self, max_steps: int = 50) -> RunResult:
        history: List[StepResult] = []
        for _ in range(max_steps):
            r = self.step()
            history.append(r)
            if r.halted:
                break
        flag = self.flag.policy.verified.value if self.flag.policy.verified else None
        return RunResult(self.phase, len(history), flag,
                         history[-1].reason if history else "", history)
