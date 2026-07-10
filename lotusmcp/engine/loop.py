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

import hashlib
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
from lotusmcp.engine.scope import Scope, ScopeVerifier
from lotusmcp.engine.selector import action_class, select
from lotusmcp.flag.facade import FlagEngine
from lotusmcp.kernel.events import EventDraft
from lotusmcp.llm.gateway import LLMGateway
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
        scope: Optional[Scope] = None,
        scope_verified: bool = True,
        reachable: bool = True,
        gateway: Optional[LLMGateway] = None,
    ) -> None:
        self.case = case
        self.executor = executor
        self.budget = budget or BudgetLedger()
        self.submit_oracle = submit_oracle
        # A signed, operator-authored scope loaded through the verify-only
        # `ScopeVerifier` (never set by the agent). When present it is the
        # authoritative per-action choke in ACT: any action bound to an
        # out-of-scope host:port is refused before the Executor ever runs it,
        # and a *verified* scope IS what "scope_verified" means. When absent the
        # choke is inactive and the legacy `scope_verified` bool drives the
        # signal — preserving the fully-deterministic, scope-less test path.
        self.scope = scope
        self.scope_verified = True if scope is not None else scope_verified
        self.reachable = reachable
        # Optional LLM gateway. When present it performs hypothesis abduction and
        # charges its OWN token spend to the loop's ONE ledger (so the flat
        # per-step notional charge below is skipped). When absent the loop stays
        # fully deterministic with no LLM — which is what keeps it testable here.
        self.gateway = gateway
        if self.gateway is not None:
            self.gateway.budget = self.budget

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

    @classmethod
    def from_scope_manifest(
        cls,
        case,
        executor: Executor,
        manifest: Dict,
        trusted_operator_keys,
        **kwargs,
    ) -> "Loop":
        """Construct a loop whose scope choke is bound to a *signed* scope
        manifest. The manifest is verified here through the verify-only
        `ScopeVerifier` (the server holds no private key and never authors
        scope); an untrusted signature raises `ScopeError` and no loop is built.
        The loop then only ever sees the resulting verified `Scope`."""
        scope = ScopeVerifier(trusted_operator_keys).load_scope(manifest)
        return cls(case, executor, scope=scope, **kwargs)

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

    def _abduce_hypotheses(self, world: World) -> bool:
        """ORIENT step (§4.1): the gateway abduces hypotheses from the current
        findings; new ones (by statement) are appended as `hypothesis.proposed`
        events. Returns True iff anything was appended. No-op without a gateway.
        The gateway cache makes a repeat call over unchanged findings free."""
        if self.gateway is None or not world.findings:
            return False
        findings = [{"id": f.id, "ftype": f.ftype, "confidence": f.confidence,
                     "subject": f.subject} for f in world.findings]
        resp = self.gateway.hypothesize(findings, phase=self.phase)
        existing = {h.statement for h in world.hypotheses}
        appended = False
        for h in resp.get("new", []):
            stmt = h["statement"]
            if stmt in existing:
                continue
            hid = "H" + hashlib.blake2b(stmt.encode("utf-8"), digest_size=4).hexdigest()
            self.case.append(EventDraft(
                "hypothesis.proposed", {"kind": "llm", "name": "gateway"},
                {"hid": hid, "statement": stmt, "status": "OPEN",
                 "confidence": h["confidence"]},
            ))
            existing.add(stmt)
            appended = True
        return appended

    def _info_gain(self, proposals):
        """DECIDE step: ask the gateway to estimate per-candidate info-gain and
        return the `InfoGainFn` the EV+UCB selector folds into `EV(a)`. Without a
        gateway, return None so the selector uses its default (1.0) and the choice
        stays fully deterministic. The estimate is ADVISORY — it only scales the
        info-gain term; phase gating, priors, cost and tie-break are unchanged."""
        if self.gateway is None or not proposals:
            return None
        cands = [{"key": "|".join(p.action.dedup_key()),
                  "yield": p.action.yield_, "cost": p.action.cost}
                 for p in proposals]
        ranking = self.gateway.rank(cands, phase=self.phase).get("ranking", [])
        ig_map = {r["key"]: r["info_gain"] for r in ranking}
        return lambda a: ig_map.get("|".join(a.dedup_key()), 1.0)

    def _maybe_submit(self, world: World) -> None:
        """On entering SOLVED_PENDING_SUBMIT with an oracle wired, try to verify."""
        if self.phase != "SOLVED_PENDING_SUBMIT" or not self.submit_oracle:
            return
        decision = self.flag.decide()
        if decision.action == "SUBMIT":
            self.budget.charge(tool_invocations=1, phase=self.phase)
            if self.flag.submit(decision, self.submit_oracle):
                self._set_phase("FLAG_FOUND", "platform oracle confirmed")

    def _scope_reason(self, action: CandidateAction, world: World) -> Optional[str]:
        """Per-action scope choke (§1, §2). Returns a refusal reason if the
        action's bound target is out of the verified scope, else None.

        No scope loaded → choke inactive (None). A target with no network
        address (a crypto artifact, a file) is not scope-gated → None. A target
        with a host but no bound port yet (e.g. a port scan) must match a scope
        host rule; a host:port target must satisfy `in_scope(host, port)`."""
        if self.scope is None:
            return None
        entity = world.get(action.target_id)
        if entity is None:
            return None                     # missing target handled in ACT
        tgt = entity.target()
        host = tgt.get("addr") or tgt.get("host")
        if not isinstance(host, str) or not host:
            return None                     # non-network target — not scope-gated
        port = tgt.get("port")
        if port is None:
            if not self.scope.host_in_scope(host):
                return f"host {host} out of scope"
            return None
        if not self.scope.in_scope(host, port):
            return f"target {host}:{port} out of scope"
        return None

    # ---------------------------------------------------------------- step
    def step(self) -> StepResult:
        # ---- OBSERVE ----
        world = self._world()

        # ---- ORIENT ----
        if self._abduce_hypotheses(world):
            world = self._world()          # refold so signals see the new hypotheses
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
        sel = select(ps.proposals, self.phase, t=self.turn, n_class=self.n_class,
                     info_gain=self._info_gain(ps.proposals))
        action = sel.action

        # ---- scope choke (per-request, before the Executor is touched) ----
        # Defense in depth: even though candidates are generated from in-scope
        # discovery, the verified scope is enforced here so an out-of-scope
        # target can never reach the Executor. Refused actions are logged and
        # dead-ended (never re-proposed), mirroring the adapterless-action path.
        deny = self._scope_reason(action, world)
        if deny is not None:
            self.case.append(EventDraft(
                type="note.added",
                actor={"kind": "system", "name": "engine"},
                payload={"note": f"scope choke refused {action.capability} "
                                 f"on {action.target_display}: {deny}",
                         "target_id": action.target_id, "kind": "scope_refused"},
            ))
            key = action.dedup_key()
            self.tried.add(key)
            self.dead_end.add(key)          # out of scope is permanent for this target
            self.progress.record(False)
            return StepResult(self.phase, action=action, progressed=False,
                              reason=f"scope choke: {deny}",
                              budget=self.budget.snapshot())

        # ---- ACT ----
        before_sig = world.signature()
        drafts = self.executor.run(action, self.case)
        for d in drafts:
            self.case.append(d)
        self._scan_for_flags(drafts)
        # With a gateway, LLM spend is charged inside oracle() on cache miss; the
        # flat notional charge is only for the gateway-less deterministic run.
        llm_flat = 0 if self.gateway is not None else _LLM_TOKENS_PER_STEP
        self.budget.charge(tool_invocations=1, llm_tokens=llm_flat, phase=self.phase)
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
