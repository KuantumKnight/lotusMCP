"""JobService — the OODA loop + flag submission as MCP-facing jobs (Phase 5).

Three tools sit on top of the deterministic engine, and (like SessionService)
all their orchestration + fail-closed policy live here with NO MCP dependency,
so they are unit-testable with a scripted executor and a mock oracle:

    lotus_next(case_id)            advisory, READ-ONLY: what would the planner
                                   do next here? Rebuild → classify → propose →
                                   EV+UCB rank. Mutates nothing.
    propose_and_run(case_id, n)    FULL/exec: advance the case up to n OODA
                                   steps with the configured sandbox executor.
                                   Fails closed if no executor is configured.
    lotus_submit(case_id, value?)  FULL: submit a flag candidate to the
                                   operator-signed platform oracle. Never
                                   auto-submits; fails closed with no oracle.

`propose_and_run` and `lotus_submit` need capabilities the server must never
hold by default (a sandbox that touches Kali; a signed submit endpoint), so
they refuse until a production launcher calls `configure(...)`. `lotus_next`
needs neither and is always available.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from lotusmcp.engine.budget import BudgetLedger
from lotusmcp.engine.loop import Loop
from lotusmcp.engine.selector import Scored, select
from lotusmcp.flag.facade import FlagEngine
from lotusmcp.flag.policy import SUBMIT, SubmitDecision
from lotusmcp.kernel.case import Case
from lotusmcp.playbooks.engine import PlaybookEngine
from lotusmcp.playbooks.model import World
from lotusmcp.triage.classify import classify


class JobError(Exception):
    """A job could not run (unknown case, bad argument)."""


class JobService:
    def __init__(
        self,
        cases_dir,
        *,
        executor_factory: Optional[Callable[[Case], Any]] = None,
        submit_oracle: Optional[Callable[[str], bool]] = None,
        gateway_factory: Optional[Callable[[Case], Any]] = None,
        scope_factory: Optional[Callable[[Case], Any]] = None,
    ) -> None:
        self.cases_dir = Path(cases_dir)
        self._executor_factory = executor_factory
        self._submit_oracle = submit_oracle
        self._gateway_factory = gateway_factory
        self._scope_factory = scope_factory

    def configure(
        self,
        *,
        executor_factory: Optional[Callable[[Case], Any]] = None,
        submit_oracle: Optional[Callable[[str], bool]] = None,
        gateway_factory: Optional[Callable[[Case], Any]] = None,
        scope_factory: Optional[Callable[[Case], Any]] = None,
    ) -> None:
        """Wire the production capabilities. Called once by the launcher; until
        then propose_and_run / lotus_submit fail closed."""
        if executor_factory is not None:
            self._executor_factory = executor_factory
        if submit_oracle is not None:
            self._submit_oracle = submit_oracle
        if gateway_factory is not None:
            self._gateway_factory = gateway_factory
        if scope_factory is not None:
            self._scope_factory = scope_factory

    # ------------------------------------------------------------------ helpers
    def _case(self, case_id: str) -> Case:
        c = Case(self.cases_dir, case_id)
        if not c.meta_path.exists():
            raise JobError(f"unknown case {case_id!r}")
        return c

    @staticmethod
    def _row(sc: Scored) -> Dict[str, Any]:
        d = sc.action.to_dict()
        d["scores"] = {"s": sc.s, "ev": sc.ev, "ucb": sc.ucb, "prior": sc.prior}
        return d

    # ------------------------------------------------------------------ next
    def next(self, case_id: str, top: int = 5) -> Dict[str, Any]:
        """READ-ONLY recommendation of the next action(s) for the case's current
        phase — the same PlaybookEngine → EV+UCB pick the loop would make, but
        without acting or mutating the case. Stateless: it does not know which
        actions a running loop has already spent this session, so it ranks from
        a fresh proposal set (advisory by design)."""
        case = self._case(case_id)
        world = World.from_graph_db(case.rebuild()["graph_db"])
        phase = case.meta.get("phase", "TRIAGE")
        tri = classify(case.meta, world)
        ps = PlaybookEngine().propose(
            world, phase, category_conf=tri.category_conf,
            tried_keys=set(), dead_end_keys=set(),
        )
        if not ps.proposals:
            return {"case_id": case_id, "phase": phase, "recommended": None,
                    "alternatives": [],
                    "reason": "no live candidate in this phase "
                              "(the loop would regress or escalate)"}
        sel = select(ps.proposals, phase)
        ranked = [self._row(sc) for sc in sel.ranked[:max(1, top)]]
        return {"case_id": case_id, "phase": phase,
                "category": tri.top, "category_conf": round(tri.confidence, 4),
                "recommended": ranked[0], "alternatives": ranked[1:],
                "reason": sel.action.rationale if sel.action else ""}

    # ------------------------------------------------------------ propose_and_run
    def propose_and_run(self, case_id: str, max_steps: int = 1) -> Dict[str, Any]:
        """Advance the case up to `max_steps` OODA steps with the configured
        sandbox executor. This is the ONE tool behind which the per-tool Kali
        adapters run — they are never individual MCP tools. Fails closed if no
        executor is configured. Loop state (tried/dead-end/turn) is preserved
        across the steps in a single call."""
        if self._executor_factory is None:
            return {"case_id": case_id, "ran": False, "refused": True,
                    "reason": "no sandbox executor configured (fail closed); a "
                              "launcher must call JobService.configure("
                              "executor_factory=...)"}
        if max_steps < 1:
            raise JobError("max_steps must be >= 1")
        case = self._case(case_id)
        executor = self._executor_factory(case)
        gateway = self._gateway_factory(case) if self._gateway_factory else None
        scope = self._scope_factory(case) if self._scope_factory else None
        loop = Loop(case, executor, budget=BudgetLedger(),
                    submit_oracle=self._submit_oracle, gateway=gateway, scope=scope)
        steps: List[Dict[str, Any]] = []
        for _ in range(max_steps):
            r = loop.step()
            steps.append({
                "phase": r.phase,
                "action": r.action.to_dict() if r.action else None,
                "progressed": r.progressed, "halted": r.halted,
                "reason": r.reason, "budget": r.budget,
            })
            if r.halted:
                break
        flag = loop.flag.policy.verified.value if loop.flag.policy.verified else None
        return {"case_id": case_id, "ran": True, "steps": steps,
                "final_phase": loop.phase, "flag": flag}

    # ------------------------------------------------------------------ submit
    def submit(self, case_id: str, value: Optional[str] = None) -> Dict[str, Any]:
        """Submit a flag to the operator-signed platform oracle. With no `value`
        the conservative SubmitPolicy chooses the best viable candidate; with a
        `value` the operator submits that specific known candidate. Never
        auto-submits and fails closed when no oracle is configured. Emits
        flag.submitted → flag.verified/flag.rejected through the log."""
        if self._submit_oracle is None:
            return {"case_id": case_id, "submitted": False, "refused": True,
                    "reason": "no operator-signed submit oracle configured "
                              "(fail closed); LotusMCP never auto-submits"}
        case = self._case(case_id)
        eng = FlagEngine(case)
        if eng.policy.terminal:
            return {"case_id": case_id, "submitted": False, "action": "DONE",
                    "reason": "flag already verified",
                    "flag": eng.policy.verified.value}
        ranked = eng.ranked()
        if value is not None:
            match = next((f for f in ranked if f.value == value), None)
            if match is None:
                return {"case_id": case_id, "submitted": False,
                        "reason": "value is not a known candidate — scan it first "
                                  "so it enters the registry"}
            if match.value_sha in eng.policy.submitted:
                return {"case_id": case_id, "submitted": False,
                        "reason": "candidate already submitted", "flag": value}
            decision = SubmitDecision(SUBMIT, match, "explicit operator submit")
        else:
            decision = eng.decide()
        if decision.action != SUBMIT:
            return {"case_id": case_id, "submitted": False,
                    "action": decision.action, "reason": decision.reason,
                    "flag": decision.flag.value if decision.flag else None}
        verified = eng.submit(decision, self._submit_oracle)
        return {"case_id": case_id, "submitted": True, "verified": verified,
                "flag": decision.flag.value, "status": case.meta.get("status"),
                "phase": case.meta.get("phase")}
