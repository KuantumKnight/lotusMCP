"""SessionService — the MCP-facing session policy, kept out of server.py.

The `session_*` MCP tools are thin delegators to this class so the whole policy —
fail-closed authorization, signature-verified scope loading, target resolution,
per-case budget — is exercisable with no MCP SDK, no sandbox, and no network.

Fail-closed is the rule for these EXEC tools: a session opens only when BOTH
(a) a sandbox backend has been configured (the real tube + script runner) AND
(b) the case has a signature-verified `Scope` (a signed scope.json + trusted
operator keys). Missing either → a structured `{"error": ...}`, never a session.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Dict, List, Optional

from lotusmcp.kernel.case import Case


class SessionService:
    def __init__(self, cases_dir, trusted_keys, backend_factory=None) -> None:
        self.cases_dir = Path(cases_dir)
        self.trusted_keys = [k for k in (trusted_keys or []) if k]
        self._mgr = None
        self._budgets: Dict[str, Any] = {}
        if backend_factory is not None:
            self.configure(backend_factory)

    # ------------------------------------------------------------------ config
    def configure(self, backend_factory) -> None:
        """Install the sandbox session factory (real tube + sandbox runner).
        `backend_factory(**kw) -> InteractiveSession`. Until called, tools refuse."""
        from lotusmcp.session.manager import SessionManager
        self._mgr = SessionManager(backend_factory)

    @property
    def configured(self) -> bool:
        return self._mgr is not None

    # ------------------------------------------------------------------ helpers
    def _case(self, case_id: str) -> Case:
        return Case(self.cases_dir, case_id)

    def _budget_for(self, case_id: str):
        """One BudgetLedger per case for the service's lifetime (skeleton:
        in-memory; production derives it from the case's budget.consumed events)."""
        from lotusmcp.engine.budget import BudgetLedger
        return self._budgets.setdefault(case_id, BudgetLedger())

    def verified_scope(self, case: Case):
        """The case's signature-verified `Scope`, or None. The signed manifest is
        the durable scope.json (§6); trusted operator keys are injected. Any
        failure (no keys, no manifest, bad type, bad signature) → None."""
        from lotusmcp.engine.scope import ScopeError, ScopeVerifier
        if not self.trusted_keys or not case.scope_path.exists():
            return None
        try:
            manifest = json.loads(case.scope_path.read_text(encoding="utf-8"))
            return ScopeVerifier(self.trusted_keys).load_scope(manifest)
        except (ScopeError, ValueError, OSError):
            return None

    # exploit-target preference, best first (mirrors Loop._pick_session_target).
    _TARGET_KINDS = ("binary", "artifact.binary", "service.tcp", "service.http",
                     "service", "endpoint", "host")

    def _resolve_target(self, case: Case, target_id: str) -> Optional[Dict[str, Any]]:
        from lotusmcp.playbooks.model import World
        world = World.from_graph_db(case.rebuild()["graph_db"])
        if target_id:
            ent = world.get(target_id)
        else:
            # no explicit id → pick the primary target deterministically
            ranked = sorted(
                (e for e in world.all()
                 if e.status not in ("retracted", "superseded")),
                key=lambda e: (self._TARGET_KINDS.index(e.kind)
                               if e.kind in self._TARGET_KINDS
                               else len(self._TARGET_KINDS), e.id))
            ent = ranked[0] if ranked else None
        if ent is None:
            return None
        t = ent.target()
        return {"id": ent.id, "display": ent.display, "host": t.get("host"),
                "addr": t.get("addr"), "port": t.get("port")}

    # ------------------------------------------------------------------ tools
    def edit_run(self, case_id: str, script: str, sid: str = "",
                 target_id: str = "", goal: str = "") -> Dict[str, Any]:
        if self._mgr is None:
            return {"error": "interactive sessions require a configured sandbox "
                             "backend (FULL mode); none is installed"}
        from lotusmcp.engine.regime import is_interactive
        from lotusmcp.flag.facade import FlagEngine

        case = self._case(case_id)
        scope = self.verified_scope(case)
        if scope is None:
            return {"error": "no signature-verified scope for this case — refusing "
                             "to open an exploit session (fail closed)"}
        phase = case.meta.get("phase", "EXPLOIT")
        if not is_interactive(phase, case.meta.get("category")):
            return {"error": f"phase {phase} / category {case.meta.get('category')} "
                             f"is not an interactive regime"}
        if not sid:
            entity = self._resolve_target(case, target_id)
            if entity is None:
                return {"error": "no target entity resolved for the session"}
            opened = self._mgr.open(
                case=case, entity=entity, goal=goal or "capture the flag",
                flag=FlagEngine(case), budget=self._budget_for(case_id),
                scope=scope, phase=phase)
            if not opened.get("opened"):
                return opened
            sid = opened["sid"]
        # the sandbox runner executes `script`; `sends` is the offline-tube model
        from lotusmcp.session.manager import SessionError
        try:
            return self._mgr.edit_run(case_id, sid, sends=[], text=script,
                                      note="mcp edit_run")
        except SessionError as e:
            return {"error": str(e)}

    def close(self, case_id: str, sid: str,
              reason: str = "closed by operator") -> Dict[str, Any]:
        if self._mgr is None:
            return {"error": "no session backend configured"}
        from lotusmcp.session.manager import SessionError
        try:
            return self._mgr.close(case_id, sid, reason)
        except SessionError as e:
            return {"error": str(e)}

    def list(self, case_id: str) -> List[Dict[str, Any]]:
        return [] if self._mgr is None else self._mgr.list(case_id)
