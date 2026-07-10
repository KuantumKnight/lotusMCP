"""SessionManager — the live registry the session MCP tools wrap.

`session_edit_run` / `session_close` / `session_list` are stateful: a session is
a *persistent* tube + workspace that survives across tool calls, so the server
needs somewhere to hold the open sessions between MCP requests. This manager is
that place — pure orchestration, no I/O of its own beyond what `InteractiveSession`
already does through the one serializer.

The tube + runner (and, in the autonomous path, the author) are supplied by an
injected `factory`, so the manager is exercised offline with deterministic pieces
and, in production, with the sandbox tube + real script runner. It never holds a
private key: the caller passes an already-verified `Scope` (from the verify-only
`ScopeVerifier`) so the write-in choke stays server-side and signature-gated.
"""
from __future__ import annotations

from typing import Any, Callable, Dict, List, Optional, Tuple

from lotusmcp.session.session import InteractiveSession

# factory(case, sid, entity, goal, flag, budget, scope, phase) -> InteractiveSession
SessionFactory = Callable[..., InteractiveSession]


class SessionError(RuntimeError):
    """A session tool was called against a missing or closed session."""


class SessionManager:
    def __init__(self, factory: SessionFactory) -> None:
        self._factory = factory
        self._sessions: Dict[Tuple[str, str], InteractiveSession] = {}
        self._seq: Dict[str, int] = {}

    # ------------------------------------------------------------------ helpers
    def _next_sid(self, case_id: str) -> str:
        n = self._seq.get(case_id, 0) + 1
        self._seq[case_id] = n
        return f"s{n}"

    def _live(self, case_id: str, sid: str) -> InteractiveSession:
        sess = self._sessions.get((case_id, sid))
        if sess is None:
            raise SessionError(f"no session {sid!r} for case {case_id!r}")
        if sess.closed:
            raise SessionError(f"session {sid!r} is closed")
        return sess

    @staticmethod
    def _view(sid: str, sess: InteractiveSession, last=None) -> Dict[str, Any]:
        out = {"sid": sid, "target_id": sess.entity.get("id"),
               "target": sess.entity.get("display", ""), "goal": sess.goal,
               "phase": sess.phase, "revisions": sess.rev, "closed": sess.closed}
        if last is not None:
            out.update({"rev": last.rev, "ok": last.ok,
                        "flag_local_ok": last.flag_local_ok,
                        "reason": last.reason})
        return out

    # ------------------------------------------------------------------ tools
    def open(self, *, case, entity: Dict[str, Any], goal: str,
             flag, budget, scope=None, phase: str = "EXPLOIT") -> Dict[str, Any]:
        """Open a persistent session against an in-scope target. Returns the
        session view; if the write-in target is out of scope the session refuses
        to open (`opened=False`) and a scope_refused note is logged."""
        sid = self._next_sid(case.case_id)
        sess = self._factory(case=case, sid=sid, entity=entity, goal=goal,
                             flag=flag, budget=budget, scope=scope, phase=phase)
        ok = sess.open()
        self._sessions[(case.case_id, sid)] = sess
        view = self._view(sid, sess)
        view["opened"] = ok
        return view

    def edit_run(self, case_id: str, sid: str, sends,
                 text: str = "", note: str = "client script") -> Dict[str, Any]:
        """Run one client-supplied script revision against the session's tube."""
        sess = self._live(case_id, sid)
        res = sess.edit_run(sends, text=text, note=note)
        return self._view(sid, sess, res)

    def close(self, case_id: str, sid: str, reason: str = "closed") -> Dict[str, Any]:
        sess = self._sessions.get((case_id, sid))
        if sess is None:
            raise SessionError(f"no session {sid!r} for case {case_id!r}")
        sess.close(reason)
        return self._view(sid, sess)

    def list(self, case_id: str) -> List[Dict[str, Any]]:
        return [self._view(sid, s) for (cid, sid), s in sorted(self._sessions.items())
                if cid == case_id]

    def get(self, case_id: str, sid: str) -> Optional[InteractiveSession]:
        return self._sessions.get((case_id, sid))
