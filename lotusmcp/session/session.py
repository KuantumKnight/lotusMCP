"""InteractiveSession — the Regime-B workspace + iterate loop (§4.2, §6).

A session is a *persistent* exploit workspace bound to one in-scope target: the
LLM (ScriptAuthor) writes/patches a script, the sandbox (ScriptRunner) runs it
against a persistent tube, the captured output is redacted and folded back, and
the author revises — repeating until the flag surfaces or a cap is hit. While a
session is open the loop suspends phase/plateau accounting (loop.py owns that);
the server still enforces the three invariants that never lapse:

  * **scope** — the target must bind to an in-scope entity (write-ins included);
  * **budget** — every run charges the one shared ledger;
  * **redaction** — all output reaches the log only through the serializer choke.

Every state change is an event (`session.opened` / `script.revised` /
`script.run` / `session.closed`); the log stays the only source of truth. The
workspace files under `sessions/<sid>/` are a convenience mirror and are redacted
before they touch disk, so no plaintext secret is written outside the vault.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

from lotusmcp.engine.scope import Scope
from lotusmcp.kernel.events import EventDraft
from lotusmcp.session.authoring import RunOutput, Script, ScriptAuthor, ScriptRunner
from lotusmcp.session.tube import Tube

_ACTOR_LLM = {"kind": "llm", "name": "gateway"}
_ACTOR_SYS = {"kind": "system", "name": "session"}


@dataclass
class IterateResult:
    rev: int
    ok: bool = False
    flag_local_ok: bool = False
    ran: bool = False
    closed: bool = False
    reason: str = ""


class InteractiveSession:
    def __init__(
        self,
        case,
        sid: str,
        entity: Dict[str, Any],
        goal: str,
        tube: Tube,
        author: ScriptAuthor,
        runner: ScriptRunner,
        flag,
        budget,
        scope: Optional[Scope] = None,
        phase: str = "EXPLOIT",
        max_revs: int = 6,
    ) -> None:
        self.case = case
        self.sid = sid
        self.entity = entity
        self.goal = goal
        self.tube = tube
        self.author = author
        self.runner = runner
        self.flag = flag
        self.budget = budget
        self.scope = scope
        self.phase = phase
        self.max_revs = max_revs

        self.rev = 0
        self.opened = False
        self.closed = False
        self.runs: List[RunOutput] = []
        self.workspace = Path(case.dir) / "sessions" / sid
        self.workspace.mkdir(parents=True, exist_ok=True)

    # ---------------------------------------------------------------- scope
    def _scope_reason(self) -> Optional[str]:
        """The write-in choke: the bound target must be in the verified scope.
        No scope loaded → not gated; a non-network target → not gated."""
        if self.scope is None:
            return None
        host = self.entity.get("addr") or self.entity.get("host")
        if not isinstance(host, str) or not host:
            return None
        port = self.entity.get("port")
        if port is None:
            return None if self.scope.host_in_scope(host) else f"host {host} out of scope"
        return None if self.scope.in_scope(host, port) else f"target {host}:{port} out of scope"

    # ---------------------------------------------------------------- lifecycle
    def open(self) -> bool:
        """Open the session iff the target is in scope. Returns False (and emits
        nothing but a refusal note) when the write-in target is out of scope."""
        if self.opened:
            return not self.closed
        deny = self._scope_reason()
        if deny is not None:
            self.case.append(EventDraft(
                "note.added", _ACTOR_SYS,
                {"note": f"session write-in refused: {deny}",
                 "target_id": self.entity.get("id"), "kind": "scope_refused"},
            ))
            self.closed = True
            return False
        self.opened = True
        self.case.append(EventDraft(
            "session.opened", _ACTOR_SYS,
            {"sid": self.sid, "target_id": self.entity.get("id"),
             "target": self.entity.get("display", ""), "goal": self.goal,
             "phase": self.phase},
        ))
        return True

    def _persist(self, script: Script, run: RunOutput) -> None:
        red_text, _ = self.case.redactor.redact_text(script.text)
        (self.workspace / f"script.rev{script.rev}.py").write_text(
            red_text, encoding="utf-8")
        lines = [f"$ {d}" if kind == "send" else d for kind, d in run.transcript]
        red_tr, _ = self.case.redactor.redact_text("\n".join(lines))
        with (self.workspace / "transcript.log").open("a", encoding="utf-8") as fh:
            fh.write(f"--- rev {script.rev} ---\n{red_tr}\n")

    def _run_script(self, script: Script) -> IterateResult:
        """Run one authored/patched script against the persistent tube and fold
        the result: emit `script.revised`/`script.run` (output redacted by the
        serializer choke), charge the shared budget, mirror the workspace, scan
        for flags, and close on a flag or the revision cap. Shared by the
        autonomous `iterate()` and the client-driven `edit_run()`."""
        self.case.append(EventDraft(
            "script.revised", _ACTOR_LLM,
            {"sid": self.sid, "rev": script.rev, "sha": script.sha(),
             "note": script.note, "target_id": script.target_id},
        ))

        run = self.runner.run(script, self.tube)
        self.runs.append(run)
        self.budget.charge(tool_invocations=1, phase=self.phase)
        self.case.append(EventDraft(
            "script.run", _ACTOR_SYS,
            {"sid": self.sid, "rev": script.rev, "ok": run.ok,
             "output": run.stdout},                # redacted by the serializer choke
        ))
        self._persist(script, run)

        # ---- fold: scan the (raw) output for flags before it is discarded ----
        if run.stdout:
            self.flag.scan([run.stdout])
        flag_local_ok = any(r.tier <= 2 for r in self.flag.ranked())

        self.rev += 1
        res = IterateResult(self.rev - 1, ok=run.ok, flag_local_ok=flag_local_ok,
                            ran=True)
        if flag_local_ok:
            self.close("flag candidate found")
            res.closed, res.reason = True, "flag candidate found"
        elif self.rev >= self.max_revs:
            self.close("revision cap reached")
            res.closed, res.reason = True, "revision cap reached"
        return res

    def _guard(self) -> Optional[IterateResult]:
        """Shared precondition check for a run: session must be open and the
        budget must not be spent."""
        if not self.opened or self.closed:
            return IterateResult(self.rev, closed=self.closed, reason="not open")
        if self.budget.exhausted():
            self.close("budget exhausted")
            return IterateResult(self.rev, closed=True, reason="budget exhausted")
        return None

    def iterate(self) -> IterateResult:
        """One autonomous author → run → fold cycle (Regime-B loop path): the
        injected `ScriptAuthor` writes the next revision, then it is run."""
        blocked = self._guard()
        if blocked is not None:
            return blocked
        script = self.author.author(self.goal, self.entity, self.runs, self.rev)
        return self._run_script(script)

    def edit_run(self, sends, text: str = "", note: str = "client script") -> IterateResult:
        """Run a client-supplied script revision (the `session_edit_run` MCP
        path, §3): the caller — a human or the LLM over MCP — authors/patches the
        script; the server runs it against the persistent tube under the same
        scope/budget/redaction invariants as the autonomous path."""
        blocked = self._guard()
        if blocked is not None:
            return blocked
        sends = tuple(sends)
        script = Script(rev=self.rev, target_id=self.entity.get("id", "?"),
                        sends=sends, note=note,
                        text=text or ("# client-supplied script\n"
                                      + "\n".join(f"send {s!r}" for s in sends) + "\n"))
        return self._run_script(script)

    def close(self, reason: str = "done") -> None:
        if self.closed:
            return
        self.closed = True
        try:
            self.tube.close()
        except Exception:  # noqa: BLE001 — closing a spent tube must never crash the loop
            pass
        self.case.append(EventDraft(
            "session.closed", _ACTOR_SYS,
            {"sid": self.sid, "reason": reason, "revisions": self.rev,
             "target_id": self.entity.get("id")},
        ))

    def run_to_completion(self, max_iters: int = 20) -> IterateResult:
        """Convenience: iterate until the session closes (flag / cap / budget)."""
        if not self.open():
            return IterateResult(self.rev, closed=True, reason="not opened")
        last = IterateResult(self.rev)
        for _ in range(max_iters):
            last = self.iterate()
            if last.closed:
                break
        return last
