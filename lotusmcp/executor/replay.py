"""ReplayExecutor — the reference Executor that closes the loop, NO Kali.

It implements the loop's `Executor` protocol using ONLY the pure-Python boundary
we already have:

    decided action ──plan_action──▶ ArgvPlan(s) ──backend──▶ stdout
                  ──parse_*──▶ EventDrafts ──▶ (loop appends them)

The `backend` is any callable `ArgvPlan -> Optional[str]` that yields a command's
stdout — a fixture map, a recorded corpus, or (in Phase 1) the real sandboxed
process. Swapping the backend for a subprocess runner is the ONLY change needed
to go live; the planning, validation, and parsing are identical in test and prod.

Design choices that keep it honest:
  - An action the argv layer refuses (`ArgvRejected`) or has no adapter for
    (`NoAdapter`) produces a `note.added`, never a silent success and never a
    crash — the loop sees "no new knowledge" and dead-ends / escalates.
  - The parser is chosen by the plan's tool, and gets the same structured target
    the argv layer used, so discovered entities land on the identity.py keys.
"""
from __future__ import annotations

from typing import Any, Callable, Dict, List, Mapping, Optional

from lotusmcp.executor.argv import ArgvPlan, ArgvRejected, NoAdapter
from lotusmcp.executor.parse import (
    parse_ffuf_json,
    parse_http_response,
    parse_nmap_xml,
)
from lotusmcp.executor.plan import plan_action
from lotusmcp.kernel.events import EventDraft
from lotusmcp.playbooks.model import World

Backend = Callable[[ArgvPlan], Optional[str]]


def _path_from_url(url: str) -> str:
    i = url.find("://")
    rest = url[i + 3:] if i != -1 else url
    j = rest.find("/")
    return rest[j:] if j != -1 else "/"


def _note(name: str, text: str) -> EventDraft:
    return EventDraft("note.added", {"kind": "system", "name": name}, {"text": text})


class ReplayExecutor:
    def __init__(self, backend: Backend) -> None:
        self.backend = backend

    def run(self, action, case) -> List[EventDraft]:
        world = World.from_graph_db(case.rebuild()["graph_db"])
        try:
            plans = plan_action(action, world)
        except NoAdapter:
            return [_note(action.capability,
                         f"{action.capability}: Regime-B capability, no Phase-1 adapter")]
        except ArgvRejected as e:
            return [_note("executor", f"action refused by argv choke: {e}")]

        ent = world.get(action.target_id)
        svc_nk: Mapping[str, Any] = ent.target() if ent else {}
        drafts: List[EventDraft] = []
        for plan in plans:
            out = self.backend(plan)
            if not out:
                continue
            drafts.extend(self._parse(plan, out, svc_nk))
        if not drafts:
            drafts.append(_note(plans[0].tool,
                               f"{plans[0].tool} ran, produced no parseable knowledge"))
        return drafts

    def _parse(self, plan: ArgvPlan, out: str, svc_nk: Mapping[str, Any]) -> List[EventDraft]:
        if plan.tool == "nmap":
            return parse_nmap_xml(out)
        if plan.tool == "curl":
            return parse_http_response(out, svc_nk, path=_path_from_url(plan.argv[-1]))
        if plan.tool == "ffuf":
            return parse_ffuf_json(out, svc_nk)
        return []


class FixtureBackend:
    """A dict-backed backend for demos/tests. Keys: 'nmap', 'ffuf', or
    'curl <path>' (matching an http_probe plan's requested path)."""

    def __init__(self, fixtures: Dict[str, str]) -> None:
        self.fixtures = fixtures

    def __call__(self, plan: ArgvPlan) -> Optional[str]:
        if plan.tool == "curl":
            return self.fixtures.get(f"curl {_path_from_url(plan.argv[-1])}")
        return self.fixtures.get(plan.tool)
