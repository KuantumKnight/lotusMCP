"""LotusMCP MCP server — the small, stable facade.

Surface: case management, read-only knowledge queries + progressive disclosure
(get_state / kb_query / kb_get), flag scanning, Regime-B interactive sessions
(session_edit_run / session_close / session_list, fail-closed), a bounded resume
packet (case_resume), and the LITE ChatGPT deep-research bridge (search / fetch)
served from the ONE surface Resolver that also backs Resources. Per-tool Kali
wrappers are NEVER individual MCP tools — they are internal adapters behind
`propose_and_run` — so the tool count stays inside the ChatGPT connector budget.

Run:  python -m lotusmcp.server        (stdio; add to your MCP client config)
Requires:  pip install "mcp[cli]"
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Optional

try:
    from mcp.server.fastmcp import FastMCP
except ImportError as e:  # pragma: no cover - helpful message if SDK missing
    raise SystemExit(
        "The MCP SDK is required to run the server: pip install \"mcp[cli]\"\n"
        "(The kernel/projector/demo run without it — see demo/seed_recon.py.)"
    ) from e

from lotusmcp import kb
from lotusmcp.kernel.case import Case

CASES_DIR = Path(os.environ.get("LOTUS_CASES_DIR", "cases")).resolve()
CASES_DIR.mkdir(parents=True, exist_ok=True)

mcp = FastMCP("lotusmcp")

# Regime-B interactive sessions are FULL-mode EXEC tools driving a persistent tube
# in the sandbox. All orchestration + fail-closed policy lives in the testable
# SessionService (no MCP dependency); here the tools only delegate. A production
# launcher calls SESSIONS.configure(backend_factory) with the real tube + sandbox
# runner — until then the tools refuse (fail closed).
from lotusmcp.session.service import SessionService  # noqa: E402

SESSIONS = SessionService(
    CASES_DIR,
    trusted_keys=[k.strip() for k in
                  os.environ.get("LOTUS_TRUSTED_OP_KEYS", "").split(",") if k.strip()],
)


from lotusmcp.gateway import Resolver  # noqa: E402

RESOLVER = Resolver(CASES_DIR)     # the ONE surface resolver (Resources + fetch)


def _case(case_id: str) -> Case:
    return Case(CASES_DIR, case_id)


def _graph_db(case_id: str) -> str:
    c = _case(case_id)
    c.rebuild()  # skeleton: rebuild-on-read; Phase-0 correctness over speed
    return str(c.dir / "projections" / "graph.db")


@mcp.tool()
def create_case(case_id: str, title: str = "", category: str = "",
                flag_format: str = "", platform: str = "") -> dict:
    """Create a new CTF case. Scope is NOT set here — it is defined out-of-band
    by the operator (control plane, signed). Returns the case id."""
    Case.create(CASES_DIR, case_id, title=title, category=category or None,
                flag_format=flag_format or None, platform=platform or None)
    return {"case_id": case_id, "state_uri": f"lotus://case/{case_id}/brief"}


@mcp.tool()
def get_state(case_id: str) -> str:
    """The bounded, salience-ranked working set (STATE.md) for a case — phase,
    attack surface, findings, live hypotheses, dead ends. Read this first."""
    return _case(case_id).rebuild()["state_md"]


@mcp.tool()
def kb_query(case_id: str, kind: str = "", limit: int = 50) -> list:
    """Query the case knowledge graph. Optional `kind` filters entities
    (e.g. 'http.endpoint', 'service.http', 'finding'). Rows carry a uri to
    drill into detail via kb_get — raw output never enters context."""
    return kb.query(_graph_db(case_id), case_id, kind or None, limit)


@mcp.tool()
def kb_get(case_id: str, entity_id: str) -> dict:
    """One graph node: its attributes (with confidence/corroboration/conflict)
    and outgoing edges."""
    return kb.get(_graph_db(case_id), case_id, entity_id)


@mcp.tool()
def flag_scan(case_id: str, text: str) -> dict:
    """Scan text/output for the flag — direct format hits and flags buried under
    stacked encodings (the bounded decode ladder). New candidates are logged as
    `flag.candidate`; returns the ranked registry (tier/confidence/decode path)
    and the submit policy's recommendation. Never auto-submits."""
    from lotusmcp.flag.facade import FlagEngine

    eng = FlagEngine(_case(case_id))
    ranked = eng.scan([text])
    decision = eng.decide()
    return {
        "candidates": [
            {"value": r.value, "tier": r.tier, "tier_name": r.tier_name,
             "confidence": r.confidence, "is_decoy": r.is_decoy,
             "source": r.source, "decode_path": list(r.decode_path),
             "reason": r.reason}
            for r in ranked
        ],
        "recommendation": {"action": decision.action, "reason": decision.reason,
                           "flag": decision.flag.value if decision.flag else None},
    }


@mcp.tool()
def session_edit_run(case_id: str, script: str, sid: str = "",
                     target_id: str = "", goal: str = "") -> dict:
    """Regime B (FULL, exec): write/patch an exploit script and run it against a
    persistent tube. Omit `sid` to open a new session bound to `target_id` (or the
    primary in-scope entity); pass an existing `sid` to patch+re-run in the same
    session (tube/session state preserved). Phase/plateau accounting is suspended
    while a session is open; scope, budget and redaction are always enforced.
    Fails closed if no sandbox backend is configured or the case has no
    signature-verified scope."""
    return SESSIONS.edit_run(case_id, script, sid=sid, target_id=target_id, goal=goal)


@mcp.tool()
def session_close(case_id: str, sid: str, reason: str = "closed by operator") -> dict:
    """Close an open Regime-B session (releases the tube). Idempotent."""
    return SESSIONS.close(case_id, sid, reason)


@mcp.tool()
def session_list(case_id: str) -> list:
    """List this case's sessions (open and closed) with their target and revision
    count — so the operator/agent can resume or close them."""
    return SESSIONS.list(case_id)


@mcp.tool()
def case_resume(case_id: str) -> dict:
    """Bounded, salience-ranked resume packet: enough to reconstruct working
    context for a fresh session (phase, scope, budget, top attack surface, open
    findings, live hypotheses, dead ends) and never more than the token budget —
    over budget, the lowest-salience items are dropped and reported in
    `truncated`. Read this to resume a case you don't have loaded."""
    from lotusmcp.kernel.resume import build_resume_packet
    case = _case(case_id)
    return build_resume_packet(case.rebuild()["graph_db"], case.meta, case.store.tip)


@mcp.tool()
def search(query: str, case_id: str) -> list:
    """LITE (ChatGPT deep-research): search the case for entities, findings and
    hypotheses matching `query`. Returns result stubs `{id, title, url, snippet}`
    where `id` is a resolvable lotus:// URI — pass it to `fetch` for full detail.
    An empty query returns the most salient items."""
    return RESOLVER.search(case_id, query)


@mcp.tool()
def fetch(id: str) -> dict:
    """LITE (ChatGPT deep-research): resolve a search result `id` (a lotus:// URI)
    to its full document `{id, title, text, url, metadata}`. Delegates to the same
    resolver as Claude Resources, so the two profiles never drift."""
    return RESOLVER.fetch(id)


@mcp.resource("lotus://case/{case_id}/brief")
def brief(case_id: str) -> str:
    """The bounded STATE.md working set as a subscribable resource."""
    return _case(case_id).state_md()


@mcp.resource("lotus://case/{case_id}/resume")
def resume_resource(case_id: str) -> str:
    """The bounded resume packet as a subscribable resource (same content the
    `case_resume` tool and `fetch` return — one resolver, no drift)."""
    import json
    return json.dumps(RESOLVER.fetch(f"lotus://case/{case_id}/resume"), indent=2)


if __name__ == "__main__":
    mcp.run()
