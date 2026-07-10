"""LotusMCP MCP server — the small, stable facade.

Phase-0 surface only: case management + read-only knowledge queries. The Kali
Executor, the OODA loop, and flag handling arrive in later phases (see
ARCHITECTURE.md build phases). Per-tool Kali wrappers are NEVER individual MCP
tools — they are internal adapters behind `propose_and_run` — so the tool count
stays inside the ChatGPT connector budget.

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


@mcp.resource("lotus://case/{case_id}/brief")
def brief(case_id: str) -> str:
    """The bounded STATE.md working set as a subscribable resource."""
    return _case(case_id).state_md()


if __name__ == "__main__":
    mcp.run()
