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

# Loop/flag jobs. Like SESSIONS, all policy is in the SDK-free JobService;
# lotus_next is read-only and always works, while propose_and_run (sandbox
# executor) and lotus_submit (signed platform oracle) fail closed until a
# launcher calls JOBS.configure(executor_factory=..., submit_oracle=...).
from lotusmcp.engine.jobs import JobService  # noqa: E402

JOBS = JobService(CASES_DIR)

# Profile gate + envelope cap (all decided in the SDK-free gateway.profile, so
# the split is unit-tested there). LITE = ChatGPT deep-research (read-only,
# tool-budget-bound); FULL = Claude/operator. `LOTUS_PROFILE=LITE|FULL`.
import functools  # noqa: E402

from lotusmcp.gateway.profile import (  # noqa: E402
    enforce_envelope, is_enabled, normalize_profile, tools_for,
)

PROFILE = normalize_profile(os.environ.get("LOTUS_PROFILE"))


def tool(fn):
    """Register `fn` as an MCP tool only if the active profile exposes it, and
    bound its output through the envelope cap. A tool the profile hides stays
    importable (for reuse/tests) but is never surfaced to the client, so the
    LITE tool count stays inside the connector budget."""
    if not is_enabled(fn.__name__, PROFILE):
        return fn

    @functools.wraps(fn)
    def wrapped(*args, **kwargs):
        capped, _report = enforce_envelope(fn(*args, **kwargs))
        return capped

    return mcp.tool()(wrapped)


def _case(case_id: str) -> Case:
    return Case(CASES_DIR, case_id)


def _graph_db(case_id: str) -> str:
    c = _case(case_id)
    c.rebuild()  # skeleton: rebuild-on-read; Phase-0 correctness over speed
    return str(c.dir / "projections" / "graph.db")


@tool
def create_case(case_id: str, title: str = "", category: str = "",
                flag_format: str = "", platform: str = "") -> dict:
    """Create a new CTF case. Scope is NOT set here — it is defined out-of-band
    by the operator (control plane, signed). Returns the case id."""
    Case.create(CASES_DIR, case_id, title=title, category=category or None,
                flag_format=flag_format or None, platform=platform or None)
    return {"case_id": case_id, "state_uri": f"lotus://case/{case_id}/brief"}


@tool
def get_state(case_id: str) -> str:
    """The bounded, salience-ranked working set (STATE.md) for a case — phase,
    attack surface, findings, live hypotheses, dead ends. Read this first."""
    return _case(case_id).rebuild()["state_md"]


@tool
def kb_query(case_id: str, kind: str = "", limit: int = 50) -> list:
    """Query the case knowledge graph. Optional `kind` filters entities
    (e.g. 'http.endpoint', 'service.http', 'finding'). Rows carry a uri to
    drill into detail via kb_get — raw output never enters context."""
    return kb.query(_graph_db(case_id), case_id, kind or None, limit)


@tool
def kb_get(case_id: str, entity_id: str) -> dict:
    """One graph node: its attributes (with confidence/corroboration/conflict)
    and outgoing edges."""
    return kb.get(_graph_db(case_id), case_id, entity_id)


@tool
def lotus_next(case_id: str, top: int = 5) -> dict:
    """Advisory, READ-ONLY: the next action(s) the planner would take in the
    case's current phase — the same PlaybookEngine → EV+UCB pick the loop makes,
    ranked with scores, but WITHOUT executing anything or mutating the case.
    Returns `{recommended, alternatives, phase, category}`."""
    return JOBS.next(case_id, top=top)


@tool
def propose_and_run(case_id: str, max_steps: int = 1) -> dict:
    """FULL (exec): advance the case up to `max_steps` OODA steps with the
    sandboxed executor — the ONE tool behind which the per-tool Kali adapters
    run (they are never individual MCP tools). Scope/budget/redaction enforced
    by the loop. Fails closed if no sandbox executor is configured."""
    return JOBS.propose_and_run(case_id, max_steps=max_steps)


@tool
def lotus_submit(case_id: str, value: str = "") -> dict:
    """FULL: submit a flag to the operator-signed platform oracle. Omit `value`
    to let the conservative submit policy pick the best viable candidate, or pass
    a specific known candidate value. Never auto-submits; fails closed with no
    oracle configured. Emits flag.submitted → flag.verified/rejected."""
    return JOBS.submit(case_id, value=value or None)


@tool
def kb_artifact(case_id: str, sha: str) -> dict:
    """Fetch a Tier-B artifact blob by content-address. Returns its status and,
    if present, the redacted text. An evicted blob degrades to
    `{present: false, note: "artifact evicted, integrity hash retained"}` —
    citations never dangle. Content is already redacted; secrets show as
    «SECRET:…» placeholders."""
    store = _case(case_id).blobs
    out = store.status(sha)
    data = store.get(sha)
    if data is not None:
        try:
            out["text"] = data.decode("utf-8")
        except UnicodeDecodeError:
            out["text"] = None
            out["binary"] = True
    return out


@tool
def case_gc(case_id: str) -> dict:
    """Enforce the Tier-B retention SLA: evict unpinned artifact blobs past
    their retention window, then LRU-evict to fit the size cap. Pinned blobs
    (flag / high-sev finding / critical-path citations) are never evicted; Tier
    A (log + graph) is untouched, so replay is unaffected. Returns eviction
    stats."""
    return _case(case_id).blobs.gc()


@tool
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


@tool
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


@tool
def session_close(case_id: str, sid: str, reason: str = "closed by operator") -> dict:
    """Close an open Regime-B session (releases the tube). Idempotent."""
    return SESSIONS.close(case_id, sid, reason)


@tool
def session_list(case_id: str) -> list:
    """List this case's sessions (open and closed) with their target and revision
    count — so the operator/agent can resume or close them."""
    return SESSIONS.list(case_id)


@tool
def case_resume(case_id: str) -> dict:
    """Bounded, salience-ranked resume packet: enough to reconstruct working
    context for a fresh session (phase, scope, budget, top attack surface, open
    findings, live hypotheses, dead ends) and never more than the token budget —
    over budget, the lowest-salience items are dropped and reported in
    `truncated`. Read this to resume a case you don't have loaded."""
    from lotusmcp.kernel.resume import build_resume_packet
    case = _case(case_id)
    return build_resume_packet(case.rebuild()["graph_db"], case.meta, case.store.tip)


@tool
def search(query: str, case_id: str) -> list:
    """LITE (ChatGPT deep-research): search the case for entities, findings and
    hypotheses matching `query`. Returns result stubs `{id, title, url, snippet}`
    where `id` is a resolvable lotus:// URI — pass it to `fetch` for full detail.
    An empty query returns the most salient items."""
    return RESOLVER.search(case_id, query)


@tool
def fetch(id: str) -> dict:
    """LITE (ChatGPT deep-research): resolve a search result `id` (a lotus:// URI)
    to its full document `{id, title, text, url, metadata}`. Delegates to the same
    resolver as Claude Resources, so the two profiles never drift."""
    return RESOLVER.fetch(id)


@tool
def case_replay(case_id: str, at_seq: int) -> dict:
    """Reconstruct the case state as of event `at_seq` — the authoritative phase
    plus a bounded snapshot of the graph at that moment. A pure fold of the log
    prefix, so it is byte-for-byte the projection the case had then."""
    from lotusmcp.replay import state_at
    return state_at(_case(case_id), at_seq)


@tool
def case_diff(case_id: str, from_seq: int, to_seq: int) -> dict:
    """The graph delta between two seqs: entities/findings/hypotheses added and
    hypotheses whose status/confidence changed, plus the phase transition."""
    from lotusmcp.replay import diff
    return diff(_case(case_id), from_seq, to_seq)


@tool
def case_writeup(case_id: str) -> dict:
    """Generate the two-stage writeup: a deterministic IR whose every claim is
    citation-checked against the log, with unsupported sentences exiled
    (`writeup.claim_rejected`). Returns the markdown + accept/reject counts. The
    writeup can never assert something the append-only log doesn't support."""
    from lotusmcp.replay import generate_writeup
    out = generate_writeup(_case(case_id))
    return {"markdown": out["markdown"], "accepted": out["accepted"],
            "rejected": out["rejected"]}


@tool
def case_repro(case_id: str) -> str:
    """Generate `repro.sh`: a deterministic bash reproduction of the solve,
    folded from the log's command trail (the exact validated argv each step
    ran), grouped by phase and annotated with rationale. Every token is
    shell-quoted; secrets stay redacted as «SECRET:…» placeholders. Same log ⇒
    byte-identical script; the generator runs nothing."""
    from lotusmcp.replay import build_repro
    return build_repro(_case(case_id))


@tool
def case_metrics(case_id: str) -> str:
    """OpenMetrics exposition for the case (events, entities, findings by
    severity, hypotheses by status, dead ends, flags, current phase) — a pure
    fold of the log/graph, safe to scrape into Prometheus/Grafana."""
    from lotusmcp.observability import render_openmetrics
    return render_openmetrics(_case(case_id))


@tool
def case_compact(case_id: str, keep_per_value: int = 4) -> dict:
    """Bound the live graph projection's claim log by collapsing redundant
    corroboration (top-`keep_per_value` claims per entity/attr/value) into one
    merged claim. Fold-preserving (noisy-OR is associative, so the asserted
    graph and STATE.md are byte-identical) and projection-internal — the
    append-only log is never touched, so a rebuild restores full history.
    Deterministic and idempotent. Returns {pruned, groups, refolded}."""
    return _case(case_id).compact(keep_per_value=keep_per_value)


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
    import sys
    print(f"lotusmcp: profile={PROFILE}  tools={tools_for(PROFILE)}", file=sys.stderr)
    mcp.run()
