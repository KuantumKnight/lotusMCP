"""OpenMetrics exposition for a case — a pure fold, never a mutated counter.

Every series is recomputed from the log + graph at scrape time, so the numbers
can never drift from what the case actually reports (the same invariant that
makes STATE.md and the writeup trustworthy). Output is valid OpenMetrics text
(the Prometheus `text/plain; version=0.0.4` superset), terminated with `# EOF`.
"""
from __future__ import annotations

import sqlite3
from typing import Dict, List, Tuple


def _esc(v: str) -> str:
    """Escape a label value per OpenMetrics (backslash, quote, newline)."""
    return str(v).replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def _labels(pairs: List[Tuple[str, str]]) -> str:
    inner = ",".join(f'{k}="{_esc(v)}"' for k, v in pairs)
    return "{" + inner + "}" if inner else ""


def render_openmetrics(case) -> str:
    """Render the case's metrics as an OpenMetrics document."""
    cid = case.meta.get("case_id", "?")
    base = [("case", cid)]

    # event counts by type + the authoritative phase, folded from the log (so a
    # scrape never disagrees with the log even if case.json lags).
    ev_by_type: Dict[str, int] = {}
    total_events = 0
    phase = "TRIAGE"
    for ev in case.store.iter_events():
        ev_by_type[ev["type"]] = ev_by_type.get(ev["type"], 0) + 1
        total_events += 1
        if ev["type"] == "case.status_changed":
            phase = ev.get("payload", {}).get("phase", phase)

    db = case.rebuild()["graph_db"]
    conn = sqlite3.connect(db)
    try:
        n_ent = conn.execute("SELECT count(*) FROM entity").fetchone()[0]
        find_by_sev = dict(conn.execute(
            "SELECT COALESCE(severity,'unknown'),count(*) FROM finding GROUP BY severity"))
        hyp_by_status = dict(conn.execute(
            "SELECT COALESCE(status,'unknown'),count(*) FROM hypothesis GROUP BY status"))
        n_deadend = conn.execute("SELECT count(*) FROM deadend").fetchone()[0]
    finally:
        conn.close()

    flags_verified = ev_by_type.get("flag.verified", 0)

    L: List[str] = []

    def metric(name: str, mtype: str, help_: str, samples: List[Tuple[str, float]]):
        L.append(f"# HELP {name} {help_}")
        L.append(f"# TYPE {name} {mtype}")
        for label_str, value in samples:
            v = int(value) if float(value).is_integer() else value
            L.append(f"{name}{label_str} {v}")

    metric("lotus_events_total", "counter", "Total events appended to the log.",
           [(_labels(base), total_events)])
    metric("lotus_events_by_type_total", "counter", "Events by type.",
           [(_labels(base + [("type", t)]), n) for t, n in sorted(ev_by_type.items())])
    metric("lotus_entities", "gauge", "Entities in the graph.",
           [(_labels(base), n_ent)])
    metric("lotus_findings", "gauge", "Findings by severity.",
           [(_labels(base + [("severity", s)]), n) for s, n in sorted(find_by_sev.items())]
           or [(_labels(base + [("severity", "none")]), 0)])
    metric("lotus_hypotheses", "gauge", "Hypotheses by status.",
           [(_labels(base + [("status", s)]), n) for s, n in sorted(hyp_by_status.items())]
           or [(_labels(base + [("status", "none")]), 0)])
    metric("lotus_deadends", "gauge", "Dead-ended (capability,target) pairs.",
           [(_labels(base), n_deadend)])
    metric("lotus_flags_verified", "gauge", "Flags verified by the platform oracle.",
           [(_labels(base), flags_verified)])
    metric("lotus_phase_info", "gauge", "Current phase (label = phase, value 1).",
           [(_labels(base + [("phase", phase)]), 1)])

    L.append("# EOF")
    return "\n".join(L) + "\n"
