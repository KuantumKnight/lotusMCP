"""Bounded resume packet (§case_resume) — enough to reconstruct working context
for a fresh session, and never more than a token budget.

A resume packet is a compact, machine-readable snapshot: the case header, phase,
scope/budget, and the *most salient* slices of the graph (attack surface, open
findings, live hypotheses, dead ends), each capped and salience-ranked via
`engine.salience`. It is derived purely from the graph projection + case meta, so
it is deterministic and replayable, and it enforces a hard token budget — when
the graph is larger than the budget allows, the lowest-salience items are dropped
and the drop is reported (no silent truncation, §"no silent caps").
"""
from __future__ import annotations

import json
import sqlite3
from typing import Any, Dict, List, Optional, Tuple

from lotusmcp.engine.salience import Salience, rank

# Per-section item caps (upper bounds; the token budget may trim further).
CAP_SURFACE = 25
CAP_FINDINGS = 15
CAP_HYPS = 8
CAP_DEADENDS = 10

# Rough token estimate: ~4 chars/token (matches the STATE.md discipline target).
CHARS_PER_TOKEN = 4
DEFAULT_TOKEN_BUDGET = 6500

_SEV_PATHFLAG = {"crit": 1.0, "critical": 1.0, "high": 0.8, "med": 0.5,
                 "medium": 0.5, "low": 0.3, "info": 0.1}


def _est_tokens(obj: Any) -> int:
    return len(json.dumps(obj, separators=(",", ":"))) // CHARS_PER_TOKEN


def _entity_saliences(conn: sqlite3.Connection, tip: int
                      ) -> List[Tuple[str, Salience, Dict[str, Any]]]:
    """Derive each entity's salience components from the graph. Documented
    heuristics (deterministic): s_conf = entity confidence; s_hyp = connected to
    the reasoning graph (has a relation); s_pathflag = max severity of a finding
    whose subject names this entity; s_deadend = named in a dead-end target."""
    connected = {r[0] for r in conn.execute("SELECT DISTINCT src_id FROM relation")}
    connected |= {r[0] for r in conn.execute("SELECT DISTINCT dst_id FROM relation")}

    # finding subject text -> max severity payoff, matched against entity displays
    finding_subjects: List[Tuple[str, float]] = []
    for subj, sev in conn.execute("SELECT subject_json,severity FROM finding"):
        finding_subjects.append((subj or "", _SEV_PATHFLAG.get((sev or "").lower(), 0.0)))
    deadend_targets = [r[0] or "" for r in conn.execute("SELECT target FROM deadend")]

    out: List[Tuple[str, Salience, Dict[str, Any]]] = []
    for eid, kind, disp, status, conf, last_seq in conn.execute(
        "SELECT entity_id,kind,key_display,status,confidence,last_seq FROM entity"
    ):
        if status in ("retracted", "superseded"):
            continue
        disp = disp or eid
        s_pathflag = max((pf for subj, pf in finding_subjects
                          if eid in subj or (disp and disp in subj)), default=0.0)
        s_deadend = 1.0 if any(disp and disp in t for t in deadend_targets) else 0.0
        sal = Salience(
            s_conf=conf if conf is not None else 0.0,
            s_hyp=1.0 if eid in connected else 0.0,
            s_pathflag=s_pathflag,
            s_deadend=s_deadend,
            last_seq=last_seq or 0,
        )
        out.append((eid, sal, {"id": eid, "kind": kind, "display": disp}))
    return out


def build_resume_packet(
    db_path: str,
    case_meta: Dict[str, Any],
    tip: int,
    *,
    token_budget: int = DEFAULT_TOKEN_BUDGET,
) -> Dict[str, Any]:
    """Build the bounded resume packet from the graph at `db_path` and `tip`."""
    conn = sqlite3.connect(db_path)
    try:
        n_ent = conn.execute("SELECT count(*) FROM entity").fetchone()[0]
        n_find = conn.execute("SELECT count(*) FROM finding").fetchone()[0]
        n_hyp = conn.execute("SELECT count(*) FROM hypothesis").fetchone()[0]

        # ---- salience-ranked attack surface ----
        sal_rows = _entity_saliences(conn, tip)
        sal_by_id = {eid: (sal, meta) for eid, sal, meta in sal_rows}
        ranked = rank([(eid, sal) for eid, sal, _ in sal_rows], tip)
        surface = [dict(sal_by_id[eid][1], salience=round(sc, 4))
                   for eid, sc in ranked[:CAP_SURFACE]]

        # ---- findings (severity, then confidence) ----
        findings = [
            {"ftype": ft, "severity": sev, "confidence": round(conf or 0.0, 3),
             "subject": _loads(subj)}
            for ft, subj, sev, conf in conn.execute(
                "SELECT ftype,subject_json,severity,confidence FROM finding "
                "ORDER BY CASE severity WHEN 'crit' THEN 0 WHEN 'critical' THEN 0 "
                "WHEN 'high' THEN 1 WHEN 'med' THEN 2 WHEN 'medium' THEN 2 "
                "WHEN 'low' THEN 3 ELSE 4 END, confidence DESC, source_seq LIMIT ?",
                (CAP_FINDINGS,))
        ]

        # ---- live hypotheses (open, by confidence) ----
        hypotheses = [
            {"hid": hid, "statement": stmt, "status": status,
             "confidence": round(conf or 0.0, 3)}
            for hid, stmt, status, conf in conn.execute(
                "SELECT hid,statement,status,confidence FROM hypothesis "
                "WHERE status!='KILLED' ORDER BY confidence DESC LIMIT ?", (CAP_HYPS,))
        ]

        # ---- dead ends (recent) ----
        dead_ends = [
            {"capability": cap, "target": tgt, "failure_mode": fm}
            for cap, tgt, fm in conn.execute(
                "SELECT capability,target,failure_mode FROM deadend "
                "ORDER BY seq DESC LIMIT ?", (CAP_DEADENDS,))
        ]
    finally:
        conn.close()

    packet: Dict[str, Any] = {
        "case_id": case_meta.get("case_id", "?"),
        "title": case_meta.get("title", ""),
        "phase": case_meta.get("phase", "TRIAGE"),
        "category": case_meta.get("category"),
        "status": case_meta.get("status", "active"),
        "flag_format": case_meta.get("flag_format"),
        "tip": tip,
        "scope": case_meta.get("scope", {}),
        "budget": case_meta.get("budget", {}),
        "counts": {"entities": n_ent, "findings": n_find, "hypotheses": n_hyp},
        "surface": surface,
        "findings": findings,
        "hypotheses": hypotheses,
        "dead_ends": dead_ends,
        "truncated": {},
    }
    _enforce_budget(packet, token_budget)
    return packet


def _enforce_budget(packet: Dict[str, Any], token_budget: int) -> None:
    """Trim lowest-salience items until the packet fits `token_budget`, recording
    what was dropped from each section. Surface is trimmed first (it is the
    largest and lowest-value tail), then dead ends, then findings — hypotheses,
    the scarce high-value reasoning, are trimmed last."""
    order = ["surface", "dead_ends", "findings", "hypotheses"]
    dropped = {k: 0 for k in order}
    # iteratively drop from the current section tail until under budget
    for section in order:
        while _est_tokens(packet) > token_budget and packet[section]:
            packet[section].pop()          # ranked ascending-importance at the tail
            dropped[section] += 1
    packet["truncated"] = {k: v for k, v in dropped.items() if v}
    packet["truncated"]["est_tokens"] = _est_tokens(packet)
    packet["truncated"]["token_budget"] = token_budget


def _loads(s: Any) -> Any:
    try:
        return json.loads(s) if s else {}
    except (json.JSONDecodeError, TypeError):
        return {}
