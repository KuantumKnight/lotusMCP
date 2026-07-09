"""STATE.md renderer — the bounded, salience-ranked working set the LLM reads.

This replaces the ever-growing CASE.md. It is regenerated deterministically
from the graph projection with hard per-section caps, so it stays small
(target <= ~6.5k tokens) no matter how large the case grows. Everything not
shown is retrievable on demand via kb_query / kb_get / kb_artifact
(progressive disclosure).
"""
from __future__ import annotations

import json
import sqlite3
from typing import Any, Dict

# hard per-section item caps (token discipline)
CAP_SERVICES = 25
CAP_ENDPOINTS = 30
CAP_FINDINGS = 20
CAP_HYPOTHESES = 8
CAP_DEADENDS = 12


def _attrs_for(conn: sqlite3.Connection, eid: str) -> Dict[str, Any]:
    out = {}
    for attr, value_json, conf, conflict in conn.execute(
        "SELECT attr,value_json,confidence,conflict FROM attribute WHERE entity_id=?", (eid,)
    ):
        v = json.loads(value_json)
        out[attr] = (v, conf, conflict)
    return out


def render_state_md(db_path: str, case_meta: Dict[str, Any]) -> str:
    conn = sqlite3.connect(db_path)
    L = []
    L.append(f"# CASE {case_meta.get('case_id','?')} - {case_meta.get('title','(untitled)')}")
    L.append("")
    L.append(f"- **Phase:** {case_meta.get('phase','TRIAGE')}  "
             f"**Category:** {case_meta.get('category','?')}  "
             f"**Status:** {case_meta.get('status','active')}")
    L.append(f"- **Flag format:** `{case_meta.get('flag_format','?')}`  "
             f"**Platform:** {case_meta.get('platform','?')}")
    scope = case_meta.get("scope", {})
    tgts = ", ".join(t.get("value", "?") for t in scope.get("targets", [])) or "(unset - control-plane signed)"
    L.append(f"- **In-scope targets:** {tgts}")
    b = case_meta.get("budget", {})
    if b:
        L.append(f"- **Budget:** {b}")
    L.append("")

    # counts overview
    n_ent = conn.execute("SELECT count(*) FROM entity").fetchone()[0]
    n_find = conn.execute("SELECT count(*) FROM finding").fetchone()[0]
    L.append(f"_Knowledge graph: {n_ent} entities, {n_find} findings "
             f"(full detail via kb_query / kb_get)._")
    L.append("")

    # Hosts & services
    L.append("## Attack surface")
    hosts = conn.execute(
        "SELECT entity_id,key_display FROM entity WHERE kind='host' ORDER BY last_seq"
    ).fetchall()
    for hid, hdisp in hosts:
        L.append(f"### {hdisp}")
        svcs = conn.execute(
            "SELECT entity_id,kind,key_display FROM entity "
            "WHERE kind IN ('service.tcp','service.http') ORDER BY last_seq LIMIT ?",
            (CAP_SERVICES,),
        ).fetchall()
        for sid, skind, sdisp in svcs:
            a = _attrs_for(conn, sid)
            prod = a.get("product", ("", 0, 0))[0] or a.get("server", ("", 0, 0))[0]
            ver = a.get("version", ("", 0, 0))[0]
            L.append(f"- `{sdisp}` {prod} {ver}".rstrip())
    ep_rows = conn.execute(
        "SELECT natural_key FROM entity WHERE kind='http.endpoint' ORDER BY last_seq LIMIT ?",
        (CAP_ENDPOINTS,),
    ).fetchall()
    if ep_rows:
        def _ep(nk_json: str) -> str:
            nk = json.loads(nk_json)
            return f"{nk.get('method','GET')} {nk.get('path','/')}"
        L.append("")
        L.append(f"**Endpoints ({min(len(ep_rows),CAP_ENDPOINTS)} shown):** "
                 + ", ".join(f"`{_ep(r[0])}`" for r in ep_rows))
    L.append("")

    # Findings
    L.append("## Findings")
    finds = conn.execute(
        "SELECT ftype,subject_json,attrs_json,severity,confidence FROM finding "
        "ORDER BY CASE severity WHEN 'crit' THEN 0 WHEN 'high' THEN 1 WHEN 'med' THEN 2 "
        "WHEN 'low' THEN 3 ELSE 4 END, source_seq LIMIT ?",
        (CAP_FINDINGS,),
    ).fetchall()
    if not finds:
        L.append("_None yet._")
    for ftype, subj, attrs, sev, conf in finds:
        subj_d = json.loads(subj)
        loc = subj_d.get("url") or subj_d.get("host") or subj_d.get("path") or ""
        L.append(f"- **[{sev}]** {ftype} @ {loc}  (conf {conf:.2f}) {json.loads(attrs) or ''}")
    L.append("")

    # Hypotheses (open, by confidence)
    L.append("## Live hypotheses")
    hyps = conn.execute(
        "SELECT hid,statement,status,confidence FROM hypothesis "
        "WHERE status!='KILLED' ORDER BY confidence DESC LIMIT ?", (CAP_HYPOTHESES,)
    ).fetchall()
    if not hyps:
        L.append("_None yet._")
    for hid, stmt, status, conf in hyps:
        L.append(f"- `{hid}` [{status} {conf:.2f}] {stmt}")
    L.append("")

    # Dead ends (never retry)
    de = conn.execute(
        "SELECT capability,target,failure_mode FROM deadend ORDER BY seq DESC LIMIT ?",
        (CAP_DEADENDS,),
    ).fetchall()
    if de:
        L.append("## Dead ends (do not retry as-is)")
        for cap, tgt, fm in de:
            L.append(f"- {cap} vs {tgt} → {fm}")
        L.append("")

    conn.close()
    return "\n".join(L)
