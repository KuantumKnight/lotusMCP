"""case_replay / case_diff — deterministic state-at-seq and graph delta (§Phase 6).

Because the graph is a pure fold of the log, the state as of any past event `seq`
is just the fold of the events up to that seq, and the diff between two seqs is
the set delta of those two folds. Both are computed by replaying event *prefixes*
through the same `GraphProjector` the live case uses — so a replay is byte-for-
byte the projection the case had at that moment, never an approximation.
"""
from __future__ import annotations

import os
import sqlite3
import tempfile
from typing import Any, Dict, List, Tuple

from lotusmcp.kernel.projector import GraphProjector

# per-section caps so a replay/diff of a huge case stays bounded
CAP = 50


def _phase_at(case, seq: int) -> str:
    """The authoritative phase as of `seq` — the last case.status_changed at or
    before it (TRIAGE if none)."""
    phase = "TRIAGE"
    for ev in case.store.iter_events():
        if ev["seq"] > seq:
            break
        if ev["type"] == "case.status_changed":
            phase = ev.get("payload", {}).get("phase", phase)
    return phase


def _build_prefix(case, seq: int) -> str:
    """Fold events with seq ≤ `seq` into a fresh temp graph db; return its path.
    Caller must unlink it."""
    fd, path = tempfile.mkstemp(suffix=".db", prefix="lotus_replay_")
    os.close(fd)
    os.unlink(path)                       # GraphProjector creates it fresh
    proj = GraphProjector(path)
    proj.build(ev for ev in case.store.iter_events() if ev["seq"] <= seq)
    proj.close()
    return path


def _snapshot(db_path: str) -> Dict[str, Any]:
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    try:
        ents = [{"id": r["entity_id"], "kind": r["kind"], "display": r["key_display"]}
                for r in conn.execute(
                    "SELECT entity_id,kind,key_display FROM entity "
                    "WHERE status IS NULL OR status NOT IN ('retracted','superseded') "
                    "ORDER BY entity_id LIMIT ?", (CAP,))]
        finds = [{"id": r["id"], "ftype": r["ftype"], "severity": r["severity"]}
                 for r in conn.execute(
                     "SELECT id,ftype,severity FROM finding ORDER BY id LIMIT ?", (CAP,))]
        hyps = [{"hid": r["hid"], "status": r["status"],
                 "confidence": r["confidence"]}
                for r in conn.execute(
                    "SELECT hid,status,confidence FROM hypothesis ORDER BY hid LIMIT ?",
                    (CAP,))]
        counts = {
            "entities": conn.execute("SELECT count(*) FROM entity").fetchone()[0],
            "findings": conn.execute("SELECT count(*) FROM finding").fetchone()[0],
            "hypotheses": conn.execute("SELECT count(*) FROM hypothesis").fetchone()[0],
        }
    finally:
        conn.close()
    return {"entities": ents, "findings": finds, "hypotheses": hyps, "counts": counts}


def state_at(case, seq: int) -> Dict[str, Any]:
    """The reconstructed case state as of event `seq`: phase + a bounded snapshot
    of the graph (entities/findings/hypotheses + counts)."""
    seq = max(0, int(seq))
    path = _build_prefix(case, seq)
    try:
        snap = _snapshot(path)
    finally:
        _rm(path)
    snap.update({"at_seq": seq, "tip": case.store.tip, "phase": _phase_at(case, seq)})
    return snap


def diff(case, from_seq: int, to_seq: int) -> Dict[str, Any]:
    """The graph delta between two seqs: entities/findings/hypotheses added, and
    hypotheses whose status/confidence changed."""
    a, b = state_at(case, from_seq), state_at(case, to_seq)

    def _added(key, idf) -> List[Dict[str, Any]]:
        seen = {idf(x) for x in a[key]}
        return [x for x in b[key] if idf(x) not in seen]

    a_hyp = {h["hid"]: h for h in a["hypotheses"]}
    changed = [{"hid": h["hid"], "from": a_hyp[h["hid"]], "to": h}
               for h in b["hypotheses"]
               if h["hid"] in a_hyp and (
                   a_hyp[h["hid"]]["status"] != h["status"]
                   or a_hyp[h["hid"]]["confidence"] != h["confidence"])]

    return {
        "from_seq": a["at_seq"], "to_seq": b["at_seq"],
        "phase_from": a["phase"], "phase_to": b["phase"],
        "entities_added": _added("entities", lambda e: e["id"]),
        "findings_added": _added("findings", lambda f: f["id"]),
        "hypotheses_added": _added("hypotheses", lambda h: h["hid"]),
        "hypotheses_changed": changed,
    }


def _rm(path: str) -> None:
    try:
        os.unlink(path)
    except OSError:
        pass
