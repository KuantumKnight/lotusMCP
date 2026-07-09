"""The graph projector — a pure, deterministic fold of the event log into a
SQLite entity-relationship knowledge graph.

The graph is a *rebuildable projection*, never a source of truth. Rebuilding
from the same log always yields the same rows (the replay-equivalence test
asserts this). Facts are stored as append-only *claims*; the winning value per
(entity, attr) is a confidence-weighted noisy-OR fold, so re-running a scan
corroborates (bumps confidence) instead of clobbering.
"""
from __future__ import annotations

import sqlite3
from typing import Any, Dict, Iterable

from lotusmcp.ontology.identity import entity_id, key_display

PROJECTOR_VERSION = 1

_SCHEMA = """
CREATE TABLE entity (
  entity_id TEXT PRIMARY KEY, kind TEXT NOT NULL, natural_key TEXT NOT NULL,
  key_display TEXT, status TEXT, confidence REAL DEFAULT 1.0,
  created_seq INT NOT NULL, last_seq INT NOT NULL);
CREATE TABLE claim (
  claim_id INTEGER PRIMARY KEY AUTOINCREMENT, entity_id TEXT NOT NULL, attr TEXT NOT NULL,
  value_json TEXT NOT NULL, confidence REAL NOT NULL, tool TEXT, source_seq INT NOT NULL);
CREATE INDEX ix_claim_ea ON claim(entity_id, attr);
CREATE TABLE attribute (
  entity_id TEXT, attr TEXT, value_json TEXT, confidence REAL,
  corroboration INT DEFAULT 1, conflict INT DEFAULT 0, last_seq INT,
  PRIMARY KEY (entity_id, attr));
CREATE TABLE relation (
  relation_id TEXT PRIMARY KEY, src_id TEXT, rel_type TEXT, dst_id TEXT,
  confidence REAL, sign INT DEFAULT 1, updated_seq INT);
CREATE INDEX ix_rel_src ON relation(src_id, rel_type);
CREATE TABLE finding (
  id TEXT PRIMARY KEY, ftype TEXT, subject_json TEXT, attrs_json TEXT,
  confidence REAL, severity TEXT, sensitive INT DEFAULT 0, source_seq INT);
CREATE TABLE hypothesis (
  hid TEXT PRIMARY KEY, statement TEXT, status TEXT, confidence REAL, last_seq INT);
CREATE TABLE deadend (
  dedup_key TEXT PRIMARY KEY, capability TEXT, target TEXT,
  failure_mode TEXT, seq INT);
CREATE TABLE checkpoint (built_through_seq INT, projector_version INT);
"""


def _resolve_entity(payload: Dict[str, Any]) -> tuple[str, str, dict]:
    """Return (entity_id, kind, natural_key) from a payload that either names an
    explicit entity_id or gives (kind, natural_key)."""
    if "entity_id" in payload and "kind" not in payload:
        return payload["entity_id"], payload.get("kind", "?"), {}
    kind = payload["kind"]
    nk = payload["natural_key"]
    return entity_id(kind, nk), kind, nk


def _noisy_or(claims: Iterable[tuple[float]]) -> float:
    prod = 1.0
    for (c,) in claims:
        prod *= (1.0 - max(0.0, min(1.0, c)))
    return round(1.0 - prod, 6)


class GraphProjector:
    def __init__(self, db_path: str) -> None:
        self.conn = sqlite3.connect(db_path)
        self.conn.executescript(_SCHEMA)

    def _upsert_entity(self, eid, kind, nk, seq, status=None):
        row = self.conn.execute(
            "SELECT created_seq FROM entity WHERE entity_id=?", (eid,)
        ).fetchone()
        import json as _j
        disp = key_display(kind, nk) if nk else None
        if row is None:
            self.conn.execute(
                "INSERT INTO entity(entity_id,kind,natural_key,key_display,status,"
                "created_seq,last_seq) VALUES(?,?,?,?,?,?,?)",
                (eid, kind, _j.dumps(nk, sort_keys=True), disp, status, seq, seq),
            )
        else:
            self.conn.execute(
                "UPDATE entity SET last_seq=?, status=COALESCE(?,status) WHERE entity_id=?",
                (seq, status, eid),
            )

    def _refold_attribute(self, eid, attr, seq):
        rows = self.conn.execute(
            "SELECT value_json, confidence FROM claim WHERE entity_id=? AND attr=?",
            (eid, attr),
        ).fetchall()
        # group claims by value; winner = highest noisy-OR aggregate.
        by_val: Dict[str, list] = {}
        for value_json, conf in rows:
            by_val.setdefault(value_json, []).append((conf,))
        best_val, best_conf = None, -1.0
        second = 0.0
        for value_json, cs in sorted(by_val.items()):  # deterministic order
            agg = _noisy_or(cs)
            if agg > best_conf:
                second = best_conf
                best_val, best_conf = value_json, agg
            elif agg > second:
                second = agg
        conflict = 1 if second >= 0.5 else 0
        self.conn.execute(
            "INSERT INTO attribute(entity_id,attr,value_json,confidence,corroboration,"
            "conflict,last_seq) VALUES(?,?,?,?,?,?,?) "
            "ON CONFLICT(entity_id,attr) DO UPDATE SET value_json=excluded.value_json,"
            "confidence=excluded.confidence,corroboration=excluded.corroboration,"
            "conflict=excluded.conflict,last_seq=excluded.last_seq",
            (eid, attr, best_val, best_conf, len(rows), conflict, seq),
        )

    def apply(self, ev: Dict[str, Any]) -> None:
        t, seq, p = ev["type"], ev["seq"], ev.get("payload", {})
        if t == "entity.asserted":
            eid, kind, nk = _resolve_entity(p)
            self._upsert_entity(eid, kind, nk, seq, p.get("status"))
        elif t == "attribute.asserted":
            eid, kind, nk = _resolve_entity(p)
            self._upsert_entity(eid, kind, nk, seq)
            conf = float(p.get("confidence", ev.get("confidence", 0.5)))
            import json as _j
            self.conn.execute(
                "INSERT INTO claim(entity_id,attr,value_json,confidence,tool,source_seq)"
                " VALUES(?,?,?,?,?,?)",
                (eid, p["attr"], _j.dumps(p["value"], sort_keys=True), conf,
                 ev["actor"].get("name"), seq),
            )
            self._refold_attribute(eid, p["attr"], seq)
        elif t == "relation.asserted":
            rid = f"{p['src_id']}|{p['rel_type']}|{p['dst_id']}"
            self.conn.execute(
                "INSERT INTO relation(relation_id,src_id,rel_type,dst_id,confidence,sign,"
                "updated_seq) VALUES(?,?,?,?,?,?,?) ON CONFLICT(relation_id) DO UPDATE SET "
                "confidence=excluded.confidence,updated_seq=excluded.updated_seq",
                (rid, p["src_id"], p["rel_type"], p["dst_id"],
                 float(p.get("confidence", 1.0)), int(p.get("sign", 1)), seq),
            )
        elif t in ("finding.raised", "finding.updated"):
            import json as _j
            self.conn.execute(
                "INSERT INTO finding(id,ftype,subject_json,attrs_json,confidence,severity,"
                "sensitive,source_seq) VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET "
                "attrs_json=excluded.attrs_json,confidence=excluded.confidence,"
                "severity=excluded.severity,source_seq=excluded.source_seq",
                (p["id"], p.get("type"), _j.dumps(p.get("subject", {}), sort_keys=True),
                 _j.dumps(p.get("attrs", {}), sort_keys=True),
                 float(p.get("confidence", 0.5)), p.get("severity", "info"),
                 int(bool(p.get("sensitive", False))), seq),
            )
        elif t in ("hypothesis.proposed", "hypothesis.updated"):
            self.conn.execute(
                "INSERT INTO hypothesis(hid,statement,status,confidence,last_seq) "
                "VALUES(?,?,?,?,?) ON CONFLICT(hid) DO UPDATE SET "
                "statement=excluded.statement,status=excluded.status,"
                "confidence=excluded.confidence,last_seq=excluded.last_seq",
                (p["hid"], p.get("statement", ""), p.get("status", "OPEN"),
                 float(p.get("confidence", 0.3)), seq),
            )
        elif t == "deadend.marked":
            self.conn.execute(
                "INSERT OR REPLACE INTO deadend(dedup_key,capability,target,failure_mode,seq)"
                " VALUES(?,?,?,?,?)",
                (p["dedup_key"], p.get("capability"), p.get("target"),
                 p.get("failure_mode"), seq),
            )
        # other event types (command.*, budget.*, notes) are recorded in the log
        # and surfaced by other projections; the graph fold ignores them.

    def build(self, events: Iterable[Dict[str, Any]]) -> int:
        last = -1
        for ev in events:
            self.apply(ev)
            last = ev["seq"]
        self.conn.execute(
            "INSERT INTO checkpoint(built_through_seq,projector_version) VALUES(?,?)",
            (last, PROJECTOR_VERSION),
        )
        self.conn.commit()
        return last

    def close(self):
        self.conn.close()
