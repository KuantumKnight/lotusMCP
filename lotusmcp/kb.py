"""Read-only knowledge-graph queries — the retrieval half of progressive
disclosure. The LLM reads the bounded STATE.md, then drills into detail here
without ever pulling raw tool output into context.

All rows carry a `uri` so an MCP client can resolve full detail via a resource
(lotus://case/{id}/entity/{eid}).
"""
from __future__ import annotations

import json
import sqlite3
from typing import Any, Dict, List, Optional


def _conn(db_path: str) -> sqlite3.Connection:
    c = sqlite3.connect(db_path)
    c.row_factory = sqlite3.Row
    return c


def query(db_path: str, case_id: str, kind: Optional[str] = None,
          limit: int = 50) -> List[Dict[str, Any]]:
    c = _conn(db_path)
    if kind:
        rows = c.execute(
            "SELECT entity_id,kind,key_display,status,confidence FROM entity "
            "WHERE kind=? ORDER BY last_seq DESC LIMIT ?", (kind, limit)
        ).fetchall()
    else:
        rows = c.execute(
            "SELECT entity_id,kind,key_display,status,confidence FROM entity "
            "ORDER BY last_seq DESC LIMIT ?", (limit,)
        ).fetchall()
    out = []
    for r in rows:
        out.append({
            "entity_id": r["entity_id"], "kind": r["kind"],
            "display": r["key_display"], "status": r["status"],
            "confidence": r["confidence"],
            "uri": f"lotus://case/{case_id}/entity/{r['entity_id']}",
        })
    c.close()
    return out


def get(db_path: str, case_id: str, eid: str) -> Dict[str, Any]:
    c = _conn(db_path)
    ent = c.execute("SELECT * FROM entity WHERE entity_id=?", (eid,)).fetchone()
    if ent is None:
        c.close()
        return {"error": "not_found", "entity_id": eid}
    attrs = {}
    for a in c.execute("SELECT attr,value_json,confidence,corroboration,conflict "
                       "FROM attribute WHERE entity_id=?", (eid,)):
        attrs[a["attr"]] = {"value": json.loads(a["value_json"]), "confidence": a["confidence"],
                            "corroboration": a["corroboration"], "conflict": bool(a["conflict"])}
    edges = [dict(r) for r in c.execute(
        "SELECT rel_type,dst_id,confidence FROM relation WHERE src_id=? LIMIT 100", (eid,))]
    c.close()
    return {"entity_id": eid, "kind": ent["kind"], "display": ent["key_display"],
            "status": ent["status"], "attributes": attrs, "edges": edges,
            "uri": f"lotus://case/{case_id}/entity/{eid}"}
