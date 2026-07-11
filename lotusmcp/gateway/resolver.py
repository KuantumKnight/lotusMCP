"""The single surface resolver — `search` + `fetch` over one URI space (§3).

ChatGPT deep-research needs a two-tool contract: `search(query)` returns result
stubs `{id, title, url}` and `fetch(id)` returns the full document
`{id, title, text, url, metadata}`. Claude gets the same content through
Resources. Both are served here from ONE resolver over one `lotus://` URI space,
so the FULL and LITE profiles can never diverge — the deep-research bridge is a
thin re-labelling of the same resolver, not a parallel implementation.

URI space (all read-only projections of the log):
    lotus://case/{cid}/brief                 the bounded STATE.md
    lotus://case/{cid}/resume                the bounded resume packet (JSON)
    lotus://case/{cid}/entity/{eid}          one graph node (attrs + edges)
    lotus://case/{cid}/finding/{fid}         one finding
    lotus://case/{cid}/hypothesis/{hid}      one hypothesis

Pure over the graph + case meta; no network, no model. `search` results are
`id == uri`, so a client round-trips search → fetch with no id bookkeeping.
"""
from __future__ import annotations

import json
import re
import sqlite3
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from lotusmcp import kb
from lotusmcp.engine.salience import Salience, score
from lotusmcp.kernel.case import Case
from lotusmcp.kernel.resume import build_resume_packet

SEARCH_LIMIT = 10
_SNIPPET = 160


def parse_uri(uri: str) -> Optional[Tuple[str, str, Optional[str]]]:
    """`lotus://case/{cid}/{kind}[/{id}]` → (cid, kind, id|None), or None if the
    URI is not a well-formed lotus case URI."""
    if not isinstance(uri, str) or not uri.startswith("lotus://case/"):
        return None
    parts = uri[len("lotus://"):].split("/")     # ["case", cid, kind, id?]
    if len(parts) < 3 or parts[0] != "case" or not parts[1]:
        return None
    cid, kind = parts[1], parts[2]
    ident = parts[3] if len(parts) >= 4 and parts[3] else None
    return cid, kind, ident


class Resolver:
    def __init__(self, cases_dir) -> None:
        self.cases_dir = Path(cases_dir)

    # ------------------------------------------------------------------ helpers
    def _case(self, cid: str) -> Case:
        return Case(self.cases_dir, cid)

    def _graph_db(self, case: Case) -> str:
        return case.rebuild()["graph_db"]

    @staticmethod
    def _uri(cid: str, kind: str, ident: str = "") -> str:
        return f"lotus://case/{cid}/{kind}" + (f"/{ident}" if ident else "")

    # ------------------------------------------------------------------ fetch
    def fetch(self, uri: str) -> Dict[str, Any]:
        """Resolve a `lotus://` URI to a deep-research document
        `{id, title, text, url, metadata}`. Unknown URIs return an error doc."""
        parsed = parse_uri(uri)
        if parsed is None:
            return self._doc(uri, "invalid uri", "not a lotus case URI", {"error": "bad_uri"})
        cid, kind, ident = parsed
        case = self._case(cid)
        if kind == "brief":
            return self._doc(uri, f"{cid} STATE", case.state_md(), {"kind": "brief"})
        if kind == "resume":
            db = self._graph_db(case)
            pkt = build_resume_packet(db, case.meta, case.store.tip)
            return self._doc(uri, f"{cid} resume packet",
                             json.dumps(pkt, indent=2), {"kind": "resume"})
        if kind == "entity" and ident:
            node = kb.get(self._graph_db(case), cid, ident)
            return self._doc(uri, f"{node.get('display', ident)}",
                             json.dumps(node, indent=2),
                             {"kind": "entity", "entity_kind": node.get("kind")})
        if kind == "finding" and ident:
            return self._fetch_row(case, cid, uri, "finding", ident)
        if kind == "hypothesis" and ident:
            return self._fetch_row(case, cid, uri, "hypothesis", ident)
        return self._doc(uri, "not found", f"no resolver for {kind!r}",
                         {"error": "not_found"})

    # Resources (Claude) resolve identical content through the same path.
    resolve = fetch

    def _fetch_row(self, case: Case, cid: str, uri: str, table: str, ident: str
                   ) -> Dict[str, Any]:
        col = "id" if table == "finding" else "hid"
        conn = sqlite3.connect(self._graph_db(case))
        conn.row_factory = sqlite3.Row
        try:
            row = conn.execute(f"SELECT * FROM {table} WHERE {col}=?", (ident,)).fetchone()
        finally:
            conn.close()
        if row is None:
            return self._doc(uri, "not found", f"no {table} {ident}", {"error": "not_found"})
        d = {k: row[k] for k in row.keys()}
        title = d.get("ftype") or d.get("statement") or ident
        return self._doc(uri, str(title)[:80], json.dumps(d, indent=2),
                         {"kind": table})

    @staticmethod
    def _doc(uri: str, title: str, text: str, metadata: Dict[str, Any]) -> Dict[str, Any]:
        return {"id": uri, "title": title, "text": text, "url": uri,
                "metadata": metadata}

    # ------------------------------------------------------------------ search
    def _fts_uris(self, conn: sqlite3.Connection, cid: str, q: str
                  ) -> Optional[Set[str]]:
        """Build a transient FTS5 index over the searchable surface and return
        the set of matching URIs for `q` (tokenized, multi-term AND, prefix), or
        None to signal the caller to fall back to substring matching (FTS5 not
        compiled in, or the query has no usable tokens). Pure over the graph —
        the index lives in `temp.` and is dropped before returning."""
        toks = re.findall(r"[a-z0-9_.]+", q)
        if not toks:
            return None
        try:
            conn.execute("DROP TABLE IF EXISTS temp.ftsidx")
            conn.execute(
                "CREATE VIRTUAL TABLE temp.ftsidx USING fts5(uri UNINDEXED, body)"
            )
            rows: List[Tuple[str, str]] = []
            for r in conn.execute(
                "SELECT entity_id,kind,key_display FROM entity "
                "WHERE status IS NULL OR status NOT IN ('retracted','superseded')"
            ):
                rows.append((self._uri(cid, "entity", r["entity_id"]),
                             f"{r['kind']} {r['key_display'] or ''}"))
            for r in conn.execute(
                "SELECT id,ftype,subject_json,attrs_json,severity FROM finding"
            ):
                rows.append((self._uri(cid, "finding", r["id"]),
                             f"{r['ftype'] or ''} {r['subject_json'] or ''} "
                             f"{r['attrs_json'] or ''} {r['severity'] or ''}"))
            for r in conn.execute(
                "SELECT hid,statement,status FROM hypothesis WHERE status!='KILLED'"
            ):
                rows.append((self._uri(cid, "hypothesis", r["hid"]),
                             f"{r['statement'] or ''} {r['status'] or ''}"))
            conn.executemany("INSERT INTO temp.ftsidx(uri,body) VALUES(?,?)", rows)
            # each token a quoted prefix term; whitespace = implicit AND.
            match = " ".join(f'"{t}"*' for t in toks)
            return {row[0] for row in conn.execute(
                "SELECT uri FROM temp.ftsidx WHERE ftsidx MATCH ?", (match,))}
        except sqlite3.OperationalError:
            return None
        finally:
            try:
                conn.execute("DROP TABLE IF EXISTS temp.ftsidx")
            except sqlite3.OperationalError:
                pass

    def search(self, cid: str, query: str, limit: int = SEARCH_LIMIT
               ) -> List[Dict[str, Any]]:
        """Deep-research `search`: full-text match over entities, findings and
        hypotheses via a transient FTS5 index (tokenized, multi-term AND,
        prefix), falling back to substring where FTS5 is unavailable. Results
        are `{id=uri, title, url, snippet}`, ranked by salience (entities) /
        severity+confidence (findings) / confidence (hypotheses). An empty
        query returns the most salient items."""
        case = self._case(cid)
        db = self._graph_db(case)
        q = (query or "").strip().lower()
        tip = case.store.tip
        hits: List[Tuple[float, Dict[str, Any]]] = []
        conn = sqlite3.connect(db)
        conn.row_factory = sqlite3.Row
        try:
            fts = self._fts_uris(conn, cid, q) if q else None

            def _skip(uri: str, hay: str) -> bool:
                if not q:
                    return False
                if fts is not None:
                    return uri not in fts
                return q not in hay      # substring fallback

            for r in conn.execute(
                "SELECT entity_id,kind,key_display,confidence,last_seq FROM entity "
                "WHERE status IS NULL OR status NOT IN ('retracted','superseded')"
            ):
                uri = self._uri(cid, "entity", r["entity_id"])
                hay = f"{r['kind']} {r['key_display']}".lower()
                if _skip(uri, hay):
                    continue
                sal = Salience(s_conf=r["confidence"] or 0.0, s_hyp=1.0,
                               last_seq=r["last_seq"] or 0)
                hits.append((score(sal, tip), {
                    "id": uri,
                    "title": f"{r['kind']}: {r['key_display']}",
                    "url": uri,
                    "snippet": f"{r['kind']} {r['key_display']}"[:_SNIPPET]}))
            for r in conn.execute(
                "SELECT id,ftype,subject_json,attrs_json,severity,confidence FROM finding"
            ):
                uri = self._uri(cid, "finding", r["id"])
                hay = (f"{r['ftype']} {r['subject_json']} {r['attrs_json']} "
                       f"{r['severity']}").lower()
                if _skip(uri, hay):
                    continue
                sev = {"crit": 3, "critical": 3, "high": 2, "med": 1,
                       "medium": 1}.get((r["severity"] or "").lower(), 0)
                hits.append((10 + sev + (r["confidence"] or 0.0), {
                    "id": uri,
                    "title": f"[{r['severity']}] {r['ftype']}",
                    "url": uri,
                    "snippet": f"{r['ftype']} @ {r['subject_json']}"[:_SNIPPET]}))
            for r in conn.execute(
                "SELECT hid,statement,status,confidence FROM hypothesis "
                "WHERE status!='KILLED'"
            ):
                uri = self._uri(cid, "hypothesis", r["hid"])
                hay = f"{r['statement'] or ''} {r['status'] or ''}".lower()
                if _skip(uri, hay):
                    continue
                hits.append((5 + (r["confidence"] or 0.0), {
                    "id": uri,
                    "title": f"hypothesis {r['hid']}",
                    "url": uri,
                    "snippet": (r["statement"] or "")[:_SNIPPET]}))
        finally:
            conn.close()
        hits.sort(key=lambda h: (-h[0], h[1]["id"]))
        return [doc for _, doc in hits[:max(0, limit)]]
