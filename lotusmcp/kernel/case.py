"""Case — ties the append-only log to its rebuildable projections.

A Case owns one directory. Writes go only through `append()` (the single
serializer). Projections (graph.db, STATE.md, state.json) are rebuilt from
the log; they are a cache, never authoritative. `rebuild()` is deterministic:
same log -> same graph -> same STATE.md.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Dict, List, Optional

from lotusmcp.kernel.events import EventDraft
from lotusmcp.kernel.log import EventStore
from lotusmcp.kernel.projector import GraphProjector
from lotusmcp.kernel.redaction import Redactor
from lotusmcp.kernel.state import render_state_md


class Case:
    def __init__(self, base_dir: str | os.PathLike, case_id: str, vault=None) -> None:
        self.case_id = case_id
        self.dir = Path(base_dir) / case_id
        self.dir.mkdir(parents=True, exist_ok=True)
        (self.dir / "projections").mkdir(exist_ok=True)
        (self.dir / "artifacts" / "blobs").mkdir(parents=True, exist_ok=True)
        self.meta_path = self.dir / "case.json"
        self.scope_path = self.dir / "scope.json"
        # One redactor per case so the flag (never redacted) and the reveal
        # vault are case-scoped. flag_format may not exist yet on first create.
        # `vault` lets a caller supply a custom reveal vault. None uses the
        # production AES-GCM per-case vault, persisted under case_dir/vault/.
        flag_format = None
        if self.meta_path.exists():
            flag_format = json.loads(
                self.meta_path.read_text(encoding="utf-8")
            ).get("flag_format")
        if vault is None:
            from lotusmcp.kernel.vault import AESGCMVault
            vault = AESGCMVault.for_case_dir(self.dir)
        self.redactor = Redactor(flag_format=flag_format, vault=vault)
        self.store = EventStore(self.dir, redactor=self.redactor)

    # ---- metadata (small, mutable header; the log remains the truth) ----
    @property
    def meta(self) -> Dict[str, Any]:
        m = {"case_id": self.case_id, "phase": "TRIAGE", "status": "active"}
        if self.meta_path.exists():
            m.update(json.loads(self.meta_path.read_text(encoding="utf-8")))
        if self.scope_path.exists():
            m["scope"] = json.loads(self.scope_path.read_text(encoding="utf-8"))
        return m

    def set_meta(self, **kw) -> None:
        m = json.loads(self.meta_path.read_text(encoding="utf-8")) if self.meta_path.exists() else {}
        m.update(kw)
        self._atomic_write(self.meta_path, json.dumps(m, indent=2))

    @classmethod
    def create(cls, base_dir, case_id, title="", category=None,
               flag_format=None, platform=None, vault=None) -> "Case":
        c = cls(base_dir, case_id, vault=vault)
        c.set_meta(case_id=case_id, title=title, category=category,
                   flag_format=flag_format, platform=platform)
        c.redactor.set_flag_format(flag_format)
        c.append(EventDraft(
            type="case.created",
            actor={"kind": "system", "name": "lotusmcp"},
            payload={"case_id": case_id, "title": title, "category": category,
                     "flag_format": flag_format, "platform": platform},
        ))
        return c

    # ---- the ONLY write path ----
    def append(self, draft: EventDraft) -> Dict[str, Any]:
        return self.store.append(draft)

    # ---- Tier-B artifact blobs (durability SLA; see kernel/blobstore.py) ----
    @property
    def blobs(self):
        """The case's content-addressed Tier-B blob store (lazy). Tier A (the
        log + graph) is authoritative; blobs are a cache with a retention SLA."""
        bs = getattr(self, "_blobs", None)
        if bs is None:
            from lotusmcp.kernel.blobstore import BlobStore
            bs = BlobStore(self.dir)
            self._blobs = bs
        return bs

    # ---- deterministic projection rebuild ----
    def rebuild(self) -> Dict[str, str]:
        graph_path = self.dir / "projections" / "graph.db"
        if graph_path.exists():
            graph_path.unlink()
        proj = GraphProjector(str(graph_path))
        built = proj.build(self.store.iter_events())
        proj.close()
        state_md = render_state_md(str(graph_path), self.meta)
        self._atomic_write(self.dir / "projections" / "STATE.md", state_md)
        self._atomic_write(
            self.dir / "projections" / "state.json",
            json.dumps({"meta": self.meta, "built_through_seq": built}, indent=2),
        )
        return {"graph_db": str(graph_path), "built_through_seq": built,
                "state_md": state_md}

    def compact(self, keep_per_value: int = 4) -> Dict[str, Any]:
        """Bound the live graph projection's claim log (top-K corroboration per
        (entity, attr, value)) without changing what it asserts. Fold-preserving
        and projection-internal: the log is untouched, so the next rebuild()
        restores full history. Re-renders STATE.md/state.json (which stay
        byte-identical, since the fold is preserved) and returns compaction
        stats. Rebuilds first if no projection exists yet."""
        graph_path = self.dir / "projections" / "graph.db"
        if not graph_path.exists():
            self.rebuild()
        proj = GraphProjector(str(graph_path), create=False)
        stats = proj.compact(keep_per_value=keep_per_value)
        proj.close()
        state_md = render_state_md(str(graph_path), self.meta)
        self._atomic_write(self.dir / "projections" / "STATE.md", state_md)
        return stats

    def state_md(self) -> str:
        p = self.dir / "projections" / "STATE.md"
        return p.read_text(encoding="utf-8") if p.exists() else self.rebuild()["state_md"]

    @staticmethod
    def _atomic_write(path: Path, text: str) -> None:
        tmp = path.with_suffix(path.suffix + ".tmp")
        tmp.write_text(text, encoding="utf-8")
        os.replace(tmp, path)
