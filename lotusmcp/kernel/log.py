"""The append-only, hash-chained event log — THE source of truth.

`EventStore` is the sole writer of a case's `events.jsonl`. It assigns
gap-free monotonic `seq`, chains `prev_hash -> hash` (sha256 over canonical
bytes), fsyncs, and maintains a `seq -> byte_offset` index. Because nothing
ever mutates an existing byte range, concurrent tools appending distinct
events can never clobber each other — the CASE.md race is structurally gone.

Skeleton note: cross-process safety here is a threading.Lock + O_APPEND.
Production replaces this with a per-case single serializer process and a
portalocker advisory lock (see ARCHITECTURE.md, Case Kernel).
"""
from __future__ import annotations

import hashlib
import json
import os
import threading
from pathlib import Path
from typing import Any, Dict, Iterator

from lotusmcp.kernel.canonical import canonical, canonical_bytes
from lotusmcp.kernel.events import (
    MAX_PAYLOAD_BYTES,
    SCHEMA_V,
    EventDraft,
    _now_iso,
    _ulid,
)

GENESIS_HASH = "sha256:" + "0" * 64
_UNSIGNED = ("hash", "sig")


class ChainError(Exception):
    pass


class EventStore:
    def __init__(self, case_dir: str | os.PathLike) -> None:
        self.dir = Path(case_dir)
        self.dir.mkdir(parents=True, exist_ok=True)
        self.path = self.dir / "events.jsonl"
        self.idx = self.dir / "events.idx"
        self._lock = threading.Lock()
        self._seq, self._hash = self._load_tail()

    def _load_tail(self) -> tuple[int, str]:
        seq, last_hash = -1, GENESIS_HASH
        if self.path.exists():
            with open(self.path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    obj = json.loads(line)
                    seq, last_hash = obj["seq"], obj["hash"]
        return seq, last_hash

    def append(self, draft: EventDraft) -> Dict[str, Any]:
        draft.validate()
        with self._lock:
            seq = self._seq + 1
            env: Dict[str, Any] = {
                "seq": seq,
                "event_id": _ulid(),
                "case_id": self.dir.name,
                "ts": _now_iso(),
                "type": draft.type,
                "schema_v": SCHEMA_V,
                "actor": draft.actor,
                "payload": draft.payload,
                "prev_hash": self._hash,
            }
            for k in ("confidence", "idempotency_key", "causation_id",
                      "correlation_id", "provenance"):
                v = getattr(draft, k)
                if v is not None:
                    env[k] = v
            if draft.redactions:
                env["redactions"] = draft.redactions

            if len(canonical_bytes(env["payload"])) > MAX_PAYLOAD_BYTES:
                raise ValueError(
                    "payload exceeds 16 KB; store an artifact and reference it by hash"
                )

            body = {k: v for k, v in env.items() if k not in _UNSIGNED}
            digest = hashlib.sha256(
                self._hash.encode("utf-8") + canonical_bytes(body)
            ).hexdigest()
            env["hash"] = "sha256:" + digest

            line = canonical(env) + "\n"
            with open(self.path, "a", encoding="utf-8") as f:
                offset = f.tell()
                f.write(line)
                f.flush()
                os.fsync(f.fileno())
            with open(self.idx, "a", encoding="utf-8") as ix:
                ix.write(f"{seq} {offset}\n")

            self._seq, self._hash = seq, env["hash"]
            return env

    def iter_events(self) -> Iterator[Dict[str, Any]]:
        if not self.path.exists():
            return
        with open(self.path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    yield json.loads(line)

    def verify_chain(self) -> int:
        """Recompute the chain; return the first divergent seq, or -1 if intact."""
        prev = GENESIS_HASH
        for obj in self.iter_events():
            if obj["prev_hash"] != prev:
                return obj["seq"]
            body = {k: v for k, v in obj.items() if k not in _UNSIGNED}
            digest = "sha256:" + hashlib.sha256(
                prev.encode("utf-8") + canonical_bytes(body)
            ).hexdigest()
            if digest != obj["hash"]:
                return obj["seq"]
            prev = obj["hash"]
        return -1

    @property
    def tip(self) -> int:
        return self._seq
