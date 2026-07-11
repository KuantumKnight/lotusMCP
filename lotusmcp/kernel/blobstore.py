"""Tier-B blob store + versions.json — the durability SLA (ARCHITECTURE.md §2.5).

Two tiers resolve the GC-vs-rebuild tension:

  * **Tier A** (never GC'd) is the event log + parsed-attribute payloads — the
    artifact-independent graph truth. Full replay needs only Tier A, so nothing
    here can ever break reproducibility.
  * **Tier B** (this module) is the raw, REDACTED, content-addressed artifact
    blobs. They are a cache with a retention SLA: PIN any blob a flag / high-sev
    finding / critical-path citation depends on, and LRU-evict the rest under a
    per-class age window and a total-size cap.

When an unpinned blob is evicted its content is deleted but its metadata —
crucially the integrity hash — is retained, so a citation degrades to
"artifact evicted, integrity hash retained" and NEVER dangles. `versions.json`
is the manifest coordinating the blob index and named version namespaces; a
version bump that depends on an evicted blob fails loudly.

Content-addressing is over the bytes handed in, which the redaction choke has
already scrubbed — so a blob file never contains a live secret. Time is
injected (`now`) so eviction is deterministic and unit-testable.
"""
from __future__ import annotations

import hashlib
import json
import os
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

MANIFEST_VERSION = 1
DAY = 86400.0

# per-retention-class age windows (seconds) and the total-size cap.
DEFAULT_WINDOWS: Dict[str, float] = {
    "recon": 7 * DAY,
    "enumerate": 7 * DAY,
    "exploit": 30 * DAY,
    "post_exploit": 30 * DAY,
}
DEFAULT_TTL = 30 * DAY
DEFAULT_CAP_BYTES = 2 * 1024 ** 3       # 2 GB


class DurabilityError(Exception):
    """A durability invariant was violated (e.g. a version bump depends on an
    evicted blob)."""


@dataclass
class BlobMeta:
    sha: str
    size: int
    kind: str            # retention class (recon / exploit / …)
    created: float
    last_access: float
    pinned: bool = False
    evicted: bool = False    # content deleted, integrity hash retained

    def ttl(self, windows: Dict[str, float]) -> float:
        return windows.get(self.kind, DEFAULT_TTL)


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class BlobStore:
    def __init__(self, case_dir: Union[str, os.PathLike]) -> None:
        self.case_dir = Path(case_dir)
        self.blob_dir = self.case_dir / "artifacts" / "blobs"
        self.blob_dir.mkdir(parents=True, exist_ok=True)
        self.manifest_path = self.case_dir / "artifacts" / "versions.json"
        self._load()

    # ------------------------------------------------------------- persistence
    def _load(self) -> None:
        if self.manifest_path.exists():
            m = json.loads(self.manifest_path.read_text(encoding="utf-8"))
        else:
            m = {}
        self.cap_bytes: int = m.get("cap_bytes", DEFAULT_CAP_BYTES)
        self.windows: Dict[str, float] = {**DEFAULT_WINDOWS, **m.get("windows", {})}
        self.blobs: Dict[str, BlobMeta] = {
            sha: BlobMeta(**meta) for sha, meta in m.get("blobs", {}).items()
        }
        self.namespaces: Dict[str, Dict[str, Any]] = m.get("namespaces", {})

    def _flush(self) -> None:
        m = {
            "manifest_version": MANIFEST_VERSION,
            "cap_bytes": self.cap_bytes,
            "windows": self.windows,
            "blobs": {sha: asdict(meta) for sha, meta in sorted(self.blobs.items())},
            "namespaces": self.namespaces,
        }
        tmp = self.manifest_path.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(m, indent=2, sort_keys=True), encoding="utf-8")
        os.replace(tmp, self.manifest_path)

    def _path(self, sha: str) -> Path:
        return self.blob_dir / sha

    @staticmethod
    def _now(now: Optional[float]) -> float:
        return time.time() if now is None else now

    # --------------------------------------------------------------------- put
    def put(self, content: Union[bytes, str], kind: str = "recon",
            pin: bool = False, now: Optional[float] = None) -> str:
        """Store already-redacted bytes; return the content-address (sha256).
        Idempotent: re-putting identical content refreshes access time (and
        restores content if it had been evicted) but never duplicates."""
        data = content.encode("utf-8") if isinstance(content, str) else bytes(content)
        sha = _sha256(data)
        t = self._now(now)
        self._path(sha).write_bytes(data)
        meta = self.blobs.get(sha)
        if meta is None:
            meta = BlobMeta(sha=sha, size=len(data), kind=kind,
                            created=t, last_access=t, pinned=pin, evicted=False)
            self.blobs[sha] = meta
        else:
            meta.last_access = t
            meta.evicted = False               # content is present again
            meta.pinned = meta.pinned or pin
        self._flush()
        return sha

    # --------------------------------------------------------------------- get
    def get(self, sha: str, now: Optional[float] = None) -> Optional[bytes]:
        """Return blob bytes, or None if unknown or evicted. Refreshes LRU
        access time on a hit."""
        meta = self.blobs.get(sha)
        if meta is None or meta.evicted:
            return None
        p = self._path(sha)
        if not p.exists():                     # content gone under us — reconcile
            meta.evicted = True
            self._flush()
            return None
        meta.last_access = self._now(now)
        self._flush()
        return p.read_bytes()

    def status(self, sha: str) -> Dict[str, Any]:
        """The citation-safe view of a blob. An evicted blob still reports its
        integrity hash and a `note`, so a citation degrades instead of
        dangling."""
        meta = self.blobs.get(sha)
        if meta is None:
            return {"sha": sha, "known": False,
                    "note": "unknown artifact (never stored)"}
        out = {"sha": sha, "known": True, "present": not meta.evicted,
               "pinned": meta.pinned, "size": meta.size, "kind": meta.kind}
        if meta.evicted:
            out["note"] = "artifact evicted, integrity hash retained"
        return out

    # -------------------------------------------------------------------- pins
    def pin(self, sha: str) -> bool:
        """Pin a blob so GC never evicts it. Returns whether its content is
        still present (pinning an already-evicted blob cannot restore it)."""
        meta = self.blobs.get(sha)
        if meta is None:
            raise DurabilityError(f"cannot pin unknown blob {sha}")
        meta.pinned = True
        self._flush()
        return not meta.evicted

    def unpin(self, sha: str) -> None:
        meta = self.blobs.get(sha)
        if meta is not None:
            meta.pinned = False
            self._flush()

    # ---------------------------------------------------------------------- gc
    def _present(self) -> List[BlobMeta]:
        return [m for m in self.blobs.values() if not m.evicted]

    def _evict(self, meta: BlobMeta) -> int:
        p = self._path(meta.sha)
        freed = meta.size if p.exists() else 0
        if p.exists():
            p.unlink()
        meta.evicted = True
        return freed

    def gc(self, now: Optional[float] = None,
           cap_bytes: Optional[int] = None) -> Dict[str, Any]:
        """Enforce the retention SLA. Deterministic given `now`:

          1. evict unpinned blobs older than their retention window;
          2. if still over the size cap, LRU-evict unpinned blobs (oldest
             last_access first) until under the cap.

        Pinned blobs are never evicted (they count against the cap but cannot be
        freed — if pins alone exceed the cap that is surfaced, not silently
        broken). Returns {evicted, freed_bytes, present_bytes, over_cap}."""
        t = self._now(now)
        cap = self.cap_bytes if cap_bytes is None else cap_bytes
        evicted: List[str] = []
        freed = 0

        # 1) age-window expiry (unpinned only), deterministic order
        for meta in sorted(self._present(), key=lambda m: (m.created, m.sha)):
            if meta.pinned:
                continue
            if t - meta.created > meta.ttl(self.windows):
                freed += self._evict(meta)
                evicted.append(meta.sha)

        # 2) size-cap LRU eviction (unpinned only)
        present_bytes = sum(m.size for m in self._present())
        if present_bytes > cap:
            for meta in sorted(self._present(),
                               key=lambda m: (m.last_access, m.sha)):
                if present_bytes <= cap:
                    break
                if meta.pinned:
                    continue
                freed += self._evict(meta)
                evicted.append(meta.sha)
                present_bytes -= meta.size

        self._flush()
        present_bytes = sum(m.size for m in self._present())
        return {"evicted": evicted, "freed_bytes": freed,
                "present_bytes": present_bytes,
                "over_cap": present_bytes > cap,
                "pinned_bytes": sum(m.size for m in self._present() if m.pinned)}

    # --------------------------------------------------- version namespaces
    def set_version(self, namespace: str, version: Any,
                    requires_sha: Optional[str] = None) -> None:
        """Record a version namespace's current version. If it depends on a blob
        (`requires_sha`), the bump FAILS LOUDLY when that blob is unknown or
        evicted — a version must never claim a tier that is gone."""
        if requires_sha is not None:
            meta = self.blobs.get(requires_sha)
            if meta is None:
                raise DurabilityError(
                    f"version bump {namespace}={version!r} requires unknown "
                    f"blob {requires_sha}")
            if meta.evicted:
                raise DurabilityError(
                    f"version bump {namespace}={version!r} requires evicted "
                    f"blob {requires_sha} (integrity hash retained, content gone)")
        self.namespaces[namespace] = {"version": version, "requires": requires_sha}
        self._flush()

    def get_version(self, namespace: str) -> Optional[Dict[str, Any]]:
        return self.namespaces.get(namespace)
