"""Tier-B blob store + versions.json durability SLA (Phase 6, ARCHITECTURE §2.5).

Blobs are content-addressed; PIN keeps a blob forever; unpinned blobs are
LRU-evicted past their retention window or over the size cap; an evicted blob
keeps its integrity hash and degrades gracefully (never dangles); versions.json
persists the index and a version bump fails loudly if it needs an evicted blob.
Time is injected so eviction is deterministic.

    PYTHONPATH=. PYTHONIOENCODING=utf-8 python tests/test_blobstore.py
"""
from __future__ import annotations

import hashlib
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from lotusmcp.kernel.blobstore import DAY, BlobStore, DurabilityError
from lotusmcp.kernel.case import Case

T0 = 1_000_000.0    # a fixed base "now" for deterministic tests


def _store(d):
    Case.create(d, "c", title="t")
    return BlobStore(Path(d) / "c")


def test_put_is_content_addressed_and_idempotent():
    with tempfile.TemporaryDirectory() as d:
        bs = _store(d)
        sha1 = bs.put("nmap output here", kind="recon", now=T0)
        sha2 = bs.put("nmap output here", kind="recon", now=T0 + 5)
        assert sha1 == sha2 == hashlib.sha256(b"nmap output here").hexdigest()
        assert bs.get(sha1) == b"nmap output here"
        assert len(bs.blobs) == 1, "identical content must not duplicate"
        print(f"content-addressed + idempotent: {sha1[:12]}")


def test_get_unknown_returns_none():
    with tempfile.TemporaryDirectory() as d:
        bs = _store(d)
        assert bs.get("deadbeef") is None
        assert bs.status("deadbeef")["known"] is False
        print("unknown blob → None + known:false")


def test_window_eviction_of_unpinned_only():
    with tempfile.TemporaryDirectory() as d:
        bs = _store(d)
        recon = bs.put("recon blob", kind="recon", now=T0)        # 7d window
        exploit = bs.put("exploit blob", kind="exploit", now=T0)  # 30d window
        # 10 days later: recon expired, exploit still fresh
        r = bs.gc(now=T0 + 10 * DAY)
        assert recon in r["evicted"] and exploit not in r["evicted"], r
        assert bs.get(recon) is None and bs.get(exploit) == b"exploit blob"
        # evicted blob keeps its hash + degraded note
        st = bs.status(recon)
        assert st["known"] and not st["present"]
        assert st["note"] == "artifact evicted, integrity hash retained"
        print(f"recon evicted at 10d, exploit retained; hash kept for {recon[:12]}")


def test_pin_survives_window_and_cap():
    with tempfile.TemporaryDirectory() as d:
        bs = _store(d)
        keep = bs.put("critical path evidence", kind="recon", now=T0)
        bs.pin(keep)
        r = bs.gc(now=T0 + 100 * DAY)      # far past any window
        assert keep not in r["evicted"]
        assert bs.get(keep) == b"critical path evidence"
        print("pinned blob survives 100d past its window")


def test_cap_lru_eviction():
    with tempfile.TemporaryDirectory() as d:
        bs = _store(d)
        # four 100-byte blobs, distinct last_access; cap = 250 bytes
        shas = []
        for i in range(4):
            shas.append(bs.put("x" * 100 + f"#{i}", kind="exploit", now=T0 + i))
        # touch the newest two so the two OLDEST by last_access are evicted
        bs.get(shas[2], now=T0 + 50)
        bs.get(shas[3], now=T0 + 51)
        r = bs.gc(now=T0 + 60, cap_bytes=250)
        assert not r["over_cap"], r
        assert shas[0] in r["evicted"] and shas[1] in r["evicted"]
        assert bs.get(shas[2]) is not None and bs.get(shas[3]) is not None
        print(f"LRU evicted {len(r['evicted'])} oldest to meet cap; "
              f"present={r['present_bytes']}B")


def test_pins_over_cap_are_surfaced_not_broken():
    with tempfile.TemporaryDirectory() as d:
        bs = _store(d)
        a = bs.put("a" * 200, kind="exploit", now=T0)
        b = bs.put("b" * 200, kind="exploit", now=T0 + 1)
        bs.pin(a); bs.pin(b)
        r = bs.gc(now=T0 + 2, cap_bytes=100)   # pins alone exceed the cap
        assert r["evicted"] == [], "pinned blobs must never be evicted"
        assert r["over_cap"] is True, "over-cap-by-pins must be surfaced"
        assert bs.get(a) and bs.get(b)
        print(f"pins {r['pinned_bytes']}B > cap 100B surfaced as over_cap")


def test_manifest_persists_across_reopen():
    with tempfile.TemporaryDirectory() as d:
        bs = _store(d)
        sha = bs.put("persist me", kind="exploit", now=T0)
        bs.pin(sha)
        # reopen a fresh store on the same dir — state comes from versions.json
        bs2 = BlobStore(Path(d) / "c")
        assert sha in bs2.blobs and bs2.blobs[sha].pinned
        assert bs2.get(sha) == b"persist me"
        assert (Path(d) / "c" / "artifacts" / "versions.json").exists()
        print("versions.json round-trips index + pin state")


def test_version_bump_fails_loudly_on_evicted():
    with tempfile.TemporaryDirectory() as d:
        bs = _store(d)
        sha = bs.put("graph snapshot", kind="recon", now=T0)
        bs.set_version("graph", 1, requires_sha=sha)      # ok while present
        assert bs.get_version("graph")["version"] == 1
        bs.gc(now=T0 + 30 * DAY)                            # recon evicted
        try:
            bs.set_version("graph", 2, requires_sha=sha)
            raise AssertionError("bump requiring an evicted blob must raise")
        except DurabilityError as e:
            assert "evicted" in str(e)
        # requiring an unknown blob also raises
        try:
            bs.set_version("x", 1, requires_sha="nope")
            raise AssertionError("bump requiring unknown blob must raise")
        except DurabilityError:
            pass
        print("version bump fails loudly on evicted / unknown tier")


def test_reput_restores_evicted_content():
    with tempfile.TemporaryDirectory() as d:
        bs = _store(d)
        sha = bs.put("re-fetchable", kind="recon", now=T0)
        bs.gc(now=T0 + 30 * DAY)
        assert bs.get(sha) is None                          # evicted
        sha2 = bs.put("re-fetchable", kind="recon", now=T0 + 31 * DAY)
        assert sha2 == sha and bs.get(sha) == b"re-fetchable"
        assert bs.status(sha)["present"] is True
        print("re-putting identical content restores an evicted blob")


def test_case_blobs_property():
    with tempfile.TemporaryDirectory() as d:
        case = Case.create(d, "c2", title="t")
        sha = case.blobs.put("via case", kind="recon", now=T0)
        assert case.blobs.get(sha) == b"via case"
        assert case.blobs is case.blobs, "blob store should be cached on the case"
        print("Case.blobs exposes the store")


TESTS = [v for k, v in sorted(globals().items()) if k.startswith("test_")]

if __name__ == "__main__":
    import traceback
    failed = 0
    for t in TESTS:
        try:
            t()
            print(f"ok   {t.__name__}")
        except Exception:  # noqa: BLE001
            failed += 1
            print(f"FAIL {t.__name__}")
            traceback.print_exc()
    print(f"\n{len(TESTS)-failed}/{len(TESTS)} passed")
    sys.exit(1 if failed else 0)
