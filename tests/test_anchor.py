"""Signed audit anchors: a trusted operator witnesses the log tip, and any later
tamper (even a fully re-hashed rewrite) or untrusted signature is detected.

    PYTHONPATH=. PYTHONIOENCODING=utf-8 python tests/test_anchor.py
"""
from __future__ import annotations

import copy
import json
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from lotusmcp.control_plane.anchor import create_anchor
from lotusmcp.control_plane.keyring import SigningKey
from lotusmcp.kernel.anchor import verify_anchor
from lotusmcp.kernel.case import Case
from lotusmcp.kernel.events import EventDraft

OP = SigningKey.generate()


def _seeded_case():
    base = Path(tempfile.mkdtemp(prefix="lotus_anchor_"))
    case = Case.create(base, "anchored", title="t", category="web",
                       flag_format=r"flag\{[^}]+\}")
    for i in range(3):
        case.append(EventDraft("note.added", {"kind": "system", "name": "seed"},
                               {"text": f"event {i}"}))
    return case


def test_anchor_verifies_on_intact_log():
    case = _seeded_case()
    anchor = create_anchor(case.store, OP)
    assert verify_anchor(anchor, case.store, trusted_hex={OP.public_hex})


def test_untrusted_anchor_rejected():
    case = _seeded_case()
    rogue = SigningKey.generate()
    anchor = create_anchor(case.store, rogue)
    assert not verify_anchor(anchor, case.store, trusted_hex={OP.public_hex})


def test_anchor_payload_tamper_rejected():
    case = _seeded_case()
    anchor = create_anchor(case.store, OP)
    t = copy.deepcopy(anchor)
    t["payload"]["tip_hash"] = "sha256:" + "0" * 64
    assert not verify_anchor(t, case.store, trusted_hex={OP.public_hex})


def test_history_rewrite_detected_by_anchor():
    """Anchor the tip, then rewrite an event AND recompute the whole chain so it
    is internally self-consistent. verify_chain passes, but the anchored tip hash
    no longer matches -> the external witness catches the fork."""
    case = _seeded_case()
    anchor = create_anchor(case.store, OP)
    assert verify_anchor(anchor, case.store, trusted_hex={OP.public_hex})

    # forge a fully re-hashed alternate history in a fresh case dir
    import hashlib
    from lotusmcp.kernel.canonical import canonical, canonical_bytes
    from lotusmcp.kernel.log import GENESIS_HASH

    rows = list(case.store.iter_events())
    rows[1]["payload"]["text"] = "EVENT ONE (tampered)"
    prev = GENESIS_HASH
    for obj in rows:
        obj["prev_hash"] = prev
        body = {k: v for k, v in obj.items() if k not in ("hash", "sig")}
        obj["hash"] = "sha256:" + hashlib.sha256(
            prev.encode("utf-8") + canonical_bytes(body)).hexdigest()
        prev = obj["hash"]
    (case.dir / "events.jsonl").write_text(
        "".join(canonical(o) + "\n" for o in rows), encoding="utf-8")

    forged = Case(case.dir.parent, case.case_id).store
    assert forged.verify_chain() == -1, "forged chain is internally consistent"
    # ...but the operator's anchor no longer matches -> rewrite detected
    assert not verify_anchor(anchor, forged, trusted_hex={OP.public_hex})


def test_anchor_after_more_events_still_matches_its_seq():
    case = _seeded_case()
    anchor = create_anchor(case.store, OP)
    seq_at_anchor = anchor["payload"]["seq"]
    case.append(EventDraft("note.added", {"kind": "system", "name": "later"},
                           {"text": "appended after anchor"}))
    # appending forward doesn't invalidate a past anchor: its seq's hash is stable
    assert verify_anchor(anchor, case.store, trusted_hex={OP.public_hex})
    assert case.store.hash_at(seq_at_anchor) == anchor["payload"]["tip_hash"]


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items())
           if k.startswith("test_") and callable(v)]
    failed = 0
    for fn in fns:
        try:
            fn()
            print(f"  ok  {fn.__name__}")
        except Exception as e:  # noqa: BLE001
            failed += 1
            print(f"FAIL  {fn.__name__}: {e}")
    print(f"\n{len(fns) - failed}/{len(fns)} passed")
    sys.exit(1 if failed else 0)
