"""The determinism guarantee: rebuilding the graph twice from the same event
log must produce byte-identical projections. This is the real reproducibility
contract (replay-equivalence), and the CI gate for the memory logic.

    python -m pytest tests/  (or) python tests/test_replay_equivalence.py
"""
from __future__ import annotations

import hashlib
import sqlite3
import tempfile
from pathlib import Path

from lotusmcp.kernel.case import Case
from lotusmcp.demo.seed_recon import _ffuf, _httpx, _nmap


def _seed(case: Case) -> None:
    for gen in (_nmap(), _httpx(), _ffuf()):
        for draft in gen:
            case.append(draft)


def _dump(db_path: str) -> str:
    conn = sqlite3.connect(db_path)
    # dump every content table in deterministic order, excluding autoincrement ids
    lines = []
    for tbl, cols in [
        ("entity", "entity_id,kind,natural_key,key_display,status,confidence,created_seq,last_seq"),
        ("attribute", "entity_id,attr,value_json,confidence,corroboration,conflict,last_seq"),
        ("relation", "relation_id,src_id,rel_type,dst_id,confidence,sign,updated_seq"),
        ("finding", "id,ftype,subject_json,attrs_json,confidence,severity,sensitive,source_seq"),
        ("hypothesis", "hid,statement,status,confidence,last_seq"),
    ]:
        for row in conn.execute(f"SELECT {cols} FROM {tbl} ORDER BY {cols.split(',')[0]}"):
            lines.append(f"{tbl}:{row}")
    conn.close()
    return "\n".join(lines)


def test_replay_equivalence():
    base = Path(tempfile.mkdtemp(prefix="lotus_test_"))
    case = Case.create(base, "replay-case", title="t", category="web")
    _seed(case)

    r1 = case.rebuild()
    dump1 = _dump(r1["graph_db"])
    state1 = case.state_md()

    r2 = case.rebuild()          # rebuild from the same immutable log
    dump2 = _dump(r2["graph_db"])
    state2 = case.state_md()

    assert dump1 == dump2, "graph projection is not deterministic"
    assert state1 == state2, "STATE.md is not deterministic"
    assert case.store.verify_chain() == -1, "hash chain broken"

    h1 = hashlib.sha256(dump1.encode()).hexdigest()
    print(f"replay-equivalence OK — graph digest {h1[:16]}  ({len(dump1)} bytes)")


def test_chain_tamper_detected():
    base = Path(tempfile.mkdtemp(prefix="lotus_tamper_"))
    case = Case.create(base, "tamper-case", title="t")
    _seed(case)
    assert case.store.verify_chain() == -1

    # corrupt one line in the middle of the log (host IP appears on every line)
    ev = case.store.path
    lines = ev.read_text(encoding="utf-8").splitlines()
    mid = len(lines) // 2
    assert "10.10.11.53" in lines[mid]
    lines[mid] = lines[mid].replace("10.10.11.53", "10.10.11.99", 1)
    ev.write_text("\n".join(lines) + "\n", encoding="utf-8")

    from lotusmcp.kernel.log import EventStore
    reopened = EventStore(case.dir)
    assert reopened.verify_chain() != -1, "tamper should be detected"
    print("tamper detection OK")


if __name__ == "__main__":
    test_replay_equivalence()
    test_chain_tamper_detected()
    print("all tests passed")
