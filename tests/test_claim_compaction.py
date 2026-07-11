"""Claim compaction is fold-preserving and projection-internal.

Re-running the same scan appends a fresh corroborating `claim` row every time,
so the claim log grows unbounded even though the *asserted* fact never changes.
`GraphProjector.compact()` / `Case.compact()` bound that log by collapsing the
redundant tail per (entity, attr, value) into one merged claim. Because the
noisy-OR fold is associative, the derived `attribute` rows — and STATE.md —
must come out byte-identical, corroboration counts included. And it must never
touch the event log, so a rebuild() still restores the full history.

    PYTHONPATH=. PYTHONIOENCODING=utf-8 python tests/test_claim_compaction.py
"""
from __future__ import annotations

import sqlite3
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from lotusmcp.kernel.case import Case
from lotusmcp.kernel.events import EventDraft


def _attr_dump(db_path: str) -> str:
    conn = sqlite3.connect(db_path)
    cols = "entity_id,attr,value_json,confidence,corroboration,conflict,last_seq"
    rows = conn.execute(
        f"SELECT {cols} FROM attribute ORDER BY entity_id,attr,value_json"
    ).fetchall()
    conn.close()
    return "\n".join(str(r) for r in rows)


def _claim_count(db_path: str) -> int:
    conn = sqlite3.connect(db_path)
    n = conn.execute("SELECT COUNT(*) FROM claim").fetchone()[0]
    conn.close()
    return n


def _attr_claim(kind, nk, attr, value, conf, name="nmap"):
    return EventDraft(
        type="attribute.asserted",
        actor={"kind": "executor", "name": name},
        payload={"kind": kind, "natural_key": nk, "attr": attr,
                 "value": value, "confidence": conf},
    )


def _seed_corroborated(case: Case, n_repeats: int = 40) -> None:
    """One service whose `version` is corroborated many times (the growth
    vector), plus a second value asserted enough times to become a conflict —
    so we cover both winner and conflict survival."""
    nk = {"host": "10.10.11.5", "port": 8080, "proto": "tcp"}
    case.append(EventDraft(
        type="entity.asserted",
        actor={"kind": "executor", "name": "nmap"},
        payload={"kind": "service.tcp", "natural_key": nk, "status": "up"},
    ))
    for _ in range(n_repeats):
        case.append(_attr_claim("service.tcp", nk, "version", "2.4.49", 0.6))
    # a competing value, corroborated enough to register as a conflict
    for _ in range(6):
        case.append(_attr_claim("service.tcp", nk, "version", "2.4.50", 0.55, name="httpx"))
    # a single-claim attribute that must be left completely untouched
    case.append(_attr_claim("service.tcp", nk, "product", "Apache", 0.9))


def test_compaction_preserves_fold_and_state():
    base = Path(tempfile.mkdtemp(prefix="lotus_compact_"))
    case = Case.create(base, "compact-case", title="t", category="web")
    _seed_corroborated(case)
    r = case.rebuild()
    db = r["graph_db"]

    before_attr = _attr_dump(db)
    before_state = case.state_md()
    before_claims = _claim_count(db)

    stats = case.compact(keep_per_value=4)
    after_attr = _attr_dump(db)
    after_state = case.state_md()
    after_claims = _claim_count(db)

    assert before_attr == after_attr, "attribute fold changed under compaction"
    assert before_state == after_state, "STATE.md changed under compaction"
    assert after_claims < before_claims, "compaction pruned nothing"
    assert stats["pruned"] == before_claims - after_claims
    # 46 version claims -> 4 (K); 6 -> 4; product (1 claim) untouched.
    assert stats["groups"] == 2, stats
    print(f"fold preserved: {before_claims} -> {after_claims} claims, "
          f"pruned {stats['pruned']} across {stats['groups']} groups")


def test_conflict_and_winner_survive():
    base = Path(tempfile.mkdtemp(prefix="lotus_compact2_"))
    case = Case.create(base, "c2", title="t")
    _seed_corroborated(case)
    case.rebuild()
    db = case.dir / "projections" / "graph.db"
    case.compact(keep_per_value=3)

    conn = sqlite3.connect(str(db))
    val, conf, corr, conflict = conn.execute(
        "SELECT value_json,confidence,corroboration,conflict FROM attribute "
        "WHERE attr='version'"
    ).fetchone()
    # every distinct value must still be present as claims
    vals = {r[0] for r in conn.execute(
        "SELECT DISTINCT value_json FROM claim WHERE attr='version'")}
    conn.close()

    assert val == '"2.4.49"', val               # winner (40 x 0.6) beats (6 x 0.55)
    assert conflict == 1, "the competing value should register as a conflict"
    assert corr == 46, corr                     # 40 + 6 corroboration preserved
    assert vals == {'"2.4.49"', '"2.4.50"'}, vals
    print(f"winner={val} conf={conf:.4f} corroboration={corr} conflict={conflict}")


def test_idempotent_and_log_untouched():
    base = Path(tempfile.mkdtemp(prefix="lotus_compact3_"))
    case = Case.create(base, "c3", title="t")
    _seed_corroborated(case)
    case.rebuild()
    db = str(case.dir / "projections" / "graph.db")

    log_before = case.store.path.read_bytes()
    case.compact(keep_per_value=4)
    first = _claim_count(db)
    stats2 = case.compact(keep_per_value=4)   # second pass is a no-op
    second = _claim_count(db)
    log_after = case.store.path.read_bytes()

    assert first == second, "compaction is not idempotent"
    assert stats2["pruned"] == 0 and stats2["groups"] == 0, stats2
    assert log_before == log_after, "compaction must never touch the event log"

    # rebuild() restores the full pre-compaction claim history from the log
    case.rebuild()
    assert _claim_count(db) > first, "rebuild should restore full claim history"
    print(f"idempotent at {first} claims; log untouched; rebuild restores history")


def test_keep_per_value_one_and_validation():
    base = Path(tempfile.mkdtemp(prefix="lotus_compact4_"))
    case = Case.create(base, "c4", title="t")
    _seed_corroborated(case)
    case.rebuild()
    db = str(case.dir / "projections" / "graph.db")

    before = _attr_dump(db)
    case.compact(keep_per_value=1)            # collapse each value to a single claim
    after = _attr_dump(db)
    assert before == after, "even keep_per_value=1 must preserve the fold"

    conn = sqlite3.connect(db)
    per_val = conn.execute(
        "SELECT COUNT(*) FROM claim WHERE attr='version' AND value_json='\"2.4.49\"'"
    ).fetchone()[0]
    conn.close()
    assert per_val == 1, per_val

    try:
        case.compact(keep_per_value=0)
        raise AssertionError("keep_per_value=0 should raise")
    except ValueError:
        pass
    print("keep_per_value=1 collapses to a single claim; 0 rejected")


TESTS = [v for k, v in sorted(globals().items()) if k.startswith("test_")]

if __name__ == "__main__":
    failed = 0
    for t in TESTS:
        try:
            t()
            print(f"ok   {t.__name__}")
        except Exception as e:  # noqa: BLE001
            failed += 1
            print(f"FAIL {t.__name__}: {e!r}")
    print(f"\n{len(TESTS)-failed}/{len(TESTS)} passed")
    sys.exit(1 if failed else 0)
