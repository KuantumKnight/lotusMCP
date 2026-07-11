"""Full-text search over the resolver surface (Phase 5).

The resolver's `search` builds a transient FTS5 index over entities/findings/
hypotheses, so queries are tokenized: multi-term queries AND their terms
(order-independent, not requiring a contiguous substring), and prefixes match.
Where FTS5 is unavailable it must fall back to substring matching. Ranking
(finding > hypothesis > entity for a shared term) is unchanged.

    PYTHONPATH=. PYTHONIOENCODING=utf-8 python tests/test_search_fts.py
"""
from __future__ import annotations

import sqlite3
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from lotusmcp.gateway.resolver import Resolver, parse_uri
from lotusmcp.kernel.case import Case
from lotusmcp.kernel.events import EventDraft

FMT = r"flag\{[^}]+\}"


def _case(tmp):
    case = Case.create(tmp, "web1", title="Titan", category="web", flag_format=FMT)
    case.append(EventDraft("entity.asserted", {"kind": "executor", "name": "nmap"},
                           {"kind": "service.http",
                            "natural_key": {"host": "10.10.11.5", "proto": "tcp", "port": 80}}))
    case.append(EventDraft("finding.raised", {"kind": "executor", "name": "x"},
                           {"id": "F-rce", "type": "path_traversal_rce", "severity": "crit",
                            "confidence": 0.95, "subject": {"host": "10.10.11.5"},
                            "attrs": {"product": "Apache", "version": "2.4.49"}}))
    case.append(EventDraft("hypothesis.proposed", {"kind": "llm", "name": "g"},
                           {"hid": "H-cve", "statement": "Apache 2.4.49 is vulnerable to CVE-2021-41773",
                            "status": "OPEN", "confidence": 0.8}))
    return case


def _kinds(results):
    return [parse_uri(r["id"])[1] for r in results]


def test_multiterm_and_is_order_independent():
    with tempfile.TemporaryDirectory() as d:
        _case(d)
        rz = Resolver(d)
        # "apache" and "2.4.49" appear in the finding but NOT contiguously in a
        # single haystack field — substring matching would miss it; FTS ANDs.
        a = rz.search("web1", "apache 2.4.49")
        b = rz.search("web1", "2.4.49 apache")   # order must not matter
        assert a, "multi-term query should match the finding + hypothesis"
        assert {r["id"] for r in a} == {r["id"] for r in b}, "term order changed results"
        assert "finding" in _kinds(a) and "hypothesis" in _kinds(a)
        print(f"multi-term AND matched {len(a)} docs, order-independent")


def test_prefix_matching():
    with tempfile.TemporaryDirectory() as d:
        _case(d)
        rz = Resolver(d)
        # "travers" is a prefix of the finding's ftype token "traversal"
        res = rz.search("web1", "travers")
        ids = {r["id"] for r in res}
        assert any("finding/F-rce" in i for i in ids), ids
        print("prefix query matched the traversal finding")


def test_ranking_finding_before_hypothesis():
    with tempfile.TemporaryDirectory() as d:
        _case(d)
        rz = Resolver(d)
        res = rz.search("web1", "apache")
        kinds = _kinds(res)
        assert kinds.index("finding") < kinds.index("hypothesis"), kinds
        print(f"ranking preserved: {kinds}")


def test_no_match_returns_empty():
    with tempfile.TemporaryDirectory() as d:
        _case(d)
        rz = Resolver(d)
        assert rz.search("web1", "nonexistent_zzz_token") == []
        print("unmatched query returns no results")


def test_substring_fallback_matches_fts_when_no_fts(monkeypatched=None):
    """Force the FTS path to report 'unavailable' and confirm search still
    finds the finding via the substring fallback."""
    with tempfile.TemporaryDirectory() as d:
        _case(d)
        rz = Resolver(d)
        orig = rz._fts_uris
        rz._fts_uris = lambda *a, **k: None      # simulate FTS5 missing
        try:
            res = rz.search("web1", "apache")     # single contiguous token
        finally:
            rz._fts_uris = orig
        assert any("finding/F-rce" in r["id"] for r in res), res
        print("substring fallback still finds the finding")


def test_temp_index_does_not_leak():
    with tempfile.TemporaryDirectory() as d:
        case = _case(d)
        rz = Resolver(d)
        rz.search("web1", "apache")
        # the FTS index lives in temp. and the connection is closed each call;
        # the persistent graph.db must carry no ftsidx table.
        db = str(case.dir / "projections" / "graph.db")
        conn = sqlite3.connect(db)
        names = {r[0] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'")}
        conn.close()
        assert "ftsidx" not in names, names
        print("transient FTS index left no residue in graph.db")


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
