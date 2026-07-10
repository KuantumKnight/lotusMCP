"""The single surface resolver: URI parsing, fetch over the lotus:// space, and
the ChatGPT deep-research search/fetch round-trip (Phase 5).

    PYTHONPATH=. PYTHONIOENCODING=utf-8 python tests/test_gateway_resolver.py
"""
from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from lotusmcp.gateway.resolver import Resolver, parse_uri  # noqa: E402
from lotusmcp.kernel.case import Case  # noqa: E402
from lotusmcp.kernel.events import EventDraft  # noqa: E402

FMT = r"flag\{[^}]+\}"


def _case(tmp):
    case = Case.create(tmp, "web1", title="Titan portal", category="web", flag_format=FMT)
    case.append(EventDraft("entity.asserted", {"kind": "executor", "name": "nmap"},
                           {"kind": "service.http",
                            "natural_key": {"host": "10.10.11.5", "proto": "tcp", "port": 80}}))
    case.append(EventDraft("finding.raised", {"kind": "executor", "name": "x"},
                           {"id": "F-sqli", "type": "sqli", "severity": "high",
                            "confidence": 0.9, "subject": {"host": "10.10.11.5"},
                            "attrs": {"param": "q"}}))
    case.append(EventDraft("hypothesis.proposed", {"kind": "llm", "name": "g"},
                           {"hid": "H-sqli", "statement": "sqli on q dumps the users table",
                            "status": "OPEN", "confidence": 0.7}))
    return case


def test_parse_uri():
    assert parse_uri("lotus://case/web1/brief") == ("web1", "brief", None)
    assert parse_uri("lotus://case/web1/entity/E1") == ("web1", "entity", "E1")
    assert parse_uri("http://evil/") is None
    assert parse_uri("lotus://case//brief") is None
    assert parse_uri("nonsense") is None


def test_fetch_brief_and_resume():
    with tempfile.TemporaryDirectory() as d:
        _case(d)
        rz = Resolver(d)
        brief = rz.fetch("lotus://case/web1/brief")
        assert brief["id"] == "lotus://case/web1/brief"
        assert "CASE web1" in brief["text"]
        resume = rz.fetch("lotus://case/web1/resume")
        pkt = json.loads(resume["text"])
        assert pkt["case_id"] == "web1" and "surface" in pkt


def test_fetch_finding_and_hypothesis():
    with tempfile.TemporaryDirectory() as d:
        _case(d)
        rz = Resolver(d)
        f = rz.fetch("lotus://case/web1/finding/F-sqli")
        assert f["metadata"]["kind"] == "finding" and "sqli" in f["text"]
        h = rz.fetch("lotus://case/web1/hypothesis/H-sqli")
        assert "users table" in h["text"]


def test_fetch_bad_uri_and_missing():
    with tempfile.TemporaryDirectory() as d:
        _case(d)
        rz = Resolver(d)
        assert rz.fetch("http://evil")["metadata"].get("error") == "bad_uri"
        miss = rz.fetch("lotus://case/web1/finding/nope")
        assert miss["metadata"].get("error") == "not_found"


def test_search_then_fetch_roundtrip():
    with tempfile.TemporaryDirectory() as d:
        _case(d)
        rz = Resolver(d)
        results = rz.search("web1", "sqli")
        assert results, "search should find the sqli finding + hypothesis"
        # every result id is a resolvable URI (deep-research contract)
        for r in results:
            assert r["id"] == r["url"] and parse_uri(r["id"]) is not None
            doc = rz.fetch(r["id"])
            assert doc["id"] == r["id"] and doc["text"]
        # a finding outranks a hypothesis for the same term
        kinds = [parse_uri(r["id"])[1] for r in results]
        assert kinds.index("finding") < kinds.index("hypothesis")


def test_search_empty_query_returns_salient_items():
    with tempfile.TemporaryDirectory() as d:
        _case(d)
        rz = Resolver(d)
        assert rz.search("web1", "") , "empty query returns most-salient items"
        assert len(rz.search("web1", "", limit=2)) <= 2


def test_resolve_is_fetch():
    with tempfile.TemporaryDirectory() as d:
        _case(d)
        rz = Resolver(d)
        assert rz.resolve("lotus://case/web1/brief") == rz.fetch("lotus://case/web1/brief")


if __name__ == "__main__":
    import traceback

    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    failed = 0
    for fn in fns:
        try:
            fn()
            print(f"ok   {fn.__name__}")
        except Exception:  # noqa: BLE001
            failed += 1
            print(f"FAIL {fn.__name__}")
            traceback.print_exc()
    print(f"\n{len(fns) - failed}/{len(fns)} passed")
    sys.exit(1 if failed else 0)
