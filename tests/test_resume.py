"""Bounded resume packet: structure, salience ordering, hard token budget, and a
scale test that a huge case still renders a small, bounded packet (Phase 5).

    PYTHONPATH=. PYTHONIOENCODING=utf-8 python tests/test_resume.py
"""
from __future__ import annotations

import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from lotusmcp.kernel.case import Case  # noqa: E402
from lotusmcp.kernel.events import EventDraft  # noqa: E402
from lotusmcp.kernel.resume import (  # noqa: E402
    CAP_SURFACE,
    DEFAULT_TOKEN_BUDGET,
    build_resume_packet,
)

FMT = r"flag\{[^}]+\}"


def _seed(case):
    case.append(EventDraft("entity.asserted", {"kind": "executor", "name": "nmap"},
                           {"kind": "host", "natural_key": {"addr": "10.10.11.5"}}))
    case.append(EventDraft("entity.asserted", {"kind": "executor", "name": "httpx"},
                           {"kind": "service.http",
                            "natural_key": {"host": "10.10.11.5", "proto": "tcp", "port": 80}}))
    case.append(EventDraft("finding.raised", {"kind": "executor", "name": "x"},
                           {"id": "F1", "type": "sqli", "severity": "high",
                            "confidence": 0.9, "subject": {"host": "10.10.11.5"},
                            "attrs": {}}))
    case.append(EventDraft("hypothesis.proposed", {"kind": "llm", "name": "g"},
                           {"hid": "H1", "statement": "sqli on q param dumps users",
                            "status": "OPEN", "confidence": 0.7}))


def _packet(case):
    built = case.rebuild()
    return build_resume_packet(built["graph_db"], case.meta, case.store.tip)


def test_packet_has_bounded_structure():
    with tempfile.TemporaryDirectory() as d:
        case = Case.create(d, "r", title="t", category="web", flag_format=FMT)
        _seed(case)
        p = _packet(case)
        assert p["case_id"] == "r" and p["phase"] == "TRIAGE"
        for key in ("surface", "findings", "hypotheses", "dead_ends", "counts",
                    "truncated"):
            assert key in p
        assert p["counts"]["entities"] >= 2
        assert any(h["hid"] == "H1" for h in p["hypotheses"])
        assert any(f["ftype"] == "sqli" for f in p["findings"])


def test_surface_is_salience_ranked():
    with tempfile.TemporaryDirectory() as d:
        case = Case.create(d, "r", title="t", category="web", flag_format=FMT)
        _seed(case)
        # a dead-ended, low-value entity should rank below the connected host
        case.append(EventDraft("entity.asserted", {"kind": "executor", "name": "x"},
                               {"kind": "http.endpoint",
                                "natural_key": {"host": "10.10.11.5", "method": "GET",
                                                "path": "/junk"}}))
        p = _packet(case)
        # every surface item carries a salience score, descending
        scores = [e["salience"] for e in p["surface"]]
        assert scores == sorted(scores, reverse=True)


def test_token_budget_is_enforced_with_report():
    with tempfile.TemporaryDirectory() as d:
        case = Case.create(d, "r", title="t", category="web", flag_format=FMT)
        _seed(case)
        for i in range(80):
            case.append(EventDraft("entity.asserted", {"kind": "executor", "name": "ffuf"},
                                   {"kind": "http.endpoint",
                                    "natural_key": {"host": "10.10.11.5",
                                                    "method": "GET", "path": f"/p{i}"}}))
        built = case.rebuild()
        tiny = build_resume_packet(built["graph_db"], case.meta, case.store.tip,
                                   token_budget=400)
        assert tiny["truncated"].get("surface", 0) > 0, "over-budget must trim surface"
        assert tiny["truncated"]["est_tokens"] <= 460, tiny["truncated"]
        assert len(tiny["surface"]) < CAP_SURFACE


def test_hypotheses_survive_truncation_over_surface():
    # the scarce high-value reasoning is trimmed last
    with tempfile.TemporaryDirectory() as d:
        case = Case.create(d, "r", title="t", category="web", flag_format=FMT)
        _seed(case)
        for i in range(60):
            case.append(EventDraft("entity.asserted", {"kind": "executor", "name": "ffuf"},
                                   {"kind": "http.endpoint",
                                    "natural_key": {"host": "10.10.11.5",
                                                    "method": "GET", "path": f"/p{i}"}}))
        built = case.rebuild()
        p = build_resume_packet(built["graph_db"], case.meta, case.store.tip,
                                token_budget=350)
        assert p["hypotheses"], "hypotheses must outlast surface under pressure"


def test_scale_case_stays_bounded_and_fast():
    with tempfile.TemporaryDirectory() as d:
        case = Case.create(d, "big", title="huge", category="web", flag_format=FMT)
        case.append(EventDraft("entity.asserted", {"kind": "executor", "name": "nmap"},
                               {"kind": "service.http",
                                "natural_key": {"host": "10.10.11.5", "proto": "tcp",
                                                "port": 80}}))
        N = 5000
        for i in range(N):
            case.append(EventDraft("entity.asserted", {"kind": "executor", "name": "ffuf"},
                                   {"kind": "http.endpoint",
                                    "natural_key": {"host": "10.10.11.5",
                                                    "method": "GET", "path": f"/e{i}"}}))
        built = case.rebuild()
        t0 = time.perf_counter()
        p = build_resume_packet(built["graph_db"], case.meta, case.store.tip)
        dt = time.perf_counter() - t0
        assert p["counts"]["entities"] >= N
        assert len(p["surface"]) <= CAP_SURFACE
        assert p["truncated"]["est_tokens"] <= DEFAULT_TOKEN_BUDGET
        # the packet build itself (not the one-time projector fold) is quick
        assert dt < 2.0, f"resume build took {dt:.3f}s on {N} endpoints"


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
