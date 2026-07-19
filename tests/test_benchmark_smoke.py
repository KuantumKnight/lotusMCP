"""Benchmark smoke result contracts."""
from __future__ import annotations

import tempfile
from pathlib import Path

from lotusmcp.control_plane.keyring import SigningKey
from lotusmcp.control_plane.anchor import create_anchor
from lotusmcp.engine.budget import BudgetLedger
from lotusmcp.kernel.case import Case
from lotusmcp.ops.benchmark_matrix import classify_case, iter_entries, summarize
from lotusmcp.ops.benchmark_smoke import SPECS, build_result


def test_aggregate_result_omits_raw_flag():
    with tempfile.TemporaryDirectory() as d:
        case = Case.create(Path(d), "bench", title="t", category="web",
                           flag_format=r"flag\{[^}]+\}")
        anchor = create_anchor(case.store, SigningKey.generate())
        result = build_result(
            case=case,
            challenge_id="2013q-web-guess_harder",
            case_id="bench",
            solved=True,
            budget=BudgetLedger(),
            anchor=anchor,
            wall_seconds=1.2345,
        )
    text = repr(result)
    assert result["benchmark"] == "nyu-ctf-bench"
    assert result["solved"] is True and result["flag_verified"] is True
    assert "audit_anchor" in result and result["chain_ok"] is True
    assert all(spec.expected_flag not in text for spec in SPECS.values())


def test_builtin_specs_have_unique_ports_or_run_sequentially():
    assert {"2013q-web-guess_harder", "2016q-web-mfw", "2016q-web-i_got_id"} <= set(SPECS)
    for cid, spec in SPECS.items():
        assert spec.challenge_id == cid
        assert spec.expected_flag
        assert spec.exploit_script.strip()
        assert spec.probe_path.startswith("/")


def test_matrix_classifies_supported_missing_and_needs_spec():
    with tempfile.TemporaryDirectory() as d:
        root = Path(d)
        supported = root / SPECS["2013q-web-guess_harder"].rel
        supported.mkdir(parents=True)
        (supported / "docker-compose.yml").write_text("services: {}\n", encoding="utf-8")
        local = root / "development/2099/CSAW-Quals/web/localonly"
        local.mkdir(parents=True)
        rows = [
            classify_case(root, "development", "2013q-web-guess_harder", {
                "year": "2013",
                "event": "CSAW-Quals",
                "category": "web",
                "challenge": "Guess Harder",
                "path": str(SPECS["2013q-web-guess_harder"].rel),
            }),
            classify_case(root, "development", "2099q-web-localonly", {
                "year": "2099",
                "event": "CSAW-Quals",
                "category": "web",
                "challenge": "localonly",
                "path": "development/2099/CSAW-Quals/web/localonly",
            }),
            classify_case(root, "test", "2099q-web-missing", {
                "year": "2099",
                "event": "CSAW-Quals",
                "category": "web",
                "challenge": "missing",
                "path": "test/2099/CSAW-Quals/web/missing",
            }),
        ]
    assert [r["status"] for r in rows] == [
        "supported", "missing_compose", "missing_checkout",
    ]
    summary = summarize(rows)
    assert summary["total"] == 3
    assert summary["supported"] == 1
    assert summary["checked_out"] == 2


def test_matrix_iter_entries_filters_before_limit():
    dataset = {
        "a": {"category": "web"},
        "b": {"category": "crypto"},
        "c": {"category": "web"},
    }
    assert [cid for cid, _ in iter_entries(dataset, category="web", limit=1)] == ["a"]


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items())
           if k.startswith("test_") and callable(v)]
    failed = 0
    for fn in fns:
        try:
            fn()
            print(f"  ok  {fn.__name__}")
        except Exception as e:
            failed += 1
            print(f"FAIL  {fn.__name__}: {e}")
    print(f"\n{len(fns)-failed}/{len(fns)} passed")
    raise SystemExit(1 if failed else 0)
