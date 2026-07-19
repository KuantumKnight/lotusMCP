"""Benchmark smoke result contracts."""
from __future__ import annotations

import tempfile
from pathlib import Path

from lotusmcp.control_plane.keyring import SigningKey
from lotusmcp.control_plane.anchor import create_anchor
from lotusmcp.engine.budget import BudgetLedger
from lotusmcp.kernel.case import Case
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
