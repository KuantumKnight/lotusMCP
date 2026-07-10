"""FlagEngine integration: scan -> candidate events -> submit -> verified,
through a real Case (single serializer, redaction, hash chain)."""
from __future__ import annotations

import base64
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from lotusmcp.flag.facade import FlagEngine  # noqa: E402
from lotusmcp.flag.policy import SUBMIT, WAIT  # noqa: E402
from lotusmcp.kernel.case import Case  # noqa: E402

FMT = r"flag\{[^}]+\}"
FLAG = "flag{engine_end_to_end}"


def test_scan_emits_one_candidate_per_value_and_chain_valid():
    with tempfile.TemporaryDirectory() as d:
        case = Case.create(d, "e1", flag_format=FMT)
        eng = FlagEngine(case)
        eng.scan([f"here is {FLAG}"])
        eng.scan([f"again {FLAG}", "and nothing else"])  # idempotent re-observe
        cands = [e for e in case.store.iter_events() if e["type"] == "flag.candidate"]
        assert len(cands) == 1
        assert cands[0]["payload"]["value"] == FLAG
        assert case.store.verify_chain() == -1


def test_full_submit_to_flag_found():
    with tempfile.TemporaryDirectory() as d:
        case = Case.create(d, "e2", flag_format=FMT)
        eng = FlagEngine(case)
        eng.scan([f"output {FLAG}"])
        decision = eng.decide()
        assert decision.action == SUBMIT
        verified = eng.submit(decision, oracle=lambda v: v == FLAG)
        assert verified is True
        assert eng.policy.terminal
        assert case.meta["status"] == "FLAG_FOUND"
        types = [e["type"] for e in case.store.iter_events()]
        assert "flag.submitted" in types
        assert "flag.verified" in types
        assert "case.status_changed" in types


def test_wrong_flag_rejected_then_next_tried():
    decoy_b64 = base64.b64encode(FLAG.encode()).decode()
    with tempfile.TemporaryDirectory() as d:
        case = Case.create(d, "e3", flag_format=FMT)
        eng = FlagEngine(case)
        # a wrong direct flag (T2) and the real one hidden in base64 (T3)
        eng.scan([f"flag{{plausible_guess_xyz}} {decoy_b64}"])
        eng.policy.min_tier = 3  # allow decoded submissions for this test
        d1 = eng.decide()
        assert d1.flag.value == "flag{plausible_guess_xyz}"
        assert eng.submit(d1, oracle=lambda v: v == FLAG) is False
        d2 = eng.decide()
        assert d2.action == SUBMIT and d2.flag.value == FLAG
        assert eng.submit(d2, oracle=lambda v: v == FLAG) is True
        assert case.meta["status"] == "FLAG_FOUND"


def test_rehydrate_from_log():
    with tempfile.TemporaryDirectory() as d:
        case = Case.create(d, "e4", flag_format=FMT)
        FlagEngine(case).scan([f"seen {FLAG}"])
        # a fresh engine on the same case must recover the candidate registry
        eng2 = FlagEngine(Case(d, "e4"))
        ranked = eng2.ranked()
        assert any(r.value == FLAG for r in ranked)
        assert eng2.decide().action == SUBMIT


def test_decoy_only_scan_waits():
    with tempfile.TemporaryDirectory() as d:
        case = Case.create(d, "e5", flag_format=FMT)
        eng = FlagEngine(case)
        eng.scan(["flag{this_is_not_the_flag}", "flag{example}"])
        assert eng.decide().action == WAIT


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
