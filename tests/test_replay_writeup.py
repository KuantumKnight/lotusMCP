"""Phase 6: deterministic state replay / diff, and the two-stage writeup whose
citation verifier exiles any sentence the log doesn't support.

    PYTHONPATH=. PYTHONIOENCODING=utf-8 python tests/test_replay_writeup.py
"""
from __future__ import annotations

import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from lotusmcp.kernel.case import Case  # noqa: E402
from lotusmcp.kernel.events import EventDraft  # noqa: E402
from lotusmcp.replay import (  # noqa: E402
    Claim,
    build_ir,
    diff,
    generate_writeup,
    state_at,
)
from lotusmcp.replay.writeup import CitationIndex, verify_claims  # noqa: E402

FMT = r"flag\{[^}]+\}"
FLAG = "flag{writeup_ci7ation_1337}"


def _case(tmp):
    case = Case.create(tmp, "wc", title="Titan", category="web", flag_format=FMT)
    case.append(EventDraft("entity.asserted", {"kind": "executor", "name": "nmap"},
                           {"kind": "service.http",
                            "natural_key": {"host": "10.10.11.5", "proto": "tcp", "port": 80}}))
    case.append(EventDraft("case.status_changed", {"kind": "system", "name": "engine"},
                           {"phase": "RECON", "reason": "scope ok"}))
    case.append(EventDraft("finding.raised", {"kind": "executor", "name": "x"},
                           {"id": "F-sqli", "type": "sqli", "severity": "high",
                            "confidence": 0.9, "subject": {"host": "10.10.11.5"},
                            "attrs": {}}))
    return case


def _win(case):
    case.append(EventDraft("case.status_changed", {"kind": "system", "name": "engine"},
                           {"phase": "FLAG_FOUND", "reason": "oracle"}))
    case.append(EventDraft("flag.verified", {"kind": "system", "name": "flag"},
                           {"value": FLAG}))


# ------------------------------------------------------------------ replay


def test_state_at_reconstructs_past_phase_and_graph():
    with tempfile.TemporaryDirectory() as d:
        case = _case(d)
        early = state_at(case, 1)           # after the service assert (seq 1)
        assert early["phase"] == "TRIAGE"
        assert early["counts"]["findings"] == 0
        late = state_at(case, case.store.tip)
        assert late["phase"] == "RECON"
        assert late["counts"]["findings"] == 1


def test_diff_reports_added_between_seqs():
    with tempfile.TemporaryDirectory() as d:
        case = _case(d)
        tip = case.store.tip
        dd = diff(case, 1, tip)
        assert dd["phase_from"] == "TRIAGE" and dd["phase_to"] == "RECON"
        assert any(f["id"] == "F-sqli" for f in dd["findings_added"])
        # the service existed at seq 1 already → not "added" in this window
        assert not dd["entities_added"]


# ------------------------------------------------------------------ writeup


def test_build_ir_verifies_clean():
    with tempfile.TemporaryDirectory() as d:
        case = _case(d)
        _win(case)
        ir = build_ir(case)
        index = CitationIndex(case)
        flat = [c for _, c in ir.all_claims()]
        accepted, rejected = verify_claims(flat, index)
        assert not rejected, rejected           # every IR claim cites real ids
        assert any("flag" in " ".join(c.citations) for c in accepted)


def test_generate_writeup_includes_flag_and_no_rejects():
    with tempfile.TemporaryDirectory() as d:
        case = _case(d)
        _win(case)
        out = generate_writeup(case)
        assert out["rejected"] == []
        assert FLAG in out["markdown"]
        assert "## Findings" in out["markdown"]
        types = [e["type"] for e in case.store.iter_events()]
        assert "writeup.generated" in types
        assert "writeup.claim_rejected" not in types


def test_unsupported_sentence_is_exiled():
    with tempfile.TemporaryDirectory() as d:
        case = _case(d)
        _win(case)
        good = Claim("The sqli finding was corroborated.", ("finding:F-sqli",))
        hallucinated = Claim("We also pivoted to the domain controller and got DA.",
                             ("finding:F-does-not-exist",))
        uncited = Claim("Trust me, it was definitely vulnerable.", ())
        out = generate_writeup(case, extra_claims=[good, hallucinated, uncited])
        md = out["markdown"]
        assert "corroborated" in md                     # supported → kept
        assert "domain controller" not in md            # bad citation → exiled
        assert "Trust me" not in md                      # no citation → exiled
        reasons = {r["reason"] for r in out["rejected"]}
        assert reasons == {"unresolved citations", "no citations"}
        # exiles are recorded on the log as claim_rejected events
        rej = [e for e in case.store.iter_events() if e["type"] == "writeup.claim_rejected"]
        assert len(rej) == 2


def test_verify_claims_pure():
    with tempfile.TemporaryDirectory() as d:
        case = _case(d)
        index = CitationIndex(case)
        assert index.resolves("finding:F-sqli")
        assert not index.resolves("finding:nope")
        assert not index.resolves("event:99999")
        assert index.resolves("event:0")               # case.created
        acc, rej = verify_claims(
            [Claim("ok", ("finding:F-sqli",)), Claim("bad", ("entity:ghost",))], index)
        assert len(acc) == 1 and len(rej) == 1


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
