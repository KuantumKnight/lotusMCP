"""Tests for the ranker + decoy filter + 4-tier registry and the submit policy."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from lotusmcp.flag.policy import (  # noqa: E402
    BLOCKED,
    DONE,
    SUBMIT,
    WAIT,
    SubmitPolicy,
)
from lotusmcp.flag.ranker import (  # noqa: E402
    T2_STRONG,
    T3_DECODED,
    T4_WEAK,
    is_decoy,
    rank,
)
from lotusmcp.flag.scanner import FlagCandidate  # noqa: E402


def _direct(v):
    return FlagCandidate(v, "direct", (), v)


def _decoded(v, path):
    return FlagCandidate(v, "decoded", tuple(path), v)


# ---- decoy filter ----
def test_decoy_detection():
    for v in ["flag{this_is_not_the_flag}", "flag{fake}", "flag{example}",
              "flag{your_flag_here}", "flag{xxxx}", "flag{test}",
              "flag{try_harder}", "flag{redacted}"]:
        assert is_decoy(v), v


def test_real_flags_not_decoys():
    for v in ["flag{r34l_d34l_1337}", "picoCTF{buffer_0verfl0w_2a3b}",
              "HTB{s0me_l0ng_r34l_fl4g}"]:
        assert not is_decoy(v), v


# ---- tiering ----
def test_direct_operator_format_is_strong():
    r = rank([_direct("flag{r34l_one}")], has_operator_format=True)
    assert r[0].tier == T2_STRONG and r[0].confidence >= 0.85


def test_generic_format_capped_at_decoded():
    r = rank([_direct("flag{shape_only}")], has_operator_format=False)
    assert r[0].tier == T3_DECODED


def test_decoded_shallow_is_tier3_deep_is_tier4():
    shallow = rank([_decoded("flag{real_body}", ["base64"])], has_operator_format=True)[0]
    deep = rank([_decoded("flag{real_body}", ["base64", "hex", "rot13", "reverse"])],
                has_operator_format=True)[0]
    assert shallow.tier == T3_DECODED
    assert deep.tier == T4_WEAK
    assert deep.confidence < shallow.confidence


def test_decoy_forced_to_tier4():
    r = rank([_direct("flag{fake}")], has_operator_format=True)
    assert r[0].tier == T4_WEAK and r[0].is_decoy


def test_ranking_order_best_first():
    r = rank([
        _decoded("flag{decoded_one}", ["base64"]),
        _direct("flag{real_direct}"),
        _direct("flag{fake}"),
    ], has_operator_format=True)
    assert r[0].value == "flag{real_direct}"      # T2 first
    assert r[1].value == "flag{decoded_one}"      # T3 next
    assert r[-1].value == "flag{fake}"            # decoy last


# ---- submit policy ----
def test_submit_then_verify_is_terminal():
    ranked = rank([_direct("flag{win}")], has_operator_format=True)
    p = SubmitPolicy()
    d = p.decide(ranked)
    assert d.action == SUBMIT and d.flag.value == "flag{win}"
    p.record_submit(d.flag)
    p.record_result(d.flag, correct=True)
    assert p.terminal
    assert p.decide(ranked).action == DONE


def test_rejected_flag_not_resubmitted_moves_on():
    ranked = rank([_direct("flag{first}"), _decoded("flag{second}", ["base64"])],
                  has_operator_format=True)
    p = SubmitPolicy()
    d1 = p.decide(ranked)
    assert d1.flag.value == "flag{first}"
    p.record_submit(d1.flag)
    p.record_result(d1.flag, correct=False)
    d2 = p.decide(ranked)
    # first is rejected; only tier-2 auto-submits by default, so second (T3) waits
    assert d2.action == WAIT
    # widen the policy to tier 3 and the second becomes submittable
    p.min_tier = T3_DECODED
    d3 = p.decide(ranked)
    assert d3.action == SUBMIT and d3.flag.value == "flag{second}"


def test_no_signed_endpoint_blocks():
    ranked = rank([_direct("flag{win}")], has_operator_format=True)
    p = SubmitPolicy(has_signed_endpoint=False)
    d = p.decide(ranked)
    assert d.action == BLOCKED and "endpoint" in d.reason


def test_budget_exhaustion_blocks():
    ranked = rank([_direct("flag{alpha_real}"), _direct("flag{beta_real}")],
                  has_operator_format=True)
    p = SubmitPolicy(max_submissions=1)
    d1 = p.decide(ranked)
    assert d1.action == SUBMIT
    p.record_submit(d1.flag)
    p.record_result(d1.flag, correct=False)
    d2 = p.decide(ranked)
    assert d2.action == BLOCKED and "budget" in d2.reason


def test_only_decoys_never_submit():
    ranked = rank([_direct("flag{fake}"), _direct("flag{example}")],
                  has_operator_format=True)
    p = SubmitPolicy()
    assert p.decide(ranked).action == WAIT


def test_require_local_check_gates_submit():
    ranked = rank([_direct("flag{win}")], has_operator_format=True)
    p = SubmitPolicy(require_local_check=True)
    assert p.decide(ranked).action == WAIT
    d = p.decide(ranked, locally_checked=["flag{win}"])
    assert d.action == SUBMIT


def test_dedup_same_value_not_submitted_twice():
    ranked = rank([_direct("flag{win}")], has_operator_format=True)
    p = SubmitPolicy()
    d = p.decide(ranked)
    p.record_submit(d.flag)
    # without a result, the same value should not be offered again
    assert p.decide(ranked).action == WAIT


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
