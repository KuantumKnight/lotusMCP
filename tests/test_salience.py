"""Decomposable salience: the formula, recency decay, and deterministic ranking.

    PYTHONPATH=. PYTHONIOENCODING=utf-8 python tests/test_salience.py
"""
from __future__ import annotations

import math
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from lotusmcp.engine.salience import (  # noqa: E402
    TAU,
    Salience,
    rank,
    recency,
    score,
    top_k,
)


def test_recency_bounds_and_decay():
    assert recency(0, 0) == 1.0                 # empty log
    assert recency(100, 100) == 1.0            # touched at the tip
    assert recency(150, 100) == 1.0            # future seq clamps to 1.0
    r = recency(0, int(TAU))                    # exactly one τ ago
    assert abs(r - math.exp(-1)) < 1e-9
    # strictly decreasing as the entity ages
    assert recency(90, 100) > recency(50, 100) > recency(0, 100)


def test_score_weights_each_component():
    tip = 100
    base = Salience(last_seq=tip)               # only recency (=1.0) contributes
    assert abs(score(base, tip) - 0.20) < 1e-9
    conf = Salience(s_conf=1.0, last_seq=tip)
    assert abs(score(conf, tip) - (0.20 + 0.15)) < 1e-9
    hyp = Salience(s_hyp=1.0, last_seq=tip)
    assert abs(score(hyp, tip) - (0.20 + 0.25)) < 1e-9
    pf = Salience(s_pathflag=1.0, last_seq=tip)
    assert abs(score(pf, tip) - (0.20 + 0.25)) < 1e-9


def test_deadend_subtracts():
    tip = 100
    live = Salience(s_hyp=1.0, last_seq=tip)
    dead = Salience(s_hyp=1.0, s_deadend=1.0, last_seq=tip)
    assert score(dead, tip) < score(live, tip)
    assert abs((score(live, tip) - score(dead, tip)) - 0.30) < 1e-9


def test_components_are_clamped():
    tip = 10
    # out-of-range components don't blow past the weighted maxima
    wild = Salience(s_conf=5.0, s_hyp=-3.0, s_pathflag=2.0, s_deadend=-1.0, last_seq=tip)
    s = score(wild, tip)
    # s_conf->1, s_hyp->0, s_pathflag->1, s_deadend->0, recency 1.0
    assert abs(s - (0.15 + 0.0 + 0.25 - 0.0 + 0.20)) < 1e-9


def test_rank_orders_by_score_desc_with_stable_tiebreak():
    tip = 100
    items = [
        ("e_low", Salience(s_deadend=1.0, last_seq=0)),
        ("e_hyp", Salience(s_hyp=1.0, last_seq=tip)),
        ("e_conf", Salience(s_conf=1.0, last_seq=tip)),
        # two identical scores -> lexical key tiebreak
        ("b_tie", Salience(s_conf=1.0, last_seq=tip)),
    ]
    ranked = rank(items, tip)
    keys = [k for k, _ in ranked]
    assert keys[0] == "e_hyp"                    # highest (0.45)
    # the two conf ties (0.35) come next, lexical: b_tie before e_conf
    assert keys[1] == "b_tie" and keys[2] == "e_conf"
    assert keys[-1] == "e_low"                   # dead end sinks to the bottom
    # scores are actually descending
    scores = [s for _, s in ranked]
    assert scores == sorted(scores, reverse=True)


def test_recency_separates_equal_static_parts():
    tip = 1000
    recent = ("recent", Salience(s_conf=0.5, last_seq=1000))
    stale = ("stale", Salience(s_conf=0.5, last_seq=0))
    assert top_k([recent, stale], 1, tip) == ["recent"]


def test_top_k_bounds():
    tip = 50
    items = [(f"e{i}", Salience(s_conf=i / 100, last_seq=i)) for i in range(20)]
    assert len(top_k(items, 5, tip)) == 5
    assert top_k(items, 0, tip) == []
    assert len(top_k(items, 999, tip)) == 20


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
