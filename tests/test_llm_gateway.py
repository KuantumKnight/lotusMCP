"""LLM gateway tests — the metered, cached, schema-enforcing single call site.

Exercises the gateway end-to-end with the offline DeterministicProvider: budget
is charged once per distinct prompt and never on a cache hit; malformed provider
output is rejected/retried; and abduction/ranking are deterministic (byte-equal
on repeat), which is what makes decision-replay exact.

    PYTHONPATH=. PYTHONIOENCODING=utf-8 python tests/test_llm_gateway.py
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from lotusmcp.engine.budget import BudgetLedger
from lotusmcp.llm.gateway import LLMGateway
from lotusmcp.llm.provider import (
    ORIENT_AND_HYPOTHESIZE,
    RANK_ACTIONS,
    DeterministicProvider,
)
from lotusmcp.llm.schema import SchemaError, validate, HYP_SCHEMA

FINDINGS = [
    {"id": "F1", "type": "exposure", "confidence": 0.9, "subject": {"url": "http://h/.git"}},
    {"id": "F2", "type": "sqli", "confidence": 0.8, "subject": {"param": "id"}},
    {"id": "F3", "type": "info", "confidence": 0.5, "subject": {"x": "y"}},  # no rule -> skipped
]
CANDS = [
    {"key": "port_scan:e1", "capability": "port_scan", "yield": 0.7, "cost": 3.0},
    {"key": "http_probe:e2", "capability": "http_probe", "yield": 0.6, "cost": 1.0},
]


def test_abduction_matches_schema_and_skips_ruleless():
    g = LLMGateway()
    resp = g.hypothesize(FINDINGS)
    validate(resp, HYP_SCHEMA)          # must be schema-valid
    assert len(resp["new"]) == 2        # exposure + sqli; info skipped
    # highest confidence first: sqli 0.75*0.8=0.6 vs exposure 0.7*0.9=0.63 -> exposure first
    assert resp["new"][0]["confidence"] >= resp["new"][1]["confidence"]
    assert all(0.0 <= h["confidence"] <= 1.0 for h in resp["new"])


def test_cache_hit_is_free_and_identical():
    budget = BudgetLedger()
    g = LLMGateway(budget=budget)
    r1 = g.hypothesize(FINDINGS, phase="ORIENT")
    charged_after_first = budget.llm_tokens
    assert charged_after_first > 0, "first call must charge budget"
    r2 = g.hypothesize(FINDINGS, phase="ORIENT")
    assert r1 == r2, "same context must replay identical output"
    assert budget.llm_tokens == charged_after_first, "cache hit must NOT re-charge"
    assert g.stats.cache_hits == 1 and g.stats.calls == 2


def test_distinct_context_charges_again():
    budget = BudgetLedger()
    g = LLMGateway(budget=budget)
    g.hypothesize(FINDINGS)
    first = budget.llm_tokens
    g.hypothesize(FINDINGS[:1])         # different context -> cache miss -> charge
    assert budget.llm_tokens > first


def test_ranking_is_info_gain_sorted():
    g = LLMGateway()
    resp = g.rank(CANDS)
    keys = [r["key"] for r in resp["ranking"]]
    # http_probe (yield .6/cost1 => .52) outranks port_scan (.7/cost3 => .48)
    assert keys[0] == "http_probe:e2", resp["ranking"]
    assert resp["ranking"][0]["info_gain"] >= resp["ranking"][1]["info_gain"]


def test_determinism_across_gateway_instances():
    a = LLMGateway().hypothesize(FINDINGS)
    b = LLMGateway().hypothesize(FINDINGS)
    assert a == b, "provider must be deterministic across instances"


def test_schema_enforced_and_retried():
    class BadThenGood(DeterministicProvider):
        def __init__(self):
            self.n = 0
        def complete(self, task, context):
            self.n += 1
            if self.n == 1:
                return {"new": [{"statement": "x"}]}   # missing required confidence
            return super().complete(task, context)
        def cost_tokens(self, task, context):
            return 100
    g = LLMGateway(provider=BadThenGood(), max_retries=2)
    resp = g.hypothesize(FINDINGS)      # first attempt invalid, retry succeeds
    assert "new" in resp and g.provider.n == 2


def test_persistently_invalid_raises():
    class AlwaysBad(DeterministicProvider):
        def complete(self, task, context):
            return {"wrong": True}
        def cost_tokens(self, task, context):
            return 10
    g = LLMGateway(provider=AlwaysBad(), max_retries=1)
    try:
        g.hypothesize(FINDINGS)
    except SchemaError:
        return
    raise AssertionError("persistently invalid output must raise SchemaError")


def test_unknown_task_rejected():
    g = LLMGateway()
    try:
        g.oracle("make_coffee", {})
    except ValueError:
        return
    raise AssertionError("unknown oracle task must raise")


def test_budget_visible_to_stopping_math():
    budget = BudgetLedger(max_llm_tokens=1000)
    g = LLMGateway(budget=budget)
    for i in range(20):
        g.hypothesize(FINDINGS[: (i % 3) + 1] + [{"id": f"X{i}", "type": "sqli",
                                                  "confidence": 0.5, "subject": {"n": i}}])
        if budget.exhausted():
            break
    assert budget.exhausted(), "gateway spend must eventually trip the ledger"


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items())
           if k.startswith("test_") and callable(v)]
    failed = 0
    for fn in fns:
        try:
            fn()
            print(f"  ok  {fn.__name__}")
        except Exception as e:  # noqa: BLE001
            failed += 1
            print(f"FAIL  {fn.__name__}: {e}")
    print(f"\n{len(fns) - failed}/{len(fns)} passed")
    sys.exit(1 if failed else 0)
