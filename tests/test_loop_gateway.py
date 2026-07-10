"""Loop + LLM gateway wiring: abduction replaces the hypothesis stub, and LLM
spend flows through the ONE ledger. The gateway is optional — the gateway-less
loop is covered by test_loop.py and must be unaffected.

    PYTHONPATH=. PYTHONIOENCODING=utf-8 python tests/test_loop_gateway.py
"""
from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from lotusmcp.engine.budget import BudgetLedger
from lotusmcp.engine.candidate import CandidateAction
from lotusmcp.engine.loop import Loop
from lotusmcp.engine.selector import select
from lotusmcp.kernel.case import Case
from lotusmcp.kernel.events import EventDraft
from lotusmcp.llm.gateway import LLMGateway
from lotusmcp.playbooks.engine import Proposal
from lotusmcp.playbooks.model import World

HOST = "10.10.11.53"


class QuietExecutor:
    """Executor that emits no events — isolates ORIENT-time abduction."""
    def run(self, action, case):
        return [EventDraft("note.added", {"kind": "system", "name": "noop"},
                           {"text": "noop"})]


def _case_with_exposure():
    base = Path(tempfile.mkdtemp(prefix="lotus_loopgw_"))
    case = Case.create(base, "loopgw", title="t", category="web",
                       flag_format=r"flag\{[^}]+\}", platform="HackTheBox")
    case.append(EventDraft("entity.asserted", {"kind": "executor", "name": "seed"},
                           {"kind": "service.http",
                            "natural_key": {"host": HOST, "proto": "tcp", "port": 80}}))
    # a real exposure finding the gateway can abduce from
    case.append(EventDraft("finding.raised", {"kind": "executor", "name": "curl"},
                           {"id": "F-git", "type": "exposure", "severity": "high",
                            "confidence": 0.9,
                            "subject": {"url": f"http://{HOST}/.git/config"},
                            "attrs": {"leak": "exposed .git"}}))
    return case


def test_gateway_abduces_hypothesis_into_log():
    case = _case_with_exposure()
    budget = BudgetLedger()
    loop = Loop(case, QuietExecutor(), budget=budget, gateway=LLMGateway())
    before = [h.statement for h in World.from_graph_db(case.rebuild()["graph_db"]).hypotheses]
    assert before == []
    loop.step()
    world = World.from_graph_db(case.rebuild()["graph_db"])
    hyps = [h for h in world.hypotheses if h.status == "OPEN"]
    assert hyps, "gateway should have abduced at least one hypothesis"
    assert any("credential" in h.statement or "recovery" in h.statement for h in hyps)
    # LLM spend flowed through the shared ledger
    assert budget.llm_tokens > 0
    assert loop.gateway.stats.calls >= 1


def test_repeat_steps_hit_cache_no_duplicate_hypotheses():
    case = _case_with_exposure()
    loop = Loop(case, QuietExecutor(), gateway=LLMGateway())
    loop.step()
    n1 = len(World.from_graph_db(case.rebuild()["graph_db"]).hypotheses)
    loop.step()
    n2 = len(World.from_graph_db(case.rebuild()["graph_db"]).hypotheses)
    assert n1 == n2, "same findings must not re-append hypotheses"
    assert loop.gateway.stats.cache_hits >= 1, "second abduction should be a cache hit"


def test_no_gateway_leaves_loop_deterministic():
    case = _case_with_exposure()
    loop = Loop(case, QuietExecutor())          # no gateway
    loop.step()
    world = World.from_graph_db(case.rebuild()["graph_db"])
    # only the seeded/no reasoning hypotheses; gateway didn't run
    assert all(h.status != "OPEN" or "gateway" not in h.statement for h in world.hypotheses)
    assert loop.budget.llm_tokens > 0   # flat notional charge still applies


def _prop(cap, prio=0.5):
    a = CandidateAction(capability=cap, category="web", target_id="e1",
                        target_display="t", params={"class": "x"}, rule_id=f"r.{cap}",
                        rationale="", phase_gate=("RECON",), yield_=0.5, priority=prio)
    return Proposal(action=a, score=0.1, novelty=1.0)


def test_info_gain_multiplier_changes_selection():
    """Two otherwise-equal proposals: the selector must prefer the one the
    gateway rates higher for info-gain."""
    p_lo, p_hi = _prop("alpha"), _prop("beta")
    ig = {"alpha|e1|x": 0.1, "beta|e1|x": 0.9}
    sel = select([p_lo, p_hi], "RECON", t=1, n_class={"alpha": 1, "beta": 1},
                 info_gain=lambda a: ig["|".join(a.dedup_key())])
    assert sel.action.capability == "beta", [s.action.capability for s in sel.ranked]
    # and with the ratings flipped, the choice flips too
    ig2 = {"alpha|e1|x": 0.9, "beta|e1|x": 0.1}
    sel2 = select([p_lo, p_hi], "RECON", t=1, n_class={"alpha": 1, "beta": 1},
                  info_gain=lambda a: ig2["|".join(a.dedup_key())])
    assert sel2.action.capability == "alpha"


def test_loop_invokes_ranking_when_gateway_present():
    case = _case_with_exposure()
    loop = Loop(case, QuietExecutor(), gateway=LLMGateway())
    loop.step()
    # a step with proposals triggers BOTH hypothesize (findings present) and rank
    assert loop.gateway.stats.calls >= 2, loop.gateway.stats
    assert any("rank" in k for k in loop.gateway._cache), "ranking not cached"


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
