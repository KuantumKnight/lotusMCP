"""Tests for EV+UCB action selection."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from lotusmcp.engine.candidate import CandidateAction  # noqa: E402
from lotusmcp.engine.selector import W_PRIOR, select  # noqa: E402
from lotusmcp.playbooks.engine import Proposal  # noqa: E402


def _prop(cap, cost=1.0, prior=0.05, rule="r", target="t", cat="web"):
    a = CandidateAction(cap, cat, target, target, {}, rule, "why",
                        phase_gate=("ENUMERATE", "EXPLOIT"), cost=cost)
    return Proposal(a, prior, 1.0)


def test_picks_highest_s():
    props = [_prop("a", cost=1.0, prior=0.02, rule="ra"),
             _prop("b", cost=1.0, prior=0.9, rule="rb")]
    sel = select(props, "ENUMERATE")
    assert sel.action.capability == "b"      # far higher prior dominates


def test_cheaper_action_wins_ev_when_equal_gain():
    props = [_prop("cheap", cost=1.0, prior=0.0, rule="r1"),
             _prop("pricey", cost=9.0, prior=0.0, rule="r2")]
    sel = select(props, "EXPLOIT")
    assert sel.action.capability == "cheap"  # EV = gain·payoff/cost


def test_ucb_explores_neglected_class():
    # two classes, identical EV/prior; one has been run many times
    props = [_prop("tried", cost=1.0, prior=0.0, rule="r1"),
             _prop("fresh", cost=1.0, prior=0.0, rule="r2")]
    sel = select(props, "ENUMERATE", t=50, n_class={"tried": 20, "fresh": 0})
    assert sel.action.capability == "fresh"  # UCB favours the unexplored class


def test_depth_guard_mutes_other_classes_while_lead_present():
    # 'lead' has a cheap untested test; 'other' is a neglected class.
    props = [_prop("lead", cost=1.0, prior=0.1, rule="r_lead"),
             _prop("other", cost=1.0, prior=0.0, rule="r_other")]
    # without the guard UCB would pull 'other' up; with it, exploration is muted
    sel = select(props, "ENUMERATE", t=100,
                 n_class={"lead": 5, "other": 0}, active_lead="lead")
    assert sel.action.capability == "lead"
    other = next(s for s in sel.ranked if s.action.capability == "other")
    assert other.ucb == 0.0


def test_ranked_sorted_and_deterministic():
    props = [_prop("a", prior=0.3, rule="ra"), _prop("b", prior=0.1, rule="rb"),
             _prop("c", prior=0.5, rule="rc")]
    s1 = select(props, "EXPLOIT")
    s2 = select(props, "EXPLOIT")
    ss = [x.s for x in s1.ranked]
    assert ss == sorted(ss, reverse=True)
    assert [x.action.rule_id for x in s1.ranked] == [x.action.rule_id for x in s2.ranked]


def test_info_gain_scales_ev():
    props = [_prop("hi", rule="r1"), _prop("lo", rule="r2")]
    gains = {"hi": 2.0, "lo": 0.1}
    sel = select(props, "EXPLOIT", info_gain=lambda a: gains[a.capability])
    assert sel.action.capability == "hi"


def test_empty_proposals():
    sel = select([], "RECON")
    assert sel.chosen is None and sel.action is None


def test_end_to_end_triage_playbook_select():
    """The full deterministic pipeline on a synthetic world: triage -> propose
    -> select, with no Kali and no LLM."""
    from lotusmcp.playbooks.engine import PlaybookEngine
    from lotusmcp.playbooks.model import World
    from lotusmcp.triage.classify import classify

    world = World.from_entity_dicts([
        {"id": "e_http", "kind": "service.http", "display": "service.http:h:80"},
        {"id": "e_p", "kind": "http.param", "display": "http.param:id",
         "attrs": {"reflected": True, "location": "query"}},
    ])
    meta = {"category": "web", "title": "login portal with id param"}
    conf = classify(meta, world).category_conf
    proposals = PlaybookEngine().propose(world, "EXPLOIT", category_conf=conf).proposals
    sel = select(proposals, "EXPLOIT")
    assert sel.action is not None
    assert sel.action.category == "web"
    assert sel.action.target_id in ("e_http", "e_p")


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
