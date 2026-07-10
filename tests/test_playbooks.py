"""Tests for the candidate scoring core and the Playbook Engine.

Covers: U(A) formula behaviour, phase gating, dead-end/novelty decay, per-kind
quota, scope binding, determinism, and firing over a REAL rebuilt graph.db.
"""
from __future__ import annotations

import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from lotusmcp.engine.candidate import CandidateAction  # noqa: E402
from lotusmcp.playbooks.engine import PlaybookEngine  # noqa: E402
from lotusmcp.playbooks.model import Rule, World  # noqa: E402


def _svc_http(port=80):
    return {"id": f"e_http{port}", "kind": "service.http",
            "display": f"service.http:10.0.0.1:{port}", "attrs": {"server": "nginx"}}


def _host(with_services=True):
    edges = {"EXPOSES": ["e_tcp80"]} if with_services else {}
    return {"id": "e_host", "kind": "host", "display": "host:10.0.0.1", "edges": edges}


def _param(name="id", reflected=False, location="query"):
    return {"id": f"e_p_{name}", "kind": "http.param", "display": f"http.param:{name}",
            "attrs": {"reflected": reflected, "location": location}}


def _rsa():
    return {"id": "e_rsa", "kind": "crypto.artifact", "display": "crypto.artifact:c1",
            "attrs": {"n": "0x123", "e": "3", "c": "0xabc"}}


# ---- scoring core ----
def test_score_zero_when_phase_gated_out():
    a = CandidateAction("dir_bruteforce", "web", "e1", "d", {}, "r", "why",
                        phase_gate=("ENUMERATE",))
    assert a.score(0.9, "RECON") == 0.0        # wrong phase
    assert a.score(0.9, "ENUMERATE") > 0.0


def test_score_rises_with_category_confidence():
    a = CandidateAction("web_attack", "web", "e1", "d", {}, "r", "why",
                        phase_gate=("EXPLOIT",), yield_=0.7, priority=0.6)
    lo = a.score(0.3, "EXPLOIT")
    hi = a.score(0.9, "EXPLOIT")
    assert hi > lo


def test_novelty_decays_score():
    a = CandidateAction("web_attack", "web", "e1", "d", {}, "r", "why",
                        phase_gate=("EXPLOIT",))
    assert a.score(0.8, "EXPLOIT", novelty=0.2) < a.score(0.8, "EXPLOIT", novelty=1.0)


def test_dedup_key_uses_param_class():
    a = CandidateAction("web_attack", "web", "e1", "d", {"class": "sqli"}, "r", "why",
                        phase_gate=("EXPLOIT",))
    assert a.dedup_key() == ("web_attack", "e1", "sqli")


# ---- engine firing ----
def test_recon_scans_only_hosts_without_services():
    eng = PlaybookEngine()
    bare = World.from_entity_dicts([_host(with_services=False)])
    scanned = World.from_entity_dicts([_host(with_services=True)])
    assert any(a.capability == "port_scan" for a in
               eng.propose(bare, "RECON").actions)
    assert not any(a.capability == "port_scan" for a in
                   eng.propose(scanned, "RECON").actions)


def test_http_service_triggers_recon_and_enum_by_phase():
    eng = PlaybookEngine()
    w = World.from_entity_dicts([_svc_http()])
    recon = {a.rule_id for a in eng.propose(w, "RECON").actions}
    enum = {a.rule_id for a in eng.propose(w, "ENUMERATE").actions}
    assert "recon.http_probe" in recon
    assert {"web.git_exposure", "web.dir_bruteforce", "web.nuclei_sweep"} <= enum
    # enum rules must NOT leak into RECON
    assert "web.dir_bruteforce" not in recon


def test_param_produces_injection_probes():
    eng = PlaybookEngine()
    w = World.from_entity_dicts([_param(name="q", reflected=True)])
    probes = {a.params["class"] for a in eng.propose(w, "EXPLOIT").actions
              if a.capability == "web_attack"}
    assert {"sqli", "ssti", "xss", "lfi", "ssrf"} <= probes


def test_rsa_artifact_fires_crypto_rules():
    eng = PlaybookEngine()
    w = World.from_entity_dicts([_rsa()])
    rules = {a.rule_id for a in eng.propose(w, "EXPLOIT",
                                            category_conf={"crypto": 0.9}).actions}
    assert "crypto.rsa_factordb" in rules
    assert "crypto.rsa_small_e" in rules      # e == 3


def test_candidates_bind_to_scope_entity():
    eng = PlaybookEngine()
    w = World.from_entity_dicts([_svc_http()])
    for a in eng.propose(w, "ENUMERATE").actions:
        assert a.target_id == "e_http80"       # every action is bound to an entity


def test_dead_end_keys_dropped_and_tried_decayed():
    eng = PlaybookEngine()
    w = World.from_entity_dicts([_svc_http()])
    base = eng.propose(w, "ENUMERATE")
    victim = base.actions[0]
    key = victim.dedup_key()
    # dead-ended -> gone
    after_dead = eng.propose(w, "ENUMERATE", dead_end_keys={key})
    assert key not in {a.dedup_key() for a in after_dead.actions}
    assert after_dead.dropped_dead_end >= 1
    # tried -> present but lower score
    after_tried = eng.propose(w, "ENUMERATE", tried_keys={key})
    p_before = next(p for p in base.proposals if p.action.dedup_key() == key)
    p_after = next(p for p in after_tried.proposals if p.action.dedup_key() == key)
    assert p_after.score < p_before.score


def test_quota_caps_per_kind():
    eng = PlaybookEngine()
    many = World.from_entity_dicts([_svc_http(8000 + i) for i in range(60)])
    ps = eng.propose(many, "RECON", quota_per_kind=10)
    # only 10 service.http entities contribute (recon.http_probe each)
    assert sum(1 for a in ps.actions if a.rule_id == "recon.http_probe") <= 10
    assert ps.dropped_quota > 0


def test_proposals_sorted_and_deterministic():
    eng = PlaybookEngine()
    w = World.from_entity_dicts([_svc_http(), _param(name="id"), _rsa()])
    a = eng.propose(w, "EXPLOIT", category_conf={"web": 0.8, "crypto": 0.7})
    b = eng.propose(w, "EXPLOIT", category_conf={"web": 0.8, "crypto": 0.7})
    scores = [p.score for p in a.proposals]
    assert scores == sorted(scores, reverse=True)
    assert [p.action.rule_id for p in a.proposals] == \
           [p.action.rule_id for p in b.proposals]


# ---- integration: fire over a real rebuilt graph ----
def test_over_real_graph_db():
    from lotusmcp.kernel.case import Case
    from lotusmcp.kernel.events import EventDraft

    with tempfile.TemporaryDirectory() as d:
        case = Case.create(d, "pg", category="web", flag_format=r"flag\{[^}]+\}")
        H = "10.10.11.53"
        case.append(EventDraft("entity.asserted", {"kind": "executor", "name": "nmap@2"},
                               {"kind": "host", "natural_key": {"addr": H}}))
        nk = {"host": H, "proto": "tcp", "port": 80}
        case.append(EventDraft("entity.asserted", {"kind": "executor", "name": "httpx@1"},
                               {"kind": "service.http", "natural_key": nk}))
        graph_db = case.rebuild()["graph_db"]

        world = World.from_graph_db(graph_db)
        assert world.entities("service.http"), "projector produced an http service"
        ps = PlaybookEngine().propose(world, "ENUMERATE", category_conf={"web": 0.8})
        caps = {a.capability for a in ps.actions}
        assert {"dir_bruteforce", "http_probe", "vuln_scan"} & caps


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
