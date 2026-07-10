"""Phase-3 demo — the deterministic decision loop, NO Kali / NO LLM.

Builds a small web case (the seed_recon graph, plus a discovered query param),
runs triage -> playbook proposal -> EV+UCB selection for each phase, and prints
the ranked action LotusMCP *would* dispatch and why. This shows the Regime-A
brain end to end without touching a network or a model.

    python -m lotusmcp.demo.decide_loop
"""
from __future__ import annotations

import tempfile
from pathlib import Path

from lotusmcp.engine.selector import action_class, select
from lotusmcp.kernel.case import Case
from lotusmcp.kernel.events import EventDraft
from lotusmcp.playbooks.engine import PlaybookEngine
from lotusmcp.playbooks.model import World
from lotusmcp.triage.classify import classify

HOST = "10.10.11.53"


def _seed(case: Case) -> None:
    ev = case.append
    ev(EventDraft("entity.asserted", {"kind": "executor", "name": "nmap@2"},
                  {"kind": "host", "natural_key": {"addr": HOST}}))
    nk = {"host": HOST, "proto": "tcp", "port": 80}
    ev(EventDraft("entity.asserted", {"kind": "executor", "name": "httpx@1"},
                  {"kind": "service.http", "natural_key": nk}))
    end_nk = {"host": HOST, "scheme": "http", "vhost": HOST, "method": "GET", "path": "/search"}
    ev(EventDraft("entity.asserted", {"kind": "executor", "name": "ffuf@1"},
                  {"kind": "http.endpoint", "natural_key": end_nk}))
    # a reflected query param — the kind of thing that unlocks EXPLOIT rules
    end_id = case  # placeholder to compute endpoint id
    from lotusmcp.ontology.identity import entity_id
    eid = entity_id("http.endpoint", end_nk)
    ev(EventDraft("entity.asserted", {"kind": "executor", "name": "paramminer@1"},
                  {"kind": "http.param",
                   "natural_key": {"endpoint_id": eid, "location": "query", "name": "q"}}))
    ev(EventDraft("attribute.asserted", {"kind": "executor", "name": "paramminer@1"},
                  {"kind": "http.param",
                   "natural_key": {"endpoint_id": eid, "location": "query", "name": "q"},
                   "attr": "reflected", "value": True, "confidence": 0.9}))


def main() -> None:
    base = Path(tempfile.mkdtemp(prefix="lotus_decide_"))
    case = Case.create(base, "titan-decide", title="Titan Gateway search",
                       category="web", flag_format=r"HTB\{[0-9a-f]{32}\}",
                       platform="HackTheBox")
    _seed(case)
    graph_db = case.rebuild()["graph_db"]
    world = World.from_graph_db(graph_db)

    tri = classify(case.meta, world)
    print("=" * 72)
    print(f"case: {case.case_id}   entities: {len(world)}")
    print(f"triage top: {tri.top} ({tri.confidence:.2f})  "
          f"conf={ {k: v for k, v in tri.category_conf.items() if v > 0.05} }")
    print(f"why: {', '.join(tri.reasons)}")
    print("=" * 72)

    engine = PlaybookEngine()
    t = 0
    n_class: dict = {}
    for phase in ("RECON", "ENUMERATE", "EXPLOIT"):
        ps = engine.propose(world, phase, category_conf=tri.category_conf)
        sel = select(ps.proposals, phase, t=t, n_class=n_class)
        print(f"\n### {phase}  ({len(ps.actions)} candidates)")
        for s in sel.ranked[:4]:
            a = s.action
            mark = "→" if s is sel.chosen else " "
            print(f" {mark} S={s.s:<7} EV={s.ev:<6} UCB={s.ucb:<6} prior={s.prior:<6} "
                  f"{a.capability}({a.params.get('class') or a.params.get('probe') or ''}) "
                  f"on {a.target_display}")
        if sel.chosen:
            print(f"   ↳ {sel.chosen.action.rationale}")
            cls = action_class(sel.chosen.action)
            n_class[cls] = n_class.get(cls, 0) + 1
            t += 1


if __name__ == "__main__":
    main()
