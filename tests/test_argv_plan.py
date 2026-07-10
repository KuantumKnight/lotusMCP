"""Bridge tests: resolve a decided action's target from a World and build argv,
including the real graph.db round-trip that carries the natural key.

    PYTHONPATH=. PYTHONIOENCODING=utf-8 python tests/test_argv_plan.py
"""
from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from lotusmcp.engine.candidate import CandidateAction
from lotusmcp.executor.argv import ArgvRejected
from lotusmcp.executor.plan import plan_action
from lotusmcp.kernel.case import Case
from lotusmcp.kernel.events import EventDraft
from lotusmcp.ontology.identity import entity_id
from lotusmcp.playbooks.model import World

HOST = "10.10.11.53"


def _action(capability, params, target_id):
    return CandidateAction(
        capability=capability, category="recon", target_id=target_id,
        target_display="t", params=params, rule_id="r", rationale="",
        phase_gate=("RECON",),
    )


def test_plan_resolves_nk_from_dicts():
    hid = entity_id("host", {"addr": HOST})
    world = World.from_entity_dicts([
        {"id": hid, "kind": "host", "nk": {"addr": HOST}},
    ])
    plans = plan_action(_action("port_scan", {"probe": "top1000"}, hid), world)
    assert plans[0].argv[-1] == HOST, plans[0].argv


def test_plan_service_http_target():
    nk = {"host": HOST, "proto": "tcp", "port": 80}
    sid = entity_id("service.http", nk)
    world = World.from_entity_dicts([{"id": sid, "kind": "service.http", "nk": nk}])
    plans = plan_action(_action("http_probe", {"paths": ["/", "/robots.txt"]}, sid), world)
    assert len(plans) == 2
    assert plans[0].argv[-1] == f"http://{HOST}:80/"


def test_missing_entity_rejected():
    world = World.from_entity_dicts([])
    try:
        plan_action(_action("port_scan", {"probe": "top1000"}, "e_ghost"), world)
    except ArgvRejected:
        return
    raise AssertionError("missing target entity must be rejected")


def test_nk_survives_real_graph_db_roundtrip():
    """entity.natural_key -> World.Entity.nk -> validated argv, through the
    actual projector/SQLite path (not synthetic dicts)."""
    base = Path(tempfile.mkdtemp(prefix="lotus_argv_"))
    case = Case.create(base, "argv-nk", title="t", category="web", flag_format=r"f\{.*\}")
    case.append(EventDraft("entity.asserted", {"kind": "executor", "name": "nmap@1"},
                           {"kind": "service.http",
                            "natural_key": {"host": HOST, "proto": "tcp", "port": 8080}}))
    world = World.from_graph_db(case.rebuild()["graph_db"])
    svc = world.entities("service.http")
    assert len(svc) == 1
    assert svc[0].nk == {"host": HOST, "proto": "tcp", "port": 8080}, svc[0].nk
    plans = plan_action(_action("dir_bruteforce",
                                {"wordlist": "common", "filter": "auto"}, svc[0].id), world)
    assert plans[0].argv[4] == f"http://{HOST}:8080/FUZZ", plans[0].argv


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
