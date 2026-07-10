"""Phase-1 demo — the OODA loop driven through the REAL adapter boundary, NO Kali.

Unlike `autonomous_solve` (which hand-scripts each tool's events), this drives
the loop with the `ReplayExecutor`: every step goes decided-action -> plan_action
-> validated argv -> fixture stdout -> parse_* -> events. The graph the brain
reasons over is built entirely by the real typed-argv + output-adapter code.

Watch it walk TRIAGE -> RECON -> ENUMERATE, fingerprint the service and raise a
.git exposure finding through the parsers, then transition to EXPLOIT where the
only candidates are Regime-B (no Phase-1 adapter) — the honest boundary of what
the deterministic recon/enum layer can do without interactive exploitation.

    python -m lotusmcp.demo.replay_solve
"""
from __future__ import annotations

import tempfile
from pathlib import Path

from lotusmcp.engine.loop import Loop
from lotusmcp.executor.replay import FixtureBackend, ReplayExecutor
from lotusmcp.kernel.case import Case
from lotusmcp.kernel.events import EventDraft
from lotusmcp.playbooks.model import World

HOST = "10.10.11.53"

NMAP_XML = f"""<?xml version="1.0"?><nmaprun><host>
 <address addr="{HOST}" addrtype="ipv4"/>
 <ports>
  <port protocol="tcp" portid="22"><state state="open"/>
   <service name="ssh" product="OpenSSH" version="8.9p1"/></port>
  <port protocol="tcp" portid="80"><state state="open"/>
   <service name="http" product="nginx" version="1.25.3"/></port>
 </ports></host></nmaprun>"""

FIXTURES = {
    "nmap": NMAP_XML,
    "curl /": "HTTP/1.1 200 OK\r\nServer: nginx/1.25.3\r\n\r\n<html>Titan</html>",
    "curl /robots.txt": "HTTP/1.1 404 Not Found\r\nServer: nginx/1.25.3\r\n\r\n",
    "curl /.git/HEAD": "HTTP/1.1 200 OK\r\nServer: nginx/1.25.3\r\n\r\nref: refs/heads/main",
    "curl /.git/config": "HTTP/1.1 200 OK\r\nServer: nginx/1.25.3\r\n\r\n[core]",
    "ffuf": '{"results":[{"input":{"FUZZ":"admin"},"status":401},'
            '{"input":{"FUZZ":"login"},"status":200}]}',
}


def main() -> None:
    base = Path(tempfile.mkdtemp(prefix="lotus_replay_demo_"))
    case = Case.create(base, "titan-replay", title="Titan Gateway", category="web",
                       flag_format=r"HTB\{[0-9a-f]{32}\}", platform="HackTheBox")
    case.append(EventDraft("entity.asserted", {"kind": "executor", "name": "seed"},
                           {"kind": "host", "natural_key": {"addr": HOST}}))
    case.append(EventDraft("entity.asserted", {"kind": "executor", "name": "seed"},
                           {"kind": "service.http",
                            "natural_key": {"host": HOST, "proto": "tcp", "port": 80}}))

    loop = Loop(case, ReplayExecutor(FixtureBackend(FIXTURES)))

    print("=" * 74)
    print(f"case {case.case_id}   target {HOST}   (loop driven through real adapters)")
    print("=" * 74)
    prev = None
    for step in range(1, 16):
        r = loop.step()
        if r.phase != prev:
            print(f"\n── phase: {r.phase}")
            prev = r.phase
        if r.action:
            mark = "✓" if r.progressed else "·"
            cls = r.action.params.get("class") or r.action.params.get("probe") or ""
            print(f"  [{step:02d}] {mark} {r.action.capability}({cls}) on {r.action.target_display}")
        elif not r.halted:
            print(f"  [{step:02d}] · {r.reason}")
        if r.halted:
            print(f"\n── HALT: {r.phase} — {r.reason}")
            break

    world = World.from_graph_db(case.rebuild()["graph_db"])
    print("\n" + "=" * 74)
    print("graph built ENTIRELY by argv + parse adapters:")
    for k in world.all_kinds():
        print(f"  {k:16} x{len(world.entities(k))}")
    for e in world.entities("service.http"):
        print(f"  service.http {e.display}: server={e.attr('server')} "
              f"version={e.attr('version')}")
    print(f"  findings: {[f.ftype + '/' + f.severity for f in world.findings]}")
    print(f"  events: {case.store.tip + 1}   chain intact: {case.store.verify_chain() == -1}")
    print("=" * 74)


if __name__ == "__main__":
    main()
