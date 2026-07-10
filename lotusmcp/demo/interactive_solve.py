"""Phase-4 demo — the OODA loop solving a pwn challenge in Regime B, NO Kali/LLM.

Where `replay_solve` stops (EXPLOIT, "the only candidates are Regime-B"), this
picks up: on an EXPLOIT-phase pwn case the loop routes to a persistent
InteractiveSession. The (deterministic) author iterates an exploit script against
a ScriptedTube — a stand-in for the sandboxed pwntools script + real socket — and
when the winning payload lands the service leaks the flag. The loop folds the
redacted output, recognises the flag, and walks SOLVED_PENDING_SUBMIT -> (oracle)
FLAG_FOUND.

Every seam that needs Kali/network/model (real tube, gateway-backed author,
sandbox runner) is injected; swapping those three is the only change to go live.

    python -m lotusmcp.demo.interactive_solve
"""
from __future__ import annotations

import tempfile
from pathlib import Path

from lotusmcp.control_plane.keyring import SigningKey, sign_manifest
from lotusmcp.engine.loop import Loop
from lotusmcp.engine.scope import ScopeVerifier
from lotusmcp.kernel.case import Case
from lotusmcp.kernel.events import EventDraft
from lotusmcp.session import (
    DeterministicScriptAuthor,
    DeterministicScriptRunner,
    InteractiveSession,
    ScriptedTube,
)

HOST, PORT = "10.10.11.53", 1337
FLAG = "flag{f0rmat_str1ng_l3ak_1337}"
OP = SigningKey.generate()


class QuietExecutor:
    """The planner ACT path — idle here; Regime B owns every step."""

    def run(self, action, case):
        return [EventDraft("note.added", {"kind": "system", "name": "x"}, {"text": "-"})]


def _win_tube() -> ScriptedTube:
    def responder(sent, _t):
        # the format-string payload leaks the flag; anything else is rejected
        return f"stack leak: {FLAG}\n" if sent.strip() == "%7$s" else "invalid input\n> "
    return ScriptedTube(responder, greeting="=== remote pwnme service ===\n> ")


def _provider(case, sid, entity, goal, flag, budget, scope, phase):
    # The author "discovers" the working payload on its 3rd attempt.
    strategies = [["AAAA"], ["%p %p %p"], ["%7$s"]]
    return InteractiveSession(
        case, sid, entity, goal, _win_tube(),
        DeterministicScriptAuthor(strategies, goal_note="format-string leak"),
        DeterministicScriptRunner(), flag, budget, scope=scope, phase=phase)


def main() -> None:
    base = Path(tempfile.mkdtemp(prefix="lotus_regimeb_demo_"))
    case = Case.create(base, "pwnme", title="format-string pwn", category="pwn",
                       flag_format=r"flag\{[^}]+\}", platform="HackTheBox")
    case.append(EventDraft("entity.asserted", {"kind": "executor", "name": "seed"},
                           {"kind": "service.tcp",
                            "natural_key": {"host": HOST, "proto": "tcp", "port": PORT}}))
    case.set_meta(phase="EXPLOIT")            # resume straight into exploitation

    scope = ScopeVerifier({OP.public_hex}).load_scope(
        sign_manifest(OP, "scope", case.case_id,
                      {"hosts": [f"{HOST}/32"], "ports": [PORT], "auto_cap": 2}))

    loop = Loop(case, QuietExecutor(), scope=scope, session_provider=_provider,
                submit_oracle=lambda v: v == FLAG)

    print("=" * 74)
    print(f"case {case.case_id}   target {HOST}:{PORT}   category=pwn   (Regime B)")
    print("=" * 74)
    prev = None
    for step in range(1, 12):
        r = loop.step()
        if r.phase != prev:
            print(f"\n── phase: {r.phase}")
            prev = r.phase
        print(f"  [{step:02d}] {'✓' if r.progressed else '·'} {r.reason}")
        if r.halted:
            print(f"\n── HALT: {r.phase} — {r.reason}")
            break

    print("\n" + "=" * 74)
    revised = [e for e in case.store.iter_events() if e["type"] == "script.revised"]
    runs = [e for e in case.store.iter_events() if e["type"] == "script.run"]
    print(f"session revisions: {len(revised)}   runs: {len(runs)}")
    for e in runs:
        p = e["payload"]
        got = "FLAG!" if FLAG in p["output"] else "…"
        print(f"  rev {p['rev']}: {p['output'].strip().splitlines()[-1][:48]}  {got}")
    ws = case.dir / "sessions"
    sids = [p.name for p in ws.iterdir()] if ws.exists() else []
    print(f"workspace: sessions/{sids}   (scripts + redacted transcript on disk)")
    print(f"flag: {loop.flag.policy.verified.value if loop.flag.policy.verified else None}")
    print(f"events: {case.store.tip + 1}   chain intact: {case.store.verify_chain() == -1}")
    print("=" * 74)


if __name__ == "__main__":
    main()
