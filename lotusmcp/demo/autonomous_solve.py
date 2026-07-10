"""Phase-3 demo — a FULL autonomous solve, NO Kali / NO LLM.

A scripted executor stands in for Kali, emitting the events each tool would
produce. The real OODA loop drives it: triage -> playbooks -> EV+UCB select ->
phase transitions -> flag submit. Watch it walk TRIAGE -> RECON -> ENUMERATE ->
EXPLOIT -> POST_EXPLOIT -> SOLVED_PENDING_SUBMIT -> FLAG_FOUND and capture the
flag — every decision landing in the tamper-evident log.

    python -m lotusmcp.demo.autonomous_solve
"""
from __future__ import annotations

import tempfile
from pathlib import Path

from lotusmcp.engine.loop import Loop
from lotusmcp.kernel.case import Case
from lotusmcp.kernel.events import EventDraft

FMT = r"flag\{[^}]+\}"
FLAG = "flag{0od4_l00p_clos3d_the_case}"
HOST = "10.10.11.53"


class KaliSim:
    """Scripted stand-in for the sandboxed Executor."""

    def run(self, action, case):
        cap = action.params.get("probe") or action.params.get("class")
        actor = {"kind": "executor", "name": action.capability}
        tid = action.target_id
        if action.capability == "http_probe" and cap == "banner":
            return [EventDraft("attribute.asserted", actor,
                               {"entity_id": tid, "attr": "server", "value": "nginx",
                                "confidence": 0.9}),
                    EventDraft("attribute.asserted", actor,
                               {"entity_id": tid, "attr": "version", "value": "1.25.3",
                                "confidence": 0.9})]
        if action.capability == "http_probe" and cap == "git":
            nk = {"endpoint_id": tid, "location": "query", "name": "id"}
            return [EventDraft("finding.raised", actor,
                               {"id": "F-git", "type": "exposure", "severity": "high",
                                "confidence": 0.9, "subject": {"t": action.target_display},
                                "attrs": {"leak": ".git exposed -> source recovered"}}),
                    EventDraft("hypothesis.proposed", {"kind": "llm", "name": "oracle"},
                               {"hid": "H1", "status": "OPEN", "confidence": 0.6,
                                "statement": "source reveals raw SQL on ?id -> injectable"}),
                    EventDraft("entity.asserted", actor,
                               {"kind": "http.param", "natural_key": nk}),
                    EventDraft("attribute.asserted", actor,
                               {"kind": "http.param", "natural_key": nk,
                                "attr": "reflected", "value": True, "confidence": 0.8})]
        if action.capability == "web_attack" and cap == "sqli":
            return [EventDraft("finding.raised", actor,
                               {"id": "F-sqli", "type": "sqli_dump", "severity": "critical",
                                "confidence": 0.92, "subject": {"p": action.target_display},
                                "attrs": {"dumped": "users, secrets"}}),
                    EventDraft("note.added", {"kind": "llm", "name": "oracle"},
                               {"text": f"secrets table row: admin_flag = {FLAG}"})]
        return [EventDraft("note.added", {"kind": "system", "name": action.capability},
                           {"text": f"{action.capability} found nothing notable"})]


def main() -> None:
    base = Path(tempfile.mkdtemp(prefix="lotus_solve_"))
    case = Case.create(base, "titan-auto", title="Titan Gateway search portal",
                       category="web", flag_format=FMT, platform="HackTheBox")
    case.append(EventDraft("entity.asserted", {"kind": "executor", "name": "nmap@2"},
                           {"kind": "host", "natural_key": {"addr": HOST}}))
    case.append(EventDraft("entity.asserted", {"kind": "executor", "name": "httpx@1"},
                           {"kind": "service.http",
                            "natural_key": {"host": HOST, "proto": "tcp", "port": 80}}))

    loop = Loop(case, KaliSim(), submit_oracle=lambda v: v == FLAG)

    print("=" * 74)
    print(f"case {case.case_id}   target {HOST}   format {FMT}")
    print("=" * 74)
    step = 0
    prev_phase = None
    while step < 20:
        r = loop.step()
        step += 1
        if r.phase != prev_phase:
            print(f"\n── phase: {r.phase}")
            prev_phase = r.phase
        if r.action:
            cls = r.action.params.get("class") or r.action.params.get("probe") or ""
            flag = "✓" if r.progressed else "·"
            print(f"  [{step:02d}] {flag} {r.action.capability}({cls}) "
                  f"on {r.action.target_display}")
            print(f"        ↳ {r.reason}")
        if r.halted:
            print(f"\n── HALT: {r.phase} — {r.reason}")
            break

    print("\n" + "=" * 74)
    print(f"final phase : {loop.phase}")
    print(f"flag        : {loop.flag.policy.verified.value if loop.flag.policy.verified else '(none)'}")
    print(f"budget      : {loop.budget.snapshot()}")
    print(f"events      : {case.store.tip + 1}   chain intact: {case.store.verify_chain() == -1}")
    print("=" * 74)


if __name__ == "__main__":
    main()
