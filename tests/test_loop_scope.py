"""The verified-scope choke wired into the OODA loop (§1, §2).

A signed, operator-authored scope loaded through the verify-only `ScopeVerifier`
becomes the loop's per-action choke: any action bound to an out-of-scope
host:port is refused *before* the Executor is ever touched, logged as a
`note.added` (kind=scope_refused), and dead-ended so it is never re-proposed.
An in-scope target runs normally, and a verified scope is itself what makes the
`scope_verified` phase signal true.

    PYTHONPATH=. PYTHONIOENCODING=utf-8 python tests/test_loop_scope.py
"""
from __future__ import annotations

import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from lotusmcp.control_plane.keyring import SigningKey, sign_manifest  # noqa: E402
from lotusmcp.engine.candidate import CandidateAction  # noqa: E402
from lotusmcp.engine.loop import Loop  # noqa: E402
from lotusmcp.engine.scope import ScopeError, ScopeVerifier  # noqa: E402
from lotusmcp.kernel.case import Case  # noqa: E402
from lotusmcp.kernel.events import EventDraft  # noqa: E402
from lotusmcp.playbooks.model import World  # noqa: E402

FMT = r"flag\{[^}]+\}"
OP = SigningKey.generate()
SCOPE_PAYLOAD = {"hosts": ["10.10.11.0/24"], "ports": [80, 443], "auto_cap": 2}


def _scope():
    m = sign_manifest(OP, "scope", "c1", SCOPE_PAYLOAD)
    return ScopeVerifier(trusted_operator_keys={OP.public_hex}).load_scope(m)


class TrackingExecutor:
    """Records every action it is actually asked to run (by capability + host)."""

    def __init__(self):
        self.calls = []

    def run(self, action, case):
        self.calls.append((action.capability, action.target_display))
        return [EventDraft("note.added", {"kind": "system", "name": action.capability},
                           {"text": f"{action.capability} found nothing"})]


def _case(tmp, host):
    case = Case.create(tmp, "scope", title="scope choke", category="web",
                       flag_format=FMT, platform="HackTheBox")
    case.append(EventDraft("entity.asserted", {"kind": "executor", "name": "nmap@2"},
                           {"kind": "host", "natural_key": {"addr": host}}))
    nk = {"host": host, "proto": "tcp", "port": 80}
    case.append(EventDraft("entity.asserted", {"kind": "executor", "name": "httpx@1"},
                           {"kind": "service.http", "natural_key": nk}))
    return case


def _scope_notes(case):
    return [e for e in case.store.iter_events()
            if e["type"] == "note.added"
            and e.get("payload", {}).get("kind") == "scope_refused"]


def test_in_scope_target_runs():
    with tempfile.TemporaryDirectory() as d:
        case = _case(d, "10.10.11.53")            # inside 10.10.11.0/24
        ex = TrackingExecutor()
        loop = Loop(case, ex, scope=_scope())
        loop.run(max_steps=15)
        assert ex.calls, "an in-scope target must be executed"
        assert not _scope_notes(case), "no scope refusal for an in-scope target"
        # the log stays intact through the whole run
        assert case.store.verify_chain() == -1


def test_out_of_scope_target_refused():
    with tempfile.TemporaryDirectory() as d:
        case = _case(d, "9.9.9.9")                # outside the CIDR
        ex = TrackingExecutor()
        loop = Loop(case, ex, scope=_scope())
        loop.run(max_steps=15)
        assert not ex.calls, "the Executor must never see an out-of-scope target"
        notes = _scope_notes(case)
        assert notes, "an out-of-scope action must be logged as scope_refused"
        assert loop.dead_end, "an out-of-scope target must be dead-ended"
        assert loop.dead_end <= loop.tried
        assert case.store.verify_chain() == -1


def test_scope_sets_verified_signal():
    with tempfile.TemporaryDirectory() as d:
        # even if the legacy bool says False, a loaded verified scope wins
        loop = Loop(_case(d, "10.10.11.53"), TrackingExecutor(),
                    scope=_scope(), scope_verified=False)
        assert loop.scope_verified is True


def test_no_scope_leaves_choke_inactive():
    # legacy path: no scope -> the bool drives the signal and nothing is gated
    with tempfile.TemporaryDirectory() as d:
        case = _case(d, "9.9.9.9")
        ex = TrackingExecutor()
        loop = Loop(case, ex)                      # no scope
        loop.run(max_steps=15)
        assert ex.calls, "without a scope the choke is inactive"
        assert not _scope_notes(case)


def test_from_scope_manifest_verifies_signature():
    with tempfile.TemporaryDirectory() as d:
        good = sign_manifest(OP, "scope", "c1", SCOPE_PAYLOAD)
        loop = Loop.from_scope_manifest(_case(d, "10.10.11.53"), TrackingExecutor(),
                                        good, {OP.public_hex})
        assert loop.scope is not None and loop.scope_verified is True
        # a manifest signed by an untrusted key builds no loop
        rogue = SigningKey.generate()
        bad = sign_manifest(rogue, "scope", "c1", SCOPE_PAYLOAD)
        try:
            Loop.from_scope_manifest(_case(d, "10.10.11.53"), TrackingExecutor(),
                                     bad, {OP.public_hex})
        except ScopeError:
            pass
        else:
            raise AssertionError("untrusted scope manifest must be refused")


def test_non_network_target_not_gated():
    # a target with no network address (a crypto artifact) is never scope-gated
    with tempfile.TemporaryDirectory() as d:
        loop = Loop(_case(d, "10.10.11.53"), TrackingExecutor(), scope=_scope())
        world = World.from_entity_dicts([
            {"id": "A1", "kind": "artifact.ciphertext", "display": "cipher.bin",
             "nk": {"sha256": "deadbeef"}},
        ])
        action = CandidateAction(
            capability="crypto_analyze", category="crypto", target_id="A1",
            target_display="cipher.bin", params={}, rule_id="r", rationale="x",
            phase_gate=("EXPLOIT",),
        )
        assert loop._scope_reason(action, world) is None


def test_host_level_scan_gated_by_host_only():
    with tempfile.TemporaryDirectory() as d:
        loop = Loop(_case(d, "10.10.11.53"), TrackingExecutor(), scope=_scope())
        world = World.from_entity_dicts([
            {"id": "H1", "kind": "host", "display": "10.10.11.53",
             "nk": {"addr": "10.10.11.53"}},
            {"id": "H2", "kind": "host", "display": "9.9.9.9",
             "nk": {"addr": "9.9.9.9"}},
        ])

        def act(tid, disp):
            return CandidateAction(
                capability="port_scan", category="recon", target_id=tid,
                target_display=disp, params={"probe": "quick"}, rule_id="r",
                rationale="x", phase_gate=("RECON",))

        # host-level action (no port yet) is allowed iff the host matches a rule
        assert loop._scope_reason(act("H1", "10.10.11.53"), world) is None
        assert loop._scope_reason(act("H2", "9.9.9.9"), world) is not None


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
