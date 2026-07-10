"""SessionService — the fail-closed policy behind the session_* MCP tools,
exercised with no MCP SDK, no sandbox, no network (Phase 4).

    PYTHONPATH=. PYTHONIOENCODING=utf-8 python tests/test_session_service.py
"""
from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from lotusmcp.control_plane.keyring import SigningKey, sign_manifest  # noqa: E402
from lotusmcp.kernel.case import Case  # noqa: E402
from lotusmcp.kernel.events import EventDraft  # noqa: E402
from lotusmcp.session import (  # noqa: E402
    DeterministicScriptAuthor,
    InteractiveSession,
    RunOutput,
    ScriptedTube,
)
from lotusmcp.session.service import SessionService  # noqa: E402

FMT = r"flag\{[^}]+\}"
FLAG = "flag{mcp_s3ss10n_pwn_1337}"
HOST, PORT = "10.10.11.53", 1337
OP = SigningKey.generate()


class TextRunner:
    """A stand-in sandbox runner that executes the *client-supplied* script text
    by driving it into the tube (models the real runner; the offline
    DeterministicScriptRunner uses `sends` instead)."""

    def run(self, script, tube):
        chunks = []
        banner = tube.recv()
        if banner:
            chunks.append(banner)
        tube.send(script.text.strip())
        chunks.append(tube.recv())
        return RunOutput(rev=script.rev, stdout="\n".join(chunks), ok=True,
                         transcript=tuple(tube.transcript))


def _win_tube():
    def responder(sent, _t):
        return f"leak: {FLAG}\n" if sent.strip() == "%7$s" else "nope\n> "
    return ScriptedTube(responder, greeting="svc\n> ")


def _factory(*, case, sid, entity, goal, flag, budget, scope, phase):
    return InteractiveSession(
        case, sid, entity, goal, _win_tube(),
        DeterministicScriptAuthor([["noop"]]), TextRunner(),
        flag, budget, scope=scope, phase=phase)


def _make_case(tmp, cid="mcp", host=HOST, category="pwn", phase="EXPLOIT",
               signed=True, key=OP):
    case = Case.create(tmp, cid, title="pwn", category=category,
                       flag_format=FMT, platform="HackTheBox")
    case.append(EventDraft("entity.asserted", {"kind": "executor", "name": "seed"},
                           {"kind": "service.tcp",
                            "natural_key": {"host": host, "proto": "tcp", "port": PORT}}))
    case.set_meta(phase=phase)
    if signed:
        manifest = sign_manifest(key, "scope", cid,
                                 {"hosts": ["10.10.11.0/24"], "ports": [PORT],
                                  "auto_cap": 2})
        case.scope_path.write_text(json.dumps(manifest), encoding="utf-8")
    return case


def test_fail_closed_without_backend():
    with tempfile.TemporaryDirectory() as d:
        _make_case(d)
        svc = SessionService(d, trusted_keys=[OP.public_hex])   # no backend
        r = svc.edit_run("mcp", "%7$s")
        assert "error" in r and "sandbox" in r["error"]


def test_fail_closed_without_verified_scope():
    with tempfile.TemporaryDirectory() as d:
        _make_case(d, signed=False)                              # no scope.json
        svc = SessionService(d, trusted_keys=[OP.public_hex], backend_factory=_factory)
        r = svc.edit_run("mcp", "%7$s")
        assert "error" in r and "scope" in r["error"]


def test_fail_closed_on_bad_signature():
    with tempfile.TemporaryDirectory() as d:
        rogue = SigningKey.generate()
        _make_case(d, key=rogue)                                 # signed by untrusted key
        svc = SessionService(d, trusted_keys=[OP.public_hex], backend_factory=_factory)
        r = svc.edit_run("mcp", "%7$s")
        assert "error" in r and "scope" in r["error"]


def test_non_interactive_phase_refused():
    with tempfile.TemporaryDirectory() as d:
        _make_case(d, phase="RECON")
        svc = SessionService(d, trusted_keys=[OP.public_hex], backend_factory=_factory)
        r = svc.edit_run("mcp", "%7$s")
        assert "error" in r and "interactive regime" in r["error"]


def test_happy_path_opens_runs_and_captures_flag():
    with tempfile.TemporaryDirectory() as d:
        _make_case(d)
        svc = SessionService(d, trusted_keys=[OP.public_hex], backend_factory=_factory)
        r = svc.edit_run("mcp", "%7$s")             # no sid, no target -> auto-open
        assert "error" not in r, r
        assert r["flag_local_ok"] and r["sid"] == "s1"
        # the session is listed and the flag reached the case's flag engine
        listed = svc.list("mcp")
        assert listed and listed[0]["sid"] == "s1"


def test_resume_same_session_by_sid():
    with tempfile.TemporaryDirectory() as d:
        _make_case(d)
        svc = SessionService(d, trusted_keys=[OP.public_hex], backend_factory=_factory)
        first = svc.edit_run("mcp", "AAAA")          # wrong payload, opens s1
        assert "error" not in first and not first["flag_local_ok"]
        sid = first["sid"]
        second = svc.edit_run("mcp", "%7$s", sid=sid)   # patch + re-run same tube
        assert second["flag_local_ok"] and second["sid"] == sid


def test_close_and_missing_session_errors():
    with tempfile.TemporaryDirectory() as d:
        _make_case(d)
        svc = SessionService(d, trusted_keys=[OP.public_hex], backend_factory=_factory)
        svc.edit_run("mcp", "AAAA")                  # open s1 (no flag)
        closed = svc.close("mcp", "s1")
        assert closed["closed"]
        again = svc.edit_run("mcp", "%7$s", sid="s1")   # closed -> error
        assert "error" in again


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
