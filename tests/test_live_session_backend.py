"""Host-native live session backend tests.

These tests avoid opening sockets so they stay runnable under the default Codex
network sandbox. The runner still executes this machine's python3.

    PYTHONPATH=. PYTHONIOENCODING=utf-8 python tests/test_live_session_backend.py
"""
from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from lotusmcp.engine.budget import BudgetLedger  # noqa: E402
from lotusmcp.engine.scope import Scope  # noqa: E402
from lotusmcp.flag.facade import FlagEngine  # noqa: E402
from lotusmcp.kernel.case import Case  # noqa: E402
from lotusmcp.session.authoring import Script  # noqa: E402
from lotusmcp.session.live import HostPythonScriptRunner, TCPTube, host_session_factory  # noqa: E402


def test_tcp_tube_is_lazy_and_closes_cleanly():
    tube = TCPTube("127.0.0.1", 31337)
    assert tube.host == "127.0.0.1"
    assert tube.port == 31337
    assert tube.closed is False
    tube.close()
    assert tube.closed is True


def test_host_python_runner_gets_target_env_and_captures_output():
    runner = HostPythonScriptRunner(timeout=5)
    tube = TCPTube("127.0.0.1", 31337)
    script = Script(
        rev=0,
        target_id="svc1",
        text=(
            "import os\n"
            "print(os.environ['LOTUS_TARGET_HOST'])\n"
            "print(os.environ['LOTUS_TARGET_PORT'])\n"
        ),
    )
    out = runner.run(script, tube)
    assert out.ok
    assert "127.0.0.1" in out.stdout and "31337" in out.stdout


def test_host_session_factory_folds_flag_from_client_script():
    flag = "flag{host_session_backend_1337}"
    with tempfile.TemporaryDirectory() as d:
        case = Case.create(d, "live", title="live", category="pwn",
                           flag_format=r"flag\{[^}]+\}")
        entity = {"id": "svc1", "display": "127.0.0.1:31337",
                  "host": "127.0.0.1", "port": 31337}
        scope = Scope.from_payload({"hosts": ["127.0.0.1/32"], "ports": [31337]})
        sess = host_session_factory(
            case=case, sid="s1", entity=entity, goal="flag",
            flag=FlagEngine(case), budget=BudgetLedger(), scope=scope,
            phase="EXPLOIT",
        )
        assert sess.open()
        script = f"print({flag!r})\n"
        res = sess.edit_run([], text=script)
        assert res.flag_local_ok, res
        assert sess.closed


if __name__ == "__main__":
    import traceback

    fns = [v for k, v in sorted(globals().items())
           if k.startswith("test_") and callable(v)]
    failed = 0
    for fn in fns:
        try:
            fn()
            print(f"  ok  {fn.__name__}")
        except Exception:  # noqa: BLE001
            failed += 1
            print(f"FAIL  {fn.__name__}")
            traceback.print_exc()
    print(f"\n{len(fns) - failed}/{len(fns)} passed")
    sys.exit(1 if failed else 0)
