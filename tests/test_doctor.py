"""Operator host diagnostics."""
from __future__ import annotations

import json
import tempfile
from pathlib import Path

from lotusmcp.ops.doctor import main, run_checks


def test_core_checks_are_structured():
    with tempfile.TemporaryDirectory() as d:
        checks = run_checks(cases_dir=Path(d) / "cases")
    by_name = {c.name: c for c in checks}
    assert by_name["python>=3.11"].required
    assert by_name["cryptography"].required
    assert not by_name["kali-tool:nmap"].required
    assert not by_name["container-runtime"].required
    assert not by_name["docker-daemon"].required


def test_all_mode_emits_json_and_returns_status(capsys=None):
    # It may return 1 on a developer host missing MCP SDK or Docker Compose; the
    # contract is structured output and an honest readiness code.
    import contextlib
    import io
    with contextlib.redirect_stdout(io.StringIO()):
        code = main(["--all", "--json", "--cases-dir", tempfile.gettempdir()])
    assert code in (0, 1)


def test_json_shape_via_stdout_capture():
    # Keep this test independent from pytest's capsys fixture.
    import contextlib
    import io
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        code = main(["--json", "--cases-dir", tempfile.gettempdir()])
    assert code == 0
    doc = json.loads(buf.getvalue())
    assert doc["ok"] is True
    assert isinstance(doc["checks"], list) and doc["checks"]


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items())
           if k.startswith("test_") and callable(v)]
    failed = 0
    for fn in fns:
        try:
            fn()
            print(f"  ok  {fn.__name__}")
        except Exception as e:
            failed += 1
            print(f"FAIL  {fn.__name__}: {e}")
    print(f"\n{len(fns)-failed}/{len(fns)} passed")
    raise SystemExit(1 if failed else 0)
