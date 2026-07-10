"""Operator CLI end-to-end: keygen -> sign -> verify, and anchor a real case.
Runs the CLI through main(argv) so the whole control-plane path is exercised.

    PYTHONPATH=. PYTHONIOENCODING=utf-8 python tests/test_operator_cli.py
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from lotusmcp.control_plane.cli import main
from lotusmcp.control_plane.keyring import SigningKey
from lotusmcp.kernel.case import Case
from lotusmcp.kernel.events import EventDraft


def _tmp():
    return Path(tempfile.mkdtemp(prefix="lotus_cli_"))


def _pub_of(pem_path: Path) -> str:
    return SigningKey.from_pem(pem_path.read_bytes()).public_hex


def test_keygen_sign_scope_verify_roundtrip():
    d = _tmp()
    key = d / "operator.pem"
    scope = d / "scope.json"
    assert main(["keygen", "--out", str(key)]) == 0
    pub = _pub_of(key)
    assert main(["sign-scope", "--key", str(key), "--case", "c1",
                 "--host", "10.10.11.0/24", "--port", "80", "--port", "8000-8100",
                 "--auto-cap", "2", "--out", str(scope)]) == 0
    manifest = json.loads(scope.read_text(encoding="utf-8"))
    assert manifest["type"] == "scope" and manifest["payload"]["auto_cap"] == 2
    assert main(["verify", "--manifest", str(scope), "--trusted", pub]) == 0
    # wrong trusted key -> INVALID -> exit 1
    other = SigningKey.generate().public_hex
    assert main(["verify", "--manifest", str(scope), "--trusted", other]) == 1


def test_encrypted_key_and_grant():
    d = _tmp()
    key = d / "op.pem"
    grant = d / "grant.json"
    assert main(["keygen", "--out", str(key), "--password", "s3cret"]) == 0
    pub = SigningKey.from_pem(key.read_bytes(), password=b"s3cret").public_hex
    assert main(["sign-grant", "--key", str(key), "--password", "s3cret",
                 "--case", "c1", "--host", "cdn.example.com", "--port", "443",
                 "--out", str(grant)]) == 0
    assert main(["verify", "--manifest", str(grant), "--trusted", pub]) == 0


def test_anchor_via_cli_over_real_case():
    d = _tmp()
    key = d / "op.pem"
    anchor = d / "anchor.json"
    main(["keygen", "--out", str(key)])
    pub = _pub_of(key)
    case = Case.create(d, "cli-case", title="t", category="web",
                       flag_format=r"flag\{[^}]+\}")
    case.append(EventDraft("note.added", {"kind": "system", "name": "x"},
                           {"text": "hello"}))
    assert main(["anchor", "--key", str(key), "--case-dir", str(case.dir),
                 "--out", str(anchor)]) == 0
    assert json.loads(anchor.read_text(encoding="utf-8"))["type"] == "audit_anchor"
    assert main(["verify", "--manifest", str(anchor), "--trusted", pub,
                 "--case-dir", str(case.dir)]) == 0
    # anchor verify without --case-dir is a usage error (exit 2)
    assert main(["verify", "--manifest", str(anchor), "--trusted", pub]) == 2


def test_tier3_toggle():
    d = _tmp()
    key = d / "op.pem"
    main(["keygen", "--out", str(key)])
    pub = _pub_of(key)
    on, off = d / "on.json", d / "off.json"
    assert main(["sign-tier3", "--key", str(key), "--case", "c", "--enabled",
                 "--out", str(on)]) == 0
    assert main(["sign-tier3", "--key", str(key), "--case", "c", "--disabled",
                 "--out", str(off)]) == 0
    assert json.loads(on.read_text())["payload"]["enabled"] is True
    assert json.loads(off.read_text())["payload"]["enabled"] is False
    assert main(["verify", "--manifest", str(on), "--trusted", pub]) == 0


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
