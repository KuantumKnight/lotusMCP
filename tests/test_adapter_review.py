"""Signed adapter-review workflow.

    PYTHONPATH=. PYTHONIOENCODING=utf-8 python tests/test_adapter_review.py
"""
from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from lotusmcp.control_plane.cli import main as op_main  # noqa: E402
from lotusmcp.control_plane.keyring import SigningKey, sign_manifest  # noqa: E402
from lotusmcp.playbooks.adapter_review import (  # noqa: E402
    AdapterReviewError,
    lint_adapter_review_payload,
    verify_adapter_review,
)

OP = SigningKey.generate()


def _payload():
    return {
        "capability": "vhost_probe",
        "category": "web",
        "tool": "ffuf",
        "argv_schema": {"shell": False, "required": ["host", "wordlist"]},
        "egress": {"hosts": ["10.10.11.0/24"], "ports": [80, 443], "auto_cap": 1},
        "reviewer": "operator",
        "rationale": "approved vhost fuzzing adapter",
    }


def test_valid_review_verifies_to_typed_record():
    m = sign_manifest(OP, "adapter_review", "c1", _payload())
    r = verify_adapter_review(m, [OP.public_hex])
    assert r.capability == "vhost_probe"
    assert r.tool == "ffuf"
    assert r.egress.in_scope("10.10.11.53", 80)


def test_untrusted_or_wrong_type_refused():
    rogue = SigningKey.generate()
    bad = sign_manifest(rogue, "adapter_review", "c1", _payload())
    try:
        verify_adapter_review(bad, [OP.public_hex])
    except AdapterReviewError:
        pass
    else:
        raise AssertionError("untrusted adapter review must fail")
    wrong = sign_manifest(OP, "scope", "c1",
                          {"hosts": ["10.0.0.0/24"], "ports": [80]})
    try:
        verify_adapter_review(wrong, [OP.public_hex])
    except AdapterReviewError:
        pass
    else:
        raise AssertionError("wrong manifest type must fail")


def test_payload_lint_rejects_unsafe_shapes():
    bad = _payload()
    bad["capability"] = "Bad-Cap"
    assert lint_adapter_review_payload(bad)
    bad = _payload()
    bad["argv_schema"]["shell"] = True
    assert "shell" in lint_adapter_review_payload(bad)[0]
    bad = _payload()
    bad["egress"] = {"hosts": [], "ports": []}
    assert "bad egress" in lint_adapter_review_payload(bad)[0]


def test_operator_cli_sign_adapter_roundtrip():
    with tempfile.TemporaryDirectory() as d:
        key = Path(d) / "op.pem"
        payload = Path(d) / "payload.json"
        out = Path(d) / "adapter.json"
        key.write_bytes(OP.to_pem())
        payload.write_text(json.dumps(_payload()), encoding="utf-8")
        assert op_main(["sign-adapter", "--key", str(key), "--case", "c1",
                        "--payload", str(payload), "--out", str(out)]) == 0
        manifest = json.loads(out.read_text(encoding="utf-8"))
        assert verify_adapter_review(manifest, [OP.public_hex]).capability == "vhost_probe"


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
