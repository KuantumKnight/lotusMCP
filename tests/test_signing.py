"""Ed25519 signing + manifest verification: the control-plane/data-plane split.

Proves the server-side verifier accepts only a valid signature from a TRUSTED
operator key, rejects tampering and unknown signers, and that keys survive a PEM
round-trip. The signing half lives in control_plane (human-only); the verifying
half in kernel (server-safe).

    PYTHONPATH=. PYTHONIOENCODING=utf-8 python tests/test_signing.py
"""
from __future__ import annotations

import copy
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from lotusmcp.control_plane.keyring import SigningKey, sign_manifest
from lotusmcp.kernel.signing import VerifyKey, verify_manifest

SCOPE_PAYLOAD = {"hosts": ["10.10.11.0/24"], "ports": [80, 443], "auto_cap": 2}


def test_sign_verify_roundtrip():
    op = SigningKey.generate()
    m = sign_manifest(op, "scope", "case-1", SCOPE_PAYLOAD)
    assert verify_manifest(m, trusted_hex={op.public_hex})


def test_untrusted_signer_rejected():
    op = SigningKey.generate()
    rogue = SigningKey.generate()
    m = sign_manifest(rogue, "scope", "case-1", SCOPE_PAYLOAD)
    # the signature IS valid for the rogue key ...
    assert VerifyKey.from_hex(rogue.public_hex).verify(
        __import__("lotusmcp.kernel.signing", fromlist=["x"]).manifest_signing_bytes(m),
        m["sig"])
    # ... but the rogue is not a trusted operator, so the manifest is rejected
    assert not verify_manifest(m, trusted_hex={op.public_hex})


def test_payload_tamper_detected():
    op = SigningKey.generate()
    m = sign_manifest(op, "scope", "case-1", SCOPE_PAYLOAD)
    tampered = copy.deepcopy(m)
    tampered["payload"]["hosts"] = ["0.0.0.0/0"]     # widen scope after signing
    assert not verify_manifest(tampered, trusted_hex={op.public_hex})


def test_type_and_case_tamper_detected():
    op = SigningKey.generate()
    m = sign_manifest(op, "scope", "case-1", SCOPE_PAYLOAD)
    for field, val in (("type", "tier3"), ("case_id", "case-2"), ("alg", "rsa")):
        t = dict(m)
        t[field] = val
        assert not verify_manifest(t, trusted_hex={op.public_hex}), field


def test_missing_fields_rejected():
    op = SigningKey.generate()
    m = sign_manifest(op, "scope", "case-1", SCOPE_PAYLOAD)
    assert not verify_manifest({k: v for k, v in m.items() if k != "sig"},
                               trusted_hex={op.public_hex})
    assert not verify_manifest({}, trusted_hex={op.public_hex})


def test_pem_roundtrip_plain_and_encrypted():
    op = SigningKey.generate()
    pem = op.to_pem()
    op2 = SigningKey.from_pem(pem)
    assert op2.public_hex == op.public_hex
    enc = op.to_pem(password=b"hunter2")
    op3 = SigningKey.from_pem(enc, password=b"hunter2")
    assert op3.public_hex == op.public_hex
    # a signature from the reloaded key still verifies under the same pubkey
    m = sign_manifest(op3, "egress_grant", "c", {"host": "example.com", "port": 443})
    assert verify_manifest(m, trusted_hex={op.public_hex})


def test_unknown_manifest_type_rejected_at_signing():
    op = SigningKey.generate()
    try:
        sign_manifest(op, "delete_everything", "c", {})
    except ValueError:
        return
    raise AssertionError("unknown manifest type must be rejected at signing")


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
