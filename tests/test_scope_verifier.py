"""Scope/Grant verifier: signature-gated loading, in-scope checks, and the
monotonic 'agent may only NARROW' rule.

    PYTHONPATH=. PYTHONIOENCODING=utf-8 python tests/test_scope_verifier.py
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from lotusmcp.control_plane.keyring import SigningKey, sign_manifest
from lotusmcp.engine.scope import Scope, ScopeError, ScopeVerifier

OP = SigningKey.generate()
SCOPE = {"hosts": ["10.10.11.0/24", "*.target.htb"], "ports": [80, 443, "8000-8100"],
         "auto_cap": 2}


def _verifier():
    return ScopeVerifier(trusted_operator_keys={OP.public_hex})


def test_load_requires_trusted_signature():
    v = _verifier()
    m = sign_manifest(OP, "scope", "c1", SCOPE)
    scope = v.load_scope(m)
    assert isinstance(scope, Scope)
    # a scope signed by an untrusted key is refused
    rogue = SigningKey.generate()
    bad = sign_manifest(rogue, "scope", "c1", SCOPE)
    try:
        v.load_scope(bad)
    except ScopeError:
        pass
    else:
        raise AssertionError("untrusted scope must be refused")


def test_wrong_manifest_type_refused():
    v = _verifier()
    grant = sign_manifest(OP, "egress_grant", "c1", {"host": "cdn.example.com", "port": 443})
    try:
        v.load_scope(grant)         # a grant is not a scope
    except ScopeError:
        return
    raise AssertionError("wrong manifest type must be refused")


def test_in_scope_cidr_wildcard_and_ports():
    scope = _verifier().load_scope(sign_manifest(OP, "scope", "c1", SCOPE))
    assert scope.in_scope("10.10.11.53", 80)
    assert scope.in_scope("10.10.11.1", 443)
    assert scope.in_scope("app.target.htb", 8050)      # wildcard + port range
    assert not scope.in_scope("10.10.12.5", 80)        # host out of CIDR
    assert not scope.in_scope("10.10.11.53", 22)       # port not allowed
    assert not scope.in_scope("evil.com", 80)          # host not matched
    assert not scope.in_scope("target.htb", 80)        # bare apex != *.target.htb


def test_narrowing_allowed_widening_rejected():
    v = _verifier()
    current = v.load_scope(sign_manifest(OP, "scope", "c1", SCOPE))
    narrower = Scope.from_payload({"hosts": ["10.10.11.53/32"], "ports": [80],
                                   "auto_cap": 1})
    assert v.accept_narrowing(current, narrower) is narrower

    for bad in (
        {"hosts": ["10.10.0.0/16"], "ports": [80], "auto_cap": 1},   # wider CIDR
        {"hosts": ["10.10.11.53/32"], "ports": [22], "auto_cap": 1}, # new port
        {"hosts": ["10.10.11.53/32"], "ports": [80], "auto_cap": 3}, # raises cap
        {"hosts": ["0.0.0.0/0"], "ports": [80], "auto_cap": 1},      # everything
    ):
        try:
            v.accept_narrowing(current, Scope.from_payload(bad))
        except ScopeError:
            continue
        raise AssertionError(f"widening must be rejected: {bad}")


def test_wildcard_subhost_narrowing():
    v = _verifier()
    current = v.load_scope(sign_manifest(OP, "scope", "c1", SCOPE))
    ok = Scope.from_payload({"hosts": ["api.target.htb"], "ports": [443]})
    assert v.accept_narrowing(current, ok) is ok
    # a name NOT under the wildcard is a widen
    try:
        v.accept_narrowing(current, Scope.from_payload({"hosts": ["api.other.htb"],
                                                        "ports": [443]}))
    except ScopeError:
        return
    raise AssertionError("host outside wildcard must be rejected")


def test_submit_allowlist_and_tier3():
    v = _verifier()
    sub = sign_manifest(OP, "submit_allowlist", "c1",
                        {"endpoints": ["https://ctf.io/submit"]})
    assert v.verify_submit_allowlist(sub) == ["https://ctf.io/submit"]
    assert v.tier3_enabled(sign_manifest(OP, "tier3", "c1", {"enabled": True}))
    assert not v.tier3_enabled(sign_manifest(OP, "tier3", "c1", {"enabled": False}))
    assert not v.tier3_enabled(None)
    # untrusted tier3 grant does not enable
    rogue = SigningKey.generate()
    assert not v.tier3_enabled(sign_manifest(rogue, "tier3", "c1", {"enabled": True}))


def test_malformed_scope_payloads():
    for bad in ({"hosts": [], "ports": [80]}, {"hosts": ["x"], "ports": []},
                {"hosts": ["10.0.0.0/8"], "ports": [99999]}):
        try:
            Scope.from_payload(bad)
        except ScopeError:
            continue
        raise AssertionError(f"malformed scope must raise: {bad}")


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
