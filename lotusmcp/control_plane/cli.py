"""Operator CLI — the human control plane (§1 "Operator CLI").

The out-of-band tool an operator uses to mint the signed artifacts the agent may
never produce itself: the Ed25519 keypair, `scope.json`, egress grants, the
submit allowlist, tier-3 enablement, and audit anchors. It is deliberately
non-interactive (passwords come from flags/env, never a prompt) so it scripts
cleanly, and it is NOT importable by the server path.

    python -m lotusmcp.control_plane.cli keygen --out operator.pem
    python -m lotusmcp.control_plane.cli pubkey --key operator.pem
    python -m lotusmcp.control_plane.cli sign-scope --key operator.pem --case c1 \
        --host 10.10.11.0/24 --host '*.target.htb' --port 80 --port 443 \
        --port 8000-8100 --auto-cap 2 --out scope.json
    python -m lotusmcp.control_plane.cli sign-grant  --key k.pem --case c1 --host cdn.x --port 443 --out g.json
    python -m lotusmcp.control_plane.cli sign-submit --key k.pem --case c1 --endpoint https://ctf/submit --out s.json
    python -m lotusmcp.control_plane.cli sign-tier3  --key k.pem --case c1 --enabled --out t3.json
    python -m lotusmcp.control_plane.cli sign-adapter --key k.pem --case c1 --payload review.json --out adapter.json
    python -m lotusmcp.control_plane.cli anchor      --key k.pem --case-dir ./cases/c1 --out anchor.json
    python -m lotusmcp.control_plane.cli verify --manifest scope.json --trusted <hex> [--case-dir ./cases/c1]
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import List, Optional

from lotusmcp.control_plane.anchor import create_anchor
from lotusmcp.control_plane.keyring import SigningKey, sign_manifest
from lotusmcp.kernel.anchor import ANCHOR_TYPE, verify_anchor
from lotusmcp.kernel.log import EventStore
from lotusmcp.kernel.signing import verify_manifest


def _password(args) -> Optional[bytes]:
    pw = getattr(args, "password", None) or os.environ.get("LOTUS_KEY_PASSWORD")
    return pw.encode("utf-8") if pw else None


def _load_key(args) -> SigningKey:
    return SigningKey.from_pem(Path(args.key).read_bytes(), password=_password(args))


def _emit(manifest: dict, out: Optional[str]) -> None:
    text = json.dumps(manifest, indent=2, sort_keys=True)
    if out:
        Path(out).write_text(text + "\n", encoding="utf-8")
        print(f"wrote {manifest.get('type', 'manifest')} -> {out}")
    else:
        print(text)


def _cmd_keygen(args) -> int:
    key = SigningKey.generate()
    Path(args.out).write_bytes(key.to_pem(password=_password(args)))
    print(f"wrote private key -> {args.out}")
    print(f"public (trusted operator) key: {key.public_hex}")
    return 0


def _cmd_pubkey(args) -> int:
    print(_load_key(args).public_hex)
    return 0


def _cmd_sign_scope(args) -> int:
    payload = {"hosts": list(args.host), "ports": list(args.port),
               "auto_cap": args.auto_cap}
    _emit(sign_manifest(_load_key(args), "scope", args.case, payload), args.out)
    return 0


def _cmd_sign_grant(args) -> int:
    payload = {"host": args.host, "port": args.port}
    _emit(sign_manifest(_load_key(args), "egress_grant", args.case, payload), args.out)
    return 0


def _cmd_sign_submit(args) -> int:
    payload = {"endpoints": list(args.endpoint)}
    _emit(sign_manifest(_load_key(args), "submit_allowlist", args.case, payload), args.out)
    return 0


def _cmd_sign_tier3(args) -> int:
    payload = {"enabled": bool(args.enabled)}
    _emit(sign_manifest(_load_key(args), "tier3", args.case, payload), args.out)
    return 0


def _cmd_sign_adapter(args) -> int:
    from lotusmcp.playbooks.adapter_review import lint_adapter_review_payload
    payload = json.loads(Path(args.payload).read_text(encoding="utf-8"))
    findings = lint_adapter_review_payload(payload)
    if findings:
        for f in findings:
            print(f"adapter review payload invalid: {f}", file=sys.stderr)
        return 1
    _emit(sign_manifest(_load_key(args), "adapter_review", args.case, payload), args.out)
    return 0


def _cmd_anchor(args) -> int:
    store = EventStore(Path(args.case_dir))
    _emit(create_anchor(store, _load_key(args)), args.out)
    return 0


def _cmd_verify(args) -> int:
    manifest = json.loads(Path(args.manifest).read_text(encoding="utf-8"))
    trusted = set(args.trusted)
    if manifest.get("type") == ANCHOR_TYPE:
        if not args.case_dir:
            print("verify: audit_anchor requires --case-dir", file=sys.stderr)
            return 2
        ok = verify_anchor(manifest, EventStore(Path(args.case_dir)), trusted)
    else:
        ok = verify_manifest(manifest, trusted)
    print(f"{'VALID' if ok else 'INVALID'}: {manifest.get('type')} "
          f"(signer {manifest.get('signer', '?')[:16]}…)")
    return 0 if ok else 1


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="lotus-operator", description=__doc__.split("\n")[0])
    sub = p.add_subparsers(dest="cmd", required=True)

    def key_args(sp):
        sp.add_argument("--key", required=True, help="operator private-key PEM")
        sp.add_argument("--password", help="PEM password (or $LOTUS_KEY_PASSWORD)")

    g = sub.add_parser("keygen", help="generate an operator keypair")
    g.add_argument("--out", required=True)
    g.add_argument("--password")
    g.set_defaults(func=_cmd_keygen)

    pk = sub.add_parser("pubkey", help="print a key's public hex")
    key_args(pk)
    pk.set_defaults(func=_cmd_pubkey)

    ss = sub.add_parser("sign-scope", help="sign a scope.json")
    key_args(ss)
    ss.add_argument("--case", required=True)
    ss.add_argument("--host", action="append", required=True)
    ss.add_argument("--port", action="append", required=True)
    ss.add_argument("--auto-cap", type=int, default=1, dest="auto_cap")
    ss.add_argument("--out")
    ss.set_defaults(func=_cmd_sign_scope)

    sg = sub.add_parser("sign-grant", help="sign an egress grant")
    key_args(sg)
    sg.add_argument("--case", required=True)
    sg.add_argument("--host", required=True)
    sg.add_argument("--port", type=int, required=True)
    sg.add_argument("--out")
    sg.set_defaults(func=_cmd_sign_grant)

    sm = sub.add_parser("sign-submit", help="sign a submit allowlist")
    key_args(sm)
    sm.add_argument("--case", required=True)
    sm.add_argument("--endpoint", action="append", required=True)
    sm.add_argument("--out")
    sm.set_defaults(func=_cmd_sign_submit)

    t3 = sub.add_parser("sign-tier3", help="sign a tier-3 enablement")
    key_args(t3)
    t3.add_argument("--case", required=True)
    grp = t3.add_mutually_exclusive_group(required=True)
    grp.add_argument("--enabled", action="store_true")
    grp.add_argument("--disabled", dest="enabled", action="store_false")
    t3.add_argument("--out")
    t3.set_defaults(func=_cmd_sign_tier3)

    sa = sub.add_parser("sign-adapter", help="sign a reviewed adapter manifest")
    key_args(sa)
    sa.add_argument("--case", required=True)
    sa.add_argument("--payload", required=True,
                    help="JSON payload with capability/category/tool/argv_schema/egress/reviewer")
    sa.add_argument("--out")
    sa.set_defaults(func=_cmd_sign_adapter)

    an = sub.add_parser("anchor", help="sign an audit anchor over a case log tip")
    key_args(an)
    an.add_argument("--case-dir", required=True, dest="case_dir")
    an.add_argument("--out")
    an.set_defaults(func=_cmd_anchor)

    ve = sub.add_parser("verify", help="verify any manifest / anchor")
    ve.add_argument("--manifest", required=True)
    ve.add_argument("--trusted", action="append", required=True,
                    help="trusted operator public-key hex (repeatable)")
    ve.add_argument("--case-dir", dest="case_dir", help="required for audit anchors")
    ve.set_defaults(func=_cmd_verify)
    return p


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    # scope ports may be ints or ranges ("8000-8100"); normalise numerics to int
    if getattr(args, "port", None) is not None and isinstance(args.port, list):
        args.port = [int(x) if str(x).isdigit() else x for x in args.port]
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
