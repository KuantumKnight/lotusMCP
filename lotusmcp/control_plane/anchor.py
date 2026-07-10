"""Signed audit anchors — CREATE side (control-plane, human/operator only).

Produces an operator-signed witness of the current log tip. Kept out of the
server path because it uses the Ed25519 private key. The server only verifies,
via `kernel/anchor.py`.
"""
from __future__ import annotations

from typing import Any, Dict

from lotusmcp.control_plane.keyring import MANIFEST_V, SigningKey
from lotusmcp.kernel.anchor import ANCHOR_TYPE
from lotusmcp.kernel.signing import ALG, SIG_FIELD, manifest_signing_bytes


def create_anchor(store, key: SigningKey) -> Dict[str, Any]:
    """Sign the store's current tip. Returns a manifest of type `audit_anchor`."""
    anchor: Dict[str, Any] = {
        "v": MANIFEST_V,
        "alg": ALG,
        "type": ANCHOR_TYPE,
        "case_id": store.dir.name,
        "payload": {
            "seq": store.tip,
            "tip_hash": store.tip_hash,
            "chain_len": store.tip + 1,
        },
        "signer": key.public_hex,
    }
    anchor[SIG_FIELD] = key.sign(manifest_signing_bytes(anchor))
    return anchor
