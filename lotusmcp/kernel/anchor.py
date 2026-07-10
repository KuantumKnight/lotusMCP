"""Signed audit anchors — VERIFY side (§Safety, "hash chain + signed anchors").

The hash chain makes the log internally tamper-evident: you cannot alter one
event without breaking every hash after it. An *anchor* adds an external witness
— an operator-signed statement "at seq S the chain tip was H". Because the
anchor is Ed25519-signed by a trusted operator, an attacker who rewrites history
(recomputing all internal hashes to stay self-consistent) still cannot forge an
anchor, so the divergence is detectable.

This module verifies anchors; creation lives in `control_plane/anchor.py` (it
needs the operator private key and must not be in the server path). An anchor is
just a signed manifest of `type: audit_anchor`, so it reuses `kernel/signing.py`.
"""
from __future__ import annotations

from typing import Any, Dict, Iterable

from lotusmcp.kernel.signing import verify_manifest

ANCHOR_TYPE = "audit_anchor"


def verify_anchor(anchor: Dict[str, Any], store, trusted_hex: Iterable[str]) -> bool:
    """True iff `anchor` is a trusted-operator signature over a tip hash that the
    log still matches. Three conditions, all required:
      1. valid Ed25519 signature from a trusted operator key;
      2. the chain is internally intact (no broken link/hash);
      3. the recorded hash at the anchored seq equals the anchored tip hash.
    Any structural problem is a rejection, never an exception."""
    try:
        if anchor.get("type") != ANCHOR_TYPE:
            return False
        if not verify_manifest(anchor, trusted_hex):
            return False
        payload = anchor.get("payload") or {}
        seq = payload.get("seq")
        tip_hash = payload.get("tip_hash")
        if not isinstance(seq, int) or not isinstance(tip_hash, str):
            return False
        if store.verify_chain() != -1:            # internal chain broken
            return False
        return store.hash_at(seq) == tip_hash     # log still matches the witness
    except (KeyError, TypeError, ValueError):
        return False
