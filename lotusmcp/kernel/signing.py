"""Server-side signature VERIFICATION (§1 Control Plane, §Safety.2).

The control-plane/data-plane split (ARCHITECTURE §2) says the private key that
signs `scope.json`, egress grants, the submit allowlist and tier-3 enablement
lives in an operator keystore and is NEVER in the server request path. This
module is the server half: it holds only PUBLIC keys and can only *verify*. The
signing half is `control_plane/keyring.py`, which the server must never import.

A signed manifest is a plain dict whose canonical bytes (everything except the
`sig` field) are signed with Ed25519. Verification is: (1) the signature is valid
for those bytes under the named signer, and (2) the signer is in the server's
trusted-operator set. Both must hold — a valid signature from an unknown key is
rejected, so the agent can never introduce its own signer.
"""
from __future__ import annotations

from typing import Any, Dict, Iterable

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from lotusmcp.kernel.canonical import canonical_bytes

ALG = "ed25519"
SIG_FIELD = "sig"


def manifest_signing_bytes(manifest: Dict[str, Any]) -> bytes:
    """The exact bytes a manifest's signature covers: canonical JSON of every
    field except `sig`. Deterministic, so signer and verifier agree byte-for-byte."""
    body = {k: v for k, v in manifest.items() if k != SIG_FIELD}
    return canonical_bytes(body)


class VerifyKey:
    """A public Ed25519 key, addressed by the hex of its 32 raw bytes."""

    __slots__ = ("_pub", "hex")

    def __init__(self, raw: bytes) -> None:
        if len(raw) != 32:
            raise ValueError("ed25519 public key must be 32 bytes")
        self._pub = Ed25519PublicKey.from_public_bytes(raw)
        self.hex = raw.hex()

    @classmethod
    def from_hex(cls, hexstr: str) -> "VerifyKey":
        return cls(bytes.fromhex(hexstr))

    def verify(self, message: bytes, sig_hex: str) -> bool:
        try:
            self._pub.verify(bytes.fromhex(sig_hex), message)
            return True
        except (InvalidSignature, ValueError):
            return False


def verify_manifest(manifest: Dict[str, Any], trusted_hex: Iterable[str]) -> bool:
    """True iff `manifest` carries a valid Ed25519 signature from a signer in
    `trusted_hex`. Any structural problem (missing fields, wrong alg, unknown
    signer, bad signature) is a rejection, never an exception."""
    try:
        if manifest.get("alg") != ALG:
            return False
        signer = manifest.get("signer")
        sig = manifest.get(SIG_FIELD)
        if not signer or not sig:
            return False
        trusted = set(trusted_hex)
        if signer not in trusted:
            return False               # valid sig from an untrusted key -> reject
        return VerifyKey.from_hex(signer).verify(manifest_signing_bytes(manifest), sig)
    except (ValueError, TypeError):
        return False
