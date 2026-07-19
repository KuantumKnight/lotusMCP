"""Operator signing key + manifest signer (control-plane, human-only).

The private half of `kernel/signing.py`. An operator generates a `SigningKey`
once (stored as an encrypted PEM in an OS keystore/HSM in production), and uses
it to sign the control-plane manifests. The server never runs this code and
never holds this key; it only verifies the resulting `signer`/`sig` fields.

Manifest types the operator signs (§1, §Safety.2):
  scope · egress_grant · submit_allowlist · tier3 · adapter_review
"""
from __future__ import annotations

from typing import Any, Dict, Optional

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from lotusmcp.kernel.signing import ALG, SIG_FIELD, manifest_signing_bytes

MANIFEST_TYPES = ("scope", "egress_grant", "submit_allowlist", "tier3",
                  "adapter_review")
MANIFEST_V = 1


class SigningKey:
    """An Ed25519 operator private key. Keep it OUT of the server path."""

    __slots__ = ("_priv",)

    def __init__(self, priv: Ed25519PrivateKey) -> None:
        self._priv = priv

    @classmethod
    def generate(cls) -> "SigningKey":
        return cls(Ed25519PrivateKey.generate())

    @classmethod
    def from_pem(cls, data: bytes, password: Optional[bytes] = None) -> "SigningKey":
        key = serialization.load_pem_private_key(data, password=password)
        if not isinstance(key, Ed25519PrivateKey):
            raise ValueError("not an Ed25519 private key")
        return cls(key)

    def to_pem(self, password: Optional[bytes] = None) -> bytes:
        enc = (serialization.BestAvailableEncryption(password)
               if password else serialization.NoEncryption())
        return self._priv.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=enc,
        )

    @property
    def public_hex(self) -> str:
        raw = self._priv.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        return raw.hex()

    def sign(self, message: bytes) -> str:
        return self._priv.sign(message).hex()


def sign_manifest(
    key: SigningKey,
    mtype: str,
    case_id: str,
    payload: Dict[str, Any],
) -> Dict[str, Any]:
    """Build and sign a control-plane manifest. Returns the full dict including
    `signer` (operator public key hex) and `sig`."""
    if mtype not in MANIFEST_TYPES:
        raise ValueError(f"unknown manifest type: {mtype}")
    manifest: Dict[str, Any] = {
        "v": MANIFEST_V,
        "alg": ALG,
        "type": mtype,
        "case_id": case_id,
        "payload": payload,
        "signer": key.public_hex,
    }
    manifest[SIG_FIELD] = key.sign(manifest_signing_bytes(manifest))
    return manifest
