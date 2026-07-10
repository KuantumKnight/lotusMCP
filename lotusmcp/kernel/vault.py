"""AES-256-GCM secret vault — the production drop-in for `SecretVault` (§Safety.4).

`redaction.py` tokenizes incidental secrets into content-addressed handles
(`«SECRET:kind:tag»`) and stores the plaintext in a vault for privileged reveal.
The skeleton vault obfuscated at rest with keyed-XOR; this one is a real AEAD:

  - AES-256-GCM (via the vetted `cryptography` lib) with a per-secret random
    nonce, so identical plaintexts don't produce identical ciphertext at rest;
  - the handle is bound in as **additional authenticated data**, so a ciphertext
    can never be moved to a different handle without failing decryption;
  - **fail-closed**: a tampered blob raises on reveal rather than returning
    corrupt plaintext.

Interface-compatible with `SecretVault` (`store`/`reveal`/`__len__`), so it drops
into `Redactor(vault=...)` and `Case(vault=...)` with no other change. Handles
are still content-addressed by `redaction.handle_for`, so idempotency and
replay-equivalence of the *log* are unaffected (the vault bytes are never
hashed into the chain).
"""
from __future__ import annotations

import hashlib
import os
from typing import Dict, Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

_NONCE_BYTES = 12


class AESGCMVault:
    def __init__(self, key: Optional[bytes] = None) -> None:
        """`key` is 32 raw bytes (AES-256). Any other length is treated as key
        *material* and stretched with blake2b; None generates a fresh key."""
        if key is None:
            key = os.urandom(32)
        elif len(key) != 32:
            key = hashlib.blake2b(key, digest_size=32).digest()
        self._aead = AESGCM(key)
        self._store: Dict[str, bytes] = {}      # handle -> nonce || ciphertext+tag

    def store(self, handle: str, plaintext: str) -> None:
        if handle in self._store:
            # Content-addressed handle => same secret. Confirm (defends against a
            # tag collision) and no-op; re-observing a secret must be idempotent.
            if self.reveal(handle) != plaintext:
                raise ValueError(f"vault handle collision: {handle}")
            return
        nonce = os.urandom(_NONCE_BYTES)
        ct = self._aead.encrypt(nonce, plaintext.encode("utf-8"),
                                handle.encode("utf-8"))
        self._store[handle] = nonce + ct

    def reveal(self, handle: str) -> Optional[str]:
        blob = self._store.get(handle)
        if blob is None:
            return None
        nonce, ct = blob[:_NONCE_BYTES], blob[_NONCE_BYTES:]
        # Raises cryptography.exceptions.InvalidTag on any tamper — fail closed.
        return self._aead.decrypt(nonce, ct, handle.encode("utf-8")).decode("utf-8")

    def __len__(self) -> int:
        return len(self._store)
