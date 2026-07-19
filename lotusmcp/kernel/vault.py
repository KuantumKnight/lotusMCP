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
import json
import os
from pathlib import Path
from typing import Dict, Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

_NONCE_BYTES = 12


class AESGCMVault:
    def __init__(
        self,
        key: Optional[bytes] = None,
        *,
        path: Optional[os.PathLike | str] = None,
    ) -> None:
        """`key` is 32 raw bytes (AES-256). Any other length is treated as key
        *material* and stretched with blake2b; None generates a fresh key.

        When `path` is supplied, ciphertexts are persisted as JSON. The key is
        still supplied by the caller; see `for_case_dir()` for the host-local
        per-case default used by `Case`.
        """
        if key is None:
            key = os.urandom(32)
        elif len(key) != 32:
            key = hashlib.blake2b(key, digest_size=32).digest()
        self._aead = AESGCM(key)
        self.path = Path(path) if path is not None else None
        self._store: Dict[str, bytes] = {}      # handle -> nonce || ciphertext+tag
        self._load()

    @classmethod
    def for_case_dir(cls, case_dir: os.PathLike | str) -> "AESGCMVault":
        """Open the default persistent vault for a case directory.

        If `LOTUS_VAULT_KEY_HEX` is set, it is used as key material. Otherwise a
        host-local per-case key file is created under `vault/key.bin` with
        best-effort 0600 permissions. This keeps plaintext secrets out of
        `events.jsonl` and out of the vault file while preserving reveal across
        case reopen on this machine.
        """
        root = Path(case_dir) / "vault"
        root.mkdir(parents=True, exist_ok=True)
        env_key = os.environ.get("LOTUS_VAULT_KEY_HEX", "").strip()
        if env_key:
            try:
                key = bytes.fromhex(env_key)
            except ValueError:
                key = env_key.encode("utf-8")
        else:
            key_path = root / "key.bin"
            if key_path.exists():
                key = key_path.read_bytes()
            else:
                key = os.urandom(32)
                key_path.write_bytes(key)
                try:
                    os.chmod(key_path, 0o600)
                except OSError:
                    pass
        return cls(key=key, path=root / "secrets.json")

    def _load(self) -> None:
        if self.path is None or not self.path.exists():
            return
        doc = json.loads(self.path.read_text(encoding="utf-8"))
        if not isinstance(doc, dict):
            raise ValueError("vault file must be a JSON object")
        self._store = {str(k): bytes.fromhex(str(v)) for k, v in doc.items()}

    def _save(self) -> None:
        if self.path is None:
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(self.path.suffix + ".tmp")
        tmp.write_text(json.dumps({k: v.hex() for k, v in sorted(self._store.items())},
                                  indent=2, sort_keys=True) + "\n",
                       encoding="utf-8")
        os.replace(tmp, self.path)

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
        self._save()

    def reveal(self, handle: str) -> Optional[str]:
        blob = self._store.get(handle)
        if blob is None:
            return None
        nonce, ct = blob[:_NONCE_BYTES], blob[_NONCE_BYTES:]
        # Raises cryptography.exceptions.InvalidTag on any tamper — fail closed.
        return self._aead.decrypt(nonce, ct, handle.encode("utf-8")).decode("utf-8")

    def __len__(self) -> int:
        return len(self._store)
