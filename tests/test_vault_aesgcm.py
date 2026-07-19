"""AES-GCM vault: real AEAD at rest, handle-bound, fail-closed — and a drop-in
for the redactor so secrets still tokenize + reveal end-to-end.

    PYTHONPATH=. PYTHONIOENCODING=utf-8 python tests/test_vault_aesgcm.py
"""
from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from lotusmcp.kernel.case import Case
from lotusmcp.kernel.events import EventDraft
from lotusmcp.kernel.redaction import Redactor, handle_for
from lotusmcp.kernel.vault import AESGCMVault


def test_store_reveal_roundtrip():
    v = AESGCMVault(key=b"a" * 32)
    h = handle_for("secret_kv", "hunter2")
    v.store(h, "hunter2")
    assert v.reveal(h) == "hunter2"
    assert v.reveal(handle_for("x", "absent")) is None


def test_ciphertext_is_randomized():
    v = AESGCMVault()
    v.store("«SECRET:a:0001»", "same-secret")
    blob1 = v._store["«SECRET:a:0001»"]
    v2 = AESGCMVault()
    v2.store("«SECRET:a:0001»", "same-secret")
    blob2 = v2._store["«SECRET:a:0001»"]
    assert blob1 != blob2, "random nonce must randomize ciphertext at rest"


def test_tamper_fails_closed():
    v = AESGCMVault(key=b"k" * 32)
    h = "«SECRET:jwt:dead»"
    v.store(h, "top-secret-value")
    blob = bytearray(v._store[h])
    blob[-1] ^= 0x01                       # flip a tag bit
    v._store[h] = bytes(blob)
    try:
        v.reveal(h)
    except Exception:                      # cryptography.exceptions.InvalidTag
        return
    raise AssertionError("tampered ciphertext must not reveal")


def test_handle_bound_as_aad():
    v = AESGCMVault(key=b"z" * 32)
    a, b = "«SECRET:kv:aaaa»", "«SECRET:kv:bbbb»"
    v.store(a, "value-a")
    # move a's ciphertext under handle b -> AAD mismatch -> reveal fails
    v._store[b] = v._store[a]
    try:
        v.reveal(b)
    except Exception:
        return
    raise AssertionError("ciphertext must be bound to its handle via AAD")


def test_idempotent_store_same_secret():
    v = AESGCMVault(key=b"q" * 32)
    h = handle_for("secret_kv", "repeat")
    v.store(h, "repeat")
    v.store(h, "repeat")                   # no-op, no raise
    assert len(v) == 1


def test_redactor_with_aesgcm_vault_end_to_end():
    v = AESGCMVault(key=b"r" * 32)
    r = Redactor(vault=v)
    text = "login with password=SuperSecret123 and token=abcdef1234567890"
    red, reds = r.redact_text(text)
    assert "SuperSecret123" not in red and "«SECRET:" in red
    assert len(reds) >= 1
    # the privileged reveal returns the original secret from the AEAD store
    for entry in reds:
        assert r.vault.reveal(entry["handle"]) is not None


def test_case_uses_aesgcm_vault():
    base = Path(tempfile.mkdtemp(prefix="lotus_vault_"))
    case = Case.create(base, "vaulted", title="t", category="web",
                       flag_format=r"flag\{[^}]+\}", vault=AESGCMVault(key=b"c" * 32))
    case.append(EventDraft("note.added", {"kind": "llm", "name": "oracle"},
                           {"text": "creds: password=Adm1nP@ss found in config"}))
    # secret is tokenized in the log (never on disk in the clear)
    log = (case.dir / "events.jsonl").read_text(encoding="utf-8")
    assert "Adm1nP@ss" not in log and "«SECRET:" in log
    # but recoverable via the case's AEAD vault
    handle = handle_for("secret_kv", "Adm1nP@ss")
    assert case.redactor.vault.reveal(handle) == "Adm1nP@ss"


def test_default_case_vault_persists_reveal_without_plaintext():
    base = Path(tempfile.mkdtemp(prefix="lotus_vault_default_"))
    case = Case.create(base, "default-vault", title="t", category="web",
                       flag_format=r"flag\{[^}]+\}")
    case.append(EventDraft("note.added", {"kind": "llm", "name": "oracle"},
                           {"text": "db password=PersistMe123"}))
    handle = handle_for("secret_kv", "PersistMe123")
    assert case.redactor.vault.reveal(handle) == "PersistMe123"
    vault_dir = case.dir / "vault"
    assert (vault_dir / "secrets.json").exists()
    assert (vault_dir / "key.bin").exists()
    assert "PersistMe123" not in (vault_dir / "secrets.json").read_text(encoding="utf-8")

    reopened = Case(base, "default-vault")
    assert reopened.redactor.vault.reveal(handle) == "PersistMe123"


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
