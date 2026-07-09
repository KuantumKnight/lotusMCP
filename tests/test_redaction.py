"""Golden + property tests for the Redaction Choke.

Guarantees under test:
  1. Structured secrets are tokenized; surrounding structure survives.
  2. Handles are content-addressed -> redaction is idempotent and replay-stable.
  3. Flags (the objective) are NEVER redacted.
  4. The vault round-trips plaintext for privileged reveal, and only there.
  5. Payload redaction walks nested dicts/lists over VALUES only (keys survive).
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from lotusmcp.kernel.redaction import (  # noqa: E402
    Redactor,
    SecretVault,
    find_handles,
    handle_for,
)

JWT = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhZG1pbiJ9.abc123DEF_signature-x"
PRIV = (
    "-----BEGIN RSA PRIVATE KEY-----\n"
    "MIIEowIBAAKCAQEA0Zx\n" * 3 + "-----END RSA PRIVATE KEY-----"
)


def test_jwt_tokenized_and_vaulted():
    r = Redactor()
    text = f"Authorization header carried {JWT} on /admin"
    red, reds = r.redact_text(text)
    assert JWT not in red
    assert len(reds) == 1 and reds[0]["kind"] == "jwt"
    handle = reds[0]["handle"]
    assert handle in red
    assert r.vault.reveal(handle) == JWT


def test_url_credential_keeps_structure():
    r = Redactor()
    red, reds = r.redact_text("mysql://root:sup3rSecret@db.internal:3306/app")
    assert "sup3rSecret" not in red
    # username + host + port + scheme preserved; only the password is a handle.
    assert red.startswith("mysql://root:«SECRET:url_credential:")
    assert "@db.internal:3306/app" in red
    assert reds[0]["kind"] == "url_credential"


def test_secret_kv_variants():
    r = Redactor()
    for line, val in [
        ("password=hunter2trombone", "hunter2trombone"),
        ("api_key: AbCdEf123456", "AbCdEf123456"),
        ('token="ghp_0123456789abcdef"', "ghp_0123456789abcdef"),
    ]:
        red, reds = r.redact_text(line)
        assert val not in red, line
        assert reds, line


def test_private_key_block():
    r = Redactor()
    red, reds = r.redact_text(f"leaked:\n{PRIV}\n(end)")
    assert "MIIEowIBAAKCAQEA0Zx" not in red
    assert reds and reds[0]["kind"] == "private_key"
    assert r.vault.reveal(reds[0]["handle"]) == PRIV


def test_aws_access_key():
    r = Redactor()
    red, reds = r.redact_text("key AKIAIOSFODNN7EXAMPLE rotated")
    assert "AKIAIOSFODNN7EXAMPLE" not in red
    assert reds[0]["kind"] == "aws_access_key"


def test_flags_are_never_redacted():
    # A flag shaped like a secret must survive verbatim.
    r = Redactor(flag_format=r"flag\{[^}]+\}")
    text = "password=flag{r3d4ct10n_is_h4rd}"
    red, reds = r.redact_text(text)
    assert "flag{r3d4ct10n_is_h4rd}" in red
    assert reds == []


def test_idempotent_and_content_addressed():
    r = Redactor()
    once, _ = r.redact_text(f"t={JWT}")
    twice, reds2 = r.redact_text(once)  # second pass over already-redacted text
    assert once == twice
    assert reds2 == []  # nothing left to redact
    # deterministic handle independent of the Redactor instance
    assert handle_for("jwt", JWT) in once


def test_two_redactors_agree_on_handles():
    a, _ = Redactor().redact_text(JWT)
    b, _ = Redactor().redact_text(JWT)
    assert a == b  # replay-equivalence across sessions


def test_payload_walks_values_not_keys():
    r = Redactor()
    payload = {
        "password": "topSecretValue1",          # key stays, value redacted
        "nested": {"list": ["ok", f"jwt {JWT}"]},
        "count": 42,
        "flag_kept": "just text",
    }
    clean, reds = r.redact_payload(payload)
    assert "password" in clean                    # key untouched
    assert clean["password"] != "topSecretValue1"
    assert JWT not in clean["nested"]["list"][1]
    assert clean["count"] == 42                    # non-strings untouched
    assert len(reds) == 2


def test_no_false_positive_on_clean_text():
    r = Redactor()
    clean = "nmap found ports 22,80,443 on host 10.10.10.5 running nginx 1.18"
    red, reds = r.redact_text(clean)
    assert red == clean and reds == []


def test_vault_reveal_only_for_known_handles():
    v = SecretVault()
    r = Redactor(vault=v)
    _, reds = r.redact_text(f"api_key: {JWT}")
    assert v.reveal(reds[0]["handle"]) is not None
    assert v.reveal("«SECRET:jwt:0000»") is None


def test_vault_survives_long_secrets():
    v = SecretVault()
    r = Redactor(vault=v)
    _, reds = r.redact_text(PRIV)  # > 64 bytes -> exercises counter-mode keystream
    assert v.reveal(reds[0]["handle"]) == PRIV


def test_find_handles_helper():
    r = Redactor()
    red, _ = r.redact_text(f"a={JWT} b=AKIAIOSFODNN7EXAMPLE")
    assert len(find_handles(red)) == 2


if __name__ == "__main__":
    import traceback

    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    failed = 0
    for fn in fns:
        try:
            fn()
            print(f"ok   {fn.__name__}")
        except Exception:  # noqa: BLE001
            failed += 1
            print(f"FAIL {fn.__name__}")
            traceback.print_exc()
    print(f"\n{len(fns) - failed}/{len(fns)} passed")
    sys.exit(1 if failed else 0)
