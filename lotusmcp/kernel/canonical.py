"""Canonical JSON serialization for the hash chain.

For the walking skeleton we use a pragmatic canonical form (recursively
sorted keys, no insignificant whitespace, UTF-8). Production should upgrade
to full RFC 8785 (JCS) — number canonicalization is the only gap and CTF
payloads are string/int-heavy, so this is byte-stable in practice.
"""
from __future__ import annotations

import json
from typing import Any


def canonical(obj: Any) -> str:
    """Deterministic, whitespace-free JSON with recursively sorted keys."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def canonical_bytes(obj: Any) -> bytes:
    return canonical(obj).encode("utf-8")
