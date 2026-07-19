"""Lotus Canonical JSON v1 for the hash chain.

The event log standard is intentionally small and stable:

* recursively sorted object keys;
* no insignificant whitespace;
* UTF-8 output with non-ASCII preserved;
* strict JSON numbers (`NaN`/`Infinity` are rejected).

LotusC14N-v1 is the compatibility contract for existing event hashes. Do not
change this function without a schema/hash-chain migration.
"""
from __future__ import annotations

import json
import math
from typing import Any


def _reject_nonfinite(obj: Any) -> None:
    if isinstance(obj, float) and not math.isfinite(obj):
        raise ValueError("non-finite JSON number is not allowed in the event log")
    if isinstance(obj, dict):
        for k, v in obj.items():
            _reject_nonfinite(k)
            _reject_nonfinite(v)
    elif isinstance(obj, (list, tuple)):
        for v in obj:
            _reject_nonfinite(v)


def canonical(obj: Any) -> str:
    """Deterministic, whitespace-free JSON with recursively sorted keys."""
    _reject_nonfinite(obj)
    return json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


def canonical_bytes(obj: Any) -> bytes:
    return canonical(obj).encode("utf-8")
