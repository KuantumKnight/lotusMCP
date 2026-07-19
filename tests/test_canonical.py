"""Lotus Canonical JSON v1."""
from __future__ import annotations

import math

from lotusmcp.kernel.canonical import canonical, canonical_bytes


def test_sorted_compact_utf8_stable():
    obj = {"z": [3, {"b": "β", "a": 1}], "a": True}
    assert canonical(obj) == '{"a":true,"z":[3,{"a":1,"b":"β"}]}'
    assert canonical_bytes(obj) == canonical(obj).encode("utf-8")


def test_rejects_nonfinite_numbers():
    for value in (math.nan, math.inf, -math.inf):
        try:
            canonical({"bad": value})
        except ValueError:
            pass
        else:
            raise AssertionError("non-finite JSON number must be rejected")


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items())
           if k.startswith("test_") and callable(v)]
    failed = 0
    for fn in fns:
        try:
            fn()
            print(f"  ok  {fn.__name__}")
        except Exception as e:
            failed += 1
            print(f"FAIL  {fn.__name__}: {e}")
    print(f"\n{len(fns)-failed}/{len(fns)} passed")
    raise SystemExit(1 if failed else 0)
