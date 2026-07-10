"""Tests for the decode ladder and the flag scanner.

Guarantees:
  1. Direct flag-format hits are found.
  2. Flags hidden under stacked encodings (base64/hex/rot13/base32/reverse) are
     recovered, with the decode path recorded.
  3. The ladder is bounded and total — hostile/garbage input never raises and
     never runs away.
  4. Everything is deterministic (same input -> same ordered output).
"""
from __future__ import annotations

import base64
import codecs
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from lotusmcp.flag.ladder import MAX_NODES, decode_ladder  # noqa: E402
from lotusmcp.flag.scanner import scan_many, scan_text  # noqa: E402

FMT = r"flag\{[^}]+\}"
FLAG = "flag{d3c0de_the_l4dder}"


def test_direct_match():
    cands = scan_text(f"output: {FLAG} done", FMT)
    assert len(cands) == 1
    assert cands[0].value == FLAG
    assert cands[0].source == "direct"
    assert cands[0].decode_path == ()


def test_base64_layer():
    blob = base64.b64encode(FLAG.encode()).decode()
    cands = scan_text(f"leaked blob {blob} here", FMT)
    assert any(c.value == FLAG and c.source == "decoded" for c in cands)
    hit = next(c for c in cands if c.value == FLAG)
    assert hit.decode_path == ("base64",)


def test_stacked_base64_of_hex():
    inner = FLAG.encode().hex()                       # hex layer
    blob = base64.b64encode(inner.encode()).decode()  # then base64
    cands = scan_text(blob, FMT)
    hit = next((c for c in cands if c.value == FLAG), None)
    assert hit is not None
    assert hit.decode_path == ("base64", "hex")


def test_rot13_layer():
    blob = codecs.encode(FLAG, "rot_13")
    hits = [c for c in scan_text(blob, FMT) if c.value == FLAG]
    assert hits and hits[0].decode_path == ("rot13",)


def test_reversed_flag():
    hits = [c for c in scan_text(FLAG[::-1], FMT) if c.value == FLAG]
    assert hits and "reverse" in hits[0].decode_path


def test_generic_format_fallback():
    cands = scan_text("we found picoCTF{generic_shape_works} in the source")
    assert any(c.value == "picoCTF{generic_shape_works}" for c in cands)


def test_direct_preferred_over_decoded_duplicate():
    blob = base64.b64encode(FLAG.encode()).decode()
    cands = scan_text(f"{FLAG} and also {blob}", FMT)
    # one entry for the value, and it's the direct (more trusted) discovery
    same = [c for c in cands if c.value == FLAG]
    assert len(same) == 1 and same[0].source == "direct"


def test_hostile_input_never_raises():
    for junk in ["", "=" * 500, "%%%%%", "\x00\x01\x02bad", "A" * 9000,
                 "////++++====", "not base64 at all!!!"]:
        # must not raise, must return a list
        assert isinstance(scan_text(junk, FMT), list)


def test_ladder_is_bounded():
    # a long decodable-looking blob must not exceed the node cap
    blob = base64.b64encode(b"A" * 400).decode()
    out = decode_ladder(blob, FMT)
    assert len(out) <= MAX_NODES + 1  # + the seed


def test_ladder_deterministic():
    blob = base64.b64encode(FLAG.encode()).decode()
    a = [(d.value, d.path) for d in decode_ladder(blob, FMT)]
    b = [(d.value, d.path) for d in decode_ladder(blob, FMT)]
    assert a == b


def test_scan_many_merges():
    blob = base64.b64encode(FLAG.encode()).decode()
    cands = scan_many([f"nothing here", f"blob {blob}", f"direct {FLAG}"], FMT)
    same = [c for c in cands if c.value == FLAG]
    assert len(same) == 1 and same[0].source == "direct"


def test_no_flag_returns_empty():
    assert scan_text("just some boring nmap output, ports 22 80 443", FMT) == []


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
