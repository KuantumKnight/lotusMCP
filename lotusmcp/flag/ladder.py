"""The bounded best-first decode ladder.

CTF flags are routinely buried under layers of encoding — base64 of hex of
rot13, a reversed base32 blob, a URL-escaped payload. The ladder walks that
space *best-first* (most flag-looking node first) with hard bounds on depth and
node count, so a hostile or adversarial blob can never make it run away.

Every transform is total: it either returns a plausible decoded string or
`None` (wrong charset, bad padding, non-text result). Nothing here raises.

Deterministic by construction — no clocks, no randomness, a fixed transform
order and a stable tie-break — so the same blob always yields the same ladder,
which keeps `flag.candidate` events replay-stable.
"""
from __future__ import annotations

import base64
import binascii
import codecs
import heapq
import re
from dataclasses import dataclass, field
from typing import Callable, List, Optional, Tuple
from urllib.parse import unquote

MAX_DEPTH = 6           # how many stacked encodings we will peel
MAX_NODES = 400         # total decode attempts across the whole search
MIN_LEN = 4             # shorter strings aren't worth decoding
MAX_LEN = 8192          # ignore absurdly large blobs (DoS guard)

_PRINTABLE = re.compile(r"[\x20-\x7e]")
_B64_RE = re.compile(r"^[A-Za-z0-9+/]+={0,2}$")
_B64URL_RE = re.compile(r"^[A-Za-z0-9_-]+={0,2}$")
_B32_RE = re.compile(r"^[A-Z2-7]+={0,6}$")
_HEX_RE = re.compile(r"^(?:[0-9a-fA-F]{2})+$")


def _printable_ratio(s: str) -> float:
    if not s:
        return 0.0
    return len(_PRINTABLE.findall(s)) / len(s)


def _text_or_none(raw: bytes) -> Optional[str]:
    try:
        s = raw.decode("utf-8")
    except UnicodeDecodeError:
        try:
            s = raw.decode("latin-1")
        except UnicodeDecodeError:
            return None
    # decoded garbage (mostly control bytes) is a dead branch
    return s if _printable_ratio(s) >= 0.85 else None


def _d_base64(s: str) -> Optional[str]:
    t = s.strip()
    if len(t) < 4 or len(t) % 4 != 0 or not _B64_RE.match(t):
        return None
    try:
        return _text_or_none(base64.b64decode(t, validate=True))
    except (binascii.Error, ValueError):
        return None


def _d_base64url(s: str) -> Optional[str]:
    t = s.strip()
    if len(t) < 4 or not _B64URL_RE.match(t) or ("-" not in t and "_" not in t):
        return None  # plain base64 handled by _d_base64; require a urlsafe char
    pad = "=" * (-len(t) % 4)
    try:
        return _text_or_none(base64.urlsafe_b64decode(t + pad))
    except (binascii.Error, ValueError):
        return None


def _d_base32(s: str) -> Optional[str]:
    t = s.strip().upper()
    if len(t) < 8 or len(t) % 8 != 0 or not _B32_RE.match(t):
        return None
    try:
        return _text_or_none(base64.b32decode(t))
    except (binascii.Error, ValueError):
        return None


def _d_hex(s: str) -> Optional[str]:
    t = s.strip()
    if len(t) < 4 or not _HEX_RE.match(t):
        return None
    try:
        return _text_or_none(bytes.fromhex(t))
    except ValueError:
        return None


def _d_rot13(s: str) -> Optional[str]:
    out = codecs.encode(s, "rot_13")
    return out if out != s else None


def _d_url(s: str) -> Optional[str]:
    if "%" not in s:
        return None
    out = unquote(s)
    return out if out != s else None


def _d_reverse(s: str) -> Optional[str]:
    return s[::-1] if len(s) > 1 else None


@dataclass(frozen=True)
class Transform:
    name: str
    fn: Callable[[str], Optional[str]]


# Fixed order — decode families first (they shrink the string toward a flag),
# then the cheap reversible tricks. Order is part of the determinism contract.
LADDER: List[Transform] = [
    Transform("base64", _d_base64),
    Transform("base64url", _d_base64url),
    Transform("base32", _d_base32),
    Transform("hex", _d_hex),
    Transform("rot13", _d_rot13),
    Transform("url", _d_url),
    Transform("reverse", _d_reverse),
]


@dataclass(order=True)
class _Node:
    # priority queue orders by (-score, seq): most flag-looking first, stable.
    neg_score: float
    seq: int
    value: str = field(compare=False)
    path: Tuple[str, ...] = field(compare=False, default=())


@dataclass(frozen=True)
class Decoded:
    """One string reachable from the seed, with the transforms that produced it."""

    value: str
    path: Tuple[str, ...]      # () means the seed itself, verbatim

    @property
    def depth(self) -> int:
        return len(self.path)


def _score(value: str, flag_re: Optional[re.Pattern]) -> float:
    """Heuristic: prefer flag-format hits, then flag-ish, printable, shorter."""
    s = 0.0
    if flag_re and flag_re.search(value):
        s += 100.0
    low = value.lower()
    if "flag" in low or "ctf" in low or "{" in value:
        s += 5.0
    s += _printable_ratio(value) * 2.0
    s -= len(value) / 1000.0     # gentle bias toward shorter, decoded forms
    return s


def decode_ladder(
    seed: str,
    flag_format: Optional[str] = None,
    max_depth: int = MAX_DEPTH,
    max_nodes: int = MAX_NODES,
) -> List[Decoded]:
    """Best-first bounded walk of everything reachable by stacked decodings.

    Returns the seed plus every distinct decoded string discovered, ordered by
    the same heuristic used to steer the search (most flag-looking first).
    """
    if not isinstance(seed, str) or not (MIN_LEN <= len(seed) <= MAX_LEN):
        return [Decoded(seed, ())] if isinstance(seed, str) else []
    flag_re = re.compile(flag_format) if flag_format else None

    seen = {seed}
    results: List[Decoded] = [Decoded(seed, ())]
    counter = 0
    heap: List[_Node] = [_Node(-_score(seed, flag_re), counter, seed, ())]
    nodes = 0

    while heap and nodes < max_nodes:
        node = heapq.heappop(heap)
        if len(node.path) >= max_depth:
            continue
        for tf in LADDER:
            nodes += 1
            if nodes > max_nodes:
                break
            decoded = tf.fn(node.value)
            if decoded is None or decoded in seen or not (MIN_LEN <= len(decoded) <= MAX_LEN):
                continue
            seen.add(decoded)
            path = node.path + (tf.name,)
            results.append(Decoded(decoded, path))
            counter += 1
            heapq.heappush(heap, _Node(-_score(decoded, flag_re), counter, decoded, path))

    return results
