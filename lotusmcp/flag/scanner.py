"""The out-of-band flag scanner.

Runs over every command output, file, and freeform string. Two ways a flag
surfaces:

  1. **Direct** — the flag format matches verbatim in the text.
  2. **Decoded** — an encoded token, peeled by the bounded decode ladder,
     matches the format at some depth.

The scanner only *finds* candidates; ranking, decoy filtering, tiering, and the
submit decision live downstream (`ranker`, `policy`). It is deterministic: same
text + same format -> same ordered candidate list.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List, Optional, Tuple

from lotusmcp.flag.ladder import decode_ladder

# When no case flag_format is set, fall back to the ubiquitous `word{...}` shape
# (picoCTF{}, HTB{}, flag{}, CTF{} ...). Deliberately conservative.
GENERIC_FLAG_RE = re.compile(r"[A-Za-z0-9_]{2,15}\{[^}\r\n]{2,200}\}")

# Tokens worth feeding to the decode ladder: long-ish, no whitespace, plausibly
# an encoded blob. Splitting on quotes/whitespace/angle brackets keeps it cheap.
_TOKEN_RE = re.compile(r"[A-Za-z0-9+/=_-]{8,}")


@dataclass(frozen=True)
class FlagCandidate:
    value: str
    source: str                      # "direct" | "decoded"
    decode_path: Tuple[str, ...]     # () for direct hits
    context: str                     # short surrounding snippet for the audit trail

    @property
    def value_sha(self) -> str:
        import hashlib
        return "sha256:" + hashlib.sha256(self.value.encode("utf-8")).hexdigest()


def _flag_re(flag_format: Optional[str]) -> re.Pattern:
    return re.compile(flag_format) if flag_format else GENERIC_FLAG_RE


def _snippet(text: str, start: int, end: int, pad: int = 24) -> str:
    lo, hi = max(0, start - pad), min(len(text), end + pad)
    s = text[lo:hi].replace("\n", " ").strip()
    return f"…{s}…" if (lo > 0 or hi < len(text)) else s


def scan_text(text: str, flag_format: Optional[str] = None) -> List[FlagCandidate]:
    """Find direct and decode-ladder flag candidates in one blob of text.

    Direct hits come first (highest trust), then decoded hits ordered by
    increasing decode depth (a shallower encoding is likelier the real flag).
    Duplicate flag values are collapsed to their most-trusted discovery.
    """
    if not isinstance(text, str) or not text:
        return []
    flag_re = _flag_re(flag_format)
    best: dict[str, FlagCandidate] = {}

    def _offer(cand: FlagCandidate, rank: Tuple[int, int]) -> None:
        prev = _ranks.get(cand.value)
        if prev is None or rank < prev:
            _ranks[cand.value] = rank
            best[cand.value] = cand

    _ranks: dict[str, Tuple[int, int]] = {}

    # 1) direct matches
    for m in flag_re.finditer(text):
        c = FlagCandidate(m.group(0), "direct", (), _snippet(text, *m.span()))
        _offer(c, (0, 0))

    # 2) decoded matches. Two seed families feed the ladder:
    #    - encoded-looking TOKENS (base64/hex/base32 blobs are brace-free, so a
    #      flag survives as one token), and
    #    - whole LINES, because transforms like rot13/url/reverse preserve the
    #      `{...}` structure and a token would be split on the braces.
    seeds: List[Tuple[str, str]] = []          # (seed, context)
    for tm in _TOKEN_RE.finditer(text):
        seeds.append((tm.group(0), _snippet(text, *tm.span())))
    for line in text.splitlines():
        line = line.strip()
        if line:
            seeds.append((line, line if len(line) <= 80 else line[:77] + "…"))

    for seed, ctx in seeds:
        for decoded in decode_ladder(seed, flag_format):
            if not decoded.path:
                continue  # depth 0 is the raw seed, already covered above
            for fm in flag_re.finditer(decoded.value):
                _offer(FlagCandidate(fm.group(0), "decoded", decoded.path, ctx),
                       (1, decoded.depth))

    ordered = sorted(best.values(), key=lambda c: (_ranks[c.value], c.value))
    return ordered


def scan_many(
    texts: List[str], flag_format: Optional[str] = None
) -> List[FlagCandidate]:
    """Scan several outputs/files; merge, keeping each value's best discovery."""
    best: dict[str, FlagCandidate] = {}
    rank: dict[str, Tuple[int, int]] = {}
    for t in texts:
        for c in scan_text(t, flag_format):
            r = (0, 0) if c.source == "direct" else (1, len(c.decode_path))
            if c.value not in rank or r < rank[c.value]:
                rank[c.value] = r
                best[c.value] = c
    return sorted(best.values(), key=lambda c: (rank[c.value], c.value))
