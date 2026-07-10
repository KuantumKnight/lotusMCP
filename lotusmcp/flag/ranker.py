"""Confidence ranker, decoy filter, and the 4-tier flag registry.

A scanner hit is only a *candidate*. The ranker turns candidates into ranked
flags with a confidence and a tier, so the submit policy can decide what (if
anything) is worth spending a precious platform-oracle attempt on.

The 4-tier registry (highest trust first):

  - **T1 CONFIRMED** — the platform oracle said yes. Terminal; only the submit
    policy can promote here, never the ranker.
  - **T2 STRONG**    — verbatim match of the *operator-set* flag format, not a
    decoy. The default auto-submit tier.
  - **T3 DECODED**   — reached only via the decode ladder (shallow), or a match
    of the generic fallback format. Plausible; submit if nothing stronger.
  - **T4 WEAK**      — decoy-suspected, deep-decoded, or otherwise low trust.
    Never auto-submitted; surfaced to a human.

Pure and deterministic: no clocks, no randomness, stable tie-breaks.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import List, Optional, Sequence

from lotusmcp.flag.scanner import FlagCandidate

T1_CONFIRMED = 1
T2_STRONG = 2
T3_DECODED = 3
T4_WEAK = 4

TIER_NAME = {1: "CONFIRMED", 2: "STRONG", 3: "DECODED", 4: "WEAK"}

# Substrings that betray a placeholder / example / troll flag. Matched against
# the flag's inner content, case-insensitively.
_DECOY_MARKERS = [
    "not_the_flag", "nottheflag", "not the flag", "nottherealflag",
    "fake", "decoy", "example", "sample", "placeholder", "changeme",
    "your_flag_here", "yourflaghere", "flag_here", "redacted", "try_harder",
    "tryharder", "nope", "wrong", "n0t_the_flag", "this_is_not",
    "testflag", "test_flag", "dummy",
]
# Content that is obviously filler rather than a real flag body.
_FILLER_RE = re.compile(r"^(?:x+|a+|\.+|\?+|-+|test|flag|example)$", re.IGNORECASE)


@dataclass(frozen=True)
class RankedFlag:
    value: str
    tier: int
    confidence: float
    is_decoy: bool
    reason: str
    source: str
    decode_path: tuple = ()

    @property
    def tier_name(self) -> str:
        return TIER_NAME[self.tier]

    @property
    def value_sha(self) -> str:
        import hashlib
        return "sha256:" + hashlib.sha256(self.value.encode("utf-8")).hexdigest()


def _inner(value: str) -> str:
    """The bit inside the braces, or the whole value if unbraced."""
    m = re.search(r"\{([^}]*)\}", value)
    return (m.group(1) if m else value).strip().lower()


def is_decoy(value: str, extra_markers: Sequence[str] = ()) -> bool:
    inner = _inner(value)
    if not inner or _FILLER_RE.match(inner):
        return True
    markers = list(_DECOY_MARKERS) + [m.lower() for m in extra_markers]
    return any(mark in inner for mark in markers)


def rank(
    candidates: Sequence[FlagCandidate],
    has_operator_format: bool = True,
    extra_decoys: Sequence[str] = (),
) -> List[RankedFlag]:
    """Score and tier candidates, best-first (tier asc, then confidence desc).

    `has_operator_format` is False when the scan fell back to the generic
    `word{...}` shape — a match then proves shape, not authority, so it is
    capped at T3.
    """
    ranked: List[RankedFlag] = []
    for c in candidates:
        decoy = is_decoy(c.value, extra_decoys)
        depth = len(c.decode_path)

        if decoy:
            tier, conf, reason = T4_WEAK, 0.05, "matches a known decoy/placeholder pattern"
        elif c.source == "direct":
            if has_operator_format:
                tier, conf, reason = T2_STRONG, 0.9, "verbatim operator-format match"
            else:
                tier, conf, reason = T3_DECODED, 0.6, "generic-format match (format unverified)"
        else:  # decoded
            conf = max(0.35, 0.82 - 0.12 * depth)
            if has_operator_format and depth <= 2:
                tier, reason = T3_DECODED, f"recovered via {'->'.join(c.decode_path)}"
            else:
                tier, reason = T4_WEAK, f"deep/low-trust decode via {'->'.join(c.decode_path)}"
                conf = min(conf, 0.4)
            if not has_operator_format:
                conf = min(conf, 0.45)

        ranked.append(RankedFlag(
            value=c.value, tier=tier, confidence=round(conf, 3),
            is_decoy=decoy, reason=reason, source=c.source,
            decode_path=c.decode_path,
        ))

    ranked.sort(key=lambda r: (r.tier, -r.confidence, r.value))
    return ranked
