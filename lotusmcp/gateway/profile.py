"""Tool profiles + envelope caps for the MCP surface (Phase 5).

Two client profiles share ONE server. The ChatGPT deep-research connector has a
hard tool-count budget and is read-only, so it gets the **LITE** profile; Claude
and operators get **FULL**. Which tools appear in which profile is decided here,
declaratively and WITHOUT importing the MCP SDK, so the split is unit-testable
and the two profiles can never silently drift.

Tool *outputs* are bounded here too: `enforce_envelope` caps a result's
serialized size so a single call can't blow a client's context, and it never
truncates silently — every trim is both marked in-band and reported.

LITE is always a strict subset of FULL. Membership is by category, so adding a
tool is one line in `TOOL_CATEGORY` (plus the server registration):

    read / flag / bridge / replay / case  -> both profiles (safe, read-mostly)
    exec / ops / scrape                    -> FULL only (mutation, maintenance, scrape)
"""
from __future__ import annotations

import json
import os
from typing import Any, Dict, List, Optional, Tuple

LITE = "LITE"
FULL = "FULL"
PROFILES = (LITE, FULL)

# category -> the minimum profile that exposes it. A LITE category is in both
# profiles; a FULL category is FULL-only.
_CATEGORY_MIN_PROFILE = {
    "case": LITE,     # create_case
    "read": LITE,     # get_state, kb_query, kb_get, case_resume
    "plan": LITE,     # lotus_next, technique_suggest  (advisory, read-only)
    "library": FULL,  # technique_promote  (human-reviewed cross-case promotion)
    "flag": LITE,     # flag_scan
    "bridge": LITE,   # search, fetch  (the mandatory deep-research pair)
    "replay": LITE,   # case_replay, case_diff, case_writeup
    "scrape": FULL,   # case_metrics  (Prometheus exposition, not a research tool)
    "ops": FULL,      # case_compact  (projection maintenance)
    "exec": FULL,     # session_*, propose_and_run  (Kali-touching execution)
    "submit": FULL,   # lotus_submit  (consequential platform submission)
}

# name -> category. The single registry the profile filter and the server share.
TOOL_CATEGORY = {
    "create_case": "case",
    "get_state": "read",
    "kb_query": "read",
    "kb_get": "read",
    "kb_artifact": "read",
    "case_resume": "read",
    "lotus_next": "plan",
    "technique_suggest": "plan",
    "technique_promote": "library",
    "propose_and_run": "exec",
    "lotus_submit": "submit",
    "flag_scan": "flag",
    "search": "bridge",
    "fetch": "bridge",
    "case_replay": "replay",
    "case_diff": "replay",
    "case_writeup": "replay",
    "case_repro": "replay",
    "case_metrics": "scrape",
    "case_compact": "ops",
    "case_gc": "ops",
    "session_edit_run": "exec",
    "session_close": "exec",
    "session_list": "exec",
}

# The deep-research contract REQUIRES exactly this pair in LITE.
MANDATORY_LITE = ("search", "fetch")


def normalize_profile(value: Optional[str]) -> str:
    """Coerce an env/user string to a valid profile; default FULL."""
    p = (value or FULL).strip().upper()
    return p if p in PROFILES else FULL


def _category_visible(profile: str, category: str) -> bool:
    if category not in _CATEGORY_MIN_PROFILE:
        raise KeyError(f"unknown tool category {category!r}")
    return profile == FULL or _CATEGORY_MIN_PROFILE[category] == LITE


def is_enabled(name: str, profile: str) -> bool:
    """Is tool `name` exposed under `profile`?"""
    if profile not in PROFILES:
        raise ValueError(f"unknown profile {profile!r}")
    cat = TOOL_CATEGORY.get(name)
    if cat is None:
        raise KeyError(f"unregistered tool {name!r}")
    return _category_visible(profile, cat)


def tools_for(profile: str) -> List[str]:
    """The sorted tool names exposed under `profile`."""
    if profile not in PROFILES:
        raise ValueError(f"unknown profile {profile!r}")
    return [n for n in sorted(TOOL_CATEGORY) if _category_visible(profile, TOOL_CATEGORY[n])]


# --------------------------------------------------------------- envelope caps
# Backstop only: generous enough that the already token-bounded STATE.md and
# resume packet (~6.5k tokens) pass untouched; catches runaway text (writeup
# markdown, a fat fetched document) before it reaches the client.
DEFAULT_ENVELOPE_BYTES = 64 * 1024

# dict fields that carry the bulk text of a document, trimmed first.
_TEXT_KEYS = ("text", "markdown", "state_md", "snippet")


def _nbytes(v: Any) -> int:
    if isinstance(v, str):
        return len(v.encode("utf-8"))
    return len(json.dumps(v, ensure_ascii=False, sort_keys=True).encode("utf-8"))


def _truncate_str(s: str, max_bytes: int) -> Tuple[str, int]:
    """Cut `s` so its UTF-8 length (with an explicit marker) fits `max_bytes`.
    Returns (new_string, bytes_dropped); bytes_dropped==0 means untouched."""
    b = s.encode("utf-8")
    if len(b) <= max_bytes:
        return s, 0
    reserve = 96  # room for the marker
    keep = max(0, max_bytes - reserve)
    head = b[:keep].decode("utf-8", "ignore")
    dropped = len(b) - len(head.encode("utf-8"))
    marker = f"\n…[{dropped} bytes truncated by envelope cap; fetch for full detail]"
    return head + marker, dropped


def enforce_envelope(value: Any, max_bytes: int = DEFAULT_ENVELOPE_BYTES) -> Tuple[Any, Optional[Dict[str, Any]]]:
    """Bound a tool result to `max_bytes` of serialized UTF-8.

    Returns `(value, report)`. `report` is None if nothing was trimmed; else a
    dict describing the trim (also mirrored in-band so a client sees it without
    inspecting the return tuple). Handles the three shapes tools return:
      * str  — truncated with a marker.
      * dict — the biggest text-bearing field(s) truncated; a `_envelope`
               key records what happened.
      * list — trailing items dropped; a final `{"_envelope_truncated": ...}`
               sentinel records the drop.
    Idempotent: a value already within the cap is returned unchanged.
    """
    if _nbytes(value) <= max_bytes:
        return value, None

    if isinstance(value, str):
        s, dropped = _truncate_str(value, max_bytes)
        return s, {"bytes_dropped": dropped}

    if isinstance(value, list):
        kept: List[Any] = []
        # reserve space for the sentinel we will append
        budget = max_bytes - 160
        for item in value:
            trial = kept + [item]
            if _nbytes(trial) > budget:
                break
            kept.append(item)
        dropped = len(value) - len(kept)
        if dropped == 0 and kept:
            # a single oversized element — shrink it recursively
            kept[0], _ = enforce_envelope(kept[0], budget)
        report = {"items_dropped": dropped, "items_kept": len(kept),
                  "reason": "envelope cap; refine the query or fetch detail"}
        return kept + [{"_envelope_truncated": report}], report

    if isinstance(value, dict):
        out = dict(value)
        report: Dict[str, Any] = {"fields_trimmed": {}}
        # trim known bulk-text fields largest-first until we fit.
        candidates = sorted(
            (k for k in out if isinstance(out[k], str)),
            key=lambda k: (_nbytes(out[k]), k in _TEXT_KEYS), reverse=True,
        )
        for k in candidates:
            if _nbytes(out) <= max_bytes:
                break
            # give this field whatever budget remains after the rest of the dict
            rest = _nbytes({kk: vv for kk, vv in out.items() if kk != k})
            field_budget = max(0, max_bytes - rest - 64)
            new_s, dropped = _truncate_str(out[k], field_budget)
            if dropped:
                out[k] = new_s
                report["fields_trimmed"][k] = dropped
        out["_envelope"] = report
        return out, report

    # unknown scalar type: stringify and cap.
    s, dropped = _truncate_str(str(value), max_bytes)
    return s, {"bytes_dropped": dropped, "coerced": True}
