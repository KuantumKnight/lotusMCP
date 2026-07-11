"""Tool-profile filtering + envelope caps for the MCP surface (Phase 5).

LITE (ChatGPT deep-research, read-only, tool-budget-bound) must be a strict
subset of FULL (Claude/operator), must contain the mandatory search/fetch pair,
and must exclude the exec/ops/scrape tools. Envelope caps bound any tool result
without ever truncating silently.

    PYTHONPATH=. PYTHONIOENCODING=utf-8 python tests/test_tool_profile.py
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from lotusmcp.gateway.profile import (
    DEFAULT_ENVELOPE_BYTES, FULL, LITE, MANDATORY_LITE, TOOL_CATEGORY,
    enforce_envelope, is_enabled, normalize_profile, tools_for,
)


def _nbytes(v):
    if isinstance(v, str):
        return len(v.encode("utf-8"))
    return len(json.dumps(v, ensure_ascii=False, sort_keys=True).encode("utf-8"))


def test_lite_is_strict_subset_of_full():
    lite, full = set(tools_for(LITE)), set(tools_for(FULL))
    assert lite < full, "LITE must be a strict subset of FULL"
    assert full == set(TOOL_CATEGORY), "FULL must expose every registered tool"
    print(f"LITE={len(lite)} tools, FULL={len(full)} tools")


def test_mandatory_and_excluded_lite_tools():
    lite = set(tools_for(LITE))
    for t in MANDATORY_LITE:
        assert t in lite, f"{t} is mandatory for deep research and missing from LITE"
    # exec / ops / scrape must never leak into the read-only LITE client
    for t in ("session_edit_run", "session_close", "session_list",
              "case_compact", "case_metrics"):
        assert t not in lite, f"{t} must be FULL-only"
    # but they ARE in FULL
    for t in ("session_edit_run", "case_compact", "case_metrics"):
        assert is_enabled(t, FULL)
    print("search/fetch in LITE; exec/ops/scrape FULL-only")


def test_is_enabled_consistency_and_errors():
    for name in TOOL_CATEGORY:
        assert is_enabled(name, FULL)
        assert is_enabled(name, LITE) == (name in set(tools_for(LITE)))
    try:
        is_enabled("nope_tool", FULL); raise AssertionError("unregistered should raise")
    except KeyError:
        pass
    try:
        is_enabled("search", "MEGA"); raise AssertionError("bad profile should raise")
    except ValueError:
        pass
    print("is_enabled agrees with tools_for; unknown tool/profile rejected")


def test_normalize_profile():
    assert normalize_profile("lite") == LITE
    assert normalize_profile("FULL") == FULL
    assert normalize_profile("  Lite ") == LITE
    assert normalize_profile(None) == FULL
    assert normalize_profile("garbage") == FULL   # safe default
    print("profile normalization + safe default OK")


def test_envelope_passes_small_values_untouched():
    for v in ["short", {"a": 1, "text": "hi"}, [1, 2, 3], 42]:
        out, report = enforce_envelope(v, max_bytes=1000)
        assert out == v and report is None, v
    print("under-cap values pass through untouched")


def test_envelope_truncates_string_and_reports():
    big = "A" * 10000
    out, report = enforce_envelope(big, max_bytes=1000)
    assert _nbytes(out) <= 1000, _nbytes(out)
    assert report and report["bytes_dropped"] > 0
    assert "truncated by envelope cap" in out          # non-silent, in-band marker
    print(f"string capped to {_nbytes(out)}B, dropped {report['bytes_dropped']}")


def test_envelope_trims_document_dict_text_field():
    doc = {"id": "u", "title": "t", "url": "u", "metadata": {"k": "v"},
           "text": "X" * 20000}
    out, report = enforce_envelope(doc, max_bytes=2000)
    assert _nbytes(out) <= 2000, _nbytes(out)
    assert out["id"] == "u" and out["title"] == "t"    # structure preserved
    assert report["fields_trimmed"].get("text", 0) > 0
    assert out["_envelope"]["fields_trimmed"]["text"] > 0
    print(f"doc dict trimmed to {_nbytes(out)}B via 'text' field")


def test_envelope_drops_list_tail_with_sentinel():
    items = [{"id": i, "blob": "z" * 500} for i in range(200)]
    out, report = enforce_envelope(items, max_bytes=4000)
    assert _nbytes(out) <= 4000, _nbytes(out)
    assert report["items_dropped"] > 0
    assert out[-1]["_envelope_truncated"]["items_dropped"] == report["items_dropped"]
    # kept items are intact prefix of the original
    kept = [x for x in out if "_envelope_truncated" not in x]
    assert kept == items[:len(kept)]
    print(f"list capped: kept {report['items_kept']}, dropped {report['items_dropped']}")


def test_envelope_idempotent():
    doc = {"text": "Q" * 50000, "id": "x"}
    once, _ = enforce_envelope(doc, max_bytes=3000)
    twice, report2 = enforce_envelope(once, max_bytes=3000)
    assert report2 is None, "second pass should be a no-op (already within cap)"
    assert once == twice
    print("envelope enforcement is idempotent")


def test_default_cap_leaves_state_md_sized_output_untouched():
    # a ~6.5k-token STATE.md is well under the 64KB backstop
    state_like = "line of case state\n" * 1200      # ~22KB
    assert _nbytes(state_like) < DEFAULT_ENVELOPE_BYTES
    out, report = enforce_envelope(state_like)
    assert out == state_like and report is None
    print(f"{_nbytes(state_like)}B STATE.md-sized output < {DEFAULT_ENVELOPE_BYTES}B cap, untouched")


TESTS = [v for k, v in sorted(globals().items()) if k.startswith("test_")]

if __name__ == "__main__":
    import traceback
    failed = 0
    for t in TESTS:
        try:
            t()
            print(f"ok   {t.__name__}")
        except Exception:  # noqa: BLE001
            failed += 1
            print(f"FAIL {t.__name__}")
            traceback.print_exc()
    print(f"\n{len(TESTS)-failed}/{len(TESTS)} passed")
    sys.exit(1 if failed else 0)
