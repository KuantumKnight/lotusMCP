"""OpenMetrics exposition — valid format, correct values, pure fold (Phase 6).

    PYTHONPATH=. PYTHONIOENCODING=utf-8 python tests/test_metrics.py
"""
from __future__ import annotations

import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from lotusmcp.kernel.case import Case  # noqa: E402
from lotusmcp.kernel.events import EventDraft  # noqa: E402
from lotusmcp.observability import render_openmetrics  # noqa: E402

FMT = r"flag\{[^}]+\}"


def _case(tmp):
    case = Case.create(tmp, "m1", title="t", category="web", flag_format=FMT)
    case.append(EventDraft("entity.asserted", {"kind": "executor", "name": "nmap"},
                           {"kind": "service.http",
                            "natural_key": {"host": "10.10.11.5", "proto": "tcp", "port": 80}}))
    case.append(EventDraft("finding.raised", {"kind": "executor", "name": "x"},
                           {"id": "F1", "type": "sqli", "severity": "high",
                            "confidence": 0.9, "subject": {}, "attrs": {}}))
    case.append(EventDraft("case.status_changed", {"kind": "system", "name": "e"},
                           {"phase": "RECON", "reason": "ok"}))
    return case


def _series(text, name):
    return [ln for ln in text.splitlines()
            if ln.startswith(name + "{") or ln == name or ln.startswith(name + " ")]


def test_valid_openmetrics_shape():
    with tempfile.TemporaryDirectory() as d:
        text = render_openmetrics(_case(d))
        assert text.endswith("# EOF\n"), "OpenMetrics must terminate with # EOF"
        assert "# TYPE lotus_events_total counter" in text
        assert "# TYPE lotus_entities gauge" in text
        assert "# HELP lotus_findings" in text


def test_values_reflect_state():
    with tempfile.TemporaryDirectory() as d:
        text = render_openmetrics(_case(d))
        # 1 entity, 1 high finding
        assert 'lotus_entities{case="m1"} 1' in text
        assert 'lotus_findings{case="m1",severity="high"} 1' in text
        # phase info carries the current phase as a label with value 1
        assert 'lotus_phase_info{case="m1",phase="RECON"} 1' in text
        # events counted by type (case.created + 3 appended = 4)
        assert 'lotus_events_total{case="m1"} 4' in text


def test_pure_fold_stable_across_calls():
    with tempfile.TemporaryDirectory() as d:
        case = _case(d)
        assert render_openmetrics(case) == render_openmetrics(case)


def test_flag_verified_counter():
    with tempfile.TemporaryDirectory() as d:
        case = _case(d)
        assert 'lotus_flags_verified{case="m1"} 0' in render_openmetrics(case)
        case.append(EventDraft("flag.verified", {"kind": "system", "name": "f"},
                               {"value": "flag{x_r3al_y}"}))
        assert 'lotus_flags_verified{case="m1"} 1' in render_openmetrics(case)


def test_label_escaping():
    # a category with a quote must not break the exposition format
    with tempfile.TemporaryDirectory() as d:
        case = Case.create(d, "m2", title='he said "hi"', category="web", flag_format=FMT)
        text = render_openmetrics(case)
        assert text.endswith("# EOF\n")


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
