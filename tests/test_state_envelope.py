"""Envelope / load test (§7 Phase 5): a huge case still renders a small, fast
STATE.md. Design target: 5000-endpoint case renders in <100 ms and ≤6.5k tokens.

    PYTHONPATH=. PYTHONIOENCODING=utf-8 python tests/test_state_envelope.py
"""
from __future__ import annotations

import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from lotusmcp.kernel.case import Case  # noqa: E402
from lotusmcp.kernel.events import EventDraft  # noqa: E402
from lotusmcp.kernel.state import CAP_ENDPOINTS, render_state_md  # noqa: E402

FMT = r"flag\{[^}]+\}"
TOKEN_BUDGET = 6500
CHARS_PER_TOKEN = 4


def _big_case(tmp, n_endpoints):
    case = Case.create(tmp, "big", title="huge", category="web", flag_format=FMT)
    case.append(EventDraft("entity.asserted", {"kind": "executor", "name": "nmap"},
                           {"kind": "service.http",
                            "natural_key": {"host": "10.10.11.5", "proto": "tcp", "port": 80}}))
    for i in range(n_endpoints):
        case.append(EventDraft("entity.asserted", {"kind": "executor", "name": "ffuf"},
                               {"kind": "http.endpoint",
                                "natural_key": {"host": "10.10.11.5",
                                                "method": "GET", "path": f"/e{i}"}}))
    return case


def test_state_md_stays_bounded_at_scale():
    with tempfile.TemporaryDirectory() as d:
        case = _big_case(d, 5000)
        built = case.rebuild()
        t0 = time.perf_counter()
        md = render_state_md(built["graph_db"], case.meta)
        dt = time.perf_counter() - t0

        est_tokens = len(md) // CHARS_PER_TOKEN
        assert est_tokens <= TOKEN_BUDGET, f"{est_tokens} tokens > {TOKEN_BUDGET}"
        # design target is <100 ms; assert a jitter-tolerant bound that still
        # catches an O(N) regression (observed ~3 ms on 5000 endpoints).
        assert dt < 0.25, f"render took {dt*1000:.1f} ms on 5000 endpoints"
        # the endpoint section is capped regardless of case size
        assert md.count("`GET ") <= CAP_ENDPOINTS
        assert "CASE big" in md


def test_state_md_scales_sublinearly():
    # 10x more endpoints must not grow STATE.md (hard caps → flat size)
    with tempfile.TemporaryDirectory() as d1, tempfile.TemporaryDirectory() as d2:
        small = render_state_md(_big_case(d1, 200).rebuild()["graph_db"],
                                Case(d1, "big").meta)
        large = render_state_md(_big_case(d2, 2000).rebuild()["graph_db"],
                                Case(d2, "big").meta)
        assert abs(len(large) - len(small)) < 200, "STATE.md must not grow with N"


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
