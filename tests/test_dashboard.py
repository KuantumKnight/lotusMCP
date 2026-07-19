"""Read-only dashboard/SSE helpers.

    PYTHONPATH=. PYTHONIOENCODING=utf-8 python tests/test_dashboard.py
"""
from __future__ import annotations

import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from lotusmcp.kernel.case import Case  # noqa: E402
from lotusmcp.kernel.events import EventDraft  # noqa: E402
from lotusmcp.observability.dashboard import Dashboard, list_case_ids, recent_events, sse_frame  # noqa: E402


def _case(base):
    c = Case.create(base, "dash", title="dash", category="web",
                    flag_format=r"flag\{[^}]+\}")
    c.append(EventDraft("entity.asserted", {"kind": "executor", "name": "seed"},
                        {"kind": "host", "natural_key": {"addr": "10.10.11.53"}}))
    return c


def test_case_listing_and_recent_events():
    with tempfile.TemporaryDirectory() as d:
        c = _case(d)
        assert list_case_ids(c.dir.parent) == ["dash"]
        rows = recent_events(c, after=0)
        assert rows and all(e["seq"] > 0 for e in rows)


def test_sse_frame_shape():
    frame = sse_frame("event", {"seq": 1, "type": "x"}, event_id=1).decode()
    assert frame.startswith("id: 1\nevent: event\n")
    assert 'data: {"seq":1,"type":"x"}' in frame
    assert frame.endswith("\n\n")


def test_dashboard_routes_are_read_only():
    with tempfile.TemporaryDirectory() as d:
        c = _case(d)
        before = c.store.tip
        dash = Dashboard(d)
        status, ctype, body = dash.response("/")
        assert status == 200 and "text/html" in ctype and b"LotusMCP" in body
        status, ctype, body = dash.response("/cases")
        assert status == 200 and json.loads(body)["cases"] == ["dash"]
        status, ctype, body = dash.response("/case/dash/state")
        assert status == 200 and "text/markdown" in ctype and b"10.10.11.53" in body
        status, ctype, body = dash.response("/case/dash/metrics")
        assert status == 200 and b"lotus_events_total" in body
        status, ctype, body = dash.response("/case/dash/events?after=-1&limit=1")
        assert status == 200 and len(json.loads(body)["events"]) == 1
        assert Case(d, "dash").store.tip == before


def test_dashboard_rejects_unknown_case():
    with tempfile.TemporaryDirectory() as d:
        status, _ctype, body = Dashboard(d).response("/case/missing/state")
        assert status == 404 and b"unknown case" in body


if __name__ == "__main__":
    import traceback

    fns = [v for k, v in sorted(globals().items())
           if k.startswith("test_") and callable(v)]
    failed = 0
    for fn in fns:
        try:
            fn()
            print(f"  ok  {fn.__name__}")
        except Exception:  # noqa: BLE001
            failed += 1
            print(f"FAIL  {fn.__name__}")
            traceback.print_exc()
    print(f"\n{len(fns) - failed}/{len(fns)} passed")
    sys.exit(1 if failed else 0)
