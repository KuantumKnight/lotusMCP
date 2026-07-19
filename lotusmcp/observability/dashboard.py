"""Stdlib read-only dashboard + SSE stream.

The dashboard is intentionally small: it serves case state, OpenMetrics, recent
events, and an SSE tail of ``events.jsonl``. It does not mutate cases and does
not become a second source of truth; every response is folded from the case log
or rebuildable projections.
"""
from __future__ import annotations

import argparse
import html
import json
import time
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Iterable, Optional
from urllib.parse import parse_qs, unquote, urlparse

from lotusmcp.kernel.case import Case
from lotusmcp.observability.metrics import render_openmetrics


def list_case_ids(cases_dir: Path) -> list[str]:
    if not cases_dir.exists():
        return []
    return sorted(p.name for p in cases_dir.iterdir()
                  if p.is_dir() and (p / "case.json").exists())


def recent_events(case: Case, after: int = -1, limit: int = 100) -> list[dict]:
    rows = [e for e in case.store.iter_events() if int(e.get("seq", -1)) > after]
    return rows[-max(1, limit):]


def sse_frame(event: str, data, event_id: Optional[int] = None) -> bytes:
    lines: list[str] = []
    if event_id is not None:
        lines.append(f"id: {event_id}")
    if event:
        lines.append(f"event: {event}")
    text = json.dumps(data, sort_keys=True, separators=(",", ":"))
    for line in text.splitlines() or [""]:
        lines.append(f"data: {line}")
    lines.append("")
    return ("\n".join(lines) + "\n").encode("utf-8")


def render_dashboard_html(cases_dir: Path) -> str:
    ids = list_case_ids(cases_dir)
    items = "\n".join(
        f'<li><a href="/case/{html.escape(cid)}/state">{html.escape(cid)}</a> '
        f'<a href="/case/{html.escape(cid)}/events">events</a> '
        f'<a href="/case/{html.escape(cid)}/metrics">metrics</a></li>'
        for cid in ids
    ) or "<li>No cases found.</li>"
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>LotusMCP dashboard</title>
  <style>
    body {{ font-family: system-ui, sans-serif; margin: 2rem; max-width: 80rem; }}
    pre {{ background: #111; color: #eee; padding: 1rem; overflow: auto; }}
    code {{ background: #eee; padding: .1rem .25rem; }}
  </style>
</head>
<body>
  <h1>LotusMCP dashboard</h1>
  <p>Read-only fold of <code>{html.escape(str(cases_dir))}</code>.</p>
  <ul>{items}</ul>
  <p>SSE: <code>/case/&lt;case_id&gt;/stream?after=-1</code></p>
</body>
</html>
"""


class Dashboard:
    def __init__(self, cases_dir) -> None:
        self.cases_dir = Path(cases_dir)

    def case(self, case_id: str) -> Case:
        if "/" in case_id or case_id in ("", ".", ".."):
            raise KeyError(case_id)
        c = Case(self.cases_dir, case_id)
        if not c.meta_path.exists():
            raise KeyError(case_id)
        return c

    def response(self, path: str) -> tuple[int, str, bytes]:
        parsed = urlparse(path)
        parts = [unquote(p) for p in parsed.path.split("/") if p]
        qs = parse_qs(parsed.query)
        if not parts:
            return 200, "text/html; charset=utf-8", render_dashboard_html(self.cases_dir).encode()
        if parts == ["cases"]:
            data = {"cases": list_case_ids(self.cases_dir)}
            return 200, "application/json; charset=utf-8", json.dumps(data).encode()
        if len(parts) == 3 and parts[0] == "case":
            try:
                case = self.case(parts[1])
            except KeyError:
                return 404, "application/json; charset=utf-8", b'{"error":"unknown case"}'
            what = parts[2]
            if what == "state":
                return 200, "text/markdown; charset=utf-8", case.state_md().encode()
            if what == "metrics":
                return 200, "text/plain; version=0.0.4; charset=utf-8", render_openmetrics(case).encode()
            if what == "events":
                after = int(qs.get("after", ["-1"])[0])
                limit = int(qs.get("limit", ["100"])[0])
                body = json.dumps({"events": recent_events(case, after=after, limit=limit)},
                                  sort_keys=True).encode()
                return 200, "application/json; charset=utf-8", body
        return 404, "application/json; charset=utf-8", b'{"error":"not found"}'


def make_handler(cases_dir):
    dashboard = Dashboard(cases_dir)

    class Handler(BaseHTTPRequestHandler):
        server_version = "LotusMCPDashboard/1"

        def log_message(self, fmt, *args):  # noqa: D401
            """Silence default stderr logging; callers can wrap the server."""
            return

        def do_GET(self):  # noqa: N802
            parsed = urlparse(self.path)
            parts = [unquote(p) for p in parsed.path.split("/") if p]
            if len(parts) == 3 and parts[0] == "case" and parts[2] == "stream":
                self._stream(parts[1], parse_qs(parsed.query))
                return
            status, ctype, body = dashboard.response(self.path)
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _stream(self, case_id: str, qs):
            try:
                case = dashboard.case(case_id)
            except KeyError:
                self.send_response(HTTPStatus.NOT_FOUND)
                self.end_headers()
                return
            after = int(qs.get("after", ["-1"])[0])
            poll = max(0.1, float(qs.get("poll", ["1.0"])[0]))
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "text/event-stream; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Connection", "keep-alive")
            self.end_headers()
            try:
                while True:
                    sent = False
                    for ev in recent_events(case, after=after, limit=500):
                        after = int(ev["seq"])
                        self.wfile.write(sse_frame("event", ev, event_id=after))
                        self.wfile.flush()
                        sent = True
                    if not sent:
                        self.wfile.write(b": keepalive\n\n")
                        self.wfile.flush()
                    time.sleep(poll)
            except (BrokenPipeError, ConnectionResetError):
                return

    return Handler


def serve(cases_dir, host: str = "127.0.0.1", port: int = 8765) -> None:
    httpd = ThreadingHTTPServer((host, int(port)), make_handler(cases_dir))
    print(f"LotusMCP dashboard: http://{host}:{port}/")
    httpd.serve_forever()


def main(argv: Optional[Iterable[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="LotusMCP read-only dashboard/SSE server")
    ap.add_argument("--cases-dir", default="cases")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8765)
    args = ap.parse_args(list(argv) if argv is not None else None)
    serve(args.cases_dir, host=args.host, port=args.port)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
