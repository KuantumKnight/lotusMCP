"""Observability (Phase 6): OpenMetrics exposition over the case projections.

Like every other artifact, metrics are a pure fold of the log/graph — no
counters mutated at call sites, so a scrape is always consistent with the state
the graph reports. The SSE dashboard streams these same numbers.
"""
from lotusmcp.observability.metrics import render_openmetrics
from lotusmcp.observability.dashboard import Dashboard, recent_events, render_dashboard_html, sse_frame

__all__ = [
    "render_openmetrics",
    "Dashboard", "recent_events", "render_dashboard_html", "sse_frame",
]
