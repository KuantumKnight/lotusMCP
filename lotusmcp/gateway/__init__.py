"""MCP gateway — the ONE surface resolver.

Claude Resources and ChatGPT `fetch()` both resolve `lotus://` URIs through the
single `Resolver` here, so the two profiles can never drift (§3). `search()`
implements the ChatGPT deep-research contract over the same graph.
"""
from lotusmcp.gateway.resolver import Resolver, parse_uri

__all__ = ["Resolver", "parse_uri"]
