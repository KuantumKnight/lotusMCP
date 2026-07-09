"""THE single entity-identity function.

Every subsystem (Executor parsers, playbooks, the graph projector) derives
entity ids from this one function, so two tools that independently discover
the same port/endpoint emit the *same* id and the projector merges them by
idempotent upsert instead of racing. This is the structural fix for dedup.

    entity_id = "e_" + blake2b_128( kind || 0x1F || canonical(natural_key) )
"""
from __future__ import annotations

import hashlib
from typing import Any, Mapping

from lotusmcp.kernel.canonical import canonical

_SEP = b"\x1f"


def entity_id(kind: str, natural_key: Mapping[str, Any]) -> str:
    payload = kind.encode("utf-8") + _SEP + canonical(natural_key).encode("utf-8")
    return "e_" + hashlib.blake2b(payload, digest_size=16).hexdigest()


def key_display(kind: str, natural_key: Mapping[str, Any]) -> str:
    """Human-readable derived label, e.g. service.http:10.10.11.5:80."""
    vals = ":".join(str(v) for v in natural_key.values())
    return f"{kind}:{vals}"
