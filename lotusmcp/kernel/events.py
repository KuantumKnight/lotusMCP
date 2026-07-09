"""Event drafts and the canonical envelope.

Tools/LLM/human never write files directly. They construct an EventDraft and
hand it to the Case Kernel's single serializer (`log.EventStore.append`),
which assigns seq/event_id/ts, chains prev_hash->hash, and appends. Payloads
are capped at 16 KB; anything larger MUST be an artifact reference so a line
can never tear.
"""
from __future__ import annotations

import os
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

MAX_PAYLOAD_BYTES = 16 * 1024
SCHEMA_V = 4

# The single event namespace shared by every subsystem.
EVENT_TYPES = {
    # command lifecycle (Executor)
    "command.requested", "command.authorized", "command.denied",
    "command.started", "command.output", "command.completed",
    "command.failed", "command.timeout", "command.killed",
    # knowledge (OutputAdapters, deterministic)
    "entity.asserted", "attribute.asserted", "relation.asserted",
    "finding.raised", "finding.updated", "finding.retracted", "finding.superseded",
    # reasoning (LLM tools only)
    "note.added", "hypothesis.proposed", "hypothesis.updated",
    "evidence.linked", "attempt.started", "attempt.result",
    "deadend.marked", "decision.made", "plan.updated", "memory.summary",
    # interactive session (Regime B)
    "session.opened", "script.revised", "script.run", "session.closed",
    # status / flag
    "flag.candidate", "flag.submitted", "flag.verified", "flag.rejected",
    "case.status_changed", "case.created",
    # budget / session
    "budget.consumed", "session.started", "session.ended",
    # reuse / writeup
    "technique.suggested", "technique.applied", "technique.promoted",
    "writeup.generated", "writeup.claim_rejected",
}


def _ulid() -> str:
    """48-bit ms timestamp + 80-bit randomness, Crockford base32 (26 chars)."""
    ts = int(time.time() * 1000)
    rnd = int.from_bytes(os.urandom(10), "big")
    val = (ts << 80) | rnd
    alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
    out = []
    for _ in range(26):
        out.append(alphabet[val & 31])
        val >>= 5
    return "".join(reversed(out))


def _now_iso() -> str:
    # gmtime avoids locale/timezone drift; second precision is enough for metadata.
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


@dataclass
class EventDraft:
    type: str
    actor: Dict[str, Any]            # {kind: executor|llm|human|system|planner, name, version?}
    payload: Dict[str, Any]
    confidence: Optional[float] = None
    idempotency_key: Optional[str] = None
    causation_id: Optional[str] = None
    correlation_id: Optional[str] = None
    provenance: Optional[Dict[str, Any]] = None
    redactions: List[Dict[str, Any]] = field(default_factory=list)

    def validate(self) -> None:
        if self.type not in EVENT_TYPES:
            raise ValueError(f"unknown event type: {self.type}")
        if "kind" not in self.actor:
            raise ValueError("actor.kind is required")
