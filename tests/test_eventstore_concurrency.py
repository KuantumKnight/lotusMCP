"""EventStore cross-handle serialization.

The serializer must be safe when two MCP tool processes have already opened
the same case. Each append must reload the chain tail under the process lock;
otherwise the second writer can reuse a stale seq/hash from construction time.
"""
from __future__ import annotations

import tempfile
from pathlib import Path

from lotusmcp.kernel.events import EventDraft
from lotusmcp.kernel.log import EventStore


def _note(text: str) -> EventDraft:
    return EventDraft(
        type="note.added",
        actor={"kind": "system", "name": "test"},
        payload={"text": text},
    )


def test_two_open_stores_do_not_reuse_stale_tail():
    base = Path(tempfile.mkdtemp(prefix="lotus_eventstore_concurrency_"))
    case_dir = base / "race"
    a = EventStore(case_dir)
    b = EventStore(case_dir)

    first = a.append(_note("first"))
    second = b.append(_note("second"))

    assert first["seq"] == 0
    assert second["seq"] == 1
    assert second["prev_hash"] == first["hash"]
    assert EventStore(case_dir).verify_chain() == -1


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items())
           if k.startswith("test_") and callable(v)]
    failed = 0
    for fn in fns:
        try:
            fn()
            print(f"  ok  {fn.__name__}")
        except Exception as e:
            failed += 1
            print(f"FAIL  {fn.__name__}: {e}")
    print(f"\n{len(fns)-failed}/{len(fns)} passed")
    raise SystemExit(1 if failed else 0)
