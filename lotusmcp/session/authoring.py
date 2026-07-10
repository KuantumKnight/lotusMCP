"""Script authoring + running — the two injected seams of a Regime-B session.

`session_edit_run` is *write/patch an exploit script, then run it against the
tube* (§3 tool table). Two responsibilities sit behind narrow interfaces so the
whole loop is deterministic and testable:

- **ScriptAuthor** — authors / revises the exploit script from the goal, the
  bound target, and the output of prior runs. In production this is the ONE
  metered `LLMGateway` (the only Regime-B LLM responsibility, §4.1); offline it
  is the rule-based `DeterministicScriptAuthor`, which walks a fixed strategy
  list so a session converges with no model.
- **ScriptRunner** — runs an authored script against the tube and returns its
  captured stdout. In production it executes the real script in the sandbox
  (pwntools/angr/z3/…) with the tube it opened; offline the
  `DeterministicScriptRunner` drives the `ScriptedTube` with the script's
  planned `sends` and concatenates what comes back.

Neither the author nor the runner touches the log; the session appends every
event through the one serializer (so all captured output is redacted first).
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any, Dict, List, Protocol, Sequence, Tuple

from lotusmcp.session.tube import Tube


@dataclass(frozen=True)
class Script:
    """One revision of an exploit script bound to an in-scope target entity."""

    rev: int
    target_id: str
    sends: Tuple[str, ...] = ()      # lines the script drives into the tube
    text: str = ""                   # the script source (rendered/real)
    note: str = ""                   # author's one-line intent for this revision

    def sha(self) -> str:
        return hashlib.blake2b(self.text.encode("utf-8"), digest_size=8).hexdigest()


@dataclass(frozen=True)
class RunOutput:
    rev: int
    stdout: str = ""
    ok: bool = True
    transcript: Tuple[Tuple[str, str], ...] = ()


class ScriptAuthor(Protocol):
    def author(
        self, goal: str, entity: Dict[str, Any], prior: List[RunOutput], rev: int
    ) -> Script: ...


class ScriptRunner(Protocol):
    def run(self, script: Script, tube: Tube) -> RunOutput: ...


def _render(target_id: str, sends: Sequence[str], note: str) -> str:
    """A readable stand-in for the real script source (what would be written to
    `sessions/<sid>/script.rev<N>.py`)."""
    lines = ["#!/usr/bin/env python3",
             "from pwntools import remote  # sandboxed",
             f"# intent: {note}" if note else "# intent: (none)",
             f"io = remote_for({target_id!r})"]
    for s in sends:
        lines.append(f"io.sendline({s!r}); print(io.recvline())")
    return "\n".join(lines) + "\n"


class DeterministicScriptAuthor:
    """Rule-based author: on revision `rev` it emits `strategies[rev]` (clamped
    to the last strategy). Each strategy is the list of lines that revision's
    script drives into the tube — modelling the LLM iterating approaches until
    one makes the service yield the flag. No network, no model."""

    def __init__(self, strategies: Sequence[Sequence[str]], goal_note: str = "exploit") -> None:
        if not strategies:
            raise ValueError("author needs at least one strategy")
        self.strategies: List[Tuple[str, ...]] = [tuple(s) for s in strategies]
        self.goal_note = goal_note

    def author(
        self, goal: str, entity: Dict[str, Any], prior: List[RunOutput], rev: int
    ) -> Script:
        sends = self.strategies[min(rev, len(self.strategies) - 1)]
        note = f"{self.goal_note} attempt {rev + 1}"
        return Script(rev=rev, target_id=entity.get("id", "?"), sends=sends,
                      text=_render(entity.get("id", "?"), sends, note), note=note)


class DeterministicScriptRunner:
    """Drives the tube with the script's planned sends and concatenates the
    banner + every reply into stdout — the offline stand-in for executing a real
    exploit script in the sandbox."""

    def run(self, script: Script, tube: Tube) -> RunOutput:
        chunks: List[str] = []
        banner = tube.recv()
        if banner:
            chunks.append(banner)
        for s in script.sends:
            tube.send(s)
            reply = tube.recv()
            if reply:
                chunks.append(reply)
        return RunOutput(rev=script.rev, stdout="\n".join(chunks), ok=True,
                         transcript=tuple(tube.transcript))
