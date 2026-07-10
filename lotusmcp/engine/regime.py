"""Which loop regime owns a phase (§4.2).

Two regimes:

- **Regime A — deterministic planner** (`PLANNER`) for `TRIAGE/RECON/ENUMERATE`,
  where checklists converge and EV/UCB is meaningful: the playbook engine is the
  sole generator and the LLM only ranks a bounded set.
- **Regime B — interactive code-synthesis** (`INTERACTIVE`) for `EXPLOIT` /
  `POST_EXPLOIT` on pwn/rev/hard-crypto/stateful-web, where a checklist cannot
  converge: the LLM authors and iterates a sandboxed exploit script against a
  persistent tube. While a Regime-B session is open the server enforces only
  scope/budget/redaction — **phase transitions and plateau accounting are
  suspended** (loop.py owns that suspension).

This is a pure classification — no state, no I/O — so the routing decision is
deterministic and replayable, exactly like every other guard.
"""
from __future__ import annotations

PLANNER = "PLANNER"
INTERACTIVE = "INTERACTIVE"

# Phases whose *work* is iterated exploit-script synthesis rather than a
# converging checklist.
_INTERACTIVE_PHASES = frozenset({"EXPLOIT", "POST_EXPLOIT"})

# Categories that genuinely need a persistent tube + iterated scripting:
# pwn/rev (binary), crypto (hard/lattice/oracle), web (stateful/session).
# Forensics/osint stay in the planner — their exploit step is still checklist-y.
_INTERACTIVE_CATEGORIES = frozenset({"pwn", "rev", "crypto", "web"})


def regime(phase: str, category: str | None) -> str:
    """Return `INTERACTIVE` iff `phase` is an exploit phase *and* `category` is
    one that needs iterated code-synthesis; otherwise `PLANNER`."""
    cat = (category or "").strip().lower()
    if phase in _INTERACTIVE_PHASES and cat in _INTERACTIVE_CATEGORIES:
        return INTERACTIVE
    return PLANNER


def is_interactive(phase: str, category: str | None) -> bool:
    return regime(phase, category) == INTERACTIVE
