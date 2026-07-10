"""BudgetLedger — the global spend accountant (§4.6).

Every call site that costs something (a tool invocation, an LLM call, wall-clock
on a long job) charges here, so the stopping math is never blind. The ledger is
a plain accumulator with hard global caps and optional per-phase tool caps; it
raises nothing on its own — callers ask `exhausted()` / `fraction_spent()` and
decide.

Wall-clock is *charged explicitly* rather than read from a clock, which keeps the
loop deterministic and replayable (the same event stream reproduces the same
budget state — no `Date.now()` in the decision path).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, Optional

# fraction of any single budget dimension past which we self-escalate if we
# still have no access (see §4.3 "budget ≥80% w/o access").
HIGH_WATER = 0.8


@dataclass
class BudgetLedger:
    max_tool_invocations: int = 60
    max_llm_tokens: int = 200_000
    max_wall_clock_s: float = 3600.0
    per_phase_tool_caps: Dict[str, int] = field(default_factory=dict)

    tool_invocations: int = 0
    llm_tokens: int = 0
    wall_clock_s: float = 0.0
    per_phase_tools: Dict[str, int] = field(default_factory=dict)

    def charge(
        self,
        *,
        tool_invocations: int = 0,
        llm_tokens: int = 0,
        wall_clock_s: float = 0.0,
        phase: Optional[str] = None,
    ) -> None:
        self.tool_invocations += tool_invocations
        self.llm_tokens += llm_tokens
        self.wall_clock_s += wall_clock_s
        if phase and tool_invocations:
            self.per_phase_tools[phase] = self.per_phase_tools.get(phase, 0) + tool_invocations

    # ---- queries ----
    def fraction_spent(self) -> float:
        """The most-consumed dimension, in [0, 1+]."""
        fracs = [
            self.tool_invocations / self.max_tool_invocations if self.max_tool_invocations else 0.0,
            self.llm_tokens / self.max_llm_tokens if self.max_llm_tokens else 0.0,
            self.wall_clock_s / self.max_wall_clock_s if self.max_wall_clock_s else 0.0,
        ]
        return max(fracs)

    def exhausted(self) -> bool:
        return self.fraction_spent() >= 1.0

    def high_water(self) -> bool:
        return self.fraction_spent() >= HIGH_WATER

    def phase_cap_reached(self, phase: str) -> bool:
        cap = self.per_phase_tool_caps.get(phase)
        return cap is not None and self.per_phase_tools.get(phase, 0) >= cap

    def snapshot(self) -> Dict[str, float]:
        return {
            "tool_invocations": self.tool_invocations,
            "llm_tokens": self.llm_tokens,
            "wall_clock_s": self.wall_clock_s,
            "fraction_spent": round(self.fraction_spent(), 4),
        }
