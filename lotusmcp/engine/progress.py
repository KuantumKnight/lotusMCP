"""Progress / plateau tracking (§4.6).

A decision point "made progress" if it produced a new entity/edge, moved a
confidence by more than a threshold, advanced a phase, or found a flag. We track
an EMA of that binary signal over *completed* decision points where a cheaper
alternative existed; when the EMA drops below the plateau threshold (after a
warm-up), the loop should self-escalate rather than keep grinding.

Deliberately simple and deterministic — the point is to stop the loop spinning,
not to model productivity precisely.
"""
from __future__ import annotations

from dataclasses import dataclass

DEFAULT_ALPHA = 0.4       # EMA weight on the newest decision
DEFAULT_THRESHOLD = 0.15  # plateau when EMA falls below this
DEFAULT_WARMUP = 4        # don't call a plateau before this many decisions


@dataclass
class ProgressTracker:
    alpha: float = DEFAULT_ALPHA
    threshold: float = DEFAULT_THRESHOLD
    warmup: int = DEFAULT_WARMUP
    ema: float = 1.0
    decisions: int = 0
    consecutive_dry: int = 0

    def record(self, progressed: bool) -> None:
        self.decisions += 1
        x = 1.0 if progressed else 0.0
        self.ema = self.alpha * x + (1.0 - self.alpha) * self.ema
        self.consecutive_dry = 0 if progressed else self.consecutive_dry + 1

    def plateaued(self) -> bool:
        return self.decisions >= self.warmup and self.ema < self.threshold

    def snapshot(self) -> dict:
        return {"decisions": self.decisions, "ema": round(self.ema, 3),
                "consecutive_dry": self.consecutive_dry, "plateaued": self.plateaued()}
