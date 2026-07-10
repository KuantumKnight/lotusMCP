"""Decomposable salience — the ranking that keeps STATE.md / the resume packet
bounded no matter how large a case grows (§2.4).

The trick is *decomposability*: the expensive, time-independent part of an
entity's importance (`s_conf, s_hyp, s_pathflag, s_deadend, last_seq`) is computed
once from the graph, and only the cheap recency term is applied at query time.
So ranking a 5000-endpoint case is O(candidates) with no O(N) rescan and no index
that can go stale — recency is a pure function of the log tip.

    score = 0.15·s_conf + 0.25·s_hyp + 0.25·s_pathflag − 0.30·s_deadend
            + 0.20·recency,   recency = exp(−(tip − last_seq)/τ)

All weights and τ live here so the renderer, the resume packet, and any future
salience consumer rank identically. Pure functions — deterministic and replayable.
"""
from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Iterable, List, Tuple, TypeVar

# Recency decay constant, in events. Larger τ = slower forgetting. At τ=200 an
# entity last touched 200 events ago retains 1/e (~0.37) of its recency weight.
TAU = 200.0

W_CONF = 0.15
W_HYP = 0.25
W_PATHFLAG = 0.25
W_DEADEND = 0.30        # subtracted — dead ends sink
W_RECENCY = 0.20

K = TypeVar("K")


@dataclass(frozen=True)
class Salience:
    """The time-independent salience components of one entity, each 0..1 except
    `last_seq` (the log seq at which the entity was last touched)."""

    s_conf: float = 0.0        # max confidence of claims on the entity
    s_hyp: float = 0.0         # referenced by an OPEN hypothesis / evidence link
    s_pathflag: float = 0.0    # on the critical path toward the flag
    s_deadend: float = 0.0     # dead-endedness (subtracted)
    last_seq: int = 0

    def clamped(self) -> "Salience":
        c = lambda x: 0.0 if x < 0.0 else 1.0 if x > 1.0 else float(x)
        return Salience(c(self.s_conf), c(self.s_hyp), c(self.s_pathflag),
                        c(self.s_deadend), int(self.last_seq))


def recency(last_seq: int, tip: int, tau: float = TAU) -> float:
    """exp(−(tip − last_seq)/τ), clamped to (0, 1]. tip ≤ 0 (empty log) → 1.0;
    an entity touched at/after the tip is fully recent (1.0)."""
    if tip <= 0:
        return 1.0
    delta = tip - last_seq
    if delta <= 0:
        return 1.0
    return math.exp(-delta / tau)


def score(sal: Salience, tip: int, tau: float = TAU) -> float:
    """The salience score of one entity at log `tip`. Higher = more worth showing."""
    s = sal.clamped()
    return (W_CONF * s.s_conf
            + W_HYP * s.s_hyp
            + W_PATHFLAG * s.s_pathflag
            - W_DEADEND * s.s_deadend
            + W_RECENCY * recency(s.last_seq, tip, tau))


def rank(items: Iterable[Tuple[K, Salience]], tip: int,
         tau: float = TAU) -> List[Tuple[K, float]]:
    """Rank `(key, Salience)` pairs by score, descending. Deterministic
    tie-break: higher score, then the key's own order (lexical for str keys) —
    so the same graph at the same tip always yields the same ordering."""
    scored = [(key, score(sal, tip, tau)) for key, sal in items]
    scored.sort(key=lambda ks: (-ks[1], str(ks[0])))
    return scored


def top_k(items: Iterable[Tuple[K, Salience]], k: int, tip: int,
          tau: float = TAU) -> List[K]:
    """The k highest-salience keys, in ranked order."""
    return [key for key, _ in rank(items, tip, tau)[:max(0, k)]]
