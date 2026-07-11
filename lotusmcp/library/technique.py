"""Cross-case Technique Library + calibration (Phase 7, ARCHITECTURE §1/§7).

A technique is an **allowlist-generalized playbook card**: an action pattern
stripped of every case-specific detail, keyed only by server-authored allowlist
values — `(capability, category, param_class)`. It carries NO host, path, or
payload, so nothing from one engagement leaks into the cross-case library.

Each card keeps a **Beta posterior** over "did this pattern make progress":
`α = wins + 1`, `β = (trials − wins) + 1`. Observing an outcome bumps one of
them — that IS the calibration. The recommender **Thompson-samples** each
eligible card's posterior and ranks by the draw, so a promising-but-untried
technique still gets explored while a proven one is exploited.

Like every other read model this is a **pure, rebuildable projection**: the
library owns an append-only `library.jsonl` and the cards are a deterministic
fold of it. Promotion (`candidate → promoted`) is a human-reviewed event, never
automatic — the recommender can surface candidates but only a person blesses one.
"""
from __future__ import annotations

import hashlib
import json
import os
import random
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional


def technique_id(capability: str, category: str, param_class: str) -> str:
    raw = f"{capability}|{category}|{param_class}"
    return "T" + hashlib.blake2b(raw.encode("utf-8"), digest_size=6).hexdigest()


@dataclass
class TechniqueCard:
    tid: str
    capability: str
    category: str
    param_class: str
    wins: int
    trials: int
    status: str                    # "candidate" | "promoted"
    phases: tuple                  # phases this pattern has been observed in
    last_seq: int

    @property
    def alpha(self) -> int:
        return self.wins + 1

    @property
    def beta(self) -> int:
        return (self.trials - self.wins) + 1

    @property
    def mean(self) -> float:
        return self.alpha / (self.alpha + self.beta)

    def to_dict(self) -> Dict[str, Any]:
        return {"tid": self.tid, "capability": self.capability,
                "category": self.category, "param_class": self.param_class,
                "wins": self.wins, "trials": self.trials, "status": self.status,
                "phases": list(self.phases),
                "posterior_mean": round(self.mean, 4),
                "alpha": self.alpha, "beta": self.beta}


class TechniqueLibrary:
    def __init__(self, root: os.PathLike | str) -> None:
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        self.log_path = self.root / "library.jsonl"
        self._events: List[Dict[str, Any]] = []
        if self.log_path.exists():
            for line in self.log_path.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if line:
                    self._events.append(json.loads(line))

    # --------------------------------------------------------------- log write
    def _append(self, ev: Dict[str, Any]) -> Dict[str, Any]:
        ev = {"seq": len(self._events), **ev}
        with self.log_path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(ev, sort_keys=True) + "\n")
        self._events.append(ev)
        return ev

    def observe(self, capability: str, category: str, param_class: str,
                phase: str, success: bool) -> str:
        """Record one outcome for a generalized pattern; returns its tid. This is
        the calibration signal — `success` is whether the action made progress."""
        tid = technique_id(capability, category, param_class)
        self._append({"type": "technique.observed", "tid": tid,
                      "capability": capability, "category": category,
                      "param_class": param_class, "phase": phase,
                      "success": bool(success)})
        return tid

    def observe_action(self, action, phase: str, success: bool) -> str:
        """Convenience for the loop: generalize a CandidateAction (dropping its
        target) and record the outcome."""
        pc = action.params.get("class") or action.params.get("probe") or "-"
        return self.observe(action.capability, action.category, str(pc),
                            phase, success)

    def promote(self, tid: str, reviewer: str) -> None:
        """Human-reviewed promotion (candidate → promoted). Fails if the tid was
        never observed — you cannot promote a card the library has never seen."""
        if tid not in {e.get("tid") for e in self._events
                       if e["type"] == "technique.observed"}:
            raise KeyError(f"unknown technique {tid!r} (never observed)")
        self._append({"type": "technique.promoted", "tid": tid,
                      "reviewer": reviewer})

    # ----------------------------------------------------------------- fold
    def cards(self) -> Dict[str, TechniqueCard]:
        """Deterministic fold of the log into the current card set."""
        acc: Dict[str, Dict[str, Any]] = {}
        promoted: set = set()
        for e in self._events:
            if e["type"] == "technique.observed":
                tid = e["tid"]
                c = acc.get(tid)
                if c is None:
                    c = {"capability": e["capability"], "category": e["category"],
                         "param_class": e["param_class"], "wins": 0, "trials": 0,
                         "phases": [], "last_seq": e["seq"]}
                    acc[tid] = c
                c["trials"] += 1
                c["wins"] += 1 if e["success"] else 0
                c["last_seq"] = e["seq"]
                if e["phase"] and e["phase"] not in c["phases"]:
                    c["phases"].append(e["phase"])
            elif e["type"] == "technique.promoted":
                promoted.add(e["tid"])
        out: Dict[str, TechniqueCard] = {}
        for tid, c in acc.items():
            out[tid] = TechniqueCard(
                tid=tid, capability=c["capability"], category=c["category"],
                param_class=c["param_class"], wins=c["wins"], trials=c["trials"],
                status="promoted" if tid in promoted else "candidate",
                phases=tuple(c["phases"]), last_seq=c["last_seq"])
        return out

    def card(self, tid: str) -> Optional[TechniqueCard]:
        return self.cards().get(tid)

    # ------------------------------------------------------------- recommend
    def suggest(self, phase: Optional[str] = None, category: Optional[str] = None,
                k: int = 5, rng: Optional[random.Random] = None,
                promoted_only: bool = False) -> List[Dict[str, Any]]:
        """Thompson-sampled recommendations. Each eligible card is scored by a
        draw from its Beta posterior (when `rng` is given — deterministic under a
        seeded Random), else by its posterior mean (pure exploitation). Filters
        by `phase`/`category`/`promoted_only`. Ties break on tid for stability."""
        cards = self.cards().values()
        elig = []
        for c in cards:
            if category is not None and c.category != category:
                continue
            if phase is not None and c.phases and phase not in c.phases:
                continue
            if promoted_only and c.status != "promoted":
                continue
            elig.append(c)
        scored = []
        for c in elig:
            score = rng.betavariate(c.alpha, c.beta) if rng is not None else c.mean
            scored.append((score, c))
        scored.sort(key=lambda x: (-x[0], x[1].tid))
        out = []
        for score, c in scored[:max(0, k)]:
            d = c.to_dict()
            d["score"] = round(score, 4)
            out.append(d)
        return out
