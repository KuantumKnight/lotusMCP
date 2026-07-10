"""FlagEngine — the flag subsystem bound to one Case.

Ties the four parts together and speaks the event vocabulary:

    scan(texts)            -> emits `flag.candidate` per newly-seen value
    decide()               -> SubmitDecision over everything seen so far
    submit(decision, oracle)-> `flag.submitted` -> oracle -> `flag.verified`
                               / `flag.rejected`, and `case.status_changed` to
                               FLAG_FOUND on a confirmed flag.

Candidate identity is the value_sha, so re-observing a flag is idempotent (one
`flag.candidate` per distinct value) and the whole registry is rebuildable from
the log. Everything the engine writes goes through the single serializer, so it
inherits redaction, hashing, and replay-equivalence for free.
"""
from __future__ import annotations

from typing import Callable, Dict, List, Optional, Sequence

from lotusmcp.flag.policy import DONE, SUBMIT, SubmitDecision, SubmitPolicy
from lotusmcp.flag.ranker import RankedFlag, rank
from lotusmcp.flag.scanner import FlagCandidate, scan_many
from lotusmcp.kernel.events import EventDraft


class FlagEngine:
    def __init__(self, case, policy: Optional[SubmitPolicy] = None) -> None:
        self.case = case
        self.flag_format: Optional[str] = case.meta.get("flag_format")
        self.policy = policy if policy is not None else SubmitPolicy()
        self._candidates: Dict[str, FlagCandidate] = {}  # value_sha -> candidate
        self._rehydrate()

    def _rehydrate(self) -> None:
        """Rebuild the candidate registry from prior flag.* events in the log."""
        for ev in self.case.store.iter_events():
            p = ev.get("payload", {})
            if ev["type"] == "flag.candidate":
                c = FlagCandidate(
                    p["value"], p.get("source", "direct"),
                    tuple(p.get("decode_path", [])), p.get("context", ""),
                )
                self._candidates[c.value_sha] = c
            elif ev["type"] == "flag.submitted":
                self.policy.submitted.add(p["value_sha"])
                self.policy.attempts += 1
            elif ev["type"] == "flag.rejected":
                self.policy.rejected.add(p["value_sha"])
            elif ev["type"] == "flag.verified":
                self.policy.verified = RankedFlag(
                    value=p["value"], tier=1, confidence=1.0, is_decoy=False,
                    reason="platform oracle confirmed",
                    source=p.get("source", "direct"),
                    decode_path=tuple(p.get("decode_path", [])),
                )

    # ---- scan & register ----
    def scan(self, texts: Sequence[str]) -> List[RankedFlag]:
        """Scan outputs/files; emit flag.candidate for new values; return ranking."""
        for c in scan_many(list(texts), self.flag_format):
            if c.value_sha not in self._candidates:
                self._candidates[c.value_sha] = c
                self.case.append(EventDraft(
                    type="flag.candidate",
                    actor={"kind": "system", "name": "flagscan"},
                    idempotency_key=f"flag:{c.value_sha}",
                    payload={
                        "value": c.value, "value_sha": c.value_sha,
                        "source": c.source, "decode_path": list(c.decode_path),
                        "context": c.context,
                    },
                ))
        return self.ranked()

    def ranked(self) -> List[RankedFlag]:
        return rank(
            list(self._candidates.values()),
            has_operator_format=bool(self.flag_format),
        )

    # ---- decide & submit ----
    def decide(self, locally_checked: Optional[Sequence[str]] = None) -> SubmitDecision:
        return self.policy.decide(self.ranked(), locally_checked)

    def submit(
        self, decision: SubmitDecision, oracle: Callable[[str], bool]
    ) -> bool:
        """Execute a SUBMIT decision against the platform oracle.

        `oracle(value) -> bool` is the operator-signed platform check (mocked in
        tests). Emits the submitted/verified/rejected events and, on success,
        transitions the case to FLAG_FOUND. Returns whether the flag verified.
        """
        if decision.action != SUBMIT or decision.flag is None:
            raise ValueError(f"not a submittable decision: {decision.action}")
        f = decision.flag
        self.case.append(EventDraft(
            type="flag.submitted",
            actor={"kind": "system", "name": "flagsubmit"},
            payload={"value": f.value, "value_sha": f.value_sha,
                     "tier": f.tier, "confidence": f.confidence},
        ))
        self.policy.record_submit(f)

        correct = bool(oracle(f.value))
        self.policy.record_result(f, correct)
        if correct:
            self.case.append(EventDraft(
                type="flag.verified",
                actor={"kind": "system", "name": "oracle"},
                confidence=1.0,
                payload={"value": f.value, "value_sha": f.value_sha,
                         "source": f.source, "decode_path": list(f.decode_path)},
            ))
            self.case.append(EventDraft(
                type="case.status_changed",
                actor={"kind": "system", "name": "flagengine"},
                payload={"status": "FLAG_FOUND", "flag_sha": f.value_sha},
            ))
            self.case.set_meta(status="FLAG_FOUND")
        else:
            self.case.append(EventDraft(
                type="flag.rejected",
                actor={"kind": "system", "name": "oracle"},
                payload={"value": f.value, "value_sha": f.value_sha},
            ))
        return correct
