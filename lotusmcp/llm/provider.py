"""Providers behind the ONE gateway.

A `Provider` is the only thing that would talk to a model API. The gateway owns
budgeting, caching, and schema enforcement; the provider only turns a task +
structured context into a schema-shaped dict. Keeping this behind a Protocol is
what lets the whole loop run and be tested here with NO network and NO key:
`DeterministicProvider` abduces hypotheses and estimates info-gain with plain
rules, so gateway behaviour (cache hits, budget charge, validation) is exercised
end-to-end offline. A real Claude/OpenAI/any-MCP client slots in later by
implementing the same two methods — the gateway never changes.
"""
from __future__ import annotations

from typing import Any, Dict, List, Protocol

# Task identifiers — the only tasks the deterministic loop asks the oracle for.
ORIENT_AND_HYPOTHESIZE = "orient_and_hypothesize"
RANK_ACTIONS = "rank_actions"
HOLISTIC_READ = "holistic_read"


class Provider(Protocol):
    def complete(self, task: str, context: Dict[str, Any]) -> Dict[str, Any]:
        """Return a structured response for `task` given `context`. Deterministic
        for a given (task, context) — the gateway assumes temp=0 semantics."""
        ...

    def cost_tokens(self, task: str, context: Dict[str, Any]) -> int:
        """Notional token cost the gateway charges to the budget on a cache MISS."""
        ...


# ---- exposure/leak statement templates keyed by finding type / signal --------
_ABDUCE = {
    "exposure": ("exposed {subject} likely permits source or credential recovery "
                 "-> pivot to authenticated surface", 0.7),
    "sqli": ("injectable parameter on {subject} -> dump credentials/secrets tables", 0.75),
    "sqli_dump": ("SQLi already dumping on {subject} -> extract flag/admin rows", 0.9),
    "auth_bypass": ("auth bypass on {subject} -> reach privileged endpoints", 0.8),
    "lfi": ("path traversal on {subject} -> read app source / secrets files", 0.65),
    "ssti": ("template injection on {subject} -> RCE via payload escalation", 0.7),
    "rce": ("command execution on {subject} -> establish shell, enumerate post-ex", 0.9),
}


def _subject_of(finding: Dict[str, Any]) -> str:
    subj = finding.get("subject") or {}
    if isinstance(subj, dict) and subj:
        return next(iter(subj.values()))
    return finding.get("id", "target")


class DeterministicProvider:
    """Offline stand-in: rule-based abduction + info-gain, no model, no network.
    Same inputs -> byte-identical output, so cache-replay is exact."""

    def complete(self, task: str, context: Dict[str, Any]) -> Dict[str, Any]:
        if task == ORIENT_AND_HYPOTHESIZE:
            return {"new": self._abduce(context.get("findings", []))}
        if task == HOLISTIC_READ:
            return self._read(context.get("text", ""))
        if task == RANK_ACTIONS:
            return {"ranking": self._rank(context.get("candidates", []))}
        return {}

    def cost_tokens(self, task: str, context: Dict[str, Any]) -> int:
        # crude but deterministic: proportional to context size.
        base = {"orient_and_hypothesize": 600, "rank_actions": 400, "holistic_read": 300}
        n = len(context.get("findings", [])) + len(context.get("candidates", []))
        return base.get(task, 300) + 40 * n

    # -- rules ---------------------------------------------------------------
    def _abduce(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        for f in findings:
            tmpl = _ABDUCE.get(f.get("type") or f.get("ftype"))
            if not tmpl:
                continue
            statement, prior = tmpl
            conf = round(prior * float(f.get("confidence", 0.5) or 0.5), 3)
            out.append({
                "statement": statement.format(subject=_subject_of(f)),
                "confidence": conf,
                "rationale": f"abduced from finding {f.get('id', '?')} "
                             f"({f.get('type') or f.get('ftype')})",
            })
        # stable order: highest-confidence first, then statement text
        out.sort(key=lambda h: (-h["confidence"], h["statement"]))
        return out

    def _read(self, text: str) -> Dict[str, Any]:
        notes: List[str] = []
        hyps: List[Dict[str, Any]] = []
        low = text.lower()
        if "password" in low or "secret" in low or "admin" in low:
            notes.append("raw output mentions credentials/secrets — worth extracting")
            hyps.append({"statement": "leaked credential in raw output -> credential replay",
                         "confidence": 0.6, "rationale": "keyword hit in holistic read"})
        return {"notes": notes, "hypotheses": hyps}

    def _rank(self, candidates: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        ranking = []
        for c in candidates:
            # info-gain proxy: how much fresh knowledge the action likely yields,
            # discounted by cost. Purely a function of server-provided priors.
            yield_ = float(c.get("yield", c.get("yield_", 0.5)))
            cost = float(c.get("cost", 1.0))
            ig = round(max(0.0, min(1.0, yield_ / (1.0 + 0.15 * cost))), 3)
            ranking.append({"key": str(c.get("key", c.get("capability", "?"))),
                            "info_gain": ig, "note": ""})
        ranking.sort(key=lambda r: (-r["info_gain"], r["key"]))
        return ranking
