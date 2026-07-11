"""Community playbooks — low-friction tuning, supply-chain-safe (Phase 8, §7).

A community playbook is DATA, never code. The threat it defends against: a
shared playbook that quietly widens scope, adds an unreviewed tool, or smuggles
in a predicate. So the only thing a community playbook may do is **re-weight or
disable EXISTING, already-in-scope capabilities** — it references built-in rules
by id and nudges their scalar knobs (`priority`/`yield`/`cost`/`risk`) or turns
them off. The engine's deterministic score sort turns those knobs into a
reordering; a playbook can never inject a `when`/`params` predicate, a new
`capability`/adapter (those require signed review), or a phase/scope change.

    doc = {
      "name": "web-first", "version": 1,
      "rules": [
        {"id": "web.sqli", "priority": 0.9, "yield": 0.8},   # promote SQLi
        {"id": "web.xss", "enabled": false}                  # disable XSS
      ]
    }

`lint_playbook` validates the document and returns structured findings (it FAILS
LOUD on anything outside the safe envelope); `apply_playbook` refuses to apply a
document with any error and otherwise returns a tuned copy of the rule list.
"""
from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Any, Dict, Iterable, List, Optional

from lotusmcp.playbooks.model import Rule

# scalar knobs a playbook may tune, and how they map onto the Rule field.
_TUNABLE = {"priority": "priority", "yield": "yield_", "cost": "cost", "risk": "risk"}
# keys whose presence means the playbook is trying to define behavior, not tune
# it — each is rejected with a specific reason.
_FORBIDDEN = {
    "capability": "new capabilities/adapters require signed review (Phase 8)",
    "kind": "changing the selected entity kind alters scope",
    "category": "changing category alters triage/scope",
    "when": "predicates are code, not data",
    "params": "param builders are code, not data",
    "phase_gate": "changing phase gating alters when a capability may run",
    "rationale": "rationale is owned by the vetted rule",
}


class CommunityPlaybookError(Exception):
    """A community playbook failed lint and cannot be applied."""

    def __init__(self, findings: "List[LintFinding]") -> None:
        self.findings = findings
        errs = "; ".join(f.message for f in findings if f.level == "error")
        super().__init__(errs or "community playbook rejected")


@dataclass
class LintFinding:
    level: str          # "error" | "warning"
    code: str
    message: str
    where: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {"level": self.level, "code": self.code,
                "message": self.message, "where": self.where}


def _num_in(v: Any, lo: float, hi: float) -> bool:
    return isinstance(v, (int, float)) and not isinstance(v, bool) and lo <= v <= hi


def lint_playbook(
    doc: Any,
    known_rule_ids: Iterable[str],
    known_capabilities: Optional[Iterable[str]] = None,
) -> List[LintFinding]:
    """Validate a community-playbook document. Returns findings; an empty list
    (or warnings only) means it is safe to apply. Never raises on bad input —
    it reports."""
    f: List[LintFinding] = []
    known = set(known_rule_ids)

    if not isinstance(doc, dict):
        return [LintFinding("error", "not_an_object", "playbook must be a JSON object")]
    if not isinstance(doc.get("name"), str) or not doc["name"].strip():
        f.append(LintFinding("error", "missing_name", "playbook needs a non-empty 'name'"))
    if "version" in doc and not isinstance(doc["version"], (int, str)):
        f.append(LintFinding("error", "bad_version", "'version' must be an int or string"))
    rules = doc.get("rules")
    if not isinstance(rules, list) or not rules:
        f.append(LintFinding("error", "no_rules", "'rules' must be a non-empty list"))
        return f

    seen: set = set()
    for i, entry in enumerate(rules):
        where = f"rules[{i}]"
        if not isinstance(entry, dict):
            f.append(LintFinding("error", "bad_entry", "rule entry must be an object", where))
            continue
        rid = entry.get("id")
        if not isinstance(rid, str) or not rid:
            f.append(LintFinding("error", "missing_id", "rule entry needs a string 'id'", where))
            continue
        where = f"{where} ({rid})"
        if rid in seen:
            f.append(LintFinding("error", "duplicate_id", f"rule {rid!r} tuned twice", where))
        seen.add(rid)
        if rid not in known:
            f.append(LintFinding(
                "error", "unknown_rule",
                f"rule {rid!r} is not a built-in rule (community playbooks may only "
                f"tune existing in-scope capabilities)", where))
        for key in entry:
            if key == "id":
                continue
            if key in _FORBIDDEN:
                f.append(LintFinding("error", "forbidden_key",
                                     f"'{key}' is not allowed: {_FORBIDDEN[key]}", where))
                continue
            if key == "enabled":
                if not isinstance(entry[key], bool):
                    f.append(LintFinding("error", "bad_enabled",
                                         "'enabled' must be a boolean", where))
                continue
            if key in _TUNABLE:
                lo, hi = (0.0, 1.0)
                ok = _num_in(entry[key], lo, hi) if key != "cost" \
                    else (isinstance(entry[key], (int, float)) and not isinstance(entry[key], bool)
                          and entry[key] > 0)
                if not ok:
                    rng = "> 0" if key == "cost" else "in [0,1]"
                    f.append(LintFinding("error", "out_of_range",
                                         f"'{key}' must be a number {rng}", where))
                continue
            f.append(LintFinding("error", "unknown_key",
                                 f"unknown tuning key '{key}'", where))
    return f


def apply_playbook(
    base_rules: List[Rule],
    doc: Dict[str, Any],
    known_capabilities: Optional[Iterable[str]] = None,
) -> List[Rule]:
    """Return a tuned copy of `base_rules` with the playbook applied. Rules the
    playbook disables are dropped; the rest are re-weighted. RAISES
    CommunityPlaybookError (with findings) if the document does not lint clean —
    an unsafe playbook is never partially applied."""
    ids = {r.id for r in base_rules}
    findings = lint_playbook(doc, ids, known_capabilities)
    if any(x.level == "error" for x in findings):
        raise CommunityPlaybookError(findings)

    tune: Dict[str, Dict[str, Any]] = {e["id"]: e for e in doc["rules"]}
    out: List[Rule] = []
    for rule in base_rules:
        e = tune.get(rule.id)
        if e is None:
            out.append(rule)
            continue
        if e.get("enabled", True) is False:
            continue                      # disabled — dropped from the effective set
        overrides = {field: e[key] for key, field in _TUNABLE.items() if key in e}
        out.append(replace(rule, **overrides) if overrides else rule)
    return out
