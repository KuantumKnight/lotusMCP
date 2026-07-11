"""Community playbooks: lint + safe apply + CLI (Phase 8, supply-chain safety).

A community playbook may ONLY re-weight or disable existing in-scope rules.
lint rejects unknown rules, new capabilities/adapters, injected predicates, and
out-of-range knobs; apply refuses anything that doesn't lint clean and otherwise
tunes the rule set (reorder happens via the engine's score sort, never by
smuggling in code/scope). The CLI is the operator gate.

    PYTHONPATH=. PYTHONIOENCODING=utf-8 python tests/test_community_playbook.py
"""
from __future__ import annotations

import io
import json
import sys
import tempfile
from contextlib import redirect_stdout
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from lotusmcp.playbooks import cli
from lotusmcp.playbooks.community import (
    CommunityPlaybookError,
    apply_playbook,
    lint_playbook,
)
from lotusmcp.playbooks.engine import PlaybookEngine
from lotusmcp.playbooks.rules import ALL_RULES

IDS = {r.id for r in ALL_RULES}
CAPS = {r.capability for r in ALL_RULES}


def _errs(findings):
    return {x.code for x in findings if x.level == "error"}


def test_valid_playbook_lints_clean():
    doc = {"name": "web-first", "version": 1,
           "rules": [{"id": "web.sqli", "priority": 0.9, "yield": 0.8},
                     {"id": "web.xss", "enabled": False}]}
    findings = lint_playbook(doc, IDS, CAPS)
    assert findings == [], [x.to_dict() for x in findings]
    print("valid playbook lints clean")


def test_unknown_rule_rejected():
    doc = {"name": "x", "rules": [{"id": "totally.made.up", "priority": 0.9}]}
    assert "unknown_rule" in _errs(lint_playbook(doc, IDS, CAPS))
    print("unknown rule id rejected")


def test_new_capability_requires_signed_review():
    # trying to define a brand-new capability/adapter through a playbook
    doc = {"name": "x", "rules": [{"id": "web.sqli", "capability": "rce_dropper"}]}
    codes = _errs(lint_playbook(doc, IDS, CAPS))
    assert "forbidden_key" in codes, codes
    print("new capability/adapter blocked (needs signed review)")


def test_injected_predicate_or_scope_change_rejected():
    for bad in ("when", "params", "phase_gate", "kind", "category"):
        doc = {"name": "x", "rules": [{"id": "web.sqli", bad: "anything"}]}
        assert "forbidden_key" in _errs(lint_playbook(doc, IDS, CAPS)), bad
    print("code/scope-changing keys all rejected")


def test_out_of_range_knobs_rejected():
    bad_docs = [
        {"name": "x", "rules": [{"id": "web.sqli", "priority": 1.5}]},
        {"name": "x", "rules": [{"id": "web.sqli", "yield": -0.1}]},
        {"name": "x", "rules": [{"id": "web.sqli", "cost": 0}]},        # cost must be > 0
        {"name": "x", "rules": [{"id": "web.sqli", "risk": "high"}]},
        {"name": "x", "rules": [{"id": "web.sqli", "priority": True}]}, # bool ≠ number
    ]
    for d in bad_docs:
        assert "out_of_range" in _errs(lint_playbook(d, IDS, CAPS)), d
    print("out-of-range / mistyped knobs rejected")


def test_structural_errors():
    assert "not_an_object" in _errs(lint_playbook([1, 2], IDS))
    assert "no_rules" in _errs(lint_playbook({"name": "x"}, IDS))
    assert "missing_name" in _errs(lint_playbook({"rules": [{"id": "web.sqli"}]}, IDS))
    dup = {"name": "x", "rules": [{"id": "web.sqli"}, {"id": "web.sqli"}]}
    assert "duplicate_id" in _errs(lint_playbook(dup, IDS))
    print("structural errors (shape, dup id, missing name) caught")


def test_apply_reweights_and_disables_only_existing_capabilities():
    doc = {"name": "web-first", "version": 1,
           "rules": [{"id": "web.sqli", "priority": 0.95, "yield": 0.9},
                     {"id": "web.xss", "enabled": False}]}
    tuned = apply_playbook(ALL_RULES, doc, CAPS)
    by_id = {r.id: r for r in tuned}
    # xss dropped, sqli re-weighted, everything else identical
    assert "web.xss" not in by_id and len(tuned) == len(ALL_RULES) - 1
    assert by_id["web.sqli"].priority == 0.95 and by_id["web.sqli"].yield_ == 0.9
    # crucially: capabilities are unchanged — no new adapter appeared
    assert {r.capability for r in tuned} <= CAPS
    # and the tuned rule keeps the SAME vetted capability/predicate object
    base_sqli = next(r for r in ALL_RULES if r.id == "web.sqli")
    assert by_id["web.sqli"].capability == base_sqli.capability
    assert by_id["web.sqli"].when is base_sqli.when      # predicate not replaced
    print("apply re-weights/disables only; capabilities + predicates untouched")


def test_apply_refuses_unsafe_playbook():
    doc = {"name": "x", "rules": [{"id": "nope", "priority": 0.9}]}
    try:
        apply_playbook(ALL_RULES, doc, CAPS)
        raise AssertionError("unsafe playbook must not apply")
    except CommunityPlaybookError as e:
        assert any(f.code == "unknown_rule" for f in e.findings)
    print("apply refuses a playbook that doesn't lint clean")


def test_reweight_actually_reorders_proposals():
    # a world with an http service so several web rules fire
    world = _web_world()
    base = PlaybookEngine(ALL_RULES).propose(world, "EXPLOIT",
                                             category_conf={"web": 1.0})
    # promote xss far above sqli/ssti and confirm the ranking changes
    doc = {"name": "xss-first",
           "rules": [{"id": "web.xss", "priority": 1.0, "yield": 1.0},
                     {"id": "web.sqli", "priority": 0.1, "yield": 0.1}]}
    tuned = apply_playbook(ALL_RULES, doc, CAPS)
    after = PlaybookEngine(tuned).propose(world, "EXPLOIT",
                                          category_conf={"web": 1.0})

    def rank(ps, rid):
        ids = [p.action.rule_id for p in ps.proposals]
        return ids.index(rid) if rid in ids else 999
    assert rank(after, "web.xss") < rank(base, "web.xss"), "xss should rise"
    assert rank(after, "web.xss") < rank(after, "web.sqli"), "xss now beats sqli"
    print("re-weighting reorders proposals via the engine's score sort")


def test_cli_lint_and_test(tmp=None):
    with tempfile.TemporaryDirectory() as d:
        good = Path(d) / "good.json"
        good.write_text(json.dumps(
            {"name": "web-first", "rules": [{"id": "web.sqli", "priority": 0.9},
                                            {"id": "web.xss", "enabled": False}]}),
            encoding="utf-8")
        bad = Path(d) / "bad.json"
        bad.write_text(json.dumps(
            {"name": "x", "rules": [{"id": "nope", "capability": "evil"}]}),
            encoding="utf-8")

        out = io.StringIO()
        with redirect_stdout(out):
            rc_lint = cli.main(["lint", str(good)])
            rc_test = cli.main(["test", str(good)])
            rc_bad = cli.main(["lint", str(bad)])
        text = out.getvalue()
        assert rc_lint == 0 and rc_test == 0 and rc_bad == 1
        assert "disabled web.xss" in text
        assert "tuned web.sqli" in text
        assert "unknown_rule" in text or "forbidden_key" in text
        # bad usage
        assert cli.main(["bogus"]) == 2
        print("CLI: lint/test pass on good, exit 1 on bad, usage guard works")


def _web_world():
    from lotusmcp.playbooks.model import World
    return World.from_entity_dicts([
        {"entity_id": "svc", "kind": "service.http", "display": "10.0.0.1:80",
         "nk": {"host": "10.0.0.1", "proto": "tcp", "port": 80},
         "attrs": {"server": "nginx"}},
        {"entity_id": "ep", "kind": "http.param", "display": "q",
         "nk": {"endpoint_id": "svc", "location": "query", "name": "q"},
         "attrs": {"reflected": True}},
    ])


TESTS = [v for k, v in sorted(globals().items()) if k.startswith("test_")]

if __name__ == "__main__":
    import traceback
    failed = 0
    for t in TESTS:
        try:
            t()
            print(f"ok   {t.__name__}")
        except Exception:  # noqa: BLE001
            failed += 1
            print(f"FAIL {t.__name__}")
            traceback.print_exc()
    print(f"\n{len(TESTS)-failed}/{len(TESTS)} passed")
    sys.exit(1 if failed else 0)
