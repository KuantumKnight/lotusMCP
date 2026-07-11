"""`lotus playbook lint|test` — the operator gate for community playbooks (§7).

Loading an untrusted playbook is a supply-chain action, so it happens through
this non-interactive CLI (operator-run), never through the MCP surface. `lint`
validates a document against the safe envelope; `test` lints then shows the
effective rule set the document would produce (which rules were re-weighted and
which disabled), so the operator sees the exact effect before trusting it.

    python -m lotusmcp.playbooks.cli lint  path/to/playbook.json
    python -m lotusmcp.playbooks.cli test  path/to/playbook.json
"""
from __future__ import annotations

import json
import sys
from typing import List, Optional

from lotusmcp.playbooks.community import (
    CommunityPlaybookError,
    apply_playbook,
    lint_playbook,
)
from lotusmcp.playbooks.rules import ALL_RULES


def _known():
    return ({r.id for r in ALL_RULES}, {r.capability for r in ALL_RULES})


def _load(path: str):
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def _print_findings(findings, out) -> int:
    n_err = sum(1 for x in findings if x.level == "error")
    for x in findings:
        loc = f" @ {x.where}" if x.where else ""
        print(f"  [{x.level}] {x.code}: {x.message}{loc}", file=out)
    if not findings:
        print("  clean — no findings", file=out)
    return n_err


def main(argv: Optional[List[str]] = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if len(argv) < 2 or argv[0] not in ("lint", "test"):
        print("usage: lotus playbook lint|test <playbook.json>", file=sys.stderr)
        return 2
    cmd, path = argv[0], argv[1]
    ids, caps = _known()
    try:
        doc = _load(path)
    except (OSError, json.JSONDecodeError) as e:
        print(f"cannot read playbook: {e}", file=sys.stderr)
        return 2

    findings = lint_playbook(doc, ids, caps)
    print(f"lint {path}:")
    n_err = _print_findings(findings, sys.stdout)

    if cmd == "lint":
        print(f"{'FAIL' if n_err else 'OK'} — {n_err} error(s)")
        return 1 if n_err else 0

    # test: show the effective rule set (only reachable if lint is clean)
    if n_err:
        print(f"FAIL — {n_err} error(s); cannot compute effect")
        return 1
    tuned = apply_playbook(ALL_RULES, doc, caps)
    base = {r.id: r for r in ALL_RULES}
    kept = {r.id for r in tuned}
    disabled = sorted(set(base) - kept)
    print(f"effective rules: {len(tuned)}/{len(ALL_RULES)} "
          f"({len(disabled)} disabled)")
    for r in tuned:
        b = base[r.id]
        deltas = [f"{k}:{getattr(b,fld)}→{getattr(r,fld)}"
                  for k, fld in (("priority", "priority"), ("yield", "yield_"),
                                 ("cost", "cost"), ("risk", "risk"))
                  if getattr(b, fld) != getattr(r, fld)]
        if deltas:
            print(f"  tuned {r.id}: {', '.join(deltas)}")
    for rid in disabled:
        print(f"  disabled {rid}")
    print("OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
