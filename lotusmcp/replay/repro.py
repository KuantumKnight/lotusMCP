"""repro.sh generation — a deterministic reproduction script from the log (Phase 6).

Like every other artifact, the script is a pure fold of the append-only log: it
folds the `command.requested` trail (the exact validated argv the Executor ran)
into a runnable bash script, grouped by the phase each command executed in and
annotated with its rationale. Same log ⇒ byte-identical script.

Safety:
  * Every token is shell-quoted with `shlex.quote`, so the script is safe to run
    even though the log's argv were already metachar-free by construction.
  * The log is already redacted at write time, so any secret shows up as a
    `«SECRET:…»` placeholder here too — never a live credential.
  * The generator runs NOTHING; it only reads the log and returns text.
"""
from __future__ import annotations

import shlex
from typing import Any, Dict, List

_HEADER = "#!/usr/bin/env bash"


def build_repro(case) -> str:
    """Fold the case log into a deterministic `repro.sh`. Returns the script
    text (also what the `case_repro` tool/`repro.sh` artifact contain)."""
    cid = case.meta.get("case_id", "?")
    phase = case.meta.get("phase", "TRIAGE")
    tip = case.store.tip

    commands: List[Dict[str, Any]] = []
    cur_phase = "TRIAGE"
    flag_verified = False
    for ev in case.store.iter_events():
        t, p = ev["type"], ev.get("payload", {})
        if t == "case.status_changed" and p.get("phase"):
            cur_phase = p["phase"]
        elif t == "command.requested":
            argv = p.get("argv") or []
            if argv:
                commands.append({
                    "argv": argv, "phase": p.get("phase") or cur_phase,
                    "capability": p.get("capability", "?"),
                    "target": p.get("target", ""),
                    "rationale": (p.get("rationale") or "").strip(),
                    "seq": ev["seq"],
                })
        elif t == "flag.verified":
            flag_verified = True

    sc = case.meta.get("scope", {})
    scope_targets = [s.get("value", "?") for s in sc.get("targets", [])]

    L: List[str] = [_HEADER]
    L.append(f"# repro.sh — deterministic reproduction of LotusMCP case {cid!r}")
    L.append(f"# Folded from the append-only log at tip seq {tip} "
             f"({len(commands)} command(s)).")
    L.append("# Secrets are redacted in the log, so they appear here as "
             "«SECRET:…» placeholders")
    L.append("# and must be supplied out of band. Every argv was scope-checked "
             "at capture time.")
    if scope_targets:
        L.append(f"# In-scope targets at capture: {', '.join(scope_targets)}")
    L.append("set -euo pipefail")
    L.append("")

    if not commands:
        L.append("# No reproducible commands were recorded for this case.")
        L.append("# (The solve used scripted or Regime-B interactive execution, "
                 "whose steps")
        L.append("#  are captured as session events, not a Phase-1 command trail.)")
        L.append("")
        return "\n".join(L) + "\n"

    # group by phase, preserving first-seen phase order (deterministic via seq).
    order: List[str] = []
    for c in commands:
        if c["phase"] not in order:
            order.append(c["phase"])

    step = 0
    for ph in order:
        L.append(f"# ── {ph} ──")
        for c in commands:
            if c["phase"] != ph:
                continue
            step += 1
            hdr = f"# [step {step}] {c['capability']}"
            if c["target"]:
                hdr += f" on {c['target']}"
            L.append(hdr)
            if c["rationale"]:
                L.append(f"#   rationale: {c['rationale']}")
            L.append(" ".join(shlex.quote(tok) for tok in c["argv"]))
            L.append("")

    L.append("# ── outcome ──")
    if flag_verified:
        L.append(f"# The recorded solve reached FLAG_FOUND (phase: {phase}); the "
                 "verified flag")
        L.append("# is in the log's flag.verified event and is intentionally not "
                 "echoed here.")
    else:
        L.append(f"# Recorded run ended in phase {phase} without a verified flag.")
    L.append("")
    return "\n".join(L) + "\n"
