"""Offline calibration from solved case logs.

The live loop can update ``TechniqueLibrary`` directly when it is injected. This
module handles the other path: a directory of already-solved cases. It folds each
case log, generalizes command trails into target-free technique observations,
and appends those observations to a cross-case library.

No host, port, path, payload, or target id is written to the library. Only
``(capability, category, param_class, phase, success)`` survives.
"""
from __future__ import annotations

import argparse
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, List, Optional

from lotusmcp.kernel.case import Case
from lotusmcp.library.technique import TechniqueLibrary


@dataclass(frozen=True)
class CalibrationObservation:
    capability: str
    category: str
    param_class: str
    phase: str
    success: bool
    case_id: str
    seq: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "capability": self.capability,
            "category": self.category,
            "param_class": self.param_class,
            "phase": self.phase,
            "success": self.success,
            "case_id": self.case_id,
            "seq": self.seq,
        }


def _param_class(payload: dict[str, Any]) -> str:
    # command.requested currently records validated argv, not original params.
    # The reproducer-safe, target-free fallback is the capability/tool class.
    cap = str(payload.get("capability") or "-")
    tool = str(payload.get("tool") or "-")
    if cap == "http_probe":
        argv = payload.get("argv") or []
        if isinstance(argv, list) and argv:
            last = str(argv[-1])
            if "/.git/" in last:
                return "git"
            return "banner"
    if cap == "dir_bruteforce":
        return "content"
    if cap == "port_scan":
        return "tcp"
    return tool


def _category(capability: str, phase: str) -> str:
    if capability == "port_scan":
        return "recon"
    if capability in ("http_probe", "dir_bruteforce", "web_attack", "vuln_scan"):
        return "web"
    if capability == "crypto_attack":
        return "crypto"
    return "recon" if phase == "RECON" else "web"


def extract_observations(case: Case) -> List[CalibrationObservation]:
    """Extract target-free observations from one case log."""
    pending: list[dict[str, Any]] = []
    out: list[CalibrationObservation] = []
    terminal_success = False
    for ev in case.store.iter_events():
        typ = ev.get("type")
        payload = ev.get("payload", {})
        if typ == "flag.verified":
            terminal_success = True
        if typ == "command.requested":
            pending.append({"seq": ev["seq"], **payload})
            continue
        if typ == "command.completed" and pending:
            req = pending.pop(0)
            cap = str(req.get("capability") or payload.get("capability") or "-")
            phase = str(req.get("phase") or case.meta.get("phase") or "")
            produced = payload.get("produced")
            success = bool(payload.get("ok")) and isinstance(produced, int) and produced > 0
            out.append(CalibrationObservation(
                capability=cap,
                category=_category(cap, phase),
                param_class=_param_class(req),
                phase=phase,
                success=success,
                case_id=case.case_id,
                seq=int(req["seq"]),
            ))
    # If the case ended solved but no individual command produced parser-visible
    # knowledge, do not invent wins. The session path is calibrated live and
    # script.run records are intentionally too free-form to generalize here.
    _ = terminal_success
    return out


def calibrate_cases(cases_dir, library_dir, case_ids: Optional[Iterable[str]] = None) -> dict[str, Any]:
    cases_root = Path(cases_dir)
    lib = TechniqueLibrary(library_dir)
    ids = list(case_ids) if case_ids is not None else sorted(
        p.name for p in cases_root.iterdir() if (p / "case.json").exists()
    )
    observations = 0
    wins = 0
    for cid in ids:
        c = Case(cases_root, cid)
        if not c.meta_path.exists():
            continue
        for obs in extract_observations(c):
            lib.observe(obs.capability, obs.category, obs.param_class,
                        obs.phase, obs.success)
            observations += 1
            wins += 1 if obs.success else 0
    return {
        "cases": ids,
        "observations": observations,
        "wins": wins,
        "cards": len(lib.cards()),
        "library": str(Path(library_dir)),
    }


def main(argv: Optional[Iterable[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="Calibrate TechniqueLibrary from case logs")
    ap.add_argument("--cases-dir", default="cases")
    ap.add_argument("--library-dir", default="library")
    ap.add_argument("--case", action="append", dest="case_ids")
    args = ap.parse_args(list(argv) if argv is not None else None)
    print(json.dumps(calibrate_cases(args.cases_dir, args.library_dir, args.case_ids),
                     indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
