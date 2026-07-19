"""Offline calibration from solved case logs.

    PYTHONPATH=. PYTHONIOENCODING=utf-8 python tests/test_library_calibrate.py
"""
from __future__ import annotations

import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from lotusmcp.engine.loop import Loop  # noqa: E402
from lotusmcp.executor.replay import FixtureBackend, ReplayExecutor  # noqa: E402
from lotusmcp.kernel.case import Case  # noqa: E402
from lotusmcp.kernel.events import EventDraft  # noqa: E402
from lotusmcp.library import TechniqueLibrary, calibrate_cases, extract_observations  # noqa: E402
from tests.test_replay_executor import FIXTURES, HOST  # noqa: E402


def _case(base):
    case = Case.create(base, "solved", title="solved web", category="web",
                       flag_format=r"flag\{[^}]+\}", platform="HackTheBox")
    case.append(EventDraft("entity.asserted", {"kind": "executor", "name": "seed"},
                           {"kind": "host", "natural_key": {"addr": HOST}}))
    case.append(EventDraft("entity.asserted", {"kind": "executor", "name": "seed"},
                           {"kind": "service.http",
                            "natural_key": {"host": HOST, "proto": "tcp", "port": 80}}))
    loop = Loop(case, ReplayExecutor(FixtureBackend(FIXTURES)))
    for _ in range(8):
        if loop.step().halted:
            break
    return case


def test_extract_observations_are_target_free():
    with tempfile.TemporaryDirectory() as d:
        case = _case(d)
        obs = extract_observations(case)
        assert obs, "expected command trail observations"
        blob = "\n".join(str(o.to_dict()) for o in obs)
        assert HOST not in blob
        assert all(o.capability for o in obs)


def test_calibrate_cases_updates_library():
    with tempfile.TemporaryDirectory() as d:
        _case(d)
        summary = calibrate_cases(d, Path(d) / "library")
        assert summary["observations"] > 0
        lib = TechniqueLibrary(Path(d) / "library")
        cards = lib.cards()
        assert cards
        assert any(c.capability == "http_probe" for c in cards.values())
        assert all(c.trials >= 1 for c in cards.values())


if __name__ == "__main__":
    import traceback

    fns = [v for k, v in sorted(globals().items())
           if k.startswith("test_") and callable(v)]
    failed = 0
    for fn in fns:
        try:
            fn()
            print(f"  ok  {fn.__name__}")
        except Exception:  # noqa: BLE001
            failed += 1
            print(f"FAIL  {fn.__name__}")
            traceback.print_exc()
    print(f"\n{len(fns) - failed}/{len(fns)} passed")
    sys.exit(1 if failed else 0)
