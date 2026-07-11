"""Cross-case Technique Library + calibration (Phase 7).

Cards are allowlist-generalized (no target leaks); Beta posteriors calibrate
from observed outcomes; the Thompson recommender is deterministic under a seeded
RNG; promotion is human-gated; the whole thing is a rebuildable fold of its log;
and an injected library calibrates from a real loop run.

    PYTHONPATH=. PYTHONIOENCODING=utf-8 python tests/test_technique_library.py
"""
from __future__ import annotations

import random
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from lotusmcp.engine.candidate import CandidateAction
from lotusmcp.engine.loop import Loop
from lotusmcp.executor.replay import FixtureBackend, ReplayExecutor
from lotusmcp.kernel.case import Case
from lotusmcp.kernel.events import EventDraft
from lotusmcp.library import TechniqueLibrary, technique_id
from tests.test_replay_executor import FIXTURES, HOST


def _lib(d):
    return TechniqueLibrary(Path(d) / "library")


def test_generalization_carries_no_target():
    with tempfile.TemporaryDirectory() as d:
        lib = _lib(d)
        act = CandidateAction(
            capability="http_probe", category="web", target_id="svc:10.10.11.5:80",
            target_display="10.10.11.5:80", params={"probe": "git"},
            rule_id="r", rationale="check .git", phase_gate=("ENUMERATE",))
        tid = lib.observe_action(act, "ENUMERATE", success=True)
        card = lib.card(tid)
        blob = str(card.to_dict())
        # the card key is (capability, category, param_class) — no host/path
        assert tid == technique_id("http_probe", "web", "git")
        assert "10.10.11.5" not in blob and "svc:" not in blob, blob
        assert card.capability == "http_probe" and card.param_class == "git"
        print(f"generalized card {tid} carries no target detail")


def test_beta_posterior_calibrates():
    with tempfile.TemporaryDirectory() as d:
        lib = _lib(d)
        for _ in range(7):
            lib.observe("web_attack", "web", "sqli", "EXPLOIT", success=True)
        for _ in range(3):
            lib.observe("web_attack", "web", "sqli", "EXPLOIT", success=False)
        c = lib.card(technique_id("web_attack", "web", "sqli"))
        assert c.trials == 10 and c.wins == 7
        assert c.alpha == 8 and c.beta == 4           # wins+1, losses+1
        assert abs(c.mean - 8 / 12) < 1e-9
        print(f"posterior after 7/3: mean={c.mean:.3f} α={c.alpha} β={c.beta}")


def test_thompson_ranks_better_technique_higher_and_is_seed_deterministic():
    with tempfile.TemporaryDirectory() as d:
        lib = _lib(d)
        # a strong technique and a weak one, same phase/category
        for _ in range(20):
            lib.observe("cap_good", "web", "-", "EXPLOIT", True)
        for _ in range(2):
            lib.observe("cap_good", "web", "-", "EXPLOIT", False)
        for _ in range(2):
            lib.observe("cap_bad", "web", "-", "EXPLOIT", True)
        for _ in range(20):
            lib.observe("cap_bad", "web", "-", "EXPLOIT", False)
        good = technique_id("cap_good", "web", "-")
        # deterministic under a seeded RNG
        r1 = lib.suggest(category="web", rng=random.Random(42))
        r2 = lib.suggest(category="web", rng=random.Random(42))
        assert [x["tid"] for x in r1] == [x["tid"] for x in r2], "seed not deterministic"
        # over many samples the strong technique wins the top slot most of the time
        top_good = sum(1 for s in range(200)
                       if lib.suggest(category="web", rng=random.Random(s))[0]["tid"] == good)
        assert top_good > 150, top_good
        print(f"Thompson: strong technique tops {top_good}/200 seeds; seeded run stable")


def test_mean_mode_is_pure_exploitation():
    with tempfile.TemporaryDirectory() as d:
        lib = _lib(d)
        for _ in range(9):
            lib.observe("a", "web", "-", "EXPLOIT", True)     # mean 10/11
        for _ in range(9):
            lib.observe("b", "web", "-", "EXPLOIT", False)    # mean 1/11
        ranked = lib.suggest(category="web")                  # no rng → mean
        assert ranked[0]["capability"] == "a" and ranked[-1]["capability"] == "b"
        print("mean-mode ranking exploits the higher posterior")


def test_phase_and_category_filters():
    with tempfile.TemporaryDirectory() as d:
        lib = _lib(d)
        lib.observe("nmap_cap", "recon", "top1000", "RECON", True)
        lib.observe("web_attack", "web", "sqli", "EXPLOIT", True)
        assert {c["capability"] for c in lib.suggest(phase="RECON")} == {"nmap_cap"}
        assert {c["capability"] for c in lib.suggest(category="web")} == {"web_attack"}
        assert lib.suggest(phase="POST_EXPLOIT") == []
        print("phase/category filters constrain the candidate set")


def test_promotion_is_human_gated_and_rebuildable():
    with tempfile.TemporaryDirectory() as d:
        lib = _lib(d)
        tid = lib.observe("web_attack", "web", "sqli", "EXPLOIT", True)
        assert lib.card(tid).status == "candidate"
        # cannot promote something never observed
        try:
            lib.promote("Tdeadbeef00", "alice"); raise AssertionError("should raise")
        except KeyError:
            pass
        lib.promote(tid, "alice")
        assert lib.card(tid).status == "promoted"
        assert lib.suggest(promoted_only=True)[0]["tid"] == tid
        # rebuild from the log in a fresh instance → identical cards
        lib2 = TechniqueLibrary(Path(d) / "library")
        a = {t: c.to_dict() for t, c in lib.cards().items()}
        b = {t: c.to_dict() for t, c in lib2.cards().items()}
        assert a == b, "library is not a deterministic rebuildable fold"
        print("promotion human-gated; cards rebuild identically from the log")


def test_loop_feeds_outcomes_into_library():
    with tempfile.TemporaryDirectory() as d:
        lib = _lib(d)
        case = Case.create(d, "cal", title="t", category="web",
                           flag_format=r"flag\{[^}]+\}", platform="HackTheBox")
        case.append(EventDraft("entity.asserted", {"kind": "executor", "name": "seed"},
                               {"kind": "host", "natural_key": {"addr": HOST}}))
        case.append(EventDraft("entity.asserted", {"kind": "executor", "name": "seed"},
                               {"kind": "service.http",
                                "natural_key": {"host": HOST, "proto": "tcp", "port": 80}}))
        loop = Loop(case, ReplayExecutor(FixtureBackend(FIXTURES)), library=lib)
        for _ in range(10):
            if loop.step().halted:
                break
        cards = lib.cards()
        assert cards, "loop should have recorded technique observations"
        # every observed card is target-free and has at least one trial
        for c in cards.values():
            assert c.trials >= 1
            assert HOST not in str(c.to_dict())
        # at least one real capability was calibrated
        caps = {c.capability for c in cards.values()}
        assert "http_probe" in caps, caps
        print(f"loop calibrated {len(cards)} techniques: {sorted(caps)}")


def test_loop_without_library_is_unaffected():
    with tempfile.TemporaryDirectory() as d:
        case = Case.create(d, "noln", title="t", category="web")
        case.append(EventDraft("entity.asserted", {"kind": "executor", "name": "seed"},
                               {"kind": "host", "natural_key": {"addr": HOST}}))
        loop = Loop(case, ReplayExecutor(FixtureBackend(FIXTURES)))  # no library
        loop.step()
        assert loop.library is None
        print("no library → loop runs unchanged")


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
