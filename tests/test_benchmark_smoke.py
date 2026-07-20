"""Benchmark smoke result contracts."""
from __future__ import annotations

import tempfile
from pathlib import Path
import subprocess

from lotusmcp.control_plane.keyring import SigningKey
from lotusmcp.control_plane.anchor import create_anchor
from lotusmcp.engine.budget import BudgetLedger
from lotusmcp.kernel.case import Case
from lotusmcp.ops.benchmark_matrix import (
    classify_case,
    dataset_path,
    iter_entries,
    summarize,
)
from lotusmcp.ops.benchmark_smoke import (
    ChallengeSpec,
    SPECS,
    _compose_env,
    _host_env,
    _recon,
    _seed_case,
    build_parser,
    stop_target,
    build_result,
    SmokeConfig,
)


def test_aggregate_result_omits_raw_flag():
    with tempfile.TemporaryDirectory() as d:
        case = Case.create(Path(d), "bench", title="t", category="web",
                           flag_format=r"flag\{[^}]+\}")
        anchor = create_anchor(case.store, SigningKey.generate())
        result = build_result(
            case=case,
            challenge_id="2013q-web-guess_harder",
            case_id="bench",
            solved=True,
            budget=BudgetLedger(),
            anchor=anchor,
            wall_seconds=1.2345,
        )
    text = repr(result)
    assert result["benchmark"] == "nyu-ctf-bench"
    assert result["solved"] is True and result["flag_verified"] is True
    assert "audit_anchor" in result and result["chain_ok"] is True
    assert all(spec.expected_flag not in text for spec in SPECS.values())


def test_builtin_specs_have_unique_ports_or_run_sequentially():
    assert {
        "2013q-web-guess_harder",
        "2015q-web-k_stairs",
        "2016q-web-mfw",
        "2016q-web-i_got_id",
        "2017q-web-notmycupofcoffe",
        "2017q-web-orange",
        "2017q-web-orangev2",
        "2019f-web-biometric",
        "2020f-web-picgram",
        "2021q-web-gatekeeping",
        "2021q-web-no_pass_needed",
        "2021q-web-poem_collection",
        "2021q-web-securinotes",
        "2023f-web-shreeramquest",
        "2023q-web-philanthropy",
        "2023q-web-smug_dino",
    } <= set(SPECS)
    for cid, spec in SPECS.items():
        assert spec.challenge_id == cid
        assert spec.split in {"development", "test"}
        assert spec.category
        assert spec.expected_flag
        assert spec.exploit_script.strip()
        if spec.target_kind == "offline":
            assert spec.category != "web"
            assert spec.probe_path.startswith("artifact://")
        else:
            assert spec.probe_path.startswith("/")


def test_compose_env_is_opt_in_and_materialized():
    spec = ChallengeSpec(
        challenge_id="demo",
        rel=Path("demo"),
        port=80,
        probe_path="/",
        expected_flag="flag{demo}",
        exploit_script="print('ok')",
        note="demo",
        compose_env=(("PUPPETEER_SKIP_DOWNLOAD", "true"),),
    )
    assert _compose_env(SPECS["2013q-web-guess_harder"]) == {}
    assert _compose_env(spec) == {"PUPPETEER_SKIP_DOWNLOAD": "true"}


def test_parser_accepts_multiple_explicit_challenges():
    args = build_parser().parse_args([
        "--bench-dir", "/bench",
        "--case-id", "multi",
        "--challenge", "2017q-cry-almost_xor",
        "--challenge", "2017q-cry-another_xor",
    ])
    assert args.challenge == ["2017q-cry-almost_xor", "2017q-cry-another_xor"]


def test_host_env_includes_challenge_dir_and_overrides():
    with tempfile.TemporaryDirectory() as d:
        challenge_dir = Path(d)
        spec = ChallengeSpec(
            challenge_id="demo",
            rel=Path("demo"),
            port=80,
            probe_path="/",
            expected_flag="flag{demo}",
            exploit_script="print('ok')",
            note="demo",
            host_start_env=(("PYTHONPATH", "/tmp/custom"),),
        )
        env = _host_env(spec, challenge_dir)
    assert env["LOTUS_CHALLENGE_DIR"] == str(challenge_dir)
    assert env["PYTHONPATH"] == "/tmp/custom"


def test_stop_target_terminates_host_process_group():
    with tempfile.TemporaryDirectory() as d:
        spec = ChallengeSpec(
            challenge_id="demo",
            rel=Path("demo"),
            port=80,
            probe_path="/",
            expected_flag="flag{demo}",
            exploit_script="print('ok')",
            note="demo",
            host_start_cmd=("python", "-c", "import time; time.sleep(60)"),
        )
        proc = subprocess.Popen(
            list(spec.host_start_cmd),
            cwd=d,
            start_new_session=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        stop_target(Path(d), spec, proc)
    assert proc.poll() is not None


def test_offline_recon_uses_artifact_entity_without_network_scope():
    with tempfile.TemporaryDirectory() as d:
        root = Path(d)
        bench = root / "bench"
        cases = root / "cases"
        challenge_dir = bench / SPECS["2017q-cry-almost_xor"].rel
        challenge_dir.mkdir(parents=True)
        (challenge_dir / "README.md").write_text("flag{demo}\n", encoding="utf-8")
        config = SmokeConfig(
            bench_dir=bench,
            cases_dir=cases,
            results=root / "results.jsonl",
            case_id="offline",
            challenge_id="2017q-cry-almost_xor",
        )
        case, _signer, scope = _seed_case(config, SPECS["2017q-cry-almost_xor"])
        target = _recon(case, scope, SPECS["2017q-cry-almost_xor"])
    assert target["display"].startswith("artifact://")
    assert scope.in_scope("127.0.0.1", 1)


def test_matrix_classifies_supported_missing_and_needs_spec():
    with tempfile.TemporaryDirectory() as d:
        root = Path(d)
        supported = root / SPECS["2013q-web-guess_harder"].rel
        supported.mkdir(parents=True)
        (supported / "docker-compose.yml").write_text("services: {}\n", encoding="utf-8")
        local = root / "development/2099/CSAW-Quals/web/localonly"
        local.mkdir(parents=True)
        rows = [
            classify_case(root, "development", "2013q-web-guess_harder", {
                "year": "2013",
                "event": "CSAW-Quals",
                "category": "web",
                "challenge": "Guess Harder",
                "path": str(SPECS["2013q-web-guess_harder"].rel),
            }),
            classify_case(root, "development", "2099q-web-localonly", {
                "year": "2099",
                "event": "CSAW-Quals",
                "category": "web",
                "challenge": "localonly",
                "path": "development/2099/CSAW-Quals/web/localonly",
            }),
            classify_case(root, "test", "2099q-web-missing", {
                "year": "2099",
                "event": "CSAW-Quals",
                "category": "web",
                "challenge": "missing",
                "path": "test/2099/CSAW-Quals/web/missing",
            }),
        ]
    assert [r["status"] for r in rows] == [
        "supported", "missing_compose", "missing_checkout",
    ]
    summary = summarize(rows)
    assert summary["total"] == 3
    assert summary["supported"] == 1
    assert summary["checked_out"] == 2


def test_matrix_iter_entries_filters_before_limit():
    dataset = {
        "a": {"category": "web"},
        "b": {"category": "crypto"},
        "c": {"category": "web"},
    }
    assert [cid for cid, _ in iter_entries(dataset, category="web", limit=1)] == ["a"]


def test_matrix_supports_nyu_and_ctf_dojo_dataset_paths():
    root = Path("/bench")
    assert dataset_path(root, "nyu-ctf-bench", "test") == root / "test_dataset.json"
    assert dataset_path(root, "ctf-dojo", "archive") == root / "ctf_archive.json"
    try:
        dataset_path(root, "ctf-dojo", "test")
    except ValueError as e:
        assert "CTF-Dojo" in str(e)
    else:
        raise AssertionError("expected invalid CTF-Dojo split to fail")


def test_ctf_dojo_inventory_is_not_marked_supported_without_runtime():
    with tempfile.TemporaryDirectory() as d:
        root = Path(d)
        row = classify_case(root, "archive", "ca-demo-pwn-task", {
            "benchmark": "ctf-archive",
            "event": "demo",
            "category": "pwn",
            "challenge": "task",
            "path": "ctf-archive/demo/task",
        }, benchmark="ctf-dojo")
    assert row["benchmark"] == "ctf-dojo"
    assert row["status"] == "missing_checkout"
    assert row["supported_smoke"] is False


def test_matrix_marks_test_split_specs_supported():
    with tempfile.TemporaryDirectory() as d:
        root = Path(d)
        spec = SPECS["2023f-web-shreeramquest"]
        target = root / spec.rel
        target.mkdir(parents=True)
        (target / "docker-compose.yml").write_text("services: {}\n", encoding="utf-8")
        row = classify_case(root, "test", spec.challenge_id, {
            "year": "2023",
            "event": "CSAW-Finals",
            "category": "web",
            "challenge": "ShreeRamQuest",
            "path": str(spec.rel),
        })
    assert row["status"] == "supported"
    assert row["supported_smoke"] is True


def test_matrix_marks_offline_specs_supported_without_compose():
    with tempfile.TemporaryDirectory() as d:
        root = Path(d)
        spec = SPECS["2017q-cry-almost_xor"]
        target = root / spec.rel
        target.mkdir(parents=True)
        row = classify_case(root, "test", spec.challenge_id, {
            "year": "2017",
            "event": "CSAW-Quals",
            "category": "crypto",
            "challenge": "almost_xor",
            "path": str(spec.rel),
        })
    assert row["status"] == "supported"
    assert row["compose_present"] is False
    assert row["supported_smoke"] is True


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items())
           if k.startswith("test_") and callable(v)]
    failed = 0
    for fn in fns:
        try:
            fn()
            print(f"  ok  {fn.__name__}")
        except Exception as e:
            failed += 1
            print(f"FAIL  {fn.__name__}: {e}")
    print(f"\n{len(fns)-failed}/{len(fns)} passed")
    raise SystemExit(1 if failed else 0)
