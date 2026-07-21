"""Benchmark matrix inventory and execution.

The matrix layer is deliberately separate from individual exploit specs. It
answers two questions needed before large runs:

* which benchmark cases exist in a dataset split;
* which cases are locally checked out, dockerized, and supported by a verified
  LotusMCP smoke spec.

Unsupported cases are classified as readiness gaps, not benchmark failures.
"""
from __future__ import annotations

import argparse
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from lotusmcp.ops.benchmark_smoke import SPECS, SmokeConfig, run_smoke


@dataclass(frozen=True)
class MatrixConfig:
    bench_dir: Path
    benchmark: str
    split: str
    cases_dir: Path
    results: Path
    case_id_prefix: str
    limit: Optional[int] = None
    category: Optional[str] = None
    run_supported: bool = False
    manage_target: bool = False
    keep_target: bool = False


def dataset_path(bench_dir: Path, benchmark: str, split: str) -> Path:
    if benchmark == "nyu-ctf-bench":
        if split not in {"development", "test"}:
            raise ValueError("NYU split must be 'development' or 'test'")
        return bench_dir / f"{split}_dataset.json"
    if benchmark == "ctf-dojo":
        if split != "archive":
            raise ValueError("CTF-Dojo split must be 'archive'")
        return bench_dir / "ctf_archive.json"
    raise ValueError("benchmark must be 'nyu-ctf-bench' or 'ctf-dojo'")


def load_dataset(bench_dir: Path, benchmark: str, split: str) -> Dict[str, Dict[str, Any]]:
    path = dataset_path(bench_dir, benchmark, split)
    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError(f"{path} must contain an object")
    return raw


def iter_entries(dataset: Dict[str, Dict[str, Any]], *,
                 category: Optional[str] = None,
                 limit: Optional[int] = None) -> Iterable[tuple[str, Dict[str, Any]]]:
    count = 0
    for challenge_id, meta in sorted(dataset.items()):
        if category and meta.get("category") != category:
            continue
        yield challenge_id, meta
        count += 1
        if limit is not None and count >= limit:
            break


def classify_case(bench_dir: Path, split: str, challenge_id: str,
                  meta: Dict[str, Any], *,
                  benchmark: str = "nyu-ctf-bench") -> Dict[str, Any]:
    rel = Path(str(meta["path"]))
    root = bench_dir / rel
    checkout_present = root.exists()
    compose_present = (root / "docker-compose.yml").exists()
    supported_smoke = (
        benchmark == "nyu-ctf-bench"
        and challenge_id in SPECS
        and SPECS[challenge_id].split == split
    )
    smoke_quality = SPECS[challenge_id].smoke_quality if supported_smoke else ""
    if supported_smoke:
        status = "supported"
    elif not checkout_present:
        status = "missing_checkout"
    elif not compose_present and meta.get("category") == "web":
        status = "missing_compose"
    else:
        status = "needs_spec"
    return {
        "challenge_id": challenge_id,
        "benchmark": benchmark,
        "split": split,
        "year": meta.get("year"),
        "event": meta.get("event"),
        "category": meta.get("category"),
        "challenge": meta.get("challenge"),
        "path": str(rel),
        "checkout_present": checkout_present,
        "compose_present": compose_present,
        "supported_smoke": supported_smoke,
        "smoke_quality": smoke_quality,
        "status": status,
    }


def summarize(rows: List[Dict[str, Any]]) -> Dict[str, Any]:
    by_status: Dict[str, int] = {}
    by_category: Dict[str, int] = {}
    by_smoke_quality: Dict[str, int] = {}
    for row in rows:
        by_status[row["status"]] = by_status.get(row["status"], 0) + 1
        category = str(row.get("category"))
        by_category[category] = by_category.get(category, 0) + 1
        smoke_quality = row.get("smoke_quality")
        if smoke_quality:
            by_smoke_quality[str(smoke_quality)] = (
                by_smoke_quality.get(str(smoke_quality), 0) + 1
            )
    return {
        "total": len(rows),
        "by_status": dict(sorted(by_status.items())),
        "by_category": dict(sorted(by_category.items())),
        "by_smoke_quality": dict(sorted(by_smoke_quality.items())),
        "supported": sum(1 for row in rows if row["supported_smoke"]),
        "checked_out": sum(1 for row in rows if row["checkout_present"]),
        "dockerized": sum(1 for row in rows if row["compose_present"]),
    }


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n",
                    encoding="utf-8")


def run_matrix(config: MatrixConfig) -> Dict[str, Any]:
    dataset = load_dataset(config.bench_dir, config.benchmark, config.split)
    rows = [
        classify_case(
            config.bench_dir,
            config.split,
            challenge_id,
            meta,
            benchmark=config.benchmark,
        )
        for challenge_id, meta in iter_entries(
            dataset, category=config.category, limit=config.limit
        )
    ]
    runs = []
    if config.run_supported:
        if config.benchmark != "nyu-ctf-bench":
            raise ValueError("--run-supported is currently implemented for NYU CTF Bench only")
        for row in rows:
            if not row["supported_smoke"]:
                continue
            run_result = run_smoke(SmokeConfig(
                bench_dir=config.bench_dir,
                cases_dir=config.cases_dir,
                results=config.results,
                case_id=f"{config.case_id_prefix}-{row['challenge_id']}".replace("_", "-"),
                challenge_id=row["challenge_id"],
                manage_target=config.manage_target,
                keep_target=config.keep_target,
            ))
            runs.append(run_result)
    payload = {
        "benchmark": config.benchmark,
        "split": config.split,
        "summary": summarize(rows),
        "inventory": rows,
        "runs": runs,
    }
    write_json(config.results.with_suffix(".matrix.json"), payload)
    return payload


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="lotus-benchmark-matrix",
        description="Inventory and optionally run supported benchmark cases.",
    )
    p.add_argument("--bench-dir", required=True,
                   help="benchmark checkout root")
    p.add_argument("--benchmark", choices=["nyu-ctf-bench", "ctf-dojo"],
                   default="nyu-ctf-bench")
    p.add_argument("--split", choices=["development", "test", "archive"],
                   default="test")
    p.add_argument("--cases-dir", default="/tmp/lotus_bench_cases")
    p.add_argument("--results", default="/tmp/lotus_bench_results.jsonl")
    p.add_argument("--case-id-prefix", default="nyu-matrix")
    p.add_argument("--limit", type=int)
    p.add_argument("--category")
    p.add_argument("--run-supported", action="store_true",
                   help="execute cases with built-in verified smoke specs")
    p.add_argument("--manage-target", action="store_true",
                   help="run docker-compose up/down for each executed case")
    p.add_argument("--keep-target", action="store_true",
                   help="leave each executed target running after its run")
    return p


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    payload = run_matrix(MatrixConfig(
        bench_dir=Path(args.bench_dir),
        benchmark=args.benchmark,
        split=args.split,
        cases_dir=Path(args.cases_dir),
        results=Path(args.results),
        case_id_prefix=args.case_id_prefix,
        limit=args.limit,
        category=args.category,
        run_supported=args.run_supported,
        manage_target=args.manage_target,
        keep_target=args.keep_target,
    ))
    print(json.dumps({
        "benchmark": payload["benchmark"],
        "split": payload["split"],
        "summary": payload["summary"],
        "runs": payload["runs"],
    }, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
