"""Host diagnostics for operating LotusMCP on Kali or benchmark containers."""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
import platform
import shutil
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable, List, Optional


@dataclass(frozen=True)
class Check:
    name: str
    ok: bool
    required: bool
    detail: str


def _which(name: str) -> Optional[str]:
    return shutil.which(name)


def _module_exists(name: str) -> bool:
    return importlib.util.find_spec(name) is not None


def _check_path(path: str, *, required: bool, name: str) -> Check:
    p = Path(path)
    return Check(name, p.exists(), required,
                 str(p) if p.exists() else f"missing: {p}")


def run_checks(
    *,
    cases_dir: str | os.PathLike = "cases",
    full: bool = False,
    mcp: bool = False,
    benchmark: bool = False,
) -> List[Check]:
    """Return host readiness checks.

    `full` means LotusMCP may execute Kali tools on the operator host.
    `benchmark` means Docker/Compose-backed benchmark targets may be launched.
    """
    checks: List[Check] = []
    py_ok = sys.version_info >= (3, 11)
    checks.append(Check("python>=3.11", py_ok, True, platform.python_version()))
    checks.append(Check("cryptography", _module_exists("cryptography"), True,
                        "importable" if _module_exists("cryptography") else "missing"))
    checks.append(Check("mcp-sdk", _module_exists("mcp"), mcp,
                        "importable" if _module_exists("mcp") else "missing"))

    cd = Path(cases_dir)
    checks.append(Check("cases-dir", cd.exists() or cd.parent.exists(), True,
                        str(cd if cd.exists() else cd.parent)))

    for tool in ("nmap", "curl", "ffuf"):
        found = _which(tool)
        checks.append(Check(f"kali-tool:{tool}", bool(found), full,
                            found or "missing"))

    checks.extend([
        _check_path("/usr/share/seclists/Discovery/Web-Content/common.txt",
                    required=full, name="wordlist:common"),
        _check_path("/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt",
                    required=False, name="wordlist:directory-small"),
    ])

    docker = _which("docker")
    podman = _which("podman")
    compose = _which("docker-compose") or (
        "docker compose" if docker else None
    )
    checks.append(Check("container-runtime", bool(docker or podman), benchmark,
                        docker or podman or "missing"))
    checks.append(Check("docker-compose", bool(compose), benchmark,
                        compose or "missing"))
    return checks


def _selected_failed(checks: Iterable[Check]) -> List[Check]:
    return [c for c in checks if c.required and not c.ok]


def _print_human(checks: Iterable[Check]) -> None:
    for c in checks:
        status = "OK" if c.ok else ("MISSING" if c.required else "optional-missing")
        req = "required" if c.required else "optional"
        print(f"{status:16} {req:8} {c.name:28} {c.detail}")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="lotus-doctor",
        description="Check this host for LotusMCP operation and benchmark runs.",
    )
    p.add_argument("--cases-dir", default=os.environ.get("LOTUS_CASES_DIR", "cases"))
    p.add_argument("--full", action="store_true",
                   help="require host Kali execution tools")
    p.add_argument("--mcp", action="store_true",
                   help="require the MCP SDK import")
    p.add_argument("--benchmark", action="store_true",
                   help="require a container runtime and compose for benchmark targets")
    p.add_argument("--all", action="store_true",
                   help="require FULL + MCP + benchmark checks")
    p.add_argument("--json", action="store_true", dest="json_out")
    return p


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    full = args.full or args.all
    mcp = args.mcp or args.all
    benchmark = args.benchmark or args.all
    checks = run_checks(
        cases_dir=args.cases_dir,
        full=full,
        mcp=mcp,
        benchmark=benchmark,
    )
    failed = _selected_failed(checks)
    if args.json_out:
        print(json.dumps({
            "ok": not failed,
            "checks": [asdict(c) for c in checks],
        }, indent=2, sort_keys=True))
    else:
        _print_human(checks)
        print(f"\n{'READY' if not failed else 'NOT READY'}")
    return 0 if not failed else 1


if __name__ == "__main__":
    raise SystemExit(main())
