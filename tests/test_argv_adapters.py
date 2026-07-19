"""Golden + hostile-argv tests for the typed-argv adapter layer.

The golden cases pin the exact argv a clean action produces. The hostile cases
prove that attacker-influenced target/param fields — the strings that arrive via
tool-discovered entities — can never smuggle a shell metacharacter, an extra
option, a traversal, or a CRLF into argv: every one is rejected outright.

    PYTHONPATH=. PYTHONIOENCODING=utf-8 python tests/test_argv_adapters.py
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from lotusmcp.engine.candidate import CandidateAction
from lotusmcp.executor.argv import (
    ArgvRejected,
    NoAdapter,
    build_argv,
    validate_host,
    validate_path,
    validate_port,
)

RECON = ("RECON",)
ENUM = ("ENUMERATE",)


def _action(capability, params, phase_gate=RECON, target_id="e_x", disp="t"):
    return CandidateAction(
        capability=capability, category="recon", target_id=target_id,
        target_display=disp, params=params, rule_id="r", rationale="",
        phase_gate=phase_gate,
    )


def _expect_reject(fn, *a, **k):
    try:
        fn(*a, **k)
    except ArgvRejected:
        return
    raise AssertionError(f"{fn.__name__}{a} should have raised ArgvRejected")


# --------------------------------------------------------------- golden argv


def test_port_scan_golden():
    a = _action("port_scan", {"probe": "top1000", "class": "tcp"})
    plans = build_argv(a, {"addr": "10.10.11.53"})
    assert len(plans) == 1, plans
    assert plans[0].tool == "nmap"
    assert plans[0].argv == (
        "nmap", "-Pn", "-n", "--open", "-oX", "-", "-sT",
        "--top-ports", "1000", "--", "10.10.11.53",
    ), plans[0].argv


def test_http_probe_golden_multi_path():
    a = _action("http_probe", {"probe": "banner",
                               "paths": ["/", "/robots.txt", "/sitemap.xml"]})
    plans = build_argv(a, {"host": "10.10.11.53", "proto": "tcp", "port": 80})
    assert len(plans) == 3, plans
    assert plans[0].argv == (
        "curl", "-sS", "-i", "-o", "-", "--max-time", "20",
        "--max-redirs", "3", "--", "http://10.10.11.53:80/",
    ), plans[0].argv
    assert plans[1].argv[-1] == "http://10.10.11.53:80/robots.txt"


def test_http_probe_https_on_443():
    a = _action("http_probe", {"paths": ["/"]})
    plans = build_argv(a, {"host": "app.htb", "port": 443})
    assert plans[0].argv[-1] == "https://app.htb:443/", plans[0].argv


def test_dir_bruteforce_golden():
    a = _action("dir_bruteforce", {"wordlist": "ctf-web", "filter": "404"}, phase_gate=ENUM)
    plans = build_argv(a, {"host": "10.10.11.53", "port": 80})
    assert plans[0].tool == "ffuf"
    assert plans[0].argv == (
        "ffuf", "-w", "/usr/share/seclists/Discovery/Web-Content/quickhits.txt", "-u",
        "http://10.10.11.53:80/FUZZ", "-t", "40", "-noninteractive",
        "-of", "json", "-o", "-", "-fc", "404",
    ), plans[0].argv


# --------------------------------------------------------------- host hostility


def test_host_command_injection():
    for evil in ["10.0.0.1; rm -rf /", "$(id)", "`id`", "a|b", "a&&b",
                 "10.0.0.1 -oN /etc/x", "host\nSET", "host\r\nX", "a b",
                 "-oX", "--script=evil", "http://x/", "a/../b", "x`\t`y",
                 "a{b}c", "*", "10.0.0.1%0a"]:
        _expect_reject(validate_host, evil)


def test_host_accepts_clean():
    assert validate_host("10.10.11.53") == "10.10.11.53"
    assert validate_host("target.htb") == "target.htb"
    assert validate_host("sub.a-b.example.com") == "sub.a-b.example.com"
    # IPv6 literal is normalised
    assert validate_host("::1") == "::1"


def test_host_rejects_non_str_and_empty():
    _expect_reject(validate_host, 12345)
    _expect_reject(validate_host, None)
    _expect_reject(validate_host, "")
    _expect_reject(validate_host, "x" * 300)


# --------------------------------------------------------------- port hostility


def test_port_validation():
    assert validate_port(80) == 80
    assert validate_port("443") == 443
    for bad in [0, -1, 65536, 999999, "80; ls", "http", 3.14, True, None, "0x50"]:
        _expect_reject(validate_port, bad)


# --------------------------------------------------------------- path hostility


def test_path_traversal_and_injection():
    for evil in ["/../../etc/passwd", "/a/../b", "no-leading-slash",
                 "/a b", "/a;b", "/a\nb", "/a\r\nb", "/a|b", "/$(x)",
                 "/a?q=1", "/a#frag", "/a\\b", "/a`b`", "/a<b>", ""]:
        _expect_reject(validate_path, evil)


def test_path_accepts_clean():
    assert validate_path("/") == "/"
    assert validate_path("/robots.txt") == "/robots.txt"
    assert validate_path("/.git/HEAD") == "/.git/HEAD"
    assert validate_path("/api/v1/users-list") == "/api/v1/users-list"


# --------------------------------------------------- hostile fields via build_argv


def test_build_rejects_hostile_discovered_host():
    # A vhost recovered from tool output that tries to smuggle an nmap option.
    a = _action("port_scan", {"probe": "top1000"})
    _expect_reject(build_argv, a, {"addr": "-oX /tmp/pwn"})
    _expect_reject(build_argv, a, {"addr": "x.htb; curl evil"})


def test_build_rejects_hostile_path_in_http_probe():
    a = _action("http_probe", {"paths": ["/", "/legit", "/../../../../etc/passwd"]})
    _expect_reject(build_argv, a, {"host": "10.0.0.1", "port": 80})


def test_probe_and_wordlist_allowlist_enforced():
    _expect_reject(build_argv, _action("port_scan", {"probe": "../../etc"}),
                   {"addr": "10.0.0.1"})
    _expect_reject(build_argv, _action("port_scan", {"probe": "top1000; rm"}),
                   {"addr": "10.0.0.1"})
    _expect_reject(build_argv,
                   _action("dir_bruteforce", {"wordlist": "/etc/passwd", "filter": "404"}),
                   {"host": "10.0.0.1", "port": 80})
    _expect_reject(build_argv,
                   _action("dir_bruteforce", {"wordlist": "ctf-web", "filter": "200; ls"}),
                   {"host": "10.0.0.1", "port": 80})


def test_missing_probe_rejected():
    _expect_reject(build_argv, _action("port_scan", {}), {"addr": "10.0.0.1"})


def test_no_adapter_for_exploit_capability():
    try:
        build_argv(_action("web_attack", {"class": "sqli"}), {"host": "10.0.0.1"})
    except NoAdapter:
        return
    raise AssertionError("web_attack must have NO Phase-1 argv adapter")


def test_target_must_be_mapping():
    _expect_reject(build_argv, _action("port_scan", {"probe": "top1000"}), "10.0.0.1")


def test_no_argv_field_begins_with_dash_operand():
    # Belt-and-suspenders: after `--`, the final operand is never option-shaped.
    plans = build_argv(_action("port_scan", {"probe": "full", "class": "syn"}),
                       {"addr": "10.0.0.1"})
    assert plans[0].argv[-2] == "--"
    assert not plans[0].argv[-1].startswith("-")


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items())
           if k.startswith("test_") and callable(v)]
    failed = 0
    for fn in fns:
        try:
            fn()
            print(f"  ok  {fn.__name__}")
        except Exception as e:  # noqa: BLE001
            failed += 1
            print(f"FAIL  {fn.__name__}: {e}")
    print(f"\n{len(fns) - failed}/{len(fns)} passed")
    sys.exit(1 if failed else 0)
