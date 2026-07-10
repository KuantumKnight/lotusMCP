"""Seed playbooks — the "first 10 minutes" reflexes, made declarative.

Distilled from CTF_Guide/00-cheatsheet.md and the web/crypto guides. Each rule
is a forward-chaining selector over the graph that proposes exactly one
capability against one in-scope entity. Capabilities are internal adapter names
(never MCP tools) — the Executor maps them to hardened argv.

Phase gates follow §4.3: RECON widens the surface, ENUMERATE drills it, EXPLOIT
tests a vulnerability class. Keeping these as Python literals is the skeleton's
stdlib-only stance; they map 1:1 onto the Phase-8 YAML schema.
"""
from __future__ import annotations

from typing import List

from lotusmcp.playbooks.model import Entity, Rule

RECON = ("RECON",)
ENUM = ("ENUMERATE",)
EXPLOIT = ("EXPLOIT",)


def _param_type(e: Entity) -> str:
    return str(e.attr("type", "") or "").lower()


def _reflected(e: Entity) -> bool:
    return bool(e.attr("reflected"))


# ---------------------------------------------------------------- recon
RECON_RULES: List[Rule] = [
    Rule(
        id="recon.port_scan", category="recon", capability="port_scan",
        kind="host", phase_gate=RECON,
        rationale="Host in scope with no enumerated services — scan TCP surface.",
        when=lambda e: not e.edges.get("EXPOSES"),
        params=lambda e: {"probe": "top1000", "class": "tcp"},
        yield_=0.7, priority=0.8, cost=3.0, risk=1.0,
    ),
    Rule(
        id="recon.http_probe", category="web", capability="http_probe",
        kind="service.http", phase_gate=RECON,
        rationale="HTTP service found — grab headers, robots.txt, sitemap, title.",
        params=lambda e: {"probe": "banner", "paths": ["/", "/robots.txt", "/sitemap.xml"]},
        yield_=0.6, priority=0.7, cost=1.0, risk=1.0,
    ),
]

# ---------------------------------------------------------------- web enumerate
WEB_ENUM_RULES: List[Rule] = [
    Rule(
        id="web.git_exposure", category="web", capability="http_probe",
        kind="service.http", phase_gate=ENUM,
        rationale="Check for exposed VCS metadata (/.git/HEAD -> git-dumper).",
        params=lambda e: {"probe": "git", "class": "vcs", "paths": ["/.git/HEAD", "/.git/config"]},
        yield_=0.5, priority=0.75, cost=1.0, risk=1.0,
    ),
    Rule(
        id="web.dir_bruteforce", category="web", capability="dir_bruteforce",
        kind="service.http", phase_gate=ENUM,
        rationale="Fuzz for hidden content (admin/api/backup) with a CTF wordlist.",
        params=lambda e: {"wordlist": "ctf-web", "class": "content", "filter": "404"},
        yield_=0.6, priority=0.7, cost=2.5, risk=1.0,
    ),
    Rule(
        id="web.nuclei_sweep", category="web", capability="vuln_scan",
        kind="service.http", phase_gate=ENUM,
        rationale="Quick known-vuln sweep (nuclei) over the HTTP service.",
        params=lambda e: {"probe": "nuclei", "class": "cve"},
        yield_=0.45, priority=0.55, cost=2.0, risk=0.9,
    ),
]

# ---------------------------------------------------------------- web exploit
_INJECT_PROBES = [
    ("web.sqli", "sqli", "'", 0.7, "Single-quote probe for SQL injection."),
    ("web.ssti", "ssti", "{{7*7}}", 0.55, "Template-injection probe (expect 49)."),
    ("web.xss", "xss", "<svg onload=alert(1)>", 0.4, "Reflected-XSS probe."),
    ("web.lfi", "lfi", "../../../../etc/passwd", 0.5, "Path-traversal / LFI probe."),
    ("web.ssrf", "ssrf", "http://169.254.169.254/", 0.45, "SSRF to cloud metadata."),
]


def _injection_rules() -> List[Rule]:
    rules: List[Rule] = []
    for rid, cls, payload, y, why in _INJECT_PROBES:
        rules.append(Rule(
            id=rid, category="web", capability="web_attack",
            kind="http.param", phase_gate=EXPLOIT,
            rationale=why,
            # reflected params are likelier injectable -> a touch more yield
            params=(lambda payload, cls: (lambda e: {
                "class": cls, "payload": payload, "location": e.attr("location", "query"),
            }))(payload, cls),
            yield_=y, priority=0.6, cost=1.5,
            risk=0.85 if cls in ("sqli", "ssrf") else 0.95,
        ))
    return rules


WEB_EXPLOIT_RULES: List[Rule] = _injection_rules() + [
    Rule(
        id="web.jwt_none", category="web", capability="web_attack",
        kind="credential", phase_gate=EXPLOIT,
        rationale="JWT credential present — try alg:none and weak-secret crack.",
        when=lambda e: str(e.attr("type", "")).lower() in ("jwt", "bearer"),
        params=lambda e: {"class": "jwt", "probe": "alg_none_and_crack"},
        yield_=0.6, priority=0.65, cost=1.5, risk=0.95,
    ),
    Rule(
        id="web.login_stuff", category="web", capability="web_attack",
        kind="credential", phase_gate=EXPLOIT,
        rationale="Discovered credential — replay it against the auth surface.",
        when=lambda e: not e.attr("validated"),
        params=lambda e: {"class": "cred_replay"},
        yield_=0.5, priority=0.55, cost=1.0, risk=0.9,
    ),
]

# ---------------------------------------------------------------- crypto
CRYPTO_RULES: List[Rule] = [
    Rule(
        id="crypto.rsa_factordb", category="crypto", capability="crypto_attack",
        kind="crypto.artifact", phase_gate=EXPLOIT,
        rationale="RSA modulus present — look up n on factordb before anything else.",
        when=lambda e: e.attr("n") is not None and e.attr("c") is not None,
        params=lambda e: {"class": "rsa", "probe": "factordb"},
        yield_=0.6, priority=0.8, cost=1.0, risk=1.0,
    ),
    Rule(
        id="crypto.rsa_small_e", category="crypto", capability="crypto_attack",
        kind="crypto.artifact", phase_gate=EXPLOIT,
        rationale="Small public exponent — try cube-root / low-exponent attack.",
        when=lambda e: str(e.attr("e", "")) in ("3", "5", "7", "17"),
        params=lambda e: {"class": "rsa", "probe": "small_e"},
        yield_=0.5, priority=0.6, cost=1.0, risk=1.0,
    ),
    Rule(
        id="crypto.rsa_fermat", category="crypto", capability="crypto_attack",
        kind="crypto.artifact", phase_gate=EXPLOIT,
        rationale="RSA with possibly close primes — Fermat factorisation.",
        when=lambda e: e.attr("n") is not None,
        params=lambda e: {"class": "rsa", "probe": "fermat"},
        yield_=0.35, priority=0.45, cost=1.5, risk=1.0,
    ),
    Rule(
        id="crypto.padding_oracle", category="crypto", capability="crypto_attack",
        kind="service.oracle", phase_gate=EXPLOIT,
        rationale="Padding oracle confirmed — run the CBC padding-oracle decrypt.",
        when=lambda e: str(e.attr("type", "")) == "padding" or e.display.endswith("padding"),
        params=lambda e: {"class": "padding_oracle", "probe": "cbc"},
        yield_=0.75, priority=0.85, cost=2.0, risk=0.95,
    ),
]

ALL_RULES: List[Rule] = (
    RECON_RULES + WEB_ENUM_RULES + WEB_EXPLOIT_RULES + CRYPTO_RULES
)
