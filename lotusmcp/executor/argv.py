"""Typed-argv adapters — the hardened translation from a decided action to a
concrete command line (Phase 1, §5 "Executor").

WHY THIS EXISTS
    A `CandidateAction` binds a capability to an *entity*. Some entities are
    discovered by earlier tool runs (a leaked vhost, a reflected parameter, a
    path recovered from an exposed `.git`). Their natural-key fields therefore
    carry **attacker-influenced strings**. If any such string reached a shell —
    or even reached a tool as an option-looking argument — it would be a command
    or argument injection. This module is the choke point that makes that
    impossible.

INVARIANTS (all enforced here, none delegated to the caller)
    1. Output is always an argv *list*; the runner MUST exec with shell=False.
       No value in this module is ever concatenated into a shell string.
    2. Every field is validated against a strict typed schema before it is
       placed in argv. A field that fails validation raises `ArgvRejected` —
       the action is dropped, never "best-effort" run.
    3. Option smuggling is blocked two ways: positional operands are placed
       after an explicit `--` end-of-options separator AND any operand that
       still begins with `-` is rejected outright (belt and suspenders).
    4. Tool flags, probe modes, wordlists and response filters come ONLY from
       server-controlled allowlists — never verbatim from entity/attacker data.

Only the three Phase-1 recon/enum capabilities are adapted here: `port_scan`,
`http_probe`, `dir_bruteforce`. Exploit/crypto capabilities run in Regime B and
route elsewhere; asking for one raises `NoAdapter`.
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from typing import Any, Dict, List, Mapping, Tuple

# --------------------------------------------------------------------------- errors


class ArgvRejected(ValueError):
    """A field failed the typed schema — the action must not be run."""


class NoAdapter(KeyError):
    """No Phase-1 argv adapter exists for this capability."""


# --------------------------------------------------------------------------- result


@dataclass(frozen=True)
class ArgvPlan:
    """One concrete command. `argv[0]` is the binary. Runner execs it verbatim
    with shell=False; `argv` is already fully validated and safe."""

    tool: str
    argv: Tuple[str, ...]
    capability: str
    target_id: str
    note: str = ""

    def as_line(self) -> str:
        """Human display only — NEVER feed this back to a shell."""
        return " ".join(self.argv)


# --------------------------------------------------------------------------- validators

# Control chars, NUL, CR, LF, and every shell metacharacter. Any hit → reject.
_FORBIDDEN = re.compile(r"[\x00-\x1f\x7f\s;&|`$<>(){}\[\]\\'\"*?!~#]")
# A DNS label: 1..63 of [A-Za-z0-9-], no leading/trailing hyphen.
_LABEL = re.compile(r"(?!-)[A-Za-z0-9-]{1,63}(?<!-)$")
# Conservative URL path: printable, no traversal, no query/fragment/space.
_PATH_CHARS = re.compile(r"[A-Za-z0-9._~%/-]*$")


def _require_str(value: Any, field: str) -> str:
    if not isinstance(value, str):
        raise ArgvRejected(f"{field}: expected str, got {type(value).__name__}")
    if value == "":
        raise ArgvRejected(f"{field}: empty")
    return value


def _no_dash_lead(value: str, field: str) -> str:
    # Even behind `--`, refuse operands that look like options.
    if value.startswith("-"):
        raise ArgvRejected(f"{field}: operand may not begin with '-' ({value!r})")
    return value


def validate_host(value: Any) -> str:
    """Accept a literal IPv4/IPv6 address or a strict DNS hostname; reject
    anything carrying metacharacters, whitespace, control chars or an option
    lead. Returns the canonical host string to place in argv."""
    host = _require_str(value, "host")
    if len(host) > 253:
        raise ArgvRejected("host: too long")
    # IP literal? (also normalises e.g. zero-compressed IPv6)
    try:
        return str(ipaddress.ip_address(host))
    except ValueError:
        pass
    if _FORBIDDEN.search(host):
        raise ArgvRejected(f"host: forbidden character in {host!r}")
    _no_dash_lead(host, "host")
    labels = host.rstrip(".").split(".")
    if not all(_LABEL.match(lab) for lab in labels):
        raise ArgvRejected(f"host: not a valid hostname ({host!r})")
    return host


def validate_port(value: Any) -> int:
    """A port is an int (or clean numeric str) in 1..65535."""
    if isinstance(value, bool):  # bool is an int subclass — refuse it explicitly
        raise ArgvRejected("port: bool is not a port")
    if isinstance(value, str):
        if not value.isdigit():
            raise ArgvRejected(f"port: not numeric ({value!r})")
        value = int(value)
    if not isinstance(value, int):
        raise ArgvRejected(f"port: expected int, got {type(value).__name__}")
    if not (1 <= value <= 65535):
        raise ArgvRejected(f"port: out of range ({value})")
    return value


def validate_path(value: Any) -> str:
    """A URL path: must be absolute, printable, traversal-free, no query/frag."""
    path = _require_str(value, "path")
    if not path.startswith("/"):
        raise ArgvRejected(f"path: must start with '/' ({path!r})")
    if len(path) > 2048:
        raise ArgvRejected("path: too long")
    if not _PATH_CHARS.match(path):
        raise ArgvRejected(f"path: forbidden character in {path!r}")
    if ".." in path:
        raise ArgvRejected(f"path: traversal segment in {path!r}")
    return path


def validate_scheme(value: Any) -> str:
    scheme = _require_str(value, "scheme").lower()
    if scheme not in ("http", "https"):
        raise ArgvRejected(f"scheme: not allowlisted ({scheme!r})")
    return scheme


def _pick(mapping: Mapping[str, Any], key: str, allow: Mapping[str, Any], field: str):
    """Look a caller-supplied token up in a server allowlist. The token itself is
    never placed in argv — only the mapped, server-authored value is."""
    token = mapping.get(key)
    if token is None:
        raise ArgvRejected(f"{field}: missing")
    if token not in allow:
        raise ArgvRejected(f"{field}: {token!r} not in allowlist {sorted(allow)}")
    return allow[token]


# --------------------------------------------------------------------------- allowlists

# nmap scan breadth (probe) and technique (class) — server-authored flags only.
_SCAN_BREADTH: Dict[str, List[str]] = {
    "quick": ["-F"],
    "top1000": ["--top-ports", "1000"],
    "full": ["-p-"],
}
_SCAN_TECH: Dict[str, List[str]] = {
    "tcp": ["-sT"],   # connect scan — works unprivileged in the sandbox
    "syn": ["-sS"],
    "udp": ["-sU"],
}

# dir_bruteforce wordlist name -> absolute path inside the sandbox image.
_WORDLISTS: Dict[str, str] = {
    "ctf-web": "/opt/wordlists/ctf-web.txt",
    "common": "/opt/wordlists/common.txt",
    "raft-medium": "/opt/wordlists/raft-medium-directories.txt",
}
# response filters -> ffuf flags.
_HTTP_FILTERS: Dict[str, List[str]] = {
    "404": ["-fc", "404"],
    "auto": ["-ac"],
    "none": [],
}


def _scheme_for(port: int, target: Mapping[str, Any]) -> str:
    if "scheme" in target:
        return validate_scheme(target["scheme"])
    proto = target.get("proto")
    if isinstance(proto, str) and proto.lower() in ("http", "https"):
        return proto.lower()
    return "https" if port == 443 else "http"


# --------------------------------------------------------------------------- adapters


def _port_scan(action, target: Mapping[str, Any]) -> List[ArgvPlan]:
    host = validate_host(target.get("addr") or target.get("host"))
    breadth = _pick(action.params, "probe", _SCAN_BREADTH, "probe")
    tech = _SCAN_TECH["tcp"]
    if "class" in action.params and action.params["class"] in _SCAN_TECH:
        tech = _SCAN_TECH[action.params["class"]]
    argv = ["nmap", "-Pn", "-n", "--open", "-oX", "-", *tech, *breadth, "--", host]
    return [ArgvPlan("nmap", tuple(argv), action.capability, action.target_id,
                     note=f"scan {host}")]


def _http_probe(action, target: Mapping[str, Any]) -> List[ArgvPlan]:
    host = validate_host(target.get("host") or target.get("addr"))
    port = validate_port(target.get("port", 80))
    scheme = _scheme_for(port, target)
    raw_paths = action.params.get("paths") or ["/"]
    if not isinstance(raw_paths, (list, tuple)):
        raise ArgvRejected("paths: expected a list")
    plans: List[ArgvPlan] = []
    for p in raw_paths:
        path = validate_path(p)
        url = f"{scheme}://{host}:{port}{path}"
        argv = ["curl", "-sS", "-i", "-o", "-", "--max-time", "20",
                "--max-redirs", "3", "--", url]
        plans.append(ArgvPlan("curl", tuple(argv), action.capability,
                              action.target_id, note=f"GET {path}"))
    return plans


def _dir_bruteforce(action, target: Mapping[str, Any]) -> List[ArgvPlan]:
    host = validate_host(target.get("host") or target.get("addr"))
    port = validate_port(target.get("port", 80))
    scheme = _scheme_for(port, target)
    wordlist = _pick(action.params, "wordlist", _WORDLISTS, "wordlist")
    flt = _pick(action.params, "filter", _HTTP_FILTERS, "filter")
    url = f"{scheme}://{host}:{port}/FUZZ"
    argv = ["ffuf", "-w", wordlist, "-u", url, "-t", "40", "-noninteractive",
            *flt]
    return [ArgvPlan("ffuf", tuple(argv), action.capability, action.target_id,
                     note=f"fuzz {scheme}://{host}:{port}/")]


_ADAPTERS: Dict[str, Any] = {
    "port_scan": _port_scan,
    "http_probe": _http_probe,
    "dir_bruteforce": _dir_bruteforce,
}


def build_argv(action, target: Mapping[str, Any]) -> List[ArgvPlan]:
    """Translate one decided `action` bound to `target` (the entity's natural
    key + any structured attrs) into one or more validated `ArgvPlan`s.

    Raises `NoAdapter` if the capability has no Phase-1 argv adapter, and
    `ArgvRejected` if any field fails the typed schema (the loop drops the
    action rather than run something unsafe).
    """
    adapter = _ADAPTERS.get(action.capability)
    if adapter is None:
        raise NoAdapter(action.capability)
    if not isinstance(target, Mapping):
        raise ArgvRejected(f"target: expected mapping, got {type(target).__name__}")
    return adapter(action, target)
