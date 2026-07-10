"""Scope / Grant Verifier — server-side, VERIFY-ONLY (§1, §2).

Scope is defined and *widened* only in the control plane, by a human-signed
manifest. The server never sets scope; it only (a) verifies the operator's
signature before trusting a scope, (b) answers `in_scope(host, port)` for the
Executor's per-request choke, and (c) enforces the one monotonic rule the agent
path is allowed: **it may only NARROW**. A proposed scope is accepted only if it
is a subset of the currently trusted scope — never a widening.

Pure functions of already-verified data; no key material, no network, no Kali.
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Tuple, Union

from lotusmcp.kernel.signing import verify_manifest


class ScopeError(ValueError):
    """A manifest failed verification or a scope rule was violated."""


# --------------------------------------------------------------------- ports


def _norm_ports(spec: Iterable[Union[int, str, List[int]]]) -> List[Tuple[int, int]]:
    out: List[Tuple[int, int]] = []
    for p in spec:
        if isinstance(p, bool):
            raise ScopeError(f"invalid port {p!r}")
        if isinstance(p, int):
            lo = hi = p
        elif isinstance(p, (list, tuple)) and len(p) == 2:
            lo, hi = int(p[0]), int(p[1])
        elif isinstance(p, str) and "-" in p:
            a, b = p.split("-", 1)
            lo, hi = int(a), int(b)
        elif isinstance(p, str) and p.isdigit():
            lo = hi = int(p)
        else:
            raise ScopeError(f"invalid port spec {p!r}")
        if not (1 <= lo <= hi <= 65535):
            raise ScopeError(f"port range out of bounds: {lo}-{hi}")
        out.append((lo, hi))
    return sorted(out)


def _port_in(ranges: List[Tuple[int, int]], port: int) -> bool:
    return any(lo <= port <= hi for lo, hi in ranges)


def _ports_subset(sub: List[Tuple[int, int]], sup: List[Tuple[int, int]]) -> bool:
    # every sub range must be fully covered by a single sup range
    return all(any(slo >= lo and shi <= hi for lo, hi in sup) for slo, shi in sub)


# --------------------------------------------------------------------- hosts


def _parse_host(h: str):
    """Return ('net', ip_network) or ('fqdn', lowered) or ('wild', suffix)."""
    h = h.strip().lower()
    if not h:
        raise ScopeError("empty host")
    if h.startswith("*."):
        return ("wild", h[1:])                 # ".example.com"
    try:
        return ("net", ipaddress.ip_network(h, strict=False))
    except ValueError:
        return ("fqdn", h)


def _host_matches(rule, host: str) -> bool:
    kind, val = rule
    host = host.strip().lower()
    if kind == "net":
        try:
            return ipaddress.ip_address(host) in val
        except ValueError:
            return False
    if kind == "fqdn":
        return host == val
    if kind == "wild":
        return host.endswith(val) and host != val.lstrip(".")
    return False


def _host_subset(sub, sup) -> bool:
    """Is host-rule `sub` fully contained by host-rule `sup`?"""
    sk, sv = sub
    pk, pv = sup
    if pk == "net" and sk == "net":
        return sv.version == pv.version and sv.subnet_of(pv)
    if pk == "net" and sk == "fqdn":
        return False                            # a name is not provably inside a CIDR
    if pk == "wild":
        if sk == "wild":
            return sv.endswith(pv)
        if sk == "fqdn":
            return sv.endswith(pv) and sv != pv.lstrip(".")
    if pk == "fqdn" and sk == "fqdn":
        return sv == pv
    return False


# --------------------------------------------------------------------- scope


@dataclass
class Scope:
    hosts: List[str]
    ports: List[Tuple[int, int]]
    auto_cap: int = 1                           # max intrusiveness auto-approved
    _rules: List[Any] = field(default_factory=list, repr=False)

    @classmethod
    def from_payload(cls, p: Dict[str, Any]) -> "Scope":
        hosts = list(p.get("hosts", []))
        if not hosts:
            raise ScopeError("scope has no hosts")
        rules = [_parse_host(h) for h in hosts]
        ports = _norm_ports(p.get("ports", []))
        if not ports:
            raise ScopeError("scope has no ports")
        return cls(hosts=hosts, ports=ports,
                   auto_cap=int(p.get("auto_cap", 1)), _rules=rules)

    def in_scope(self, host: str, port: int) -> bool:
        try:
            port = int(port)
        except (TypeError, ValueError):
            return False
        if not _port_in(self.ports, port):
            return False
        return any(_host_matches(r, host) for r in self._rules)

    def is_subset_of(self, other: "Scope") -> bool:
        """True iff this scope only NARROWS `other`: every host contained, every
        port covered, and intrusiveness not raised."""
        if self.auto_cap > other.auto_cap:
            return False
        if not _ports_subset(self.ports, other.ports):
            return False
        return all(any(_host_subset(s, o) for o in other._rules) for s in self._rules)


# --------------------------------------------------------------------- verifier


class ScopeVerifier:
    def __init__(self, trusted_operator_keys: Iterable[str]) -> None:
        self.trusted = set(trusted_operator_keys)

    def _verified_payload(self, manifest: Dict[str, Any], mtype: str) -> Dict[str, Any]:
        if manifest.get("type") != mtype:
            raise ScopeError(f"expected {mtype} manifest, got {manifest.get('type')!r}")
        if not verify_manifest(manifest, self.trusted):
            raise ScopeError(f"{mtype} manifest signature not trusted")
        payload = manifest.get("payload")
        if not isinstance(payload, dict):
            raise ScopeError("manifest payload missing")
        return payload

    def load_scope(self, manifest: Dict[str, Any]) -> Scope:
        return Scope.from_payload(self._verified_payload(manifest, "scope"))

    def verify_egress_grant(self, manifest: Dict[str, Any]) -> Dict[str, Any]:
        return self._verified_payload(manifest, "egress_grant")

    def verify_submit_allowlist(self, manifest: Dict[str, Any]) -> List[str]:
        payload = self._verified_payload(manifest, "submit_allowlist")
        return list(payload.get("endpoints", []))

    def tier3_enabled(self, manifest: Optional[Dict[str, Any]]) -> bool:
        if manifest is None:
            return False
        try:
            return bool(self._verified_payload(manifest, "tier3").get("enabled"))
        except ScopeError:
            return False

    def accept_narrowing(self, current: Scope, proposed: Scope) -> Scope:
        """Agent-path scope change: allowed ONLY if it narrows. Returns the
        proposed scope on success, raises `ScopeError` on any attempt to widen."""
        if not proposed.is_subset_of(current):
            raise ScopeError("proposed scope widens the trusted scope — rejected")
        return proposed
