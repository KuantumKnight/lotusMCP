"""Output adapters — deterministic tool-stdout -> EventDrafts.

The mirror of the typed-argv layer: argv turns a decision into a command; these
turn that command's stdout back into knowledge events. Pure, stdlib-only, and
testable on Windows with recorded fixtures. Every adapter here:

  - is a TOTAL function: malformed, partial, or empty output yields fewer
    events, never an exception — a crashing parser would strand a real run;
  - emits the SAME natural keys `ontology/identity.py` derives, so the projector
    merges re-discoveries by idempotent upsert instead of duplicating them;
  - treats tool output as UNTRUSTED — it is attacker-influenced. It never evals
    it, caps input size, and refuses XML that declares a DTD/entity (billion-
    laughs / XXE guard).

A value discovered here can only re-enter a command through the typed-argv layer
(`argv.py`), which re-validates every field — so a hostile banner or path can
never become part of a command line.
"""
from __future__ import annotations

import hashlib
import json
import xml.etree.ElementTree as ET
from typing import Any, Dict, List, Mapping, Optional

from lotusmcp.kernel.events import EventDraft

_MAX_INPUT = 4 * 1024 * 1024          # 4 MiB — a scan of one host never exceeds this
_HTTP_SVC_NAMES = {"http", "https", "http-proxy", "http-alt", "https-alt"}


def _actor(name: str) -> Dict[str, str]:
    return {"kind": "executor", "name": name}


def _finding_id(ftype: str, *parts: Any) -> str:
    """Content-addressed, so the same exposure re-parsed upserts to one finding."""
    h = hashlib.blake2b("\x1f".join(str(p) for p in parts).encode("utf-8"),
                        digest_size=6).hexdigest()
    return f"F-{ftype}-{h}"


def _split_server(value: str) -> Dict[str, str]:
    """'nginx/1.25.3 (Ubuntu)' -> {'server': 'nginx', 'version': '1.25.3'}."""
    token = value.strip().split()[0] if value.strip() else ""
    if "/" in token:
        prod, _, ver = token.partition("/")
        out = {"server": prod}
        if ver:
            out["version"] = ver
        return out
    return {"server": token} if token else {}


# --------------------------------------------------------------------- nmap XML


def parse_nmap_xml(xml_text: str, actor: str = "nmap") -> List[EventDraft]:
    """nmap `-oX -` output -> host + open-service entities with product/version."""
    if not isinstance(xml_text, str) or len(xml_text) > _MAX_INPUT:
        return []
    lowered = xml_text.lower()
    if "<!doctype" in lowered or "<!entity" in lowered:
        return []                      # refuse DTD/entity declarations (XML bomb / XXE)
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return []

    out: List[EventDraft] = []
    act = _actor(actor)
    for host_el in root.iter("host"):
        addr = None
        for a in host_el.findall("address"):
            if a.get("addrtype") in ("ipv4", "ipv6"):
                addr = a.get("addr")
                break
        if not addr:
            continue
        out.append(EventDraft("entity.asserted", act,
                              {"kind": "host", "natural_key": {"addr": addr}}))
        ports_el = host_el.find("ports")
        if ports_el is None:
            continue
        for port_el in ports_el.findall("port"):
            state = port_el.find("state")
            if state is None or state.get("state") != "open":
                continue
            try:
                port = int(port_el.get("portid"))
            except (TypeError, ValueError):
                continue
            proto = port_el.get("protocol", "tcp")
            svc = port_el.find("service")
            svc_name = (svc.get("name") if svc is not None else "") or ""
            kind = "service.http" if svc_name in _HTTP_SVC_NAMES else "service.tcp"
            nk = {"host": addr, "proto": proto, "port": port}
            out.append(EventDraft("entity.asserted", act,
                                  {"kind": kind, "natural_key": nk}))
            if svc is not None:
                for attr, key, conf in (("product", "product", 0.95),
                                        ("version", "version", 0.9),
                                        ("name", "service", 0.9)):
                    val = svc.get(attr)
                    if val:
                        out.append(EventDraft("attribute.asserted", act,
                                              {"kind": kind, "natural_key": nk,
                                               "attr": key, "value": val,
                                               "confidence": conf}))
    return out


# --------------------------------------------------------------------- HTTP response


def parse_http_response(
    raw: str,
    service_nk: Mapping[str, Any],
    path: str = "/",
    actor: str = "curl",
) -> List[EventDraft]:
    """`curl -i` output for ONE (service, path) -> Server/version attrs on the
    service.http entity, plus an exposure finding for a live VCS path."""
    if not isinstance(raw, str) or len(raw) > _MAX_INPUT:
        return []
    nk = {"host": service_nk.get("host"), "proto": service_nk.get("proto", "tcp"),
          "port": service_nk.get("port")}
    if nk["host"] is None or nk["port"] is None:
        return []

    # First header block only (stop at the blank line separating headers/body).
    head = raw.split("\r\n\r\n", 1)[0].split("\n\n", 1)[0]
    lines = head.replace("\r\n", "\n").split("\n")
    status: Optional[int] = None
    if lines and lines[0].startswith("HTTP/"):
        parts = lines[0].split()
        if len(parts) >= 2 and parts[1].isdigit():
            status = int(parts[1])

    out: List[EventDraft] = []
    act = _actor(actor)
    for line in lines[1:]:
        if ":" not in line:
            continue
        name, _, value = line.partition(":")
        if name.strip().lower() == "server":
            for attr, val in _split_server(value).items():
                out.append(EventDraft("attribute.asserted", act,
                                      {"kind": "service.http", "natural_key": nk,
                                       "attr": attr, "value": val, "confidence": 0.9}))
            break

    if path.startswith("/.git/") and status == 200:
        out.append(EventDraft("finding.raised", act, {
            "id": _finding_id("exposure", nk["host"], nk["port"], "git"),
            "type": "exposure", "severity": "high", "confidence": 0.9,
            "subject": {"host": nk["host"],
                        "url": f"http://{nk['host']}:{nk['port']}{path}"},
            "attrs": {"leak": "exposed .git — source recoverable via git-dumper"},
        }))
    return out


# --------------------------------------------------------------------- ffuf JSON


def parse_ffuf_json(
    text: str,
    service_nk: Mapping[str, Any],
    actor: str = "ffuf",
) -> List[EventDraft]:
    """ffuf `-o json` output -> one http.endpoint entity per hit, with status."""
    if not isinstance(text, str) or len(text) > _MAX_INPUT:
        return []
    try:
        doc = json.loads(text)
    except (json.JSONDecodeError, TypeError):
        return []
    results = doc.get("results") if isinstance(doc, dict) else None
    if not isinstance(results, list):
        return []

    host = service_nk.get("host")
    port = service_nk.get("port")
    if host is None or port is None:
        return []
    scheme = "https" if port == 443 or service_nk.get("proto") == "https" else "http"

    out: List[EventDraft] = []
    act = _actor(actor)
    for r in results:
        if not isinstance(r, dict):
            continue
        word = (r.get("input") or {}).get("FUZZ") if isinstance(r.get("input"), dict) else None
        if not isinstance(word, str) or not word:
            continue
        path = word if word.startswith("/") else "/" + word
        status = r.get("status")
        nk = {"host": host, "scheme": scheme, "vhost": host, "method": "GET", "path": path}
        out.append(EventDraft("entity.asserted", act,
                              {"kind": "http.endpoint", "natural_key": nk}))
        if isinstance(status, int):
            out.append(EventDraft("attribute.asserted", act,
                                  {"kind": "http.endpoint", "natural_key": nk,
                                   "attr": "status", "value": status, "confidence": 0.99}))
    return out
