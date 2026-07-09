"""Phase-0 walking-skeleton demo — NO Kali required.

Hand-injects the events a recon chain (nmap -> httpx -> ffuf) would emit, then
rebuilds the projection and prints the bounded STATE.md. This proves the core
claim: many independent "tools" only ever APPEND immutable events; the graph
and the working set are pure folds of the log — zero shared-file writes, zero
races, deterministic rebuild.

    python -m lotusmcp.demo.seed_recon
"""
from __future__ import annotations

import tempfile
from pathlib import Path

from lotusmcp.kernel.case import Case
from lotusmcp.kernel.events import EventDraft
from lotusmcp.ontology.identity import entity_id

HOST = "10.10.11.53"


def _nmap(actor="nmap_xml@2"):
    yield EventDraft("entity.asserted", {"kind": "executor", "name": actor},
                     {"kind": "host", "natural_key": {"addr": HOST}})
    for port, prod, ver in [(22, "OpenSSH", "8.9p1"), (80, "nginx", "1.25.3")]:
        nk = {"host": HOST, "proto": "tcp", "port": port}
        yield EventDraft("entity.asserted", {"kind": "executor", "name": actor},
                         {"kind": "service.tcp", "natural_key": nk})
        yield EventDraft("attribute.asserted", {"kind": "executor", "name": actor},
                         {"kind": "service.tcp", "natural_key": nk, "attr": "product",
                          "value": prod, "confidence": 0.95})
        yield EventDraft("attribute.asserted", {"kind": "executor", "name": actor},
                         {"kind": "service.tcp", "natural_key": nk, "attr": "version",
                          "value": ver, "confidence": 0.9})


def _httpx(actor="httpx@1"):
    nk = {"host": HOST, "proto": "tcp", "port": 80}
    yield EventDraft("entity.asserted", {"kind": "executor", "name": actor},
                     {"kind": "service.http", "natural_key": nk})
    yield EventDraft("attribute.asserted", {"kind": "executor", "name": actor},
                     {"kind": "service.http", "natural_key": nk, "attr": "server",
                      "value": "nginx", "confidence": 0.9})
    yield EventDraft("attribute.asserted", {"kind": "executor", "name": actor},
                     {"kind": "service.http", "natural_key": nk, "attr": "title",
                      "value": "Titan Gateway", "confidence": 0.8})


def _ffuf(actor="ffuf_json@1"):
    for path, status in [("/admin", 401), ("/login", 200), ("/api/v1/users", 200),
                         ("/.git/config", 200)]:
        nk = {"host": HOST, "scheme": "http", "vhost": HOST, "method": "GET", "path": path}
        yield EventDraft("entity.asserted", {"kind": "executor", "name": actor},
                         {"kind": "http.endpoint", "natural_key": nk})
        yield EventDraft("attribute.asserted", {"kind": "executor", "name": actor},
                         {"kind": "http.endpoint", "natural_key": nk, "attr": "status",
                          "value": status, "confidence": 0.99})
    # a finding + a hypothesis (LLM reasoning, also an event)
    yield EventDraft("finding.raised", {"kind": "executor", "name": actor},
                     {"id": "F-000001", "type": "exposure",
                      "subject": {"host": HOST, "url": f"http://{HOST}/.git/config"},
                      "attrs": {"leak": "git repository exposed"},
                      "confidence": 0.9, "severity": "high"})
    yield EventDraft("hypothesis.proposed", {"kind": "llm", "name": "oracle"},
                     {"hid": "H1", "statement": "Exposed .git allows source recovery -> "
                      "credential or logic leak into /admin", "status": "OPEN",
                      "confidence": 0.6})


def main() -> None:
    base = Path(tempfile.mkdtemp(prefix="lotus_demo_"))
    case = Case.create(base, "htb-titan-demo", title="Titan Gateway",
                       category="web", flag_format=r"HTB\{[0-9a-f]{32}\}",
                       platform="HackTheBox")
    # "concurrent" tools — each only appends; order via seq, never clobber.
    for gen in (_nmap(), _httpx(), _ffuf()):
        for draft in gen:
            case.append(draft)

    result = case.rebuild()
    print("=" * 70)
    print(f"case dir: {case.dir}")
    print(f"events: {case.store.tip + 1}   chain intact: {case.store.verify_chain() == -1}")
    print(f"built_through_seq: {result['built_through_seq']}")
    print("=" * 70)
    print(result["state_md"])


if __name__ == "__main__":
    main()
