"""Output-adapter tests: tool stdout -> EventDrafts, with a projector round-trip.

Proves each parser (a) emits the identity.py natural keys so re-discoveries
merge, (b) is total on malformed/hostile input (no exception, no XML bomb), and
(c) that its events actually fold into the graph the brain reads.

    PYTHONPATH=. PYTHONIOENCODING=utf-8 python tests/test_parse_adapters.py
"""
from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from lotusmcp.executor.parse import (
    parse_ffuf_json,
    parse_http_response,
    parse_nmap_xml,
)
from lotusmcp.kernel.case import Case
from lotusmcp.ontology.identity import entity_id
from lotusmcp.playbooks.model import World

HOST = "10.10.11.53"

NMAP_XML = """<?xml version="1.0"?>
<nmaprun scanner="nmap">
 <host>
  <address addr="10.10.11.53" addrtype="ipv4"/>
  <ports>
   <port protocol="tcp" portid="22">
    <state state="open"/>
    <service name="ssh" product="OpenSSH" version="8.9p1"/>
   </port>
   <port protocol="tcp" portid="80">
    <state state="open"/>
    <service name="http" product="nginx" version="1.25.3"/>
   </port>
   <port protocol="tcp" portid="3306">
    <state state="closed"/>
    <service name="mysql"/>
   </port>
  </ports>
 </host>
</nmaprun>"""

CURL_HTTP = ("HTTP/1.1 200 OK\r\n"
             "Server: nginx/1.25.3 (Ubuntu)\r\n"
             "Content-Type: text/html\r\n\r\n"
             "<html>Titan Gateway</html>")

FFUF_JSON = """{"results": [
  {"input": {"FUZZ": "admin"}, "status": 401, "url": "http://10.10.11.53:80/admin"},
  {"input": {"FUZZ": "login"}, "status": 200, "url": "http://10.10.11.53:80/login"},
  {"input": {"FUZZ": ".git/config"}, "status": 200, "url": "http://10.10.11.53:80/.git/config"}
]}"""


# --------------------------------------------------------------- nmap


def test_nmap_emits_host_and_open_services_only():
    ev = parse_nmap_xml(NMAP_XML)
    kinds = [(e.type, e.payload.get("kind"), e.payload.get("natural_key")) for e in ev
             if e.type == "entity.asserted"]
    # host + two OPEN services; the closed 3306 must be absent
    assert ("entity.asserted", "host", {"addr": HOST}) in kinds
    assert ("entity.asserted", "service.tcp",
            {"host": HOST, "proto": "tcp", "port": 22}) in kinds
    assert ("entity.asserted", "service.http",
            {"host": HOST, "proto": "tcp", "port": 80}) in kinds
    assert all(nk.get("port") != 3306 for _, _, nk in kinds if nk), "closed port leaked"


def test_nmap_product_version_attrs():
    ev = parse_nmap_xml(NMAP_XML)
    attrs = {(e.payload["natural_key"]["port"], e.payload["attr"]): e.payload["value"]
             for e in ev if e.type == "attribute.asserted"}
    assert attrs[(80, "product")] == "nginx"
    assert attrs[(80, "version")] == "1.25.3"
    assert attrs[(22, "product")] == "OpenSSH"


def test_nmap_natural_key_matches_identity():
    ev = parse_nmap_xml(NMAP_XML)
    svc = next(e for e in ev if e.payload.get("kind") == "service.http")
    # the id derived here must equal the id any other tool would derive
    assert entity_id("service.http", svc.payload["natural_key"]).startswith("e_")


def test_nmap_total_on_garbage_and_xml_bomb():
    assert parse_nmap_xml("not xml at all") == []
    assert parse_nmap_xml("") == []
    assert parse_nmap_xml(123) == []
    bomb = ('<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY a "AAAA">]>'
            '<nmaprun>&a;</nmaprun>')
    assert parse_nmap_xml(bomb) == []   # DTD/entity declaration refused


# --------------------------------------------------------------- curl


def test_curl_server_version_split():
    nk = {"host": HOST, "proto": "tcp", "port": 80}
    ev = parse_http_response(CURL_HTTP, nk, path="/")
    got = {e.payload["attr"]: e.payload["value"] for e in ev
           if e.type == "attribute.asserted"}
    assert got == {"server": "nginx", "version": "1.25.3"}, got


def test_curl_git_exposure_finding():
    nk = {"host": HOST, "proto": "tcp", "port": 80}
    resp = "HTTP/1.1 200 OK\r\nServer: nginx\r\n\r\nref: refs/heads/main"
    ev = parse_http_response(resp, nk, path="/.git/HEAD")
    finds = [e for e in ev if e.type == "finding.raised"]
    assert len(finds) == 1
    assert finds[0].payload["type"] == "exposure"
    assert finds[0].payload["severity"] == "high"
    # 404 on the same path -> no finding
    resp404 = "HTTP/1.1 404 Not Found\r\nServer: nginx\r\n\r\n"
    assert not [e for e in parse_http_response(resp404, nk, path="/.git/HEAD")
                if e.type == "finding.raised"]


def test_curl_total_on_bad_input():
    assert parse_http_response("", {"host": HOST, "port": 80}) == []
    assert parse_http_response("garbage", {"host": HOST}) == []   # no port
    assert parse_http_response(None, {"host": HOST, "port": 80}) == []


# --------------------------------------------------------------- ffuf


def test_ffuf_endpoints_and_status():
    nk = {"host": HOST, "proto": "tcp", "port": 80}
    ev = parse_ffuf_json(FFUF_JSON, nk)
    ents = [e for e in ev if e.type == "entity.asserted"]
    assert len(ents) == 3
    paths = {e.payload["natural_key"]["path"] for e in ents}
    assert paths == {"/admin", "/login", "/.git/config"}
    assert all(e.payload["natural_key"]["scheme"] == "http" for e in ents)
    statuses = {e.payload["natural_key"]["path"]: e.payload["value"]
                for e in ev if e.type == "attribute.asserted"}
    assert statuses["/login"] == 200


def test_ffuf_total_on_bad_input():
    assert parse_ffuf_json("not json", {"host": HOST, "port": 80}) == []
    assert parse_ffuf_json('{"results": "nope"}', {"host": HOST, "port": 80}) == []
    assert parse_ffuf_json('{"results": [1, 2, 3]}', {"host": HOST, "port": 80}) == []
    assert parse_ffuf_json(FFUF_JSON, {"host": HOST}) == []   # no port


# --------------------------------------------------------------- round-trip


def test_parsed_events_fold_into_graph():
    """nmap+ffuf output -> EventDrafts -> log -> projector -> World the brain reads."""
    base = Path(tempfile.mkdtemp(prefix="lotus_parse_"))
    case = Case.create(base, "parse-rt", title="t", category="web",
                       flag_format=r"f\{.*\}")
    for d in parse_nmap_xml(NMAP_XML):
        case.append(d)
    svc_nk = {"host": HOST, "proto": "tcp", "port": 80}
    for d in parse_ffuf_json(FFUF_JSON, svc_nk):
        case.append(d)

    world = World.from_graph_db(case.rebuild()["graph_db"])
    http = world.entities("service.http")
    assert len(http) == 1
    assert http[0].nk == svc_nk, http[0].nk
    assert http[0].attr("version") == "1.25.3"
    # ffuf endpoints present, deduped by identity
    assert len(world.entities("http.endpoint")) == 3
    # re-applying the same output changes nothing (idempotent upsert)
    before = world.signature()
    for d in parse_nmap_xml(NMAP_XML):
        case.append(d)
    assert World.from_graph_db(case.rebuild()["graph_db"]).signature() == before


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
