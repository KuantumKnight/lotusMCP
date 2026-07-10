"""Tests for the triage ensemble classifier."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from lotusmcp.playbooks.model import World  # noqa: E402
from lotusmcp.triage.classify import CATEGORIES, classify  # noqa: E402


def _world(*dicts):
    return World.from_entity_dicts(list(dicts))


def test_conf_normalizes_to_one():
    r = classify({"category": "web", "title": "login portal"}, _world())
    assert abs(sum(r.category_conf.values()) - 1.0) < 1e-6
    assert set(r.category_conf) == set(CATEGORIES)


def test_declared_category_wins_on_thin_signal():
    r = classify({"category": "crypto", "title": "mystery"}, _world())
    assert r.top == "crypto"


def test_graph_evidence_drives_web():
    w = _world({"id": "e1", "kind": "service.http", "display": "service.http:h:80"},
               {"id": "e2", "kind": "http.param", "display": "http.param:id"})
    r = classify({"title": "untitled"}, w)
    assert r.top == "web"
    assert r.category_conf["web"] > 0.5


def test_rsa_artifact_drives_crypto():
    w = _world({"id": "e_rsa", "kind": "crypto.artifact", "display": "crypto.artifact:c",
                "attrs": {"n": "0x1", "e": "65537", "c": "0x2"}})
    r = classify({"title": "the modulus"}, w)
    assert r.top == "crypto"


def test_hard_graph_evidence_beats_misleading_title():
    # title screams crypto, but there is a real HTTP app with params
    w = _world({"id": "e1", "kind": "service.http", "display": "service.http:h:80"},
               {"id": "e2", "kind": "http.param", "display": "http.param:q"},
               {"id": "e3", "kind": "http.param", "display": "http.param:p"},
               {"id": "e4", "kind": "http.endpoint", "display": "http.endpoint:/x"})
    r = classify({"title": "AES cipher oracle"}, w)
    assert r.top == "web"


def test_forensics_from_artifact_mime():
    w = _world({"id": "a1", "kind": "artifact", "display": "artifact:x",
                "attrs": {"mime": "audio/wav"}})
    r = classify({"title": "listen closely"}, w)
    assert r.top == "forensics"


def test_pwn_from_raw_tcp_port():
    w = _world({"id": "s1", "kind": "service.tcp", "display": "service.tcp:h:31337",
                "attrs": {"port": 31337, "product": ""}})
    r = classify({"title": "connect with nc"}, w)
    assert r.top == "pwn"


def test_web_from_standard_http_port():
    w = _world({"id": "s1", "kind": "service.tcp", "display": "service.tcp:h:443",
                "attrs": {"port": 443}})
    r = classify({"title": ""}, w)
    assert r.category_conf["web"] > r.category_conf["pwn"]


def test_no_signal_uniform_prior():
    r = classify({}, _world())
    vals = set(r.category_conf.values())
    assert len(vals) == 1                     # all equal
    assert r.confidence < 0.3


def test_deterministic():
    w = _world({"id": "e1", "kind": "service.http", "display": "service.http:h:80"})
    a = classify({"category": "web", "title": "sql login"}, w)
    b = classify({"category": "web", "title": "sql login"}, w)
    assert a.category_conf == b.category_conf and a.top == b.top


def test_feeds_playbook_engine():
    # the whole point: triage output plugs straight into PlaybookEngine.propose
    from lotusmcp.playbooks.engine import PlaybookEngine
    w = _world({"id": "e1", "kind": "service.http", "display": "service.http:h:80"})
    conf = classify({"category": "web", "title": "portal"}, w).category_conf
    ps = PlaybookEngine().propose(w, "ENUMERATE", category_conf=conf)
    assert ps.actions and ps.proposals[0].score > 0


if __name__ == "__main__":
    import traceback

    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    failed = 0
    for fn in fns:
        try:
            fn()
            print(f"ok   {fn.__name__}")
        except Exception:  # noqa: BLE001
            failed += 1
            print(f"FAIL {fn.__name__}")
            traceback.print_exc()
    print(f"\n{len(fns) - failed}/{len(fns)} passed")
    sys.exit(1 if failed else 0)
