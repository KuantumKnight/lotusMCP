"""Triage — the ensemble classifier that estimates challenge category.

Its output, `category_conf` (a per-category confidence in [0,1]), is the knob the
Playbook Engine reads to weight `U(A)` (a web rule matters more on a web
challenge). Getting triage roughly right is what lets the deterministic loop
spend its budget on the right playbooks first.

Design: several cheap, independent **voters** each look at one signal source
(declared metadata, the graph's entity kinds, attached artifacts, open ports)
and cast weighted votes for categories, each with a human-readable reason. The
ensemble sums the votes and normalises. Independence is the point — no single
voter can dominate, and a wrong metadata hint is outvoted by hard graph
evidence (a real binary beats a misleading title).

Pure and deterministic: same (meta, world) -> same result.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Tuple

from lotusmcp.playbooks.model import World

CATEGORIES = ("web", "pwn", "rev", "crypto", "forensics", "osint")

# keyword -> category, weight. Drawn from CTF_Guide category reflexes.
_KEYWORDS: Dict[str, List[Tuple[str, float]]] = {
    "web": [("http", 1.0), ("url", 0.6), ("login", 0.8), ("api", 0.7),
            ("cookie", 0.7), ("jwt", 0.9), ("sql", 0.9), ("xss", 0.9),
            ("php", 0.7), ("flask", 0.7), ("admin", 0.6), ("portal", 0.6),
            ("gateway", 0.5), ("website", 0.8), ("web", 0.8), ("ssrf", 0.8),
            ("ssti", 0.8), ("upload", 0.6)],
    "pwn": [("overflow", 1.0), ("buffer", 0.9), ("ret2", 1.0), ("libc", 0.9),
            ("pwn", 1.0), ("shellcode", 0.9), ("canary", 0.8), ("rop", 0.9),
            ("format string", 0.9), ("heap", 0.8), ("stack", 0.6),
            ("exploit", 0.5), ("gadget", 0.7)],
    "rev": [("reverse", 1.0), ("decompile", 0.9), ("ghidra", 0.9),
            ("keygen", 0.9), ("license", 0.7), ("crackme", 1.0),
            ("disassemble", 0.8), ("unpack", 0.7), ("obfuscat", 0.7),
            ("serial", 0.6), ("flareon", 0.8)],
    "crypto": [("rsa", 1.0), ("aes", 0.9), ("cipher", 0.9), ("encrypt", 0.8),
               ("decrypt", 0.8), ("xor", 0.8), ("padding", 0.9), ("oracle", 0.8),
               ("ecb", 0.9), ("cbc", 0.8), ("nonce", 0.8), ("lattice", 0.9),
               ("ecc", 0.8), ("crypto", 0.9), ("prime", 0.7)],
    "forensics": [("pcap", 1.0), ("wireshark", 0.9), ("memory dump", 1.0),
                  ("volatility", 0.9), ("disk", 0.7), ("stego", 1.0),
                  ("steghide", 0.9), ("lsb", 0.8), ("spectrogram", 0.9),
                  ("exif", 0.8), ("carve", 0.7), ("binwalk", 0.8),
                  ("forensic", 0.9), ("recover", 0.6)],
    "osint": [("osint", 1.0), ("geolocation", 1.0), ("username", 0.8),
              ("profile", 0.7), ("twitter", 0.7), ("linkedin", 0.7),
              ("location", 0.7), ("photo", 0.6), ("who is", 0.7),
              ("reconnaissance of", 0.6)],
}

# entity kind -> category votes (hard evidence from the graph)
_KIND_VOTES: Dict[str, List[Tuple[str, float]]] = {
    "service.http": [("web", 2.0)],
    "http.endpoint": [("web", 1.0)],
    "http.param": [("web", 1.5)],
    "crypto.artifact": [("crypto", 2.5)],
    "service.oracle": [("crypto", 2.0)],
    "binary.elf": [("pwn", 1.5), ("rev", 1.2)],
}

# artifact mime/extension -> category
_MIME_VOTES: List[Tuple[str, str, float]] = [
    ("image/", "forensics", 1.2),
    ("audio/", "forensics", 1.5),
    ("application/vnd.tcpdump", "forensics", 2.0),
    ("application/x-pcap", "forensics", 2.0),
    ("application/x-executable", "pwn", 1.2),
    ("application/x-elf", "pwn", 1.2),
    ("application/x-dosexec", "rev", 1.2),
    ("application/x-pem", "crypto", 1.5),
]

Vote = Tuple[str, float, str]        # (category, weight, reason)
Voter = Callable[[Dict, World], List[Vote]]


@dataclass
class TriageResult:
    category_conf: Dict[str, float]
    top: str
    confidence: float
    reasons: List[str] = field(default_factory=list)


def _text_of(meta: Dict) -> str:
    parts = [str(meta.get(k, "")) for k in ("title", "description", "category", "prompt")]
    return " ".join(parts).lower()


def metadata_voter(meta: Dict, world: World) -> List[Vote]:
    votes: List[Vote] = []
    # an explicitly declared category is a strong (but not absolute) prior
    declared = str(meta.get("category", "")).lower().strip()
    if declared in CATEGORIES:
        votes.append((declared, 3.0, f"declared category '{declared}'"))
    text = _text_of(meta)
    for cat, kws in _KEYWORDS.items():
        for kw, w in kws:
            if kw in text:
                votes.append((cat, w, f"keyword '{kw}'"))
    return votes


def graph_voter(meta: Dict, world: World) -> List[Vote]:
    votes: List[Vote] = []
    for kind, kvotes in _KIND_VOTES.items():
        n = len(world.entities(kind))
        if n:
            # diminishing returns: sqrt(count) so 50 endpoints != 50x a web vote
            scale = (n ** 0.5)
            for cat, w in kvotes:
                votes.append((cat, round(w * scale, 3), f"{n}x {kind}"))
    return votes


def artifact_voter(meta: Dict, world: World) -> List[Vote]:
    votes: List[Vote] = []
    for art in world.entities("artifact"):
        mime = str(art.attr("mime", "")).lower()
        for prefix, cat, w in _MIME_VOTES:
            if mime.startswith(prefix):
                votes.append((cat, w, f"artifact mime {mime}"))
    return votes


def port_voter(meta: Dict, world: World) -> List[Vote]:
    votes: List[Vote] = []
    for svc in world.entities("service.tcp"):
        port = svc.attr("port") or _port_from_display(svc.display)
        product = str(svc.attr("product", "")).lower()
        if port in (80, 443, 8080, 8000, 8443):
            votes.append(("web", 0.8, f"tcp/{port}"))
        elif "ssh" in product:
            continue
        elif port and port > 1024:
            # a raw high TCP port with no HTTP is the classic nc-style pwn service
            votes.append(("pwn", 0.6, f"raw tcp/{port}"))
    return votes


def _port_from_display(display: str) -> int:
    m = re.search(r":(\d+)$", display)
    return int(m.group(1)) if m else 0


DEFAULT_VOTERS: List[Voter] = [metadata_voter, graph_voter, artifact_voter, port_voter]


def classify(
    meta: Dict, world: World, voters: List[Voter] = DEFAULT_VOTERS
) -> TriageResult:
    """Run the voter ensemble and return normalised per-category confidence."""
    totals: Dict[str, float] = {c: 0.0 for c in CATEGORIES}
    reasons: Dict[str, List[str]] = {c: [] for c in CATEGORIES}
    for voter in voters:
        for cat, weight, why in voter(meta, world):
            if cat in totals:
                totals[cat] += weight
                reasons[cat].append(why)

    grand = sum(totals.values())
    if grand <= 0.0:
        # no signal -> uniform prior, low confidence
        conf = {c: round(1.0 / len(CATEGORIES), 3) for c in CATEGORIES}
        return TriageResult(conf, "web", conf["web"], ["no signal: uniform prior"])

    conf = {c: round(v / grand, 3) for c, v in totals.items()}
    top = max(conf, key=lambda c: (conf[c], c))
    top_reasons = sorted(set(reasons[top]))
    return TriageResult(conf, top, conf[top], top_reasons)
