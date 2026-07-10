"""Two-stage writeup: deterministic IR, then a citation verifier that exiles any
sentence the log does not support (§Phase 6).

Stage 1 (`build_ir`) is pure: it walks the graph + log and emits an intermediate
representation where **every claim carries citations** — references to the exact
events/entities/findings/flag that back it. Stage 2 (`verify_claims`) resolves
each citation against the log; a claim with a missing (or empty) citation is
REJECTED and never reaches the prose. This is the anti-hallucination guarantee:
narration (normally the LLM's job) can propose any sentence, but only sentences
whose citations actually resolve survive into `writeup.md`; the rest are exiled
as `writeup.claim_rejected` events. So the writeup can never assert something the
append-only log doesn't support.

Citation grammar: `event:<seq>`, `entity:<id>`, `finding:<id>`,
`hypothesis:<hid>`, `flag:<value>`.
"""
from __future__ import annotations

import sqlite3
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

from lotusmcp.kernel.events import EventDraft

_FLAG_EVENT_TYPES = ("flag.verified", "flag.candidate", "flag.submitted")


@dataclass(frozen=True)
class Claim:
    text: str
    citations: Tuple[str, ...] = ()


@dataclass
class Section:
    title: str
    claims: List[Claim] = field(default_factory=list)


@dataclass
class WriteupIR:
    case_id: str
    title: str
    category: Optional[str]
    sections: List[Section] = field(default_factory=list)

    def all_claims(self) -> List[Tuple[str, Claim]]:
        return [(s.title, c) for s in self.sections for c in s.claims]


# ------------------------------------------------------------------ citations


class CitationIndex:
    """Everything the log can support, gathered once for O(1) citation checks."""

    def __init__(self, case) -> None:
        self.event_seqs: Set[int] = set()
        self.flags: Set[str] = set()
        for ev in case.store.iter_events():
            self.event_seqs.add(ev["seq"])
            if ev["type"] in _FLAG_EVENT_TYPES:
                v = ev.get("payload", {}).get("value") or ev.get("payload", {}).get("flag")
                if isinstance(v, str):
                    self.flags.add(v)
        db = case.rebuild()["graph_db"]
        conn = sqlite3.connect(db)
        try:
            self.entities = {r[0] for r in conn.execute("SELECT entity_id FROM entity")}
            self.findings = {r[0] for r in conn.execute("SELECT id FROM finding")}
            self.hypotheses = {r[0] for r in conn.execute("SELECT hid FROM hypothesis")}
        finally:
            conn.close()

    def resolves(self, citation: str) -> bool:
        try:
            kind, _, ref = citation.partition(":")
        except AttributeError:
            return False
        if not ref:
            return False
        if kind == "event":
            return ref.isdigit() and int(ref) in self.event_seqs
        if kind == "entity":
            return ref in self.entities
        if kind == "finding":
            return ref in self.findings
        if kind == "hypothesis":
            return ref in self.hypotheses
        if kind == "flag":
            return ref in self.flags
        return False


def verify_claims(claims: List[Claim], index: CitationIndex
                  ) -> Tuple[List[Claim], List[Dict[str, object]]]:
    """Split claims into (accepted, rejected). A claim is accepted iff it has ≥1
    citation and EVERY citation resolves. Rejected entries carry the reason."""
    accepted: List[Claim] = []
    rejected: List[Dict[str, object]] = []
    for c in claims:
        if not c.citations:
            rejected.append({"text": c.text, "reason": "no citations"})
            continue
        bad = [cit for cit in c.citations if not index.resolves(cit)]
        if bad:
            rejected.append({"text": c.text, "reason": "unresolved citations",
                             "unresolved": bad})
        else:
            accepted.append(c)
    return accepted, rejected


# ------------------------------------------------------------------ stage 1: IR


def build_ir(case) -> WriteupIR:
    """Deterministically assemble the writeup IR from the graph + log. Every
    claim it emits cites real ids, so a clean build verifies with zero rejects."""
    meta = case.meta
    ir = WriteupIR(case_id=meta.get("case_id", "?"), title=meta.get("title", ""),
                   category=meta.get("category"))

    created_seq = next((ev["seq"] for ev in case.store.iter_events()
                        if ev["type"] == "case.created"), None)
    overview = Section("Overview")
    if created_seq is not None:
        overview.claims.append(Claim(
            f"Case {ir.case_id} ({ir.category or 'uncategorized'}) — {ir.title}.",
            (f"event:{created_seq}",)))
    ir.sections.append(overview)

    db = case.rebuild()["graph_db"]
    conn = sqlite3.connect(db)
    conn.row_factory = sqlite3.Row
    try:
        surface = Section("Attack surface")
        for r in conn.execute(
            "SELECT entity_id,kind,key_display FROM entity "
            "WHERE kind IN ('service.tcp','service.http','host','binary') "
            "ORDER BY entity_id"
        ):
            surface.claims.append(Claim(
                f"Identified {r['kind']} `{r['key_display']}`.",
                (f"entity:{r['entity_id']}",)))
        if surface.claims:
            ir.sections.append(surface)

        findings = Section("Findings")
        for r in conn.execute(
            "SELECT id,ftype,severity,subject_json FROM finding "
            "ORDER BY CASE severity WHEN 'crit' THEN 0 WHEN 'critical' THEN 0 "
            "WHEN 'high' THEN 1 WHEN 'med' THEN 2 WHEN 'medium' THEN 2 "
            "WHEN 'low' THEN 3 ELSE 4 END, id"
        ):
            findings.claims.append(Claim(
                f"A {r['severity']} {r['ftype']} was identified.",
                (f"finding:{r['id']}",)))
        if findings.claims:
            ir.sections.append(findings)
    finally:
        conn.close()

    # Exploitation: cite the session run events, if any.
    exploit = Section("Exploitation")
    for ev in case.store.iter_events():
        if ev["type"] == "script.run":
            p = ev.get("payload", {})
            exploit.claims.append(Claim(
                f"Ran exploit-script revision {p.get('rev')} in session "
                f"{p.get('sid')}.", (f"event:{ev['seq']}",)))
    if exploit.claims:
        ir.sections.append(exploit)

    # Flag: cite both the flag value and the event that recorded it.
    flag_ev = next((ev for ev in case.store.iter_events()
                    if ev["type"] == "flag.verified"), None)
    if flag_ev is not None:
        val = flag_ev.get("payload", {}).get("value") or flag_ev.get("payload", {}).get("flag")
        if val:
            ir.sections.append(Section("Flag", [Claim(
                f"The flag `{val}` was recovered and verified.",
                (f"flag:{val}", f"event:{flag_ev['seq']}"))]))
    return ir


# ------------------------------------------------------------------ stage 2 + render


def _render_md(ir: WriteupIR, accepted: Set[int]) -> str:
    L = [f"# Writeup — {ir.case_id}: {ir.title}", ""]
    idx = 0
    for section in ir.sections:
        shown = []
        for c in section.claims:
            keep = idx in accepted
            idx += 1
            if keep:
                shown.append(c)
        if not shown:
            continue
        L.append(f"## {section.title}")
        for c in shown:
            cites = " ".join(f"[{cit}]" for cit in c.citations)
            L.append(f"- {c.text}  {cites}".rstrip())
        L.append("")
    return "\n".join(L).rstrip() + "\n"


def generate_writeup(case, extra_claims: Optional[List[Claim]] = None) -> Dict[str, object]:
    """Build the IR, optionally fold in narration `extra_claims` (simulating the
    LLM), verify every claim, exile the unsupported ones (emitting
    `writeup.claim_rejected`), and render `writeup.md` from what survived. Appends
    a final `writeup.generated`. Returns {markdown, accepted, rejected, ir}."""
    ir = build_ir(case)
    if extra_claims:
        ir.sections.append(Section("Narrative", list(extra_claims)))

    index = CitationIndex(case)
    flat = [c for _, c in ir.all_claims()]

    # Decide acceptance by position (robust to value-identical claims); reuse the
    # same rule verify_claims exposes as the tested pure function.
    accepted_ids = {i for i, c in enumerate(flat)
                    if c.citations and all(index.resolves(cit) for cit in c.citations)}
    accepted, rejected = verify_claims(flat, index)

    for r in rejected:
        case.append(EventDraft(
            "writeup.claim_rejected", {"kind": "system", "name": "writeup"},
            {"text": r["text"], "reason": r["reason"],
             "unresolved": r.get("unresolved", [])}))

    md = _render_md(ir, accepted_ids)
    case.append(EventDraft(
        "writeup.generated", {"kind": "system", "name": "writeup"},
        {"claims": len(flat), "accepted": len(accepted), "rejected": len(rejected)}))
    return {"markdown": md, "accepted": len(accepted), "rejected": rejected, "ir": ir}
