"""The world view a playbook rule matches against, and the Rule itself.

`World` is a read-only projection of the knowledge graph at the log tip: entities
by kind, their folded attributes, and outgoing edges. Rules are pure selectors
over that world — no rule ever touches the log, Kali, or the network. A rule that
matches an entity emits a `CandidateAction` bound to that (in-scope) entity.

`World` can be built from a real `graph.db` (production path) or from plain
dicts (tests), so the engine is exercisable without a projector run.
"""
from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

from lotusmcp.engine.candidate import CandidateAction


@dataclass(frozen=True)
class Entity:
    id: str
    kind: str
    display: str
    status: str = "active"
    confidence: float = 1.0
    attrs: Dict[str, Any] = field(default_factory=dict)
    edges: Dict[str, List[str]] = field(default_factory=dict)  # rel_type -> [dst_id]

    def attr(self, name: str, default: Any = None) -> Any:
        return self.attrs.get(name, default)


class World:
    def __init__(self, entities: List[Entity]) -> None:
        self._by_kind: Dict[str, List[Entity]] = {}
        self._by_id: Dict[str, Entity] = {}
        for e in entities:
            self._by_kind.setdefault(e.kind, []).append(e)
            self._by_id[e.id] = e

    def entities(self, kind: str) -> List[Entity]:
        return list(self._by_kind.get(kind, ()))

    def get(self, entity_id: str) -> Optional[Entity]:
        return self._by_id.get(entity_id)

    def all_kinds(self) -> List[str]:
        return sorted(self._by_kind)

    def __len__(self) -> int:
        return len(self._by_id)

    # ---- constructors ----
    @classmethod
    def from_entity_dicts(cls, rows: List[Dict[str, Any]]) -> "World":
        """Build from lightweight dicts (tests / synthetic worlds)."""
        ents = []
        for r in rows:
            ents.append(Entity(
                id=r.get("id") or r["entity_id"],
                kind=r["kind"],
                display=r.get("display", r.get("id", "")),
                status=r.get("status", "active"),
                confidence=r.get("confidence", 1.0),
                attrs=r.get("attrs", {}),
                edges=r.get("edges", {}),
            ))
        return cls(ents)

    @classmethod
    def from_graph_db(cls, db_path: str) -> "World":
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        ents: List[Entity] = []
        for row in conn.execute(
            "SELECT entity_id,kind,key_display,status,confidence FROM entity"
        ):
            eid = row["entity_id"]
            attrs: Dict[str, Any] = {}
            for a in conn.execute(
                "SELECT attr,value_json FROM attribute WHERE entity_id=?", (eid,)
            ):
                try:
                    attrs[a["attr"]] = json.loads(a["value_json"])
                except (json.JSONDecodeError, TypeError):
                    attrs[a["attr"]] = a["value_json"]
            edges: Dict[str, List[str]] = {}
            for e in conn.execute(
                "SELECT rel_type,dst_id FROM relation WHERE src_id=?", (eid,)
            ):
                edges.setdefault(e["rel_type"], []).append(e["dst_id"])
            ents.append(Entity(eid, row["kind"], row["key_display"],
                               row["status"], row["confidence"], attrs, edges))
        conn.close()
        return cls(ents)


# A predicate/param builder over one entity.
Predicate = Callable[[Entity], bool]
ParamBuilder = Callable[[Entity], Dict[str, Any]]


@dataclass(frozen=True)
class Rule:
    """A forward-chaining rule: match `kind` entities where `when`, emit a
    `capability` candidate bound to each match."""

    id: str
    category: str
    capability: str
    kind: str                                   # entity kind this rule selects
    phase_gate: tuple
    rationale: str
    when: Predicate = lambda e: True            # extra attribute predicate
    params: ParamBuilder = lambda e: {}
    yield_: float = 0.5
    priority: float = 0.5
    cost: float = 1.0
    risk: float = 1.0

    def fire(self, world: World) -> List[CandidateAction]:
        out: List[CandidateAction] = []
        for e in world.entities(self.kind):
            if e.status in ("retracted", "superseded"):
                continue
            if not self.when(e):
                continue
            out.append(CandidateAction(
                capability=self.capability,
                category=self.category,
                target_id=e.id,
                target_display=e.display,
                params=self.params(e),
                rule_id=self.id,
                rationale=self.rationale,
                phase_gate=self.phase_gate,
                yield_=self.yield_,
                priority=self.priority,
                cost=self.cost,
                risk=self.risk,
            ))
        return out
