"""Bridge from a decided action + the current world to a validated ArgvPlan.

The OODA loop selects a `CandidateAction` bound to an entity id. To run it, the
sandboxed Executor needs the *structured* target (addr/host/proto/port), which
lives on that entity's natural key. `plan_action` resolves the bound entity from
the world and hands its `target()` to the typed-argv layer — so the runner never
parses a display string and never sees an un-validated field.
"""
from __future__ import annotations

from typing import List

from lotusmcp.executor.argv import ArgvPlan, ArgvRejected, build_argv


def plan_action(action, world) -> List[ArgvPlan]:
    """Resolve `action`'s bound entity in `world` and build its argv plan(s).

    Raises `ArgvRejected` if the target entity is missing (a decided action must
    always bind to a live entity) or if any field fails the typed schema. Lets
    `NoAdapter` propagate for capabilities with no Phase-1 adapter.
    """
    entity = world.get(action.target_id)
    if entity is None:
        raise ArgvRejected(f"target entity {action.target_id!r} not in world")
    return build_argv(action, entity.target())
