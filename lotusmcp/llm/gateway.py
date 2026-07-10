"""THE single LLM gateway (§1, §4.1).

Every model call site in the system — hypothesis abduction (oracle), candidate
ranking / info-gain (oracle), holistic reads of raw output — goes through this
one object. It is the only place that:

  - charges the one `BudgetLedger` (on a cache MISS only — a replayed answer is
    free), so the stopping math is never blind to model spend;
  - caches `prompt_hash -> response`, which is what makes the loop
    *decision-reproducible*: the same recorded observations replay the same
    decisions without re-calling the provider;
  - enforces the response schema, asking the provider to retry a malformed
    answer rather than letting the loop consume it;
  - fixes model/temperature (temp=0 semantics) — callers never choose them.

The gateway holds NO Kali access and never runs a command; it only turns a task
+ a bounded context packet into validated, budgeted, cached structured output.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Optional

from lotusmcp.engine.budget import BudgetLedger
from lotusmcp.kernel.canonical import canonical
from lotusmcp.llm import schema as S
from lotusmcp.llm.provider import (
    HOLISTIC_READ,
    ORIENT_AND_HYPOTHESIZE,
    RANK_ACTIONS,
    DeterministicProvider,
    Provider,
)

_SCHEMA_FOR = {
    ORIENT_AND_HYPOTHESIZE: S.HYP_SCHEMA,
    RANK_ACTIONS: S.RANK_SCHEMA,
    HOLISTIC_READ: S.READ_SCHEMA,
}


@dataclass
class GatewayStats:
    calls: int = 0
    cache_hits: int = 0
    tokens_charged: int = 0


class LLMGateway:
    def __init__(
        self,
        provider: Optional[Provider] = None,
        budget: Optional[BudgetLedger] = None,
        model: str = "deterministic-stub",
        temperature: float = 0.0,
        max_retries: int = 2,
    ) -> None:
        self.provider: Provider = provider or DeterministicProvider()
        self.budget = budget or BudgetLedger()
        self.model = model
        self.temperature = temperature
        self.max_retries = max_retries
        self._cache: Dict[str, Dict[str, Any]] = {}
        self.stats = GatewayStats()

    # ----------------------------------------------------------------- helpers
    def _prompt_hash(self, task: str, context: Dict[str, Any]) -> str:
        # model+temp are part of the key: a config change invalidates replay.
        key = {"task": task, "model": self.model, "temp": self.temperature,
               "context": context}
        return canonical(key)

    # ------------------------------------------------------------------ oracle
    def oracle(
        self,
        task: str,
        context: Dict[str, Any],
        phase: Optional[str] = None,
    ) -> Dict[str, Any]:
        """The one call site. Returns validated structured output for `task`.
        A cache hit is free; a miss charges the provider's notional token cost
        to the budget. Raises `SchemaError` if the provider can't produce a
        schema-valid answer within `max_retries`."""
        if task not in _SCHEMA_FOR:
            raise ValueError(f"unknown oracle task: {task}")
        self.stats.calls += 1
        h = self._prompt_hash(task, context)
        if h in self._cache:
            self.stats.cache_hits += 1
            return self._cache[h]

        schema = _SCHEMA_FOR[task]
        last_err: Optional[Exception] = None
        for _ in range(self.max_retries + 1):
            resp = self.provider.complete(task, context)
            try:
                S.validate(resp, schema)
            except S.SchemaError as e:
                last_err = e
                continue
            tokens = int(self.provider.cost_tokens(task, context))
            self.budget.charge(llm_tokens=tokens, phase=phase)
            self.stats.tokens_charged += tokens
            self._cache[h] = resp
            return resp
        raise S.SchemaError(f"{task}: provider returned invalid output: {last_err}")

    # ------------------------------------------------ typed convenience wrappers
    def hypothesize(self, findings, phase: Optional[str] = None) -> Dict[str, Any]:
        return self.oracle(ORIENT_AND_HYPOTHESIZE,
                           {"findings": list(findings)}, phase=phase)

    def rank(self, candidates, phase: Optional[str] = None) -> Dict[str, Any]:
        return self.oracle(RANK_ACTIONS, {"candidates": list(candidates)}, phase=phase)

    def holistic_read(self, text: str, phase: Optional[str] = None) -> Dict[str, Any]:
        return self.oracle(HOLISTIC_READ, {"text": text}, phase=phase)
