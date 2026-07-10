"""The single LLM gateway subsystem (§1 "LLM Gateway", §4.1 determinism boundary).

Import surface: the gateway, the pluggable provider protocol + offline stub, and
the oracle task ids. Everything the LLM does here is ADVISORY — hypothesis
abduction and info-gain ranking that the server-authoritative loop math folds
in; the gateway never decides, runs a command, or writes the log itself.
"""
from lotusmcp.llm.gateway import GatewayStats, LLMGateway
from lotusmcp.llm.provider import (
    HOLISTIC_READ,
    ORIENT_AND_HYPOTHESIZE,
    RANK_ACTIONS,
    DeterministicProvider,
    Provider,
)
from lotusmcp.llm.schema import READ_SCHEMA, HYP_SCHEMA, RANK_SCHEMA, SchemaError

__all__ = [
    "LLMGateway", "GatewayStats", "Provider", "DeterministicProvider",
    "ORIENT_AND_HYPOTHESIZE", "RANK_ACTIONS", "HOLISTIC_READ",
    "HYP_SCHEMA", "RANK_SCHEMA", "READ_SCHEMA", "SchemaError",
]
