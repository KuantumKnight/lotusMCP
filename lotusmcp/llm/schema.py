"""Tiny structured-output schemas + a stdlib validator for the LLM gateway.

The determinism boundary (§4.1) requires that the LLM only ever return
*structured, typed* JSON that the server then treats as advisory input to its own
math. So every oracle call declares a schema, and the gateway rejects any
response that doesn't match — the provider is asked to retry rather than the loop
swallowing a malformed answer. jsonschema isn't a stdlib module, so this is a
deliberately small validator covering exactly the shapes the oracle uses:
object/array/string/number/boolean, `required`, `properties`, `items`, and a
numeric `min`/`max` range.
"""
from __future__ import annotations

from typing import Any, Dict


class SchemaError(ValueError):
    """A response did not match its declared schema."""


def validate(obj: Any, schema: Dict[str, Any], path: str = "$") -> None:
    t = schema.get("type")
    if t == "object":
        if not isinstance(obj, dict):
            raise SchemaError(f"{path}: expected object")
        for req in schema.get("required", []):
            if req not in obj:
                raise SchemaError(f"{path}.{req}: required key missing")
        props = schema.get("properties", {})
        for k, sub in props.items():
            if k in obj:
                validate(obj[k], sub, f"{path}.{k}")
    elif t == "array":
        if not isinstance(obj, list):
            raise SchemaError(f"{path}: expected array")
        item_schema = schema.get("items")
        if item_schema is not None:
            for i, item in enumerate(obj):
                validate(item, item_schema, f"{path}[{i}]")
    elif t == "string":
        if not isinstance(obj, str):
            raise SchemaError(f"{path}: expected string")
    elif t == "number":
        if isinstance(obj, bool) or not isinstance(obj, (int, float)):
            raise SchemaError(f"{path}: expected number")
        if "min" in schema and obj < schema["min"]:
            raise SchemaError(f"{path}: {obj} < min {schema['min']}")
        if "max" in schema and obj > schema["max"]:
            raise SchemaError(f"{path}: {obj} > max {schema['max']}")
    elif t == "boolean":
        if not isinstance(obj, bool):
            raise SchemaError(f"{path}: expected boolean")
    # unknown/None type -> accept (no constraint declared)


_CONF = {"type": "number", "min": 0.0, "max": 1.0}

# oracle(ORIENT_AND_HYPOTHESIZE) -> abduced hypotheses over the current graph.
HYP_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "required": ["new"],
    "properties": {
        "new": {
            "type": "array",
            "items": {
                "type": "object",
                "required": ["statement", "confidence"],
                "properties": {
                    "statement": {"type": "string"},
                    "confidence": _CONF,
                    "rationale": {"type": "string"},
                },
            },
        }
    },
}

# oracle(RANK_ACTIONS) -> per-candidate info-gain estimate (advisory multiplier).
RANK_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "required": ["ranking"],
    "properties": {
        "ranking": {
            "type": "array",
            "items": {
                "type": "object",
                "required": ["key", "info_gain"],
                "properties": {
                    "key": {"type": "string"},
                    "info_gain": _CONF,
                    "note": {"type": "string"},
                },
            },
        }
    },
}

# holistic_read(raw) -> notes/hypotheses abduced from small/interesting raw bytes.
READ_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "properties": {
        "notes": {"type": "array", "items": {"type": "string"}},
        "hypotheses": HYP_SCHEMA["properties"]["new"],
    },
}
