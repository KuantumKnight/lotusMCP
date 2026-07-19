"""Signed review artifacts for brand-new adapters.

Community playbooks can only tune existing rules. If a new adapter/capability is
needed, the operator signs an ``adapter_review`` manifest that records the human
review decision: capability name, category, tool, argv schema summary, and the
egress envelope the adapter is expected to use.

This module does not load code and does not make dynamic adapters executable.
It validates the signed artifact so a code review can cite it and automation can
fail loud when an adapter lacks an operator-approved review record.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List

from lotusmcp.engine.scope import Scope, ScopeError
from lotusmcp.kernel.signing import verify_manifest

_IDENT = re.compile(r"^[a-z][a-z0-9_]{2,48}$")
_TOOL = re.compile(r"^[A-Za-z0-9_.+-]{1,64}$")
_CATEGORIES = {"web", "pwn", "rev", "crypto", "forensics", "osint", "recon"}


class AdapterReviewError(ValueError):
    """A signed adapter review was missing, untrusted, or malformed."""


@dataclass(frozen=True)
class AdapterReview:
    capability: str
    category: str
    tool: str
    argv_schema: Dict[str, Any]
    egress: Scope
    reviewer: str
    rationale: str = ""


def _require_str(payload: Dict[str, Any], key: str) -> str:
    value = payload.get(key)
    if not isinstance(value, str) or not value.strip():
        raise AdapterReviewError(f"{key} must be a non-empty string")
    return value.strip()


def _payload_to_review(payload: Dict[str, Any]) -> AdapterReview:
    cap = _require_str(payload, "capability")
    if not _IDENT.match(cap):
        raise AdapterReviewError("capability must be snake_case and 3..49 chars")
    category = _require_str(payload, "category")
    if category not in _CATEGORIES:
        raise AdapterReviewError(f"category must be one of {sorted(_CATEGORIES)}")
    tool = _require_str(payload, "tool")
    if not _TOOL.match(tool):
        raise AdapterReviewError("tool contains unsafe characters")
    argv_schema = payload.get("argv_schema")
    if not isinstance(argv_schema, dict) or not argv_schema:
        raise AdapterReviewError("argv_schema must be a non-empty object")
    if "shell" in argv_schema and argv_schema["shell"] is not False:
        raise AdapterReviewError("argv_schema.shell must be false when present")
    egress_doc = payload.get("egress")
    if not isinstance(egress_doc, dict):
        raise AdapterReviewError("egress must be a scope-like object")
    try:
        egress = Scope.from_payload(egress_doc)
    except ScopeError as e:
        raise AdapterReviewError(f"bad egress: {e}") from e
    reviewer = _require_str(payload, "reviewer")
    rationale = str(payload.get("rationale", ""))
    return AdapterReview(cap, category, tool, dict(argv_schema), egress,
                         reviewer, rationale)


def verify_adapter_review(manifest: Dict[str, Any], trusted_keys: Iterable[str]) -> AdapterReview:
    if manifest.get("type") != "adapter_review":
        raise AdapterReviewError(f"expected adapter_review manifest, got {manifest.get('type')!r}")
    if not verify_manifest(manifest, set(trusted_keys)):
        raise AdapterReviewError("adapter_review signature not trusted")
    payload = manifest.get("payload")
    if not isinstance(payload, dict):
        raise AdapterReviewError("manifest payload missing")
    return _payload_to_review(payload)


def lint_adapter_review_payload(payload: Any) -> List[str]:
    """Return schema errors for an unsigned payload. Empty means signable."""
    if not isinstance(payload, dict):
        return ["payload must be an object"]
    try:
        _payload_to_review(payload)
    except AdapterReviewError as e:
        return [str(e)]
    return []
