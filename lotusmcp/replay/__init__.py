"""Replay, diff, and two-stage writeup (Phase 6).

Every artifact is a pure fold of the append-only log, so the state at any past
seq — and the delta between two seqs — is deterministically reconstructible
(`state_at` / `diff`). The writeup is built the same way: a deterministic IR
whose every claim carries citations, then a citation verifier that exiles any
sentence the log does not support (`generate_writeup`).
"""
from lotusmcp.replay.state import diff, state_at
from lotusmcp.replay.writeup import (
    Claim,
    Section,
    WriteupIR,
    build_ir,
    generate_writeup,
    verify_claims,
)

__all__ = [
    "state_at", "diff",
    "Claim", "Section", "WriteupIR",
    "build_ir", "verify_claims", "generate_writeup",
]
