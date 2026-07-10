"""Control plane — HUMAN operator tooling ONLY.

Nothing here may be imported by the server / agent request path (ARCHITECTURE
§2, §1 "Operator CLI"). This package holds the Ed25519 *private* key and the
signing helpers for the artifacts the agent may never mint itself: `scope.json`,
egress grants, the flag-submission allowlist, tier-3 enablement, and audit
anchors. The server only ever sees the PUBLIC half via `kernel/signing.py`.
"""
