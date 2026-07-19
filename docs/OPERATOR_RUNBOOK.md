# LotusMCP operator runbook

This runbook is for operating LotusMCP from this Kali host. Use it only against
systems where you have explicit authorization.

## Execution model

Best practice is hybrid:

- Run LotusMCP itself on the operator host so it can use the installed Kali
  toolchain, local case store, operator keys, and MCP stdio transport directly.
- Run benchmark or lab targets in isolated containers/VMs when the target
  benchmark provides them that way. The target environment is disposable; the
  LotusMCP case log remains on the host.

## 1. Check host readiness

Core check:

```bash
PYTHONPATH=. python -m lotusmcp.ops.doctor
```

FULL host-execution check:

```bash
PYTHONPATH=. python -m lotusmcp.ops.doctor --full --mcp
```

Benchmark-target check, including Docker/Compose:

```bash
PYTHONPATH=. python -m lotusmcp.ops.doctor --benchmark
```

Everything:

```bash
PYTHONPATH=. python -m lotusmcp.ops.doctor --all
```

## 2. Create an operator key

```bash
mkdir -p ops
PYTHONPATH=. python -m lotusmcp.control_plane.cli keygen --out ops/operator.pem
export LOTUS_TRUSTED_OP_KEYS="$(
  PYTHONPATH=. python -m lotusmcp.control_plane.cli pubkey --key ops/operator.pem
)"
```

Keep `ops/operator.pem` private. Do not commit it.

## 3. Create and sign target scope

Example for an isolated benchmark target exposed on localhost port 8080:

```bash
export CASE_ID=nyu-dev-smoke
mkdir -p "cases/$CASE_ID"

PYTHONPATH=. python -m lotusmcp.control_plane.cli sign-scope \
  --key ops/operator.pem \
  --case "$CASE_ID" \
  --host 127.0.0.1 \
  --port 8080 \
  --auto-cap 3 \
  --out "cases/$CASE_ID/scope.json"
```

Use exact IPs/hosts/ports. The agent can only narrow scope, never widen it.

## 4. Launch LotusMCP

```bash
export LOTUS_PROFILE=FULL
export LOTUS_CASES_DIR="$PWD/cases"
export LOTUS_BACKEND=subprocess
PYTHONPATH=. python -m lotusmcp.launcher
```

For a read-only dashboard in another terminal:

```bash
PYTHONPATH=. python -m lotusmcp.observability.dashboard \
  --cases-dir "$PWD/cases" --host 127.0.0.1 --port 8765
```

## 5. After a solve

Create an audit anchor:

```bash
PYTHONPATH=. python -m lotusmcp.control_plane.cli anchor \
  --key ops/operator.pem \
  --case-dir "cases/$CASE_ID" \
  --out "cases/$CASE_ID/audit_anchor.json"
```

Build deterministic reproduction material through the MCP `case_repro` tool, or
from code using `lotusmcp.replay.repro.build_repro(case)`.

Calibrate the cross-case Technique Library:

```bash
PYTHONPATH=. python -m lotusmcp.library.calibrate \
  --cases-dir "$PWD/cases" \
  --library-dir "$PWD/library"
```

The calibration importer generalizes to `(capability, category, param_class,
phase, success)` and does not copy target hosts, ports, paths, payloads, or
entity ids into the shared library.
