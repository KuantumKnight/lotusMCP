# LotusMCP

**An autonomous CTF case-management MCP server that bridges an LLM (ChatGPT / Claude / any MCP client) to a Kali Linux environment.**

Point an LLM at an *authorized* CTF or lab target. LotusMCP drives Kali through a
server-authoritative reasoning loop, systematically hunts the flag, and writes up
the solve — while every command, finding, and decision lands in a single
tamper-evident event log.

> ⚠️ **Authorized use only.** LotusMCP is built for CTF platforms, labs, and
> education. Target scope is defined **out-of-band by a human operator and
> signed**; the agent can only *narrow* scope, never widen it. See
> [`ARCHITECTURE.md`](ARCHITECTURE.md) § Safety.

---

## The core idea (and why it's different)

The original design made **`CASE.md` the brain** — one big markdown file every tool
merges into. That file both **races** under concurrent tools and eventually
**overflows the context window**. LotusMCP inverts it:

> **The log is the brain. Everything else is a rebuildable projection.**

- **One append-only, hash-chained event log** (`events.jsonl`) is the *only* source
  of truth. Tools never edit shared state — they append immutable, idempotency-keyed
  events. Clobbering is structurally impossible.
- The **knowledge graph** (SQLite: hosts → services → endpoints → params →
  creds → findings → hypotheses → attempts → flags) and the bounded **`STATE.md`**
  working set the LLM reads are *pure folds* of the log. Same log → same graph →
  byte-identical `STATE.md` (a CI-enforced determinism guarantee).
- Every fact is a **claim** with **confidence + provenance** (which event/tool/command
  produced it). Re-running a scan *corroborates* instead of overwriting.
- **Replay and writeups come for free** from the log; a fresh LLM session (even a
  different vendor) resumes cold by reading a small working set.

Full design, including the autonomous OODA loop, the two execution regimes, the
CTF playbooks, and the server-side safety model, is in
[`ARCHITECTURE.md`](ARCHITECTURE.md).

---

## Status

This repo now contains the deterministic LotusMCP core plus host-native Kali
execution glue. The pure core still runs on the standard library alone; FULL
execution mode uses the tools installed on this Kali machine directly.

| Component | State |
|---|---|
| Append-only hash-chained event log (`kernel/log.py`) | ✅ working |
| Single entity-id function + ontology (`ontology/`) | ✅ working |
| Deterministic SQLite graph projector (`kernel/projector.py`) | ✅ working |
| Bounded `STATE.md` working-set renderer (`kernel/state.py`) | ✅ working |
| Redaction choke — deterministic secret tokenizer + persistent AES-GCM reveal vault (`kernel/redaction.py`, `kernel/vault.py`) | ✅ working (mandatory on the serializer) |
| Read-only graph queries (`kb.py`) | ✅ working |
| Flag subsystem — decode ladder, scanner, ranker + decoy filter, 4-tier registry, submit policy (`flag/`) | ✅ working |
| Playbook engine — forward-chaining rules, `U(A)` scoring, dead-end/novelty/quota (`playbooks/`, `engine/`) | ✅ working (sole candidate generator) |
| Triage ensemble — category classifier feeding `category_conf` (`triage/`) | ✅ working |
| EV+UCB selector, budget ledger, phase machine (`engine/`) | ✅ working |
| OODA `step()` loop — observe/orient/decide/act, Regime A (`engine/loop.py`) | ✅ working (executor/LLM injected) |
| MCP facade: LITE/FULL tool surface (`server.py`) | ✅ working (needs `mcp` SDK) |
| Replay-equivalence + tamper-detection tests | ✅ passing |
| Host Kali executor — `nmap` / `curl` / `ffuf` through typed argv + `shell=False` | ✅ working |
| Regime-B live sessions — TCP tube + host `python3` script runner | ✅ working |
| LLM gateway, replay/writeup, library, community playbooks | ✅ working in deterministic/testable form |
| Operator readiness diagnostics (`lotusmcp.ops.doctor`) | ✅ working |
| Host/container benchmark workflow docs (`docs/BENCHMARKING.md`) | ✅ working |
| Remaining external-bound work | Real solved-case collection / live validation |

---

## Quickstart

```bash
# 1. See the kernel work end-to-end — no dependencies required.
#    Injects the events an nmap -> httpx -> ffuf recon chain would emit,
#    rebuilds the graph, and prints the bounded STATE.md.
python -m lotusmcp.demo.seed_recon

# 2. See the deterministic BRAIN decide — triage -> playbooks -> EV+UCB select.
#    No Kali, no LLM: prints the action it would dispatch each phase, and why.
python -m lotusmcp.demo.decide_loop

# 2b. Watch a FULL autonomous solve drive the OODA loop end to end — a scripted
#     executor stands in for Kali: TRIAGE -> RECON -> ENUMERATE -> EXPLOIT ->
#     POST_EXPLOIT -> SOLVED_PENDING_SUBMIT -> FLAG_FOUND, flag captured.
python -m lotusmcp.demo.autonomous_solve

# 3. Run tests. pytest is not required; every test file has a __main__ runner.
PYTHONPATH=. PYTHONIOENCODING=utf-8 python tests/test_replay_equivalence.py

# Full suite:
for t in tests/test_*.py; do PYTHONPATH=. PYTHONIOENCODING=utf-8 python "$t" || exit 1; done

# 4. Run the read-only/default MCP server (needs the SDK).
pip install "mcp[cli]"
python -m lotusmcp.server           # stdio transport
```

Check this host before operating:

```bash
PYTHONPATH=. python -m lotusmcp.ops.doctor --all
```

For FULL host execution mode, launch through `lotusmcp.launcher` instead of
`lotusmcp.server`. This wires `propose_and_run` to this machine's Kali tools and
`session_edit_run` to the host TCP/Python session backend:

```bash
export LOTUS_PROFILE=FULL
export LOTUS_CASES_DIR="$PWD/cases"
export LOTUS_TRUSTED_OP_KEYS="<operator-public-key-hex>"
python -m lotusmcp.launcher
```

FULL execution still requires a per-case signed `scope.json`; without one,
interactive sessions fail closed and scoped actions are refused by the verified
scope choke.

Optional read-only dashboard/SSE stream:

```bash
PYTHONPATH=. python -m lotusmcp.observability.dashboard \
  --cases-dir "$PWD/cases" --host 127.0.0.1 --port 8765
```

Useful endpoints:

- `/` — case list
- `/case/<case_id>/state` — current `STATE.md`
- `/case/<case_id>/metrics` — OpenMetrics text
- `/case/<case_id>/events?after=<seq>` — recent JSON events
- `/case/<case_id>/stream?after=<seq>` — server-sent event tail

Signed adapter-review artifact for brand-new capabilities:

```bash
python -m lotusmcp.control_plane.cli sign-adapter \
  --key operator.pem --case <case_id> \
  --payload adapter-review-payload.json \
  --out adapter-review.json
```

This records operator approval for a new adapter’s capability/category/tool,
argv schema summary, and egress envelope. It does not dynamically load code.

Calibrate the cross-case Technique Library from solved case logs:

```bash
PYTHONPATH=. python -m lotusmcp.library.calibrate \
  --cases-dir "$PWD/cases" \
  --library-dir "$PWD/library"
```

The importer writes only generalized observations
`(capability, category, param_class, phase, success)` to the library; target
hosts, ports, paths, payloads, and entity ids are not copied cross-case.

Register the stdio server with an MCP client (Claude Desktop / Claude Code):

```jsonc
{
  "mcpServers": {
    "lotusmcp": { "command": "python", "args": ["-m", "lotusmcp.launcher"] }
  }
}
```

Cases are written under `./cases/<case_id>/` (override with `LOTUS_CASES_DIR`).

Operator docs:

- [`docs/OPERATOR_RUNBOOK.md`](docs/OPERATOR_RUNBOOK.md) — host readiness,
  scope signing, launch, anchoring, calibration.
- [`docs/BENCHMARKING.md`](docs/BENCHMARKING.md) — best-practice live/benchmark
  validation workflow, including NYU CTF Bench target containers.

---

## Layout

```
lotusmcp/
  kernel/      # THE Case Kernel: log (source of truth) + projector + STATE.md renderer + Case
  ontology/    # kinds.yaml (the entity ontology) + identity.py (the one entity-id function)
  kb.py        # read-only knowledge-graph queries (progressive disclosure)
  server.py    # small stable MCP facade (tools/resources)
  demo/        # deterministic demos; no live target required
tests/         # stdlib __main__ test runners
scope.example.json   # operator-signed scope manifest (the safety anchor)
ARCHITECTURE.md      # the full design
```

## License

MIT. Use only against systems you are explicitly authorized to test.
