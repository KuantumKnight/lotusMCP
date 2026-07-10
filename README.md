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

This repo is the **Phase-0 walking skeleton** — the Case Kernel is real and runs on
the **standard library alone** (no Kali, no LLM, no external deps):

| Component | State |
|---|---|
| Append-only hash-chained event log (`kernel/log.py`) | ✅ working |
| Single entity-id function + ontology (`ontology/`) | ✅ working |
| Deterministic SQLite graph projector (`kernel/projector.py`) | ✅ working |
| Bounded `STATE.md` working-set renderer (`kernel/state.py`) | ✅ working |
| Redaction choke — deterministic secret tokenizer + reveal vault (`kernel/redaction.py`) | ✅ working (mandatory on the serializer) |
| Read-only graph queries (`kb.py`) | ✅ working |
| Flag subsystem — decode ladder, scanner, ranker + decoy filter, 4-tier registry, submit policy (`flag/`) | ✅ working |
| Playbook engine — forward-chaining rules, `U(A)` scoring, dead-end/novelty/quota (`playbooks/`, `engine/`) | ✅ working (sole candidate generator) |
| Triage ensemble — category classifier feeding `category_conf` (`triage/`) | ✅ working |
| MCP facade: `create_case` / `get_state` / `kb_query` / `kb_get` / `flag_scan` (`server.py`) | ✅ working (needs `mcp` SDK) |
| Replay-equivalence + tamper-detection tests | ✅ passing |
| Kali Executor (sandbox), OODA `step()` loop, LLM gateway | ⏳ Phases 1/3–8 (see roadmap) |

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

# 3. Run the determinism + tamper-evidence tests.
python -m pytest tests/ -q          # or: PYTHONPATH=. python tests/test_replay_equivalence.py

# 4. Run the MCP server (needs the SDK).
pip install "mcp[cli]"
python -m lotusmcp.server           # stdio transport
```

Register the stdio server with an MCP client (Claude Desktop / Claude Code):

```jsonc
{
  "mcpServers": {
    "lotusmcp": { "command": "python", "args": ["-m", "lotusmcp.server"] }
  }
}
```

Cases are written under `./cases/<case_id>/` (override with `LOTUS_CASES_DIR`).

---

## Layout

```
lotusmcp/
  kernel/      # THE Case Kernel: log (source of truth) + projector + STATE.md renderer + Case
  ontology/    # kinds.yaml (the entity ontology) + identity.py (the one entity-id function)
  kb.py        # read-only knowledge-graph queries (progressive disclosure)
  server.py    # small stable MCP facade (tools/resources)
  demo/        # seed_recon.py — Phase-0 proof, no Kali needed
tests/         # replay-equivalence + tamper detection
scope.example.json   # operator-signed scope manifest (the safety anchor)
ARCHITECTURE.md      # the full design
```

## License

MIT. Use only against systems you are explicitly authorized to test.
