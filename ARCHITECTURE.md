# LotusMCP Architecture

*An autonomous CTF case-management MCP server bridging an LLM to Kali Linux.*

This is the reconciled design produced by a multi-architect design pass (six
subsystem designs → three adversarial critiques → one synthesis). It supersedes
the original "`CASE.md` is the brain" model.

---

## 0. Philosophy: the log is the brain; everything else is a lens

LotusMCP solves **authorized** CTF/lab challenges by driving a Kali environment
through a **server-authoritative OODA loop**, using the LLM as a *bounded oracle*
for the deterministic phases and as a *free-form exploit author* for the hard ones.

The central architectural act is to collapse every subsystem's "single source of
truth" into **one** thing: a per-case **Case Kernel** — a single serializer process
that owns one append-only, hash-chained event log (`events.jsonl`). Every other
artifact (the SQLite entity graph, `STATE.md`, `findings.json`, the dashboard, the
resume packet, the writeup, the Technique Library) is a **pure, rebuildable
projection** of that log.

Tools never write shared state. They RPC *event drafts* into the kernel, which
assigns gap-free `seq`, chains `prev_hash → hash`, redacts, fsyncs, and folds. This
structurally kills the `CASE.md` clobbering race, audit-chain fragmentation, and the
multi-write-path conflict in one move.

### The seven hard reconciliations

1. **One writer, one chain.** The log is single-threaded; the "lock-free
   multi-writer append" idea is dropped. Payloads are capped (16 KB); oversized
   content is *always* an artifact reference, so a line can never tear.
2. **Control-plane / data-plane split.** Scope definition, scope **widening**,
   external egress, flag-submission endpoints, and tier-3 tool enablement are
   **human-signed with an out-of-band key** and are structurally unreachable from any
   LLM/agent tool call. The agent may only **narrow** scope.
3. **One egress choke.** All network traffic (target *and* external) is forced through
   one audited forward proxy that enforces scope **per-request** (redirects, crawler
   URLs, DNS-rebinding, vhost fuzzing), behind a dual-stack default-DROP `nftables`
   netns as a kernel backstop.
4. **Redact-before-hash.** The streaming tee tokenizes incidental secrets into an
   encrypted vault *before* hashing and *before* any disk write, so content-addressing,
   byte-range provenance, and audit hashes stay valid. Redaction is also a mandatory
   choke for **all** LLM-authored text.
5. **Two loop regimes.** A deterministic *planner* regime for recon/enumerate (where
   playbooks + EV/UCB math genuinely converge) and an *interactive code-synthesis*
   regime for exploit/pwn/rev/hard-crypto (the LLM edits and re-runs sandboxed scripts
   against a persistent session). This removes the "system ceiling = union of playbook
   rules" cap.
6. **One LLM gateway** meters every call site (oracle, extractor, distiller, narrator)
   against one budget and one replay cache.
7. **One ontology + one entity-id function** so all subsystems interoperate.

A `SOLVED_PENDING_SUBMIT` soft-terminal, CTF-aware plateau logic (long jobs excluded,
wall-clock not turns), corroboration-gated `CONFIRM`, and raw-signal injection for
small/interesting outputs make it converge on flags instead of stalling.

---

## 1. Components

**Control Plane** (human, out-of-band — never reachable from the agent path)
- **Operator CLI + HSM/OS-keystore (ed25519).** Signs `scope.json`, egress grants, the
  flag-submission allowlist, and tier-3 enablement. The private key is never in the
  server request path.
- **Scope/Grant Verifier.** Server-side, *verify-only*. Enforces that any agent action
  may only narrow scope.

**Case Kernel** (exactly ONE serializer process per case)
- **Append Serializer.** Sole writer of `events.jsonl`; assigns `seq`, sets
  `prev_hash → hash`, batched `fsync`, updates `events.idx`. Everyone else emits event
  drafts via RPC.
- **Redaction Choke.** Mandatory: every payload and all LLM-authored text passes the
  secret/PII detector → vault tokenizer before it is hashed and written.
- **Synchronous Graph Projector.** Folds events into SQLite transactionally; the loop
  reads it only at `watermark == log tip`.
- **Async Renderers** (debounced ≤250 ms). `STATE.md`, `state.json`, dashboard SSE,
  FTS index, resume packet, compat `findings.json`/`timeline.json`.

**Orchestration Engine** (OODA, server-authoritative, two regimes). Owns the phase
machine, budget, dead-end ledger, EV+UCB selection, escalation.

**Playbook Engine + Triage.** Forward-chaining YAML rules over the graph emit scored
`CandidateAction`s; the playbook score becomes the engine's server prior.

**LLM Gateway** (single call site). Charges the one `BudgetLedger`, caches
`prompt_hash → response`, is the only place model/temperature are set.

**Executor** (only component that touches Kali). Adapter registry (typed argv = the
scope choke), job scheduler, Tubes + interactive session workspaces, redact-before-hash
tee, per-case rootless-Podman sandbox, scope-gw netns, and the audited forward proxy.

**Flag Subsystem.** Out-of-band scanner on every output/file, bounded best-first decode
ladder, confidence ranker with decoy filter, submit-policy state machine.

**Replay / Writeup / Observability.** Deterministic state replay; two-stage writeup
(deterministic IR + citation-verified narration); OpenMetrics + SSE dashboard; hash
chain + signed anchors = tamper-evident audit trail.

**Technique Library** (cross-case). Allowlist-generalized playbook cards with
Beta-posterior stats; promotion requires human review.

### Data-flow diagram

```
            ┌──────────── CONTROL PLANE (human, out-of-band) ─────────────┐
            │ Operator CLI ── HSM/OS-keystore (ed25519, never in server)   │
            │ signs: scope.json · egress grants · submit allowlist · tier3 │
            └───────────────────────────┬─────────────────────────────────┘
                                         │ signed manifests (VERIFY-ONLY in server)
 MCP client (ChatGPT LITE / Claude FULL) ▼
      │ tools/resources/prompts   ┌────────────────────┐
      ▼                           │ Scope/Grant Verifier│ agent may only NARROW
 ┌────────────┐                   └─────────┬──────────┘
 │ MCP Gateway│ FULL / LITE                 │
 │  facade    │──────────────┐              ▼
 └─────┬──────┘              │   ┌────────────────────────────────────────────┐
       │ next()/submit()     │   │        CASE KERNEL  (ONE process / case)     │
       ▼                     │   │  ┌──────────────────────────────────────────┐│
 ┌───────────────┐  Decision │   │  │ Append Serializer (SOLE writer)          ││
 │ Orchestration │◄─Request──┼───┼─▶│  seq · prev_hash→hash · sig · fsync · idx ││
 │ Engine (OODA) │  submit() │   │  │  ══ Redaction Choke (payloads + LLM text)══││
 │  A: planner   │           │   │  └───────────────┬──────────────────────────┘│
 │  B: interactive│          │   │      events.jsonl  │  (THE source of truth)   │
 └─┬────┬─────────┘          │   │                    │ fold()                   │
   │    │ scored candidates  │   │   sync,watermark=tip ▼        async,debounced ▼│
   │    ▼                    │   │   ┌───────────────┐   ┌──────────────────────┐│
   │ ┌──────────┐  server    │   │   │ Graph Projector│   │ Renderers: STATE.md, ││
   │ │ Playbook │  prior     │   │   │  (SQLite/WAL)  │   │ dashboard, FTS,      ││
   │ │ Engine + │            │   │   │  read at tip   │   │ resume, compat views ││
   │ │ Triage   │            │   │   └───────────────┘   └──────────────────────┘│
   │ └──────────┘            │   └────────────────────────────────────────────────┘
   │    │                    │            ▲ event drafts (RPC) from every subsystem
   │    ▼                    │            │
   │ ┌──────────────┐  oracle/│           │
   │ │ LLM Gateway  │◄extract/┘           │
   │ │ 1 budget +   │ distill/narrate      │
   │ │ 1 cache      │ (all metered+cached) │
   │ └──────────────┘                      │
   ▼                                        │
 ┌──────────────────────────────────────────┴───────────────────────────┐
 │ EXECUTOR (only component touching Kali)                                │
 │  Adapter registry (typed argv = scope choke) · Job scheduler ·         │
 │  Tubes + interactive session workspace · redact-BEFORE-hash tee        │
 │  ┌──────── per-case sandbox (rootless Podman; gVisor | runc rawnet) ──┐│
 │  │ tools/scripts run here; NO route except ↓                          ││
 │  └──────────────────────────┬──────────────────────────────────────────┘│
 │        ┌───────────────────▼─────────────────────┐                      │
 │        │ scope-gw netns: nftables v4+v6 default-  │──▶ in-scope target   │
 │        │ DROP (forward hook) + AUDITED FORWARD    │──▶ granted external  │
 │        │ PROXY (per-request scope, redirect/rebind│    (proxied only)    │
 │        │ re-check) — kernel drop = backstop only  │                      │
 │        └───────────────────────────────────────────┘                    │
 └────────────────────────────────────────────────────────────────────────┘
            │ emits command.* / finding.asserted / flag.candidate drafts
            ▼  (back into the ONE Case Kernel log)
 Replay · Writeup(IR+citation verifier) · Observability(SSE+OpenMetrics+audit)
 Technique Library (allowlist-generalized, human-reviewed) — all READ projections
```

**Why it is internally consistent:** every "single source of truth" claim now names
the *same* file, owned by the *same* process. Optimistic-concurrency `rev`/`etag`
tokens are deleted (meaningless under a single writer). The Executor's side WALs are
deleted; it emits `finding.asserted`/`command.*` into the shared log, so scope
decisions and argv live inside the tamper-evident chain. `next()/submit()` is the sole
execution path; all `kb.*`/`query_*` are read-only; dead-end filtering lives on the
execution path so no surface routes around it.

---

## 2. Data model

### 2.1 Canonical event (`schema_v = 4`)

`cases/<case_id>/events.jsonl` — one RFC 8785 (JCS) canonical-JSON object per line,
UTF-8, `\n`-terminated, immutable. Companion `events.idx` maps `seq → byte_offset`.

```jsonc
{
  "seq": 1423,                       // gap-free monotonic int, assigned by the serializer
  "event_id": "01J8Z...",            // ULID (time-sortable)
  "case_id": "htb-lame",
  "ts": "2026-07-09T12:34:56Z",      // metadata only; ordering is by seq
  "type": "finding.asserted",
  "schema_v": 4,
  "actor": {"kind":"executor|llm|human|system|planner","name":"nmap_xml@2","version":"1.4"},
  "causation_id": "01J..",           // the event that directly caused this (DAG)
  "correlation_id": "01J..",         // groups one plan-step (scan→parse→assert)
  "idempotency_key": "ent:service.tcp:host=10.10.10.3|proto=tcp|port=445",
  "confidence": 0.95,
  "provenance": {
    "tool_run_id": "r-88", "command_hash": "sha256:..",
    "artifact_refs": ["sha256:ab12.."],
    "source_span": {"kind":"xpath|byte","value":"/nmaprun/host[1]/ports/port[2]"},
    "matched_scope_rule": "rule#3"   // present on command.* — proves in-scope for audit
  },
  "redactions": [{"handle":"«SECRET:jwt:1a2b»","kind":"jwt"}],
  "payload": { /* <= 16 KB; anything larger MUST be an artifact_ref, never inline */ },
  "prev_hash": "sha256:9f..",
  "hash": "sha256:2b..",             // sha256(prev_hash_bytes || jcs(envelope \ {hash,sig}))
  "sig": "ed25519:.."                // optional per event; anchors carry the strong guarantee
}
```

### 2.2 Event taxonomy (one namespace, all subsystems)

- **Command lifecycle (Executor):** `command.requested` → `command.authorized|denied`
  (scope verdict + matched rule) → `command.started` → `command.output` (artifact ref)
  → `command.completed|failed|timeout|killed`.
- **Knowledge (auto, OutputAdapters):** `entity.asserted`, `attribute.asserted`,
  `relation.asserted`, `finding.raised|updated`, `finding.retracted|superseded`.
- **Reasoning (LLM tools only):** `note.added`, `hypothesis.proposed|updated`,
  `evidence.linked` (SUPPORTS/REFUTES), `attempt.started|result`, `deadend.marked`,
  `decision.made`, `plan.updated`, `memory.summary`.
- **Interactive session (Regime B):** `session.opened`, `script.revised`, `script.run`,
  `session.closed`.
- **Status/flag:** `flag.candidate`, `flag.submitted`, `flag.verified|rejected`,
  `case.status_changed`.
- **Budget:** `budget.consumed` (tokens/usd/wall/attempts, from every call site).
- **Reuse/writeup:** `technique.suggested|applied|promoted`, `writeup.generated`,
  `writeup.claim_rejected`.

**Who translates raw output → knowledge (two writers, both via events):**
(a) versioned deterministic **OutputAdapters** (`NmapXmlAdapter@2`, `FfufJsonAdapter@1`,
…) parse the redacted content-addressed artifact and emit `finding.asserted` with
byte-range provenance + confidence; (b) the **LLM** contributes interpretation only via
reasoning tools. Freeform output falls to the **Tier-2 LLM extractor**
(schema-constrained, verbatim-quote checked, `confidence ≤ 0.6`, never auto-promoted),
plus a **holistic raw-read pass** on small/interesting outputs so the parser is never
the only reader of a body that might contain the bug.

### 2.3 Entity ontology + ONE id function

`entity_id = "e_" + blake2b_128( kind || 0x1F || jcs(natural_key) )`. See
[`ontology/kinds.yaml`](lotusmcp/ontology/kinds.yaml) and
[`ontology/identity.py`](lotusmcp/ontology/identity.py).

| kind | natural_key | notes |
|---|---|---|
| `host` | `{addr}` | IP or lowercased FQDN, scope-checked |
| `service.tcp` / `service.http` | `{host,proto,port}` | http carries scheme/vhost |
| `http.endpoint` | `{host,scheme,vhost,method,path}` | path normalized |
| `http.param` | `{endpoint_id,location,name}` | query/body/header/cookie/path |
| `credential` | `{type,username,realm}` + `value_sha` | secret hashed, never plaintext in key |
| `crypto.artifact` | `{id}` | n/e/c, encoding, entropy |
| `binary.elf\|pe\|macho` | `{sha256}` | arch/bits/pie/nx/canary/relro |
| `service.oracle` | `{endpoint,type}` | padding/encryption/mac/rng |
| `artifact` | `{sha256}` | content-addressed REDACTED blob |
| `finding` | `{finding_type,primary_entity_id,param?}` | |
| `hypothesis` | `{hid}` | near-dup merged via embedding ≥0.92 |
| `attempt` | `{attempt_id}` | never deduped |
| `flag` | `{value_sha}` | |

**Relations:** `host EXPOSES service`, `service SERVES endpoint`,
`endpoint HAS_PARAM param`, `credential AUTHENTICATES_TO service|endpoint`,
`finding AFFECTS *`, `finding EVIDENCED_BY artifact`, `hypothesis ABOUT *`,
`evidence SUPPORTS|REFUTES hypothesis`, `attempt TESTS hypothesis`,
`attempt YIELDED credential|flag`, `flag FOUND_ON host`.

### 2.4 Knowledge graph (SQLite/WAL, a read-only projection)

Facts are stored as append-only **claims**; the materialized winner per `(entity,attr)`
is a **confidence-weighted noisy-OR** fold, `agg(v) = 1 − Π(1 − r_tool·c_claim)`, with a
deterministic tie-break (latest `source_seq`, then lexicographic `entity_id`). A losing
value scoring ≥0.5 sets `conflict=1` so the planner can schedule a disambiguating scan.
LLM-authored claims carry a low reliability prior and can never supersede a tool-sourced
claim. See [`kernel/projector.py`](lotusmcp/kernel/projector.py) for the working fold.

- **Claim compaction:** keep top-K (default 8) claims per `(entity,attr)` by
  `reliability·confidence` + a rolling corroboration counter.
- **Decomposable salience (no O(N) / stale index):** store time-independent parts
  (`s_conf, s_hyp, s_pathflag, s_deadend, last_seq`) and apply recency at query time:
  `score = 0.15·s_conf + 0.25·s_hyp + 0.25·s_pathflag − 0.30·s_deadend + 0.20·recency`,
  `recency = exp(−(tip − last_seq)/τ)`, over a pre-filtered candidate set.

### 2.5 Durability tiers (resolves GC-vs-rebuild)

- **Tier A (never GC'd):** `events.jsonl` + parsed-attribute payloads = artifact-
  independent graph truth. Full state replay needs only Tier A.
- **Tier B (retention SLA):** raw redacted artifact blobs. PIN any blob referenced by a
  flag / high-sev finding / critical-path citation; LRU-evict the rest (recon 7d, exploit
  30d, 2 GB cap). Evicted citations degrade to "artifact evicted, integrity hash
  retained", never dangle. A `versions.json` manifest coordinates all version namespaces
  and fails loudly if a bump needs an evicted tier.

---

## 3. MCP surface

**Design rule:** Kali per-tool wrappers (nmap/ffuf/sqlmap/…) are **not** MCP tools —
that would blow ChatGPT's tool-count budget. They are internal **adapters** selected by
an `adapter` enum inside `propose_and_run`/`submit`. The MCP surface is a small facade
generated from ONE resolver, so Resources (Claude) and `fetch()` (ChatGPT) can never
drift. **FULL ≈ 24 tools; LITE ≈ 13.**

### Tools (selected)

| Tool | Profile | Kind | Purpose |
|---|---|---|---|
| `create_case` | FULL+LITE | write | New case. Scope is NOT set here (control-plane, signed). |
| `get_state` | FULL+LITE | read | Cockpit: phase, scope, budget, top-K hypotheses, next actions — the bounded `STATE.md`. |
| `lotus.next` | FULL+LITE | read | Returns the typed `DecisionRequest` (what to produce + schema + bounded orientation packet). |
| `lotus.submit` | FULL+LITE | write | Validated response; the **server** then executes the chosen in-scope action itself and appends events. |
| `propose_and_run` | FULL+LITE | exec | Transport the loop uses. `commit=false` → plan preview + scope verdict + cost; `commit=true` → `{job_id}` (returns <1s). |
| `session_edit_run` | FULL+LITE | exec | Regime B: write/patch an exploit script and run it vs a persistent tube. Phase/plateau accounting suspended. |
| `tube_open/send/recv/close` | FULL | exec | PTY/socket expect-semantics, scope-checked + IP-pinned. |
| `get_job` / `job_wait` / `cancel_job` | FULL+LITE | read/exec | Poll or long-poll (≤55s); progress via `notifications/progress`. |
| `kb_query` / `kb_get` / `kb_search` / `kb_artifact` | FULL+LITE | read | Graph query / node detail / FTS over text artifacts / paged raw bytes (byte-range mandatory-defaulted). |
| `note_add` / `hypothesis_upsert` / `evidence_link` / `deadend_mark` / `decision_made` / `plan_update` | FULL+LITE | write | LLM reasoning → events (redacted at the serializer). |
| `flag_scan` / `flag_scan_graph` / `flag_submit` | FULL+LITE | read/exec | Decode-ladder sweep; submit only to operator-signed platform endpoints, rate-limited, audit-chained. |
| `case_replay` / `case_diff` / `case_writeup` / `case_resume` | FULL+LITE | read | State-at-seq, graph delta, writeup, bounded resume packet. |
| `audit_verify` / `audit_prove` | FULL | read | Recompute chain; Merkle inclusion proof for one command. |
| `technique_suggest` / `technique_apply` | FULL+LITE | read/write | Thompson-sampled recommendations. |
| `search` / `fetch` | LITE only | read | ChatGPT deep-research contract; `fetch` delegates to the same resolver as Resources. |

**NOT exposed to the agent (control-plane, human-signed only):** `set_scope` /
scope-widening, `add_egress_grant`, `set_submit_endpoint`, `enable_tier3`.

### Adapter enum (inside `propose_and_run`; each has a typed arg model + parser)

| adapter | tier | binaries | parses → |
|---|---|---|---|
| `port_scan` | 1 | nmap/rustscan | host, service.* |
| `http_probe` | 0 | httpx/whatweb | host, tech, tls, service.http (redirects OFF by default) |
| `dir_bruteforce` | 2 | ffuf/feroxbuster | http.endpoint |
| `param_discover` | 1 | arjun | http.param |
| `nuclei_scan` | 2 | nuclei (tag-scoped) | vuln.cve |
| `sqli` | 2 | sqlmap (`--batch`) | vuln.sqli, credential |
| `hydra` | 3 | hydra/medusa (attempt-capped) | credential |
| `jwt_analyze` | 2 | jwt_tool | vuln.jwt |
| `crypto` | 0 | internal + openssl/sage | crypto.artifact, rsa.facts |
| `binary_triage` | 0 | file/strings/checksec/r2 | binary.* |
| `msf_module` | 3 | metasploit | policy-gated |
| `exec_script` / `run_raw` | 3 | sandboxed python/bash | DISABLED whenever any external egress grant is active |

### Resources (FULL) & Prompts

Resources use `lotus://case/{id}/…` (state, brief, findings, entity/{eid}, timeline,
job/{jid}[/output], artifact/{sha} with Range, session/{sid}, dashboard, writeup) and
`lotus://library/technique/{tid}`. All read-only; writes go through tools. Claude
subscribes to job/session/state; LITE polls; `fetch()` resolves the same URIs.

Prompts (FULL slash-commands) embed the live bounded brief: `lotus.recon.kickoff`,
`lotus.methodology.{web,pwn,crypto,rev,forensics,osint}`, `lotus.triage.next_move`,
`lotus.exploit.session`, `lotus.hypothesis.review`, `lotus.writeup.replay`.

---

## 4. Autonomous control loop

### 4.1 Determinism boundary

| SERVER (pure fn of CaseState) | LLM via the ONE gateway (temp=0, cached) |
|---|---|
| phase transitions & guards; candidate generation/filtering; scope enforcement; budget accounting; dead-end filtering; final `S(a)` math + tie-break; Bayesian update when regex-checkable; kill/confirm thresholds; seeded RNG | hypothesis abduction; candidate ranking + info-gain estimate; outcome bucketing (only when not regex-checkable); Regime-B exploit-script authoring; writeup narration |

**Reproducibility (honestly scoped):** *decision-reproducible* via cache-replay given
recorded observations. Live re-runs are not bit-exact (providers don't guarantee
temp=0 determinism). CI gate = **replay-equivalence** (rebuild graph twice, diff
byte-for-byte) + a golden `STATE.md` test. (Both implemented — see
[`tests/`](tests/test_replay_equivalence.py).)

### 4.2 Two regimes

- **Regime A (deterministic planner)** for `TRIAGE/RECON/ENUMERATE` — checklists
  converge, EV/UCB is meaningful, the LLM only ranks a bounded set.
- **Regime B (interactive code-synthesis)** for `EXPLOIT/POST_EXPLOIT` on
  pwn/rev/hard-crypto/stateful-web — the LLM authors and iterates a sandboxed script
  against a persistent Tube + threaded session/cookie-jar. The server enforces only
  scope/budget/redaction, not action shape. Phase transitions and plateau accounting are
  **suspended** while a session is open. *(This is the core effectiveness fix — the
  system is no longer capped at the union of playbook rules.)*

### 4.3 Phase machine (global, authoritative)

| From | To | Guard |
|---|---|---|
| TRIAGE | RECON | scope verified (signed) ∧ target reachable ∧ flag_format set |
| RECON | ENUMERATE | ≥1 service fingerprinted with product/version |
| ENUMERATE | EXPLOIT | ≥1 OPEN hypothesis conf ≥ exploit_gate(0.40) ∧ payoff ≥ 0.6 |
| EXPLOIT | POST_EXPLOIT | CONFIRMED "access gained" (HARD signal: shell/creds/authz bypass) |
| POST_EXPLOIT | SOLVED_PENDING_SUBMIT | flag string matches format ∧ local check passes |
| SOLVED_PENDING_SUBMIT | FLAG_FOUND | platform oracle returns correct (else soft-terminal: stop, surface to human) |
| EXPLOIT | ENUMERATE (regress) | all exploit candidates dead-ended ∧ new surface discovered |
| any | ESCALATED | plateau-after-self-escalation ∨ scope conflict ∨ budget ≥80% w/o access |
| any | EXHAUSTED | budget exhausted ∧ no OPEN hypothesis with payoff ≥ 0.6 |

### 4.4 One candidate pipeline

The **Playbook Engine** is the sole generator: forward-chaining rules over the graph
emit `CandidateAction`s scored by
`U(A) = categoryConf^1.5 · yield · priorityNorm · novelty · phaseGate / (cost+10) · riskGate`.
That `U(A)` becomes the **server prior**. The loop then applies EV+UCB:

```
EV(a) = info_gain_LLM(a,h) · payoff(h,phase) / cost(a)   # payoff: recon .2 enum .4 exploit .8 flag 1.0
S(a)  = w_ev·EV(a) + w_ucb·c·sqrt(ln(T+1)/(n_class(a)+1)) + w_prior·U_playbook(a)
        # w_ev=1.0 w_ucb=0.4 w_prior=0.2 c=1.4 ; tie-break: higher S, lower cost, lex id
```
UCB explores by action-class only after depth on the current lead is spent (don't
broaden while an active hypothesis has an untested cheap test).

### 4.5 One iteration (pseudocode)

```python
def step(case) -> StepResult:
    # ---- OBSERVE (single-writer commit at watermark == log tip) ----
    last = case.timeline.last_action_result
    if last:
        delta = OutputAdapters.extract(last)         # deterministic parser over REDACTED artifact
        if last.small_or_interesting:                # don't starve the model of raw signal
            kernel.append(LLMGateway.holistic_read(last))   # note/hypothesis from raw bytes
        kernel.commit(delta)                         # RPC to the ONE serializer; folds synchronously
        budget.charge(last.cost)
        update_hypotheses(case, delta, last.action)  # LR fold, corroboration-gated confirm/kill
        record_progress(case, delta, last)

    # ---- ORIENT ----
    seed_hypotheses_from_playbooks(case)
    g = check_phase_transition(case)                 # reads graph at watermark==tip ONLY
    if g.transition: case.phase = g.next; spawn_children_on_hard_signal(case, g)
    if terminal(case): return finalize(case)         # FLAG_FOUND / SOLVED_PENDING_SUBMIT / EXHAUSTED
    stop = check_stop(case)                            # CTF-aware plateau
    if stop.escalate: return escalation_request(case, stop)

    if regime(case.phase, case.category) == "INTERACTIVE":
        return run_interactive_session(case)          # Regime B: edit/run scripts vs tube; no plateau

    packet = ContextAssembler.orient(case, token_budget=5000)   # bounded, salience-ranked
    hyp = LLMGateway.oracle(ORIENT_AND_HYPOTHESIZE, packet, HYP_SCHEMA)
    merge_hypotheses(case, hyp.new)                   # dedup by content hash; killed hashes blocked

    # ---- DECIDE ----
    cands = PlaybookEngine.propose(case.world)         # SOLE generator; per-entity-class quota first
    cands = filter_candidates(cands, case)             # scope, dead-ends (cap+mode), preconds, budget
    if not cands: return escalate_or_regress(case)
    topK = server_prescore(cands, case)[:12]
    rank = LLMGateway.oracle(RANK_ACTIONS, packet, RANK_SCHEMA, candidates=topK)  # +≤1 write-in, in-scope
    chosen = select_action(topK, rank, case)           # S(a) argmax, deterministic tie-break

    # ---- ACT (server executes; the LLM never runs a command directly) ----
    if chosen.intrusiveness > case.scope.auto_cap:
        return approval_request(case, chosen)          # human gate (never an LLM decision)
    job = Executor.run(chosen, case.scope)             # sandboxed, per-request-proxy-scoped, redacted
    case.timeline.append(job); budget.charge(tool_attempts=1); case.turn += 1
    return StepResult(continue=True)
```

### 4.6 Budget & CTF-aware stopping

`BudgetLedger`: global `{wall_clock_s, llm_tokens, tool_invocations}`, per-phase caps,
per-tool attempt caps, per-hypothesis cap (3 attempts / 90s). **Every** LLM call site
charges here, so the stopping math is not blind.

- **Progress** per *completed* decision point = 1 if a new entity/edge, or |Δconf|>0.05,
  or phase advance, or flag. **In-progress long jobs are excluded** (a running
  hashcat/feroxbuster/padding-oracle is *productive waiting*, not a plateau). Measured in
  wall-clock and per-action-class, not raw turns.
- **Plateau** counts only over completed decision points where a cheaper alternative
  existed; EMA<0.15 over a 20-min window → self-escalate; second plateau → human.
- **Dead-end key** = `(capability, target, param_class)` + stored `failure_mode`
  (WAF-403 vs 200-no-injection). A smarter retry with a new technique/tamper is allowed
  and records why the prior failure doesn't apply.
- **Hypothesis caps** are per-category with reserved capacity for low-frequency/
  high-surprise leads; SUSPEND is revivable by a periodic exploration budget.
- **CONFIRM requires corroboration:** phase advance / child spawning needs ≥2
  independent sources OR a regex-checkable predicted observation OR a HARD signal. A
  single LLM "STRONG_CONFIRM" updates confidence but cannot alone advance a phase — the
  "LLM said yes" cascade is closed.
- **Terminals:** FLAG_FOUND (oracle-validated); **SOLVED_PENDING_SUBMIT** (high-confidence
  flag, no oracle → stop active spend, surface to human); EXHAUSTED; ESCALATED/SUSPENDED.

### 4.7 Escalation ladder

`escalation_policy ∈ {autonomous, ask_on_block, ask_before_exploit}`. Rung 1:
self-escalate (raise intrusiveness cap *within signed scope*, widen catalog, lower
exploit_gate 0.1). Rung 2: typed `HumanHintRequest`. Rung 3: `ApprovalRequest` for
intrusiveness > auto_cap. **Scope widening is never a rung** — it requires an
out-of-band operator signature.

---

## 5. Safety (enforced server-side and structurally)

No LLM output — and no prompt-injection payload in target output — can widen reach.

1. **Control-plane / data-plane split.** Scope definition/widening, egress grants,
   flag-submission endpoints, and tier-3 enablement are human-signed (ed25519) with an
   out-of-band key never in the server request path. The server is verify-only; the
   agent may only narrow scope. See [`scope.example.json`](scope.example.json).
2. **One audited egress proxy + dual-stack default-deny backstop.** Every flow (target
   and external) goes through one audited forward proxy on a pinned IP enforcing scope
   *per-request* — redirects, crawler URLs, DNS-rebinding, vhost fuzzing are all checked
   at request time. Behind it, a per-case netns runs dual-stack `nftables` in the
   `forward` hook, `policy drop`, deny-set first (cloud metadata `169.254.169.254` /
   `fd00:ec2::254`, mgmt subnet, broadcast/multicast). A booted-netns CI test asserts
   egress to metadata/RFC1918/arbitrary hosts is DROPPED.
3. **Zero arbitrary shell; hardened argv.** `shell=False`, argv arrays only; typed arg
   model with a flag allowlist; validate every value *before* templating; one rendered
   value = exactly one argv token; reject leading `-`/`--` on free-text (argument
   injection); wordlists are enum→fixed-path; path args `realpath`-confined under `/work`.
   Ship hostile-input golden tests.
4. **Redact-before-hash + serializer-wide redaction.** The tee redacts *before* hashing
   and *before* any disk write, so `sha256(stored) == artifact_id` holds and audit proofs
   stay valid; plaintext secrets never touch disk (AES-GCM vault for privileged reveal).
   Redaction is also a mandatory choke on the serializer for all LLM-authored text —
   closing the non-Executor leak path into `events.jsonl → STATE.md → resume → writeup →
   Technique Library`. **Flags** (the objective) are captured verbatim; incidental
   secrets are tokenized.
5. **Prompt-injection containment.** No LLM output may cause a scope change, egress
   grant, submission-endpoint change, or new external destination — those paths are
   human-signed and structurally unreachable. LLM "write-in" actions must bind to
   already-in-scope entities. The extractor/holistic passes run a verbatim-quote check
   and can only trigger `finding/note/hypothesis`, never a side effect.
6. **Abuse-resistance ceiling + tamper-evident audit.** Public targets default-denied; a
   public grant is a signed, expiring `AuthorizationGrant` capped at /24, intersected
   last with an always-wins denylist. Rate/attempt budgets enforced in wrapper flags AND
   kernel. The hash chain IS the audit log; every `command.*` carries resolved IP +
   matched scope rule + argv. Signed checkpoint anchors make history rewrite detectable;
   `audit_verify` reports the first divergent seq, `audit_prove` gives a Merkle inclusion
   proof for one command. Technique-Library promotion uses positive placeholder
   allowlisting + salted-hash leak diff + mandatory human review.

---

## 6. Directory layout

### Server repository

```
lotusmcp/
  server.py                 # MCP entrypoint (stdio + Streamable-HTTP), FULL/LITE profiles
  gateway/                  # surface resolver, result envelopes + size caps, profile filtering
  kernel/                   # THE Case Kernel (one serializer per case)
    log.py                  # events.jsonl: seq, prev_hash→hash, fsync, idx        [implemented]
    projector.py            # synchronous fold → SQLite graph                        [implemented]
    state.py                # bounded STATE.md working-set renderer                  [implemented]
    case.py                 # ties log + projections, deterministic rebuild          [implemented]
    canonical.py            # JCS-style canonical JSON                               [implemented]
    redaction.py            # detectors + vault tokenizer (payloads + LLM text)      [phase 2]
    renderers/              # async: state_md, dashboard, fts, resume, compat        [phase 5/6]
    snapshots.py anchors.py versions.py
  ontology/
    kinds.yaml              # THE entity ontology                                    [implemented]
    identity.py             # entity_id = blake2b_128(kind||0x1F||jcs(natural_key))  [implemented]
  engine/                   # OODA loop, phases, EV+UCB selection, budget, stopping  [phase 3]
  playbooks/                # forward-chaining YAML rules (web/pwn/crypto/rev/...)    [phase 3]
  triage/                   # ensemble voters + classify                            [phase 3]
  llm/                      # THE single gateway: budget charge + cache + oracle...  [phase 3]
  executor/                 # only component touching Kali: adapters, sandbox,       [phase 1]
                            #   netns, audited proxy, jobs, tubes, redact-tee
  flag/                     # scanner, decode ladder, ranker, submit policy          [phase 2]
  replay/                   # state replay, writeup IR + narrate + citation verifier [phase 6]
  library/                  # cross-case Technique Library                          [phase 7]
  control_plane/            # HUMAN CLI ONLY — not importable by the server path     [phase 2]
  kb.py                     # read-only graph queries                               [implemented]
tests/                      # replay-equivalence, tamper, hostile-argv, netns egress
```

### Per-case folder (one directory = one case; the log is the brain)

```
cases/<case_id>/
  case.json                 # status, flag_format, platform, created, owner
  scope.json                # OPERATOR-SIGNED manifest (verify-only) — in-scope hosts/CIDRs
  grants/                   # operator-signed egress + submit-endpoint grants (expiring)
  events.jsonl              # ← THE SOURCE OF TRUTH: append-only, hash-chained, redacted
  events.idx                # seq→byte offset (rebuildable cache)
  anchors.jsonl             # signed checkpoint anchors (tamper-evidence)
  llm_cache.jsonl           # prompt_hash→response (decision-replay)
  projections/              # CACHE — always rebuildable; never authoritative
    graph.db                # SQLite entity/claim/attribute/relation/provenance/fts
    STATE.md  state.json    # bounded, salience-ranked working set (LLM-facing)
    findings.json timeline.json
  snapshots/                # O(tail) rebuild + crash recovery
  artifacts/blobs/          # REDACTED, content-addressed (never plaintext secrets)
  redaction/secrets.enc     # AES-GCM vault: handle→plaintext (privileged reveal)
  sessions/<sid>/           # Regime-B interactive workspace (scripts + tube transcript)
  writeups/                 # writeup.json / writeup.md / repro.sh
```

**Invariants:** only `events.jsonl` (+ idx/anchors/cache) and the signed
`scope.json`/`grants` must survive to reconstruct decisions; `projections/` and
`snapshots/` are disposable. Atomic publish via `*.tmp` + `os.replace`.

---

## 7. Build roadmap

- **Phase 0 — Case Kernel + walking skeleton.** ✅ *Done in this repo.* Single serializer,
  hash chain, ONE ontology + id function, synchronous SQLite projector, bounded
  `STATE.md`, stdio MCP facade (`create_case`/`get_state`/`kb_query`/`kb_get`),
  replay-equivalence + tamper CI tests. No Kali — synthetic events.
- **Phase 1 — Safe Executor MVP (recon only).** Rootless Podman + gVisor sandbox;
  dual-stack default-DROP nftables netns (booted-netns egress test); audited forward
  proxy; adapters `port_scan`/`http_probe`/`dir_bruteforce` with typed argv + hostile-argv
  golden tests; redact-before-hash tee; async jobs.
- **Phase 2 — Control plane + scope authorization.** Operator CLI + HSM signing;
  verify-only Scope/Grant Verifier; agent-can-only-narrow; serializer-wide redaction;
  flag subsystem (4-tier registry, decode ladder, decoy filter, submit policy); signed
  anchors + `audit_verify`/`audit_prove`.
- **Phase 3 — Deterministic loop (Regime A) + playbooks + one LLM gateway.** OODA
  step() for TRIAGE/RECON/ENUMERATE; playbook engine as sole candidate generator;
  EV+UCB selection; triage ensemble; single metered gateway + cache; CTF-aware stopping;
  seed web/crypto playbooks. *Target: solves easy web/crypto end-to-end.*
- **Phase 4 — Interactive code-synthesis (Regime B).** Session workspace + persistent
  tube; `session_edit_run`; write-ins bound to in-scope entities; pwn/rev/hard-crypto
  primitives (checksec/r2/Ghidra-headless/angr/z3/Sage/pwntools). *Target: ret2libc pwn +
  an RSA/lattice challenge via iterated scripting.*
- **Phase 5 — Context discipline at scale + ChatGPT LITE parity.** Decomposable
  salience + claim compaction; bounded resume packet; envelope-size integration test;
  LITE `search`/`fetch` bridge (~13-tool surface). *Load test: 5000-endpoint case renders
  `STATE.md` <100 ms and ≤6.5k tokens.*
- **Phase 6 — Replay, writeup, observability.** Two-stage writeup (deterministic IR +
  citation verifier exiling unsupported sentences); `case_replay`/`case_diff`; SSE
  dashboard + OpenMetrics; two-tier durability SLA.
- **Phase 7 — Cross-case Technique Library + calibration.** Allowlist generalization +
  leak diff + human review; Thompson-sampled recommender; escalation UX; calibrate all
  constants against SOLVED medium/hard corpora.
- **Phase 8 — Community extensibility + supply-chain safety.** Playbook JSON-Schema +
  `lotus playbook lint/test`; community playbooks (reorder in-scope capabilities only)
  low-friction; new adapters (define argv/egress) require signed review.
