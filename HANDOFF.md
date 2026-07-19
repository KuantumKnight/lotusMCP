# LotusMCP — Complete Handoff

Single source of truth for picking up this project cold, in a new session/agent with no prior memory. Originally written 2026-07-15; updated 2026-07-19 after host-only Kali execution work. Verify anything time-sensitive against current code/git before acting on it — this is a snapshot.

---

## 1. What this project is

LotusMCP is an autonomous CTF case-management MCP server that bridges an LLM to Kali Linux tooling. Core design principle: **the append-only, hash-chained event log is the only source of truth; the entity graph and STATE.md are pure, deterministic folds of that log.** Nothing is stored that can't be rebuilt by replaying the log.

- Full architecture and the phase roadmap: `ARCHITECTURE.md` (§7 = phase plan).
- Repo root in this Kali workspace: `/home/katana/Desktop/lotusMCP`
- Main package: `lotusmcp/` — subpackages: `kernel/`, `ontology/`, `flag/`, `playbooks/`, `triage/`, `engine/`, `executor/`, `session/`, `gateway/`, `llm/`, `replay/`, `observability/`, `control_plane/`, `library/`, `ops/`, `demo/`, plus `kb.py` and `server.py` (stdio MCP entrypoint).
- Tests: `tests/` — direct `__main__` runners, full suite green as of latest run.
- Git: branch `main`, clean working tree expected after each slice; use `git log --oneline -20` for the current latest commit because this handoff is updated incrementally.
- Author identity for this repo: **KuantumKnight <msarvesh.dav@gmail.com>** — see §4.

---

## 2. Build state — what's done, phase by phase

**Everything except real solved-case collection/live validation is now built/tested in this Kali workspace.** FULL execution is host-only by user instruction: use this exact Kali machine; do not use Docker/Podman/venv execution paths. Full direct test suite green.

### Phase 0 — Case Kernel (DONE)
`kernel/` — append-only hash-chained event log (`log.py`, `canonical.py`, `events.py`) with LotusC14N-v1 strict canonical JSON, per-case host advisory locking and tail reload under lock, deterministic projector → SQLite (`projector`/graph), `state.py`, `case.py`. `ontology/identity.py` (natural-key identity), `kb.py`. Stdio MCP `server.py`. Replay-equivalence, tamper-detection, canonicalization, and stale-tail concurrency tests pass.

### Phase 2 — Redaction + Flags + Control Plane (DONE)
- Redaction choke `kernel/redaction.py`: content-addressed `«SECRET:kind:tag»` handles, flag-aware, mandatory serializer choke, redact-before-hash (secrets never touch the log).
- Flag subsystem `flag/`: decode ladder, scanner, ranker + decoy filter + 4-tier registry, submit policy, `FlagEngine` facade, `flag_scan` MCP tool.
- Control plane crypto split — **verify-only** in server-safe `kernel/signing.py` (rejects a valid signature from an untrusted key); **private-key signing** lives in `control_plane/` (server code must never import this). Pieces: signed manifests (scope/egress_grant/submit_allowlist/tier3/adapter_review) via `control_plane/keyring.py`; verify-only scope verifier `engine/scope.py` (`in_scope(host,port)` over CIDR/wildcard/FQDN+ports; agents may only *narrow* scope, never widen); persistent AES-256-GCM vault `kernel/vault.py` (per-secret nonce, handle-as-AAD, fail-closed, default `Case` vault under `case/vault/`, optional `LOTUS_VAULT_KEY_HEX`); signed audit anchors (`kernel/anchor.py` verify, `control_plane/anchor.py` create — detects full history rewrite); operator CLI `control_plane/cli.py` (keygen/sign-*/anchor/verify).
- Real crypto via the `cryptography` library (Ed25519/AES-GCM), not toy implementations.

### Phase 3 — Playbook Engine + LLM Gateway + OODA Loop (DONE)
- `playbooks/`: forward-chaining Rules as Python literals (not YAML yet), sole candidate generator, `U(A)` scoring in `engine/candidate.py`.
- `triage/`: triage ensemble. `engine/selector.py`: EV+UCB selector. `engine/{budget,phases,progress}.py`: budget ledger + phase state machine.
- `engine/loop.py`: full OODA `step()` loop (observe/orient/decide/act), Executor and LLM injected via interfaces.
- `llm/` package: `LLMGateway` — the ONE metered/cached/schema-enforcing LLM call site. Charges the budget ledger only on cache miss (so replays are free and decisions stay reproducible); typed schema enforcement with retry-on-mismatch; offline `DeterministicProvider` (rule-based, no network/key needed) behind a `Provider` Protocol so a real provider drops in later. Wired into `loop.py` as optional `gateway=` (default None = unchanged deterministic behavior); everything the LLM returns is advisory only.
- Demos: `demo/decide_loop.py`, `demo/autonomous_solve.py`.

### Phase 1 — Executor boundary (DONE for host-only Kali)
`executor/`:
- `argv.py`: hardened `build_argv(action, target)` for port_scan/http_probe/dir_bruteforce. Strict typed schema, allowlisted flags/wordlists only, `--` end-of-options, no shell, no process spawn — output is always an argv list. Untrusted input → `ArgvRejected`.
- `parse.py`: total parsers for nmap XML / http response / ffuf JSON → EventDrafts, hardened against untrusted input (size caps, DTD/entity refusal).
- `replay.py`: `ReplayExecutor` implements the loop's `Executor` protocol (plan → stdout → parse → events); `backend` is swappable.
- `executor/sandbox.py` (commit `81fa61e`): host-only `SubprocessBackend` runs validated argv directly on this Kali machine with `shell=False`, scrubbed env, stdout cap, timeout, and a second backend-local scope check before spawn. `backend_from_env()` only supports `subprocess`/`host`.
- `launcher.py` wires `propose_and_run` to `ReplayExecutor(backend_from_env(...))`.
- Scope wiring done: `Loop(scope=Scope|None)` — a verified `Scope` gates every action in ACT before the Executor runs (out-of-scope → refused, dead-ended, never re-proposed).
- User explicitly said: **do not use any other venv or Docker; use this exact machine.** Podman/runsc were installed earlier but are not used by the project.

### Phase 4 — Regime B interactive sessions (DONE for host-only Kali)
`engine/regime.py` routes EXPLOIT/POST_EXPLOIT on pwn/rev/crypto/web to INTERACTIVE. `session/` package: `Tube` protocol + offline `ScriptedTube`, `Script`/`RunOutput`, `ScriptAuthor`/`ScriptRunner` protocols with deterministic offline impls. `InteractiveSession` = per-session workspace, author→run→fold loop, enforces scope/budget/redaction. `session/manager.py` (`SessionManager`, live per-case registry) and `session/service.py` (`SessionService`, fail-closed MCP policy — opens only with a configured sandbox backend AND a signature-verified Scope). MCP tools: `session_edit_run`, `session_close`, `session_list`.
`session/live.py` (commit `b3b0ba9`): host-native `TCPTube`, `HostPythonScriptRunner`, and `host_session_factory`; uses stdlib sockets and host `python3`, no pwntools dependency, no venv. `launcher.py` wires `SESSIONS.configure(host_session_factory)`. Scripts receive `LOTUS_TARGET_HOST`/`LOTUS_TARGET_PORT`/`LOTUS_TARGET_ID`/`LOTUS_TARGET_DISPLAY`.

### Phase 5 — Context discipline / ChatGPT LITE parity (DONE)
- `engine/salience.py`: decomposable salience scoring/ranking (`Salience(s_conf/s_hyp/s_pathflag/s_deadend/last_seq)`, weights+τ centralized, recency = exp(−(tip−last_seq)/τ)).
- `kernel/resume.py`: `build_resume_packet(db, meta, tip, token_budget=6500)` — salience-ranked, token-bounded (≤6.5k tokens, 25-item surface, <2s build even at 5000-endpoint scale), trims lowest-salience over budget and reports drops in `truncated` (never silent).
- `gateway/resolver.py`: `Resolver` — the ONE surface resolver (`search(cid,q)`/`fetch(uri)` over `lotus://case/{cid}/{brief|resume|entity|finding|hypothesis}` URIs) shared by Claude Resources and ChatGPT deep-research `fetch()` so the two profiles can't drift.
- Claim compaction (commit `ee994ec`): `GraphProjector.compact(keep_per_value=4)` bounds the claim log — collapses redundant corroboration per (entity,attr,value) into one merged `«compacted»` claim (noisy-OR of the tail), keeps top K-1 real claims by conf/seq/id. Log untouched (`rebuild()` restores full history), folds/STATE.md byte-identical before/after, new `claim.weight` column. `Case.compact()` + `case_compact` MCP tool.
- FTS5 full-text search (commit `c8a3448`) in `Resolver.search` — transient `temp.ftsidx`, multi-term AND tokenized matching; falls back to substring if FTS5 unavailable or query has no tokenizable chars.
- LITE/FULL tool-profile filtering (commit `c3c2c6f`): `gateway/profile.py` (`TOOL_CATEGORY`, `_CATEGORY_MIN_PROFILE`); LITE ⊂ FULL, exec/ops/scrape categories are FULL-only, `search`/`fetch` always in LITE. `enforce_envelope(value,max_bytes=64KB)` bounds tool output (trims largest bulk-text fields first, in-band marker, never silent). `server.py`'s `@tool` decorator wraps every registration.
- Job tools (commit `f7fe2db`): `engine/jobs.py` `JobService` — `next(case_id,top=5)` (read-only recommendation, asserts log tip unchanged), `propose_and_run(case_id,max_steps=1)` (drives `Loop.step()` with a configured executor), `submit(case_id,value?)` (flag submission via signed oracle, dedup/terminal-safe, never auto-submits). All fail closed until `configure(executor_factory/submit_oracle/gateway_factory/scope_factory)` is called. Registered as `lotus_next`(LITE)/`propose_and_run`(FULL)/`lotus_submit`(FULL).
- **Tool counts hit the design target: LITE=15, FULL=24.**
- Test suites: `test_salience`(7), `test_resume`(5), `test_gateway_resolver`(7), `test_state_envelope`(2), `test_claim_compaction`(4), `test_search_fts`(6), `test_tool_profile`(10), `test_jobs`(10).

### Phase 6 — Replay, writeup, durability, observability (DONE)
- `replay/state.py`: `state_at(case,seq)` (fold log prefix → phase+graph snapshot) and `diff(case,a,b)`.
- `replay/writeup.py`: two-stage writeup — every claim in the IR carries a citation into the log; uncited/hallucinated claims get exiled as `writeup.claim_rejected` events. LLM narrates, verifier disposes.
- `observability/metrics.py`: pure-fold OpenMetrics text.
- `replay/repro.py`: `build_repro(case)` — deterministic bash repro script folded from the validated argv command trail (secrets stay redacted, flags never echoed).
- `kernel/blobstore.py` (commit `4128771`): Tier-B content-addressed (sha256) blob store for redacted artifacts under `artifacts/blobs/`, manifest `artifacts/versions.json`. Age-window (recon/enumerate 7d, exploit/post_exploit/else 30d) + LRU-to-cap (2GB) eviction; pinned blobs never evicted; evicted blobs keep their hash + a degraded-status note so citations never dangle; `set_version` fails loud (`DurabilityError`) if a required blob is gone. `Case.blobs` lazy property. MCP: `kb_artifact`(LITE), `case_gc`(FULL).
- `replay/repro.py` (commit `c865db7`): folds the validated argv command trail (`command.requested`/`command.completed` events) into a deterministic bash repro script — grouped by phase, `shlex.quote`d, secrets stay redacted, flags never echoed. MCP: `case_repro`(LITE).
- `observability/dashboard.py` (commit `5a0eba5`): stdlib read-only dashboard + SSE tail. Endpoints: `/`, `/cases`, `/case/<cid>/state`, `/case/<cid>/metrics`, `/case/<cid>/events`, `/case/<cid>/stream`.
- Test suites include `test_replay_writeup`(6), `test_metrics`(5), `test_repro`(6), `test_blobstore`(10), `test_dashboard`(4).

### Phase 7 — Cross-case Technique Library + calibration (DONE, commit `bc71887`)
`lotusmcp/library/`: `TechniqueLibrary` lives OUTSIDE any case dir, cards keyed only by `(capability, category, param_class)` via `technique_id()` — no target/host/path/payload, so nothing leaks cross-case. Beta-posterior calibration per card (`alpha=wins+1`, `beta=losses+1`; `observe`/`observe_action` bump it), Thompson-sampling `suggest(phase?,category?,k=5,rng?)` (deterministic under seeded `random.Random`, mean-mode if `rng=None`), human-gated `promote(tid,reviewer)` (raises `KeyError` if never observed). Pure rebuildable fold of its own `library.jsonl`. `Loop(library=None)` optional hook: after ACT, `library.observe_action(action, phase, progressed)`. MCP: `technique_suggest`(LITE, unseeded), `technique_promote`(FULL). Test suite: `test_technique_library`(8).
`library/calibrate.py` (post-`67f8cfd`): offline importer folds solved case logs into target-free technique observations and updates `TechniqueLibrary`. Still needs real solved case data for meaningful constants.

### Phase 8 — Community playbook lint + safe apply + signed adapter review (DONE)
`playbooks/community.py`: community playbooks are treated as DATA, not code. `lint_playbook(doc, known_rule_ids, known_caps)` never raises, fails loud (returns findings) on: unknown rule id, forbidden keys (`capability`/`kind`/`category`/`when`/`params`/`phase_gate`/`rationale` — new capabilities need signed review), out-of-range knobs (priority/yield/risk∈[0,1], cost>0, bool≠number), structural errors (not-an-object/no-rules/missing-name/duplicate-id). Only tunable keys: `priority/yield/cost/risk`/`enabled`. `apply_playbook(base_rules, doc)` raises `CommunityPlaybookError` unless lint-clean, else returns tuned rules via `dataclasses.replace` (vetted `capability`/`when` objects preserved identity). `playbooks/cli.py` `main(argv)`: operator-gated `lotus playbook lint|test` CLI. Untrusted playbook loading is deliberately NOT exposed on the MCP surface. Test suite: `test_community_playbook`(10).
`playbooks/adapter_review.py` + `control_plane.cli sign-adapter` (commit `8b6a9c2`): signed `adapter_review` manifests validate capability/category/tool/argv_schema/egress/reviewer and verify with trusted operator keys. This is an auditable approval artifact only; it does not dynamically load adapter code.

---

## 3. What's left

1. **Collect real solved cases / authorized live validation** — calibration tooling exists, but meaningful tuning needs actual solved case logs.
2. Optional deployment hardening if packaging beyond this Kali host: rootless Podman/gVisor/netns/proxy for LotusMCP itself. Current best-practice mode is host-native LotusMCP plus isolated benchmark/lab targets when those targets are supplied as containers.

Recommended next step if continuing this work: run against authorized lab targets or NYU CTF Bench development challenges with signed `scope.json` and collect solved/failed case logs for calibration. See `docs/OPERATOR_RUNBOOK.md` and `docs/BENCHMARKING.md`.

---

## 4. Operating conventions (must follow)

### Git / commits
- **Commit every small, independent change as its own commit and push immediately** — don't batch unrelated changes into one commit. The user works in small increments, hands off frequently, and relies on the pushed remote reflecting current state.
- **Author identity is `KuantumKnight <msarvesh.dav@gmail.com>` — set locally via `git config user.name`/`user.email` (not global).** Never add Claude as an author or co-author; omit any `Co-Authored-By: Claude` trailer even though the default harness instruction says to add one — this project overrides that. GitHub account `KuantumKnight` is already `gh`-authenticated.

### Testing
- **pytest is NOT installed in this environment.** Every file in `tests/` has a `__main__` runner that discovers `test_*` functions and prints `N/N passed`. Run tests individually:
  ```
  PYTHONPATH=. PYTHONIOENCODING=utf-8 python tests/test_<name>.py
  ```
- `PYTHONPATH=.` is mandatory (package isn't installed).
- `PYTHONIOENCODING=utf-8` is mandatory — redaction handles use guillemets `«»`; without UTF-8, Windows cp1252 stdout garbles/throws and string assertions mislead.
- New tests should follow the same pattern: pure-stdlib, a `__main__` block running all `test_*` fns, `sys.exit(1 if failed)`. Keep everything runnable with **no Kali, no LLM, no network**.
- **Fixture gotcha (ranker/flag tests):** flag bodies containing decoy markers (`fake`, `wrong`, `example`, `test`, filler like `a`/`xxxx`) get auto-classified as decoys → tier 4. Use realistic bodies like `flag{r34l_body_1337}` or tiering assertions will fail.
- Demos (all need `PYTHONPATH=.` + UTF-8): `python -m lotusmcp.demo.seed_recon`, `.decide_loop`, `.autonomous_solve`.

---

## 5. Quick orientation for a new agent

1. Read `ARCHITECTURE.md` first for the design philosophy and full phase plan (§7).
2. Run the test suite (or a sample of it) per §4 to confirm the snapshot above is still accurate — memories/handoffs are point-in-time, code may have moved on.
3. Check `git log --oneline -20` and `git status` to see if work has continued since commit `8b6a9c2`.
4. If picking up new work: the remaining meaningful work is empirical calibration from real solved cases or authorized live-target/benchmark validation.
5. Follow the git/commit and testing conventions in §4 exactly — they've been corrected by the user before and are firm preferences, not suggestions.
