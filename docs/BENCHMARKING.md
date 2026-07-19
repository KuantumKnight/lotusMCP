# Benchmarking LotusMCP

## Recommended benchmark path

Use live authorized CTF/lab targets for final validation, and use benchmark
datasets for repeatable scoring.

For the paper the user referenced, the relevant project is NYU CTF Bench:

- Paper/site: <https://nyu-llm-ctf.github.io/>
- Benchmark repo: <https://github.com/NYU-LLM-CTF/NYU_CTF_Bench>
- Agent framework repo: <https://github.com/NYU-LLM-CTF/nyuctf_agents>

NYU CTF Bench is appropriate for LotusMCP evaluation because it is designed for
LLM-agent CTF evaluation and includes CSAW challenges across web, pwn, forensics,
reverse engineering, crypto, and misc. Its benchmark repository documents 200
test challenges and 55 development challenges; server-backed challenges are
dockerized and launched with Docker Compose.

## Host vs Docker policy

Use Docker/Compose for benchmark targets when the benchmark supplies a target
container. This is the benchmark’s reproducibility boundary.

Run LotusMCP on the operator host unless you are intentionally testing a packaged
deployment. The host process owns:

- `cases/` event logs and projections;
- operator keys and trusted public-key configuration;
- Kali tools used by the executor (`nmap`, `curl`, `ffuf`);
- MCP stdio server process.

This keeps the agent’s source of truth stable while allowing disposable target
containers to be reset between runs.

## Suggested NYU CTF Bench workflow

1. Use the development split first. Treat it as tuning/calibration data.
2. Start one challenge target with the benchmark’s Docker Compose instructions
   (`sudo docker-compose ...` if this host requires sudo for Docker).
3. Map the exposed service to a loopback host/port.
4. Create a LotusMCP case and signed `scope.json` for only that host/port.
5. Run LotusMCP FULL mode against the target.
6. Record:
   - solved/unsolved;
   - flag verified locally or by platform;
   - wall-clock time;
   - tool budget consumed;
   - LotusMCP case id;
   - audit anchor hash;
   - generated repro script.
7. Import solved/failed case logs into the Technique Library calibration pass.
8. Only after tuning on the development split, evaluate on the test split.

## Built-in smoke runner

After sparse-checking out the NYU CTF Bench repository and the selected
development challenge directories, this repository includes a repeatable smoke
command for built-in deterministic web specs.

```bash
PYTHONPATH=. python -m lotusmcp.ops.benchmark_smoke \
  --bench-dir "$PWD/benchmarks/NYU_CTF_Bench_sparse" \
  --cases-dir /tmp/lotus_bench_cases \
  --results /tmp/lotus_bench_results.jsonl \
  --case-id nyu-dev-guessharder-smoke \
  --challenge 2013q-web-guess_harder \
  --manage-target
```

Run the current built-in batch (`2013q-web-guess_harder`, `2016q-web-mfw`,
`2016q-web-i_got_id`) sequentially:

```bash
PYTHONPATH=. python -m lotusmcp.ops.benchmark_smoke \
  --bench-dir "$PWD/benchmarks/NYU_CTF_Bench_sparse" \
  --cases-dir /tmp/lotus_bench_cases \
  --results /tmp/lotus_bench_results.jsonl \
  --case-id nyu-dev-web-batch \
  --batch \
  --manage-target
```

Inventory a larger NYU split before execution. This is the safe path toward the
full 200-case test split because it separates unsupported or missing local
targets from real benchmark failures:

```bash
PYTHONPATH=. python -m lotusmcp.ops.benchmark_matrix \
  --bench-dir "$PWD/benchmarks/NYU_CTF_Bench_sparse" \
  --benchmark nyu-ctf-bench \
  --split test \
  --limit 200 \
  --results /tmp/lotus_bench_results.jsonl
```

CTF-Dojo can also be inventoried after cloning its repository. Its public
manifest contains 658 entries; execution requires generating or checking out the
challenge runtime archive described by CTF-Dojo.

```bash
PYTHONPATH=. python -m lotusmcp.ops.benchmark_matrix \
  --bench-dir "$PWD/benchmarks/CTF-Dojo" \
  --benchmark ctf-dojo \
  --split archive \
  --limit 200 \
  --results /tmp/lotus_dojo_results.jsonl
```

Execute any matrix entries that already have verified built-in smoke specs:

```bash
PYTHONPATH=. python -m lotusmcp.ops.benchmark_matrix \
  --bench-dir "$PWD/benchmarks/NYU_CTF_Bench_sparse" \
  --benchmark nyu-ctf-bench \
  --split development \
  --run-supported \
  --manage-target
```

Run it as root or through `sudo env PYTHONPATH=...` if this host requires sudo
for Docker and privileged localhost scans. The aggregate result omits the raw
flag; the case log remains the authoritative audit record.

## Minimal benchmark-result schema

Store benchmark results outside case logs, for example in
`benchmarks/results.jsonl`:

```json
{
  "benchmark": "nyu-ctf-bench",
  "split": "development",
  "challenge_id": "2021f-rev-maze",
  "case_id": "nyu-dev-2021f-rev-maze",
  "category": "rev",
  "target": "127.0.0.1:8080",
  "solved": true,
  "flag_verified": true,
  "wall_seconds": 1234,
  "tool_budget": {"tool_calls": 42, "llm_tokens": 12000},
  "audit_anchor": "sha256:...",
  "notes": ""
}
```

Do not copy challenge flags into benchmark aggregate files. The case log already
records objective flags according to LotusMCP’s normal flag policy.
