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
