# ProofFlow Public Contract Benchmark

This directory contains a deterministic, synthetic-only quality and safety contract suite for
the ProofFlow reference core.

The parser allowlist case only verifies that an instruction-like JSON field is not extracted by
the deterministic parser. It does not exercise an LLM, MCP, AgentTeams, or a prompt-injection
defense. The suite also does not measure legal accuracy or performance.

Run it from the repository root:

```bash
uv run python -m benchmarks.run_contract_suite \
  --output .proofflow/benchmark-report.json
```

The command prints the same JSON report to stdout and returns exit code `0` only when every
declared contract is satisfied. See [the benchmark protocol](../docs/06_PUBLIC_BENCHMARK.md) for
scope, scenarios, report semantics, and limitations.
