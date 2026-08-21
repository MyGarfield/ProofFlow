# Provider-neutral Worker evaluation contracts

This package contains the machine-readable protocol for comparing three arms:

- `deterministic_reference`: the no-LLM reference contract;
- `single_agent`: one real Worker with the same ProofFlow tool contracts;
- `six_agent`: the six-Worker AgentTeams DAG.

The package is deliberately an offline validator. It does not start a Worker,
call an LLM, read an API key, inspect an environment dump, or call a network
endpoint.

Validate the protocol and emit a no-execution report:

```bash
uv run python -m benchmarks.evaluation.run \
  --output .proofflow/evaluation-protocol-report.json
```

The report uses `UNKNOWN` and `points: null` for every unexecuted arm and
official score item. It never treats missing cost, latency, or Worker evidence
as zero. A future provider/orchestrator adapter must normalize its public
synthetic run evidence to `worker-run-evidence.schema.json` before the Worker
gate can open.

The scenario manifest, schemas, gate, and tests are independent of the existing
deterministic public contract and local HTTP performance suites. Those suites
remain unchanged and retain their narrower measurement boundaries.

The AgentTeams topology is explicit in the Worker evidence contract:
`readyWorkers` is the specialist count, not the total Worker count. A
Leader-only `single_agent` run requires `leader_phase=Running`,
`specialist_ready_workers=0`, and `total_worker_containers=1`. The
`six_agent` run requires `leader_phase=Running`,
`specialist_ready_workers=5`, and `total_worker_containers=6`. A value of six
for the specialist field is rejected as a semantic mismatch.
