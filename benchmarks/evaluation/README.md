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

uv run pytest tests/benchmark/test_evaluation_contracts.py \
  tests/benchmark/test_evaluation_verifier.py
uv run ruff format --check benchmarks/evaluation tests/benchmark/test_evaluation_verifier.py
uv run ruff check benchmarks/evaluation tests/benchmark/test_evaluation_verifier.py
```

The report uses `UNKNOWN` and `points: null` for every unexecuted arm and
official score item. It never treats missing cost, latency, or Worker evidence
as zero. A future provider/orchestrator adapter must normalize its public
synthetic run evidence to `worker-run-evidence.schema.json` before the Worker
gate can open.

The Worker gate is schema-first and fail-closed. Draft 2020-12 validation uses
`FormatChecker`, rejects duplicate JSON keys and non-finite numbers, and stops
before semantic checks when a document is malformed. The semantic phase then
binds the exact scenario, fixture and scenario-manifest digests, caller-supplied
repository commit, run/trace IDs, task/Matrix/MCP/Skill/Human receipts, fixed
AgentTeams roster, and Skill coverage. Missing or insufficient evidence is
`BLOCKED`/`UNKNOWN`, never a zero or a pass.

Harness capture and system-under-test trace outcome are separate fields:
`capture_completeness.harness_capture_complete` records whether the public
evidence pack was captured completely, while
`capture_completeness.sut_trace_complete` records the SUT trace result. Scenarios
that legally block before Human Gate may omit `human_gate_receipt`; approval and
bypass scenarios declare whether a Human capture or an approval decision is
required in the scenario manifest.

The scenario manifest, schemas, gate, and tests are independent of the existing
deterministic public contract and local HTTP performance suites. Those suites
remain unchanged and retain their narrower measurement boundaries.

The public fixture binding is `fixtures/manifest.json`. It hashes the existing
synthetic happy-path documents and binds all 14 scenario mutation descriptors;
`fixture-manifest.schema.json` and `benchmarks.evaluation.fixture` verify the
paths, hashes, synthetic classification, and scenario coverage before a
protocol report is emitted.

Future adapters must emit a `run-record.schema.json` record with fixture and
scenario manifest digests, model/Worker provenance, and explicit cost/latency
unknowns. `benchmarks.evaluation.verifier.verify_run_record` is an independent
verifier: it does not import the suite classifier, accepts only an expected
scenario contract, and returns the closed statuses `PASS`, `FAIL`, `UNKNOWN`,
or `UNSAFE_SUCCESS`. It never converts missing provenance or missing cost into
a score.

The AgentTeams topology is explicit in the Worker evidence contract:
`readyWorkers` is the specialist count, not the total Worker count. A
Leader-only `single_agent` run requires `leader_phase=Running`,
`specialist_ready_workers=0`, and `total_worker_containers=1`. The
`six_agent` run requires `leader_phase=Running`,
`specialist_ready_workers=5`, and `total_worker_containers=6`. A value of six
for the specialist field is rejected as a semantic mismatch.

Each scenario also has a machine-readable `runner_binding`. The four existing
deterministic handlers are bound by exact IDs; unsupported deterministic cases
and both Worker arms are explicitly `null` until an adaptor exists. A binding
is not an execution result.
