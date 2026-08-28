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
  tests/benchmark/test_worker_evidence_attack_corpus.py \
  tests/benchmark/test_evaluation_ledger_v2.py \
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
binds the exact scenario, fixture/scenario/rule-catalog digests, formula version,
caller-supplied repository commit, run/trace IDs, task/Matrix/MCP/Skill/Human
receipts, fixed AgentTeams roster, and Skill coverage. Missing or insufficient evidence is
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

Future adapters must emit a `run-record.schema.json` record with replicate and
retry-attempt IDs, fixture/scenario/rule-catalog digests, formula version,
model/Worker provenance, and explicit cost/latency unknowns.
`benchmarks.evaluation.verifier.verify_run_record` is an independent
verifier: it does not import the suite classifier, accepts only an expected
scenario contract from the checked-in manifest, and only accepts a caller-
supplied compatibility contract when it is deeply equal to that manifest truth.
It requires an explicit expected repository commit and runs the complete Worker
semantic evidence gate after recomputing the raw evidence hash. It returns the
closed statuses `PASS`, `FAIL`, `UNKNOWN`, or `UNSAFE_SUCCESS`; missing
provenance, missing cost, or an absent commit expectation never becomes a
score. The Worker-evidence and ledger verifiers are structural/semantic
consistency gates over unsigned declarations; they do not prove execution
authenticity. Authenticity requires public raw AgentTeams/Task/Matrix/MCP
receipts or a signed/attested evidence package.

The AgentTeams topology is explicit in the Worker evidence contract:
`readyWorkers` is the specialist count, not the total Worker count. A
Leader-only `single_agent` run requires `leader_phase=Running`,
`specialist_ready_workers=0`, and `total_worker_containers=1`. The
`six_agent` run requires `leader_phase=Running`,
`specialist_ready_workers=5`, and `total_worker_containers=6`. A value of six
for the specialist field is rejected as a semantic mismatch.

Each scenario also has a machine-readable `runner_binding`. The four existing
deterministic handlers and six exact deterministic adapters are bound by exact
IDs; both Worker arms are explicitly `null` until an authorized adapter exists.
A binding is not an execution result. `benchmarks.evaluation.ledger` can run
the ten deterministic scenarios into a hash-chained append-only v2 ledger. Its
explicit `coverage_plan` expands every applicable arm/scenario for each
declared replicate and retry attempt; each entry has an ordered index,
previous-entry hash, entry hash, and the ledger has a root hash. An `attempt`
is never a new replicate. Aggregation selects exactly one result per
arm/scenario/replicate using
`UNSAFE_SUCCESS_PRECEDENCE_THEN_HIGHEST_TERMINAL_ATTEMPT_ELSE_HIGHEST_ATTEMPT`.
Any unsafe success is sticky across retries and becomes the selected result;
otherwise the highest-numbered attempt with an executed terminal result wins,
or the highest-numbered UNKNOWN attempt when none reached a terminal state.
Pairs containing unsafe success are counted as release-blocked, never complete.
Blocked-pair randomization is only planned: no seed, arm order, or block assignment
has been recorded, so the manifest says
`PLANNED_BLOCKED_PAIRS_SEED_NOT_RECORDED`.
Worker entries also carry
`worker_evidence` plus its recomputed `worker_evidence_sha256`; unexecuted
Worker arms remain `null`/`UNKNOWN`. `ledger_verifier` independently checks
manifest coverage, sequence/hash-chain, provenance, evidence binding, pairing,
the frozen rule/formula match across all selected arms, the model-configuration
digest match across executed single/six arms, and the cost/latency unknown
contract before `aggregate_run_ledger` emits an
`EXECUTED` or `MIXED_EXECUTION` report. These hashes are tamper-evident
consistency checks, not signatures or attestations. Official score points
remain `UNKNOWN`/`null` until paired arms and their required evidence exist.

The Worker evidence contract requires more than `worker_execution_observed` or
`llm_inference_observed` booleans: every expected participant needs a bound
Worker session receipt and LLM inference receipt with session/container/task
links, trace IDs, request/response hashes, model configuration digest, and
explicit token/cost completeness. Human decisions require a pseudonymous
`actor_kind=HUMAN` receipt with actor role, method, decision time, subject hash,
and task/Matrix/trace links. The gate remains `BLOCKED`/`UNKNOWN` when these
receipts are absent.
