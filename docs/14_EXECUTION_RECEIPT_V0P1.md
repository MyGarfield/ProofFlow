# ExecutionReceipt v0.1

Status: observer-signed, public-synthetic reference slice. It is not a production execution or
outcome attestation.

## What this slice verifies

ExecutionReceipt v0.1 records what a configured observer says it saw during one attempt. Its wire
profile is fixed to:

- DSSE 1.0.2 PAE and `payloadType = application/vnd.in-toto+json`;
- in-toto Statement v1;
- `predicateType = https://proofflow.dev/attestations/execution-receipt/v0.1`;
- Ed25519 verification supplied by `cryptography` and shared with ActionCertificate;
- strict, immutable Pydantic models and bounded Draft 2020-12 Schemas;
- exact signed payload bytes as the receipt identity. Semantically equivalent payloads with a
  different byte encoding have different SHA-256 values and conflict in the v0.1 index.

The predicate binds an exact ActionCertificate reference, tenant and case, attempt, executor
workload, runtime build and instance, protocol exchange, OTel trace identifiers and raw observer
evidence digest, input/output artifacts, Tool or Skill operation, nullable model invocation, effect
attempt, cost, duration, and local digest-only provenance references. There is no prompt, response
body, personal-information field, URL resolver, plugin loader, or network fetch.

`LOCAL`, MCP `2026-07-28`, and A2A `1.0.1` are a discriminated union. Fields from another branch,
unknown versions, and extra fields are rejected. The current executable fixture exercises only
`LOCAL` with `PUBLIC_SYNTHETIC` values. No MCP/A2A connection is made.
Every receipt also carries runtime-independent `execution_id` and `task_id`; retries use distinct
attempt IDs under the same logical execution. Protocol and Tool/Skill request/response digests must
match, preventing one observed exchange from being attached to another logical operation.

## ActionCertificate handoff is external trusted input

The receipt cannot make its own authorization valid by writing `ACCEPT` or `reserved=true`.
`verify_execution_receipt` requires all of the following external, operator-controlled inputs:

1. the exact ActionCertificate DSSE envelope bytes;
2. a strict `ActionCertificateVerificationResult` produced by the pre-execution verifier;
3. an independently prepared `ExpectedExecutionBinding`.

The receipt and expected binding carry the exact certificate ID, envelope SHA-256, decoded payload
SHA-256, approval-scope intent SHA-256, and canonical verification-result SHA-256. The verifier
recomputes them, requires `status=ACCEPT`, the sole `ACCEPTED` reason and `reserved=true`, then parses
the already-accepted ActionCertificate payload. It cross-checks tenant, case, workload, trace,
input artifacts, approved Action name/parameters, logical request, effect type/target/intent, and
idempotency key. An observed provider request must equal the approved logical request digest.

The operator binding also supplies UTC `verification_at` and `reserved_at` declarations. The
verifier requires `verification_at <= reserved_at <= attempt.started_at` and keeps the complete
attempt within the ActionCertificate `not_before`/`expires_at` window (subject only to configured
clock skew). These timestamps are not fields in the unsigned ActionCertificate result, so v0.1
treats their accuracy as an explicit operator-controlled assumption, not cryptographic proof.

The expected binding also carries operator-controlled human and workload public-key fingerprints.
They are not self-reported by the receipt. The verifier uses them only as a deny set for observer
independence; v0.1 depends on the operator having bound those fingerprints to the named identities.

The verification result is not signed and the ActionCertificate replay reservation is process
local. This handoff is therefore a trusted local verifier input, not a durable reservation
attestation. If an attacker controls the envelope, result, expected binding, and trust policy
together, v0.1 cannot establish authorization. PostgreSQL, a signed acceptance attestation, and
durable recovery remain future gates.

## Observer trust and independence

Only roots explicitly configured by the operator with all of these properties count:

- `purpose=EXECUTION_OBSERVER`;
- matching tenant, fixed receipt audience, and predicate type;
- a principal in `allowed_execution_observer_principals`;
- all seven v0.1 scopes: runtime, artifact I/O, protocol, trace export, inference response, effect
  attempt, and metrics;
- a current, non-revoked Ed25519 key.

The observer key must be valid both at the signed receipt `issued_at` and at verification time.
Action issuer/approval keys are reverified over the exact ActionCertificate envelope and evaluated
at the operator-declared ActionCertificate verification time.

The threshold counts distinct principals and distinct public-key fingerprints. Repeated signatures,
duplicate root records, multiple keys for one principal, or one key assigned to multiple principals
cannot fake a threshold. An observer principal or key must also differ from the executor workload
and human identities fixed by the expected binding, and from every ActionCertificate issuer/approval
authority referenced by the accepted result. A
self-observer is rejected even if it was accidentally allowlisted.

This first slice requires each qualifying root to have authority for the whole receipt. It does not
combine a runtime-only observer and billing-only observer into authority over all fields. Per-scope
thresholds are a future versioned policy feature.

## `OBSERVED` and `UNKNOWN`

Model inference, token usage, effect evidence, cost, and duration never default to zero or a
boolean. Each uses a closed `OBSERVED | UNKNOWN` state:

- `UNKNOWN` requires all associated fields to be present as explicit `null` values;
- `OBSERVED` requires the complete v0.1 value and evidence digest;
- an observed zero cost or zero duration is legal only with observer evidence.

Observed cost uses a canonical decimal string, ISO currency, and rate-card digest—never a JSON
float. Observed duration uses integer milliseconds, a declared monotonic clock and precision, plus
its evidence digest; wall timestamps are correlation fields, not the duration measurement.

The included local fixture has no model invocation, unknown model/usage/cost, and unknown effect
evidence. It observes a local duration. `effect.status=OBSERVED` would still mean that the observer
saw the full effect-attempt evidence set. The only closed provider result that resembles success is
`TRANSPORT_ACK`; there is deliberately no `EFFECT_SUCCEEDED` value.

An MCP response only shows that an exchange was observed; tool annotations or JSON-RPC success do
not prove tool internals or a real-world effect. A2A task state and Artifacts remain remote Agent
declarations. An OTel span proves that telemetry bytes reached the observer, not causality or
business truth. Provider acknowledgements and operation IDs are not OutcomeClosure.

## Verification and index order

The verifier performs these steps in fixed order:

1. Bound and strictly parse the DSSE envelope, rejecting duplicate JSON keys and non-finite values.
2. Verify Ed25519 signatures over the exact payload bytes before parsing the payload.
3. Parse the strict in-toto statement and apply the trusted expected binding.
4. Cross-check the external accepted ActionCertificate inputs and authority-root mapping.
5. Apply observer purpose, scope, tenant, audience, time, revocation, independence, and threshold
   rules.
6. Atomically append to a process-local, bounded, append-only index.

The index uses `(tenant, receipt_id)`, `(tenant, execution_id, attempt_id)`, and
`(tenant, idempotency_key) -> intent_sha256`. It never overwrites or evicts:

- first valid payload: `ACCEPT / APPENDED`;
- exact same payload: idempotent `ACCEPT / ALREADY_PRESENT`, with no second append;
- changed bytes under the same receipt or attempt: closed conflict and `REJECT`;
- one idempotency key with another intent: `REJECT / IDEMPOTENCY_CONFLICT`;
- unavailable or full index: `UNKNOWN / RECEIPT_INDEX_UNAVAILABLE`.

The index is not durable, cross-process, crash safe, or evidence of exactly-once delivery.

## CLI and Schemas

All CLI inputs are local regular files controlled by the operator:

```bash
uv run proofflow receipt verify \
  --envelope execution-receipt.dsse.json \
  --trust-policy operator-trust.json \
  --expected-binding expected-execution.json \
  --action-certificate-envelope action-certificate.dsse.json \
  --action-certificate-verification accepted-action-result.json \
  --at 2026-08-30T04:00:00Z
```

Exit codes are `0=ACCEPT`, `1=REJECT`, `3=UNKNOWN`, and `2=input/configuration error`. Each CLI
process creates a new index, so cross-process replay handling is out of scope.

The machine contracts are exported as `schemas/execution-receipt-*.schema.json`. Regenerate and
check them with:

```bash
uv run python scripts/export_schemas.py
uv run python scripts/export_schemas.py --check
```

Runtime-only invariants that portable JSON Schema cannot express are disclosed through
`x-proofflow-runtime-invariants`. Security decisions must use the strict model and verifier, not a
generic Schema validator alone.

## Explicit non-claims and next gates

This slice does not run Worker/LLM, perform a provider effect, connect MCP/A2A/OTLP, query an
authoritative outcome, store PostgreSQL data, or provide production identity and tenant isolation.
A signature proves exact-byte integrity and configured signer provenance. It does not prove the
observer is independent in deployment, that its input source was honest, that a model ran, that a
tool completed internally, or that a real-world effect occurred exactly once.

The strongest objection remains valid: a same-process observer that merely signs Agent-reported
events moves trust without creating independent facts. Durable outbox/inbox recovery, authoritative
state queries, signed acceptance evidence, per-scope trust, and OutcomeClosure are required before
making a production or real-effect claim.

The `src/`, Schema, test, and documentation changes do not refresh the historical tool-service
image, SBOM, or Trivy evidence. The current verifier has no `ordinary` mode: consistency mode
reports `HISTORICAL_CONSISTENT_STALE`, while release mode rejects the v1.1 snapshot as historically
ineligible. This slice does not manufacture replacement evidence.
