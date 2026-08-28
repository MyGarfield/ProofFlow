# ActionCertificate v0.1

Status: first independently verifiable pre-execution slice. It is not a production release gate.

## What this slice proves

ActionCertificate v0.1 is a signed authorization object for one intended high-risk action. The
wire format is fixed to:

- DSSE 1.0.2 envelope and PAE;
- `payloadType = application/vnd.in-toto+json`;
- in-toto Statement v1;
- `predicateType = https://proofflow.dev/attestations/action-certificate/v0.1`;
- Ed25519 signatures supplied by `cryptography`, never handwritten cryptography;
- strict Pydantic contracts whose object schemas use `additionalProperties: false`.

The PAE and `keyid` behavior follow the official
[DSSE 1.0.2 protocol](https://github.com/secure-systems-lab/dsse/blob/master/protocol.md); the
Statement fields follow the official
[in-toto v1 Statement specification](https://github.com/in-toto/attestation/blob/main/spec/v1/statement.md).
The verifier accepts DSSE standard and URL-safe padded Base64 and treats an absent `keyid` as the
same empty hint. For this security-focused v0.1 profile, unknown envelope fields are rejected rather
than ignored. That intentional fail-closed restriction is stricter and less forward-compatible than
the base DSSE envelope parsing rule; a future extensible profile requires a separate versioned
contract and attack review.

The predicate binds the human and workload principals, delegation chain, tenant, audience,
Subject/Action/Resource/Context, input artifact SHA-256 digests, classification, policy revision
and decision, approval scope, intended effect, idempotency key, nonce, and validity window.

## Verification order

The reference verifier is deliberately fail-closed:

1. Bound the envelope, payload, signature, root, and revocation-snapshot sizes.
2. Parse only the outer DSSE envelope with duplicate-key and non-finite-number rejection.
3. Decode the payload, construct DSSE PAE, and verify the signature over the **exact payload
   bytes** against inline operator-configured roots.
4. Only after at least one configured root verifies those bytes, parse the strict in-toto payload.
5. Match every execution-owned field against `ExpectedBinding` and every identity/audience/
   predicate/purpose field against `TrustPolicy`.
6. Require a distinct-authority and distinct-key `ACTION_ISSUER` threshold. Repeated signatures,
   duplicated root records for one public key, or multiple keys assigned to one principal count
   once.
7. When approval is required, require the configured `HUMAN_APPROVAL` threshold over the same
   payload, recompute the approval subject, reject self approval, and query the operator-controlled
   `ApprovalRevocationResolver` at verification time. Its snapshot carries mandatory UTC `as_of`
   and `valid_until` values. It is current only for
   `as_of <= verification_time <= valid_until`; both boundaries are inclusive.
8. Only a fully verified candidate reaches `reserve_once`. The reference ledger atomically checks
   tenant+nonce and tenant+idempotency key under one process lock.

`keyid` is only a local lookup-order hint. It neither supplies nor upgrades trust. The policy has no
URL, JWK-set, certificate-chain, plugin, or remote-reference field, and the verifier performs no
network access.

## Closed outcomes

- `ACCEPT`: all checks passed and the process-local ledger atomically reserved the intent.
- `REJECT`: malformed/untrusted input, binding or policy mismatch, invalid time, revoked approval,
  self approval, replay, or idempotency conflict.
- `UNKNOWN`: current approval revocation state or replay-ledger availability could not be
  established. A not-yet-current or expired revocation snapshot is `UNKNOWN`. `UNKNOWN` never
  reserves and never becomes an approval boolean.

Only `ACCEPT` reports `reserved=true`. The result contains closed reason codes, verified root IDs,
and the exact signed-payload SHA-256; it does not contain `approved=true` or `observed=true`.

## CLI

All inputs are local regular JSON files. The verification time is explicit so the result is
reproducible and does not silently depend on wall-clock time. `--at` accepts only the v0.1 UTC
profile `YYYY-MM-DDTHH:MM:SS[.fraction]Z`, with one to six fractional digits when present. A space
separator, missing timezone, lowercase `z`, or numeric offset such as `+00:00` is rejected as a
configuration error.

```bash
uv run proofflow certificate verify \
  --envelope action.dsse.json \
  --trust-policy operator-trust.json \
  --expected-binding expected-action.json \
  --approval-revocations approval-revocations.json \
  --at 2026-08-29T04:00:00Z
```

Exit codes are `0=ACCEPT`, `1=REJECT`, `3=UNKNOWN`, and `2=input/configuration error`. A new CLI
process creates a new reference ledger, so cross-process replay resistance is intentionally out of
scope.

Exported schemas live under `schemas/action-certificate-*.schema.json` and are regenerated with:

```bash
uv run python scripts/export_schemas.py
uv run python scripts/export_schemas.py --check
```

The exporter adds Draft 2020-12 constraints that Pydantic cannot infer from Python validators:

- `ApprovalBinding.required` conditionally requires complete non-null approval fields, or requires
  their null/empty forms when approval is not required;
- verification `status`, `reason_codes`, and `reserved` form three closed branches; `ACCEPTED` is
  exclusive to `ACCEPT`, rejection and unavailable reasons are disjoint, and only `ACCEPT` reserves;
- canonical padded DSSE Base64 shapes, conditional trust-policy approval authorities, and exact
  array uniqueness are machine-enforced;
- revocation snapshot timestamps are required and use the same UTC trailing-`Z` wire profile.

Some runtime invariants cannot be represented by portable Draft 2020-12 JSON Schema: ordering two
arbitrary timestamps (including `as_of <= valid_until`), comparing delegation fields across adjacent
array elements, and uniqueness by one subfield while other subfields differ. Each affected schema
publishes these limitations in
`x-proofflow-runtime-invariants`. A generic Schema validator checks the representable wire contract;
security decisions must still use the strict model and `verify_action_certificate`, which enforce
the listed runtime invariants. The extension is disclosure, not a claim that generic validators
execute custom semantics.

## Explicit non-claims and next gate

This slice does not integrate Worker, LLM, MCP, A2A, OTLP, PostgreSQL, a policy engine, a workload
identity provider, or any real external effect. The in-memory ledger is not durable and cannot
provide multi-process or crash-safe exactly-once semantics. A DSSE signature proves integrity and
configured signer provenance; it does not prove that the action, evidence, or business conclusion
is true.

The dependency and `src/` changes make the existing tool-image SBOM/Trivy/build-input evidence
stale. See [`deploy/tool-service/SUPPLY_CHAIN_EVIDENCE.md`](../deploy/tool-service/SUPPLY_CHAIN_EVIDENCE.md).
A releasable image requires a fresh locked build, SBOMs, vulnerability scan, image digest, runtime
regression, and independent evidence binding; this slice does not manufacture or refresh them.
