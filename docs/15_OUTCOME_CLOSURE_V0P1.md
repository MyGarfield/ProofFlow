# OutcomeClosure v0.1

Status: observer-signed, public-synthetic reference slice. It is not a production
business-outcome attestation.

OutcomeClosure is the final verifier-derived verdict over one exact ActionCertificate,
one exact ExecutionReceipt, and a separate outcome-observer reconciliation. It does
not execute an effect, query a provider, or turn a producer's `claimed_outcome` into
truth. Its wire profile is strict DSSE 1.0.2, in-toto Statement v1, and Ed25519 over
the exact payload bytes.

The outcome observer must use a configured `OUTCOME_OBSERVER` trust root with all four
v0.1 scopes: authorization binding, execution-receipt binding, effect reconciliation,
and business-state evidence. The verifier requires distinct observer principals and
keys, tenant/audience/predicate matches, current roots, and independence from the
ActionCertificate authorities, workload, human, and ExecutionReceipt observer.

The operator supplies the exact ActionCertificate and ExecutionReceipt envelopes,
their already accepted verification results, and an independently prepared expected
binding as read-only **operator handoff inputs**. These inputs are not produced by
the Outcome observer or closure producer. If a caller lets the producer rewrite them,
the verdict is outside this verifier's safety claim and must not be presented as a
governed PASS/FAIL. The verifier requires
a complete trust policy containing the corresponding ActionCertificate issuer,
approval, and ExecutionReceipt observer roots. It checks their exact envelope
SHA-256, payload SHA-256, object identity, canonical verification-result SHA-256,
root purpose/tenant/audience/predicate/allowlist/threshold/current status, signature
coverage, and the expected binding. A closure cannot self-authorize by embedding
`ACCEPT` or `recorded=true`. The accepted result's reservation authenticity remains
an operator-trusted local assumption; this slice does not independently prove durable
reservation or a signed verifier attestation.

The signed reconciliation binds every effect attempt to the approved type, target,
intent digest, and idempotency key, with unique effect, attempt, and provider
operation identities. It records explicit terminal succeeded/failed attempts and
explicit unresolved effects. `PASS` requires exact terminal coverage and exactly the
expected number of committed effects. `FAIL` requires complete authoritative terminal
rejection/no-effect coverage. A gap such as expected count 2 with one failure is not
`FAIL`; it remains `UNKNOWN`. Missing/unavailable reconciliation is `UNKNOWN`, while
success-like output without accepted authorization, accepted execution, complete
binding, or an unresolved/duplicate effect is `UNSAFE_SUCCESS`. Missing evidence is
never converted to zero or success.

The in-memory index is bounded, process-local, append-only, and keyed by tenant plus
closure ID, execution ID, attempt ID, closure sequence, previous payload digest, and
idempotency intent. An exact payload replay is `ALREADY_PRESENT`; changed bytes,
sequence gaps, previous-digest changes, or another closure for the same execution,
attempt, and sequence are conflicts; closure IDs remain tenant-global. Capacity
failure is `UNKNOWN`. This index is not durable, crash-safe,
cross-process, or proof of exactly-once delivery.
An `UNKNOWN` closure is not appended in v0.1, so a later sequence cannot use an
untrusted unknown as its predecessor; operators must retry with a new exact evidence
set or leave the sequence open.

The CLI is local-file only:

```bash
uv run proofflow outcome verify \
  --envelope outcome-closure.dsse.json \
  --trust-policy operator-trust.json \
  --expected-binding expected-outcome.json \
  --action-certificate-envelope action-certificate.dsse.json \
  --action-certificate-verification action-certificate-result.json \
  --execution-receipt-envelope execution-receipt.dsse.json \
  --execution-receipt-verification execution-receipt-result.json \
  --evidence outcome-evidence.json \
  --at 2026-08-30T04:00:00Z
```

Exit codes are `0=PASS`, `1=FAIL`, `2=input/configuration error`, `3=UNKNOWN`, and
`4=UNSAFE_SUCCESS`.

`outcome-evidence.json` is a bounded local JSON map from each `sha256:` digest to
canonical base64 bytes. The resolver validates the source event, every before/after
state, provider event, and observer evidence digest, as well as the source validity
window. Missing, substituted, or mismatched bytes remain `UNKNOWN`.
The evidence source kind, version, and principal are operator-bound in both the
expected binding and the trust root; v0.1's reference source is only
`LOCAL_BYTES` in memory.

## Explicit non-claims

This slice uses only public-synthetic values. It does not run a Worker or LLM, connect
to a runtime/provider/MCP/A2A/OTLP service, query authoritative business state, or
provide production tenant isolation. A same-process observer is not an independent
physical source of truth; a signature proves exact bytes and configured signer
provenance, not that the observer's source was honest. Provider acknowledgements,
operation IDs, and local state digests are not a production outcome proof. No schema
or code change refreshes the historical tool-service image, SBOM, Trivy scan, or
release evidence; supply-chain state remains
`HISTORICAL_CONSISTENT_STALE` with `release_eligible=false`.
