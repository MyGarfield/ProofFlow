# ProofFlow Global Product Roadmap

Status date: 2026-08-28

This document defines targets and release gates. It does not claim that the
targets are already implemented.

## Strategic thesis

ProofFlow will not compete as another general-purpose Agent runtime. Runtime,
memory, sandboxing, human interruption, tracing, and evaluation are becoming
standard capabilities in major cloud and open-source platforms.

ProofFlow instead targets a cross-runtime governance plane for high-risk Agent
actions:

> An action must carry independently verifiable authorization before execution,
> and independently verifiable execution and outcome receipts after execution.
> Incomplete proof produces no usable result.

The first domain pack remains a public-synthetic labor-dispute workflow. It is
the first adversarial validation environment, not the boundary of the product.

## Current verified baseline

The current public baseline is a deterministic, public-synthetic reference
runtime. It verifies object contracts, a guarded state machine, artifact-bound
human approval, deterministic calculation, packaging, and tamper rejection.

It does not yet prove:

- running AgentTeams Workers or LLM inference;
- persistent or multi-instance state;
- production workload identity, tenant isolation, or authorization;
- exactly-once external effects or crash recovery;
- signed run receipts or independent observation of real effects;
- production legal accuracy, customer adoption, or a service-level objective.

Contest decks, ZIP builders, and submission evidence are historical delivery
assets. They are not product maturity metrics and must not drive Core design.

## Product primitives

### ActionCertificate

A versioned certificate binds:

- human principal and workload principal;
- delegation chain and tenant;
- Subject, Action, Resource, and authorization-relevant Context;
- input artifact digests and data classification;
- policy revision and policy decision;
- approval scope, expiry, revocation state, and separation-of-duty result;
- intended effect target and idempotency key.

### ExecutionReceipt

A receipt binds the actual runtime facts:

- runtime, Worker, model, tool, Skill, MCP/A2A protocol version;
- task, trace, span, parent/link, and attempt identifiers;
- input and output artifact digests;
- tool request/response and effect target without default prompt/body capture;
- idempotency, retry, timeout, resource, latency, and cost evidence;
- signer, trust root, and provenance envelope.

The executing Agent cannot establish trust by writing `observed=true`. A trusted
observer or independently checkable event source must support the receipt.

### OutcomeClosure

An independent verifier checks whether the approved real-world state change:

- occurred;
- occurred exactly once;
- matched the approved Subject, Action, Resource, and Context;
- remained within tenant and data boundaries;
- left no unresolved side effect.

Closed verdicts are `PASS`, `FAIL`, `UNKNOWN`, and `UNSAFE_SUCCESS`. Missing
evidence never becomes zero cost, zero latency, or a passing result.

## Standards anchors

Adapters are version-pinned and conformance-tested. A generic “supports MCP” or
“supports A2A” claim is insufficient.

- [MCP 2026-07-28](https://github.com/modelcontextprotocol/modelcontextprotocol/releases/tag/2026-07-28):
  request-scoped capabilities and trace context; ProofFlow business state must
  not depend on protocol sessions.
- [A2A v1.0.1](https://github.com/a2aproject/A2A/releases/tag/v1.0.1) and the
  [A2A TCK](https://github.com/a2aproject/a2a-tck): cross-runtime opaque Agent
  tasks, artifacts, visibility, and Agent Card verification.
- [AuthZEN 1.0](https://openid.net/specs/authorization-api-1_0.html): a portable
  Subject/Action/Resource/Context policy decision contract.
- [SPIFFE](https://spiffe.io/docs/latest/spiffe-about/spiffe-concepts/) and
  [OpenAI workload identity federation](https://developers.openai.com/api/docs/guides/workload-identity-federation):
  short-lived workload identity instead of shared static bearer credentials.
- [OpenTelemetry GenAI semantic conventions](https://github.com/open-telemetry/semantic-conventions/tree/main/docs/gen-ai):
  real OTLP traces, pinned to an exact development revision until stable.
- [W3C PROV](https://www.w3.org/TR/prov-dm/),
  [SLSA v1.2](https://slsa.dev/spec/v1.2/), and
  [Sigstore](https://docs.sigstore.dev/cosign/signing/overview/): provenance and
  release integrity. Signed provenance does not prove business truth.

Proof-carrying Agent actions already have public research precedents, including
[PCAA](https://arxiv.org/abs/2606.04104). ProofFlow must not claim conceptual
first invention. Its moat must come from executable standards mappings,
independent verification, multi-runtime conformance, and adversarial domain
benchmarks.

## North-star metrics

The primary metric is:

`verified_closed_high_risk_actions / attempted_high_risk_actions`

Mandatory guardrail metrics are:

- `unsafe_success_rate`;
- proof completeness;
- duplicate external-effect count;
- independent reproduction rate;
- unknown-result rate;
- p50/p95/p99 latency, total cost, and human-wait time.

Agent count, tool count, test count, and generated text quality are supporting
signals, not product success metrics.

## 0–30 days: independent single-runtime proof

Before any Worker or LLM launch, the exposed credential must be revoked and
replaced. Until the user explicitly confirms `已轮换`, the launch gate remains
closed.

Targets:

- define `ActionCertificate v0.1`, `ExecutionReceipt v0.1`, and a verifier that
  trusts configured roots rather than the producing Agent;
- add real OTLP workflow/Agent/tool/policy/approval spans pinned to an exact
  conventions revision;
- run the frozen deterministic, single-Agent, and six-Agent evaluation arms
  without presuming that more Agents win;
- sign release provenance and publish a reproducible verification command;
- merge only independently reviewed security, evaluation, Demo, and evidence
  work; keep competition-only packaging outside Core.

Acceptance targets:

- 100% of high-risk attempts carry S/A/R/C, policy digest, approval subject,
  execution receipt, and outcome receipt;
- trace completeness at least 99% across 100 public-synthetic runs;
- default telemetry captures zero prompt, output, or PII bodies;
- every scenario/arm cell has at least 18 valid paired runs out of 20 planned,
  otherwise the cell remains `UNKNOWN`;
- `UNSAFE_SUCCESS=0`; any occurrence blocks release and is published.

## 31–60 days: identity, policy, and durable recovery

Targets:

- PostgreSQL row-level tenant isolation, append-only event ledger, outbox/inbox,
  and durable idempotency;
- per-Worker short-lived workload identity with exact issuer and audience;
- a provider-neutral AuthZEN PEP/PDP adapter and fail-closed policy loading;
- approval revocation, separation of duty, conflict-of-interest checks, and
  current-policy re-evaluation;
- a native MCP 2026-07-28 adapter and conformance gate.

Acceptance targets:

- at least 1,000 injected crash-window runs with zero duplicate effects;
- at least 500 wrong-issuer/audience/tenant, expiry, revocation, and replay
  attacks with zero unauthorized acceptance;
- PDP timeout, unknown decision, and invalid policy signature always block;
- at least 200 approval swap, self-approval, stale-policy, expiry, and revocation
  attacks with `UNSAFE_SUCCESS=0`.

## 61–90 days: multi-runtime evidence ecosystem

Targets:

- adapters for AgentTeams, one durable workflow runtime, and one independent
  external Agent framework;
- A2A v1.0.1 HTTP+JSON support with signed Agent Card and tenant/task visibility;
- at least 100 frozen public-synthetic holdout scenarios across two high-risk
  domain packs;
- open verifier CLI, schemas, trust-root policy, attack fixtures, and anonymized
  traces;
- two independent teams reproducing the release from a clean environment.

Acceptance targets:

- 100% of claimed A2A TCK MUST requirements pass, with every skip disclosed;
- certificate field coverage of 100% and independent verification at least 99%
  across three runtimes;
- at least 1,000 cross-runtime adversarial runs with zero accepted tenant,
  approval, or duplicate-effect violations;
- two external source-to-verdict reproductions without private state or a warm
  developer cache.

## Kill criteria and strongest objections

- If ProofFlow becomes a generic memory/chat/tool-calling runtime, stop that
  work. Existing platforms have the distribution and resources to win it.
- If deterministic or single-Agent arms are not worse than six Agents on safety,
  quality, cost, and latency, remove the redundant roles.
- If a verifier relies on self-reported booleans rather than signed raw events
  or independently observed state, the claim remains unverified.
- If a checkpoint can replay a real effect, the workflow is not durable enough;
  test the effect-after-write/receipt-before-write crash window explicitly.
- If signing is presented as proof that evidence or a legal conclusion is true,
  narrow the claim. Signing proves integrity and provenance, not domain truth.
- If fewer than two independent users can reproduce the release, developer
  experience and evidence portability remain P0, regardless of internal tests.
