# Governance

ProofFlow currently uses a maintainer-led alpha governance model.

## Roles

- Maintainer: owns release decisions, trust roots, security response, roadmap scope and repository settings.
- Contributor: proposes focused changes with tests, evidence boundaries and reproducible review steps.
- Reviewer: verifies the change independently and records unresolved risk or claim limitations.

The current repository maintainer is `@MyGarfield`. This is a project role, not a claim of independent audit.

## Decision rules

- Public code and documentation changes use pull requests and exact-head CI.
- Security-sensitive changes require an explicit threat model and an independent review before merge.
- A green test or signature does not override contradictory runtime or external-state evidence.
- Missing evidence remains `UNKNOWN`; an unsafe result cannot be washed out by a later retry.
- Core scope is cross-runtime proof governance. Generic runtime, chat, memory and tool-calling features require a
  written reason they strengthen authorization, receipts or outcome closure.

## Bootstrap exception

The repository currently has one maintainer. Until a second trusted human reviewer is appointed, a
security-sensitive bootstrap change may merge only when its pull request records exact-head CI, a separate
read-only review with no unresolved P0/P1 finding, and the absence of sensitive data. This is a temporary
single-maintainer exception, not an independent human audit. Issue #16 tracks adding a second maintainer and
branch-protection review policy; the exception ends when that policy is active.

## Releases

A release requires a clean, reviewed commit; current tests; fresh supply-chain evidence; reproducible assets;
checksums and provenance; and an honest limitations section. The maintainer must not publish a production,
signed or conformance claim while its corresponding gate is open.

Governance changes use the same pull-request process and should include a transition plan when maintainership or
release trust roots change.
