# Security policy

## Current support boundary

ProofFlow is an alpha, synthetic-data-only reference implementation. It is not approved for real cases,
personal information, employment decisions, payments, signatures, submissions or production systems.

Only the latest `main` and the most recent tagged alpha release, when one exists, receive security fixes.

## Reporting

GitHub private vulnerability reporting is enabled. Submit a confidential report through
[New repository security advisory](https://github.com/MyGarfield/ProofFlow/security/advisories/new).
Do not open a public issue containing an exploit, secret, personal information, customer material or a real
case. If GitHub reports that the private form is unavailable, do not publish the details; open a content-free
`Security channel unavailable` issue asking the maintainer to restore the private channel.

Include the affected Git SHA, environment, minimal synthetic reproduction, expected/actual control, and whether
any external side effect occurred. Never attach production credentials or restricted data.

The maintainer targets an initial acknowledgement within 5 business days and a status update within 10
business days. These are alpha-project response targets, not an SLA. Please allow coordinated remediation
before public disclosure. Reports that involve active credential exposure, cross-tenant access, approval
bypass or an unexpected external side effect should be marked urgent.

## In scope

- authorization, tenant or approval bypass;
- unsafe success, replay or duplicate external-effect behavior;
- certificate, receipt, provenance or evidence-verifier forgery;
- secret, personal-data or cross-tenant disclosure;
- build, release, dependency or artifact-integrity compromise;
- denial of service that defeats a documented resource bound.

General feature requests, unsupported production deployments and legal/domain correctness questions belong
in public issues without sensitive material.

## Secrets and data

Do not commit API keys, tokens, cookies, passwords, private keys, connection strings, internal endpoints, real
personal information, customer documents or unlicensed rule corpora. Local registration/contact data belongs in
the ignored `submission/private/` directory.

## Known non-production gaps

- AgentTeams, MCP authorization and production Human identity are not verified.
- Local files are not a WORM store or signed transparency log.
- There is no database RLS, production RBAC, MFA, secret manager, sandbox or egress policy.
- The pinned Alibaba Cloud Skill preflight is an offline source/static-contract check. Its upstream executable
  target set is empty for Markdown-only ProofFlow Skills (`OFFICIAL_TARGET_POLICY_EXCLUDES_SKILL_MD_ONLY_INPUTS`),
  so it is inconclusive and not a safety certification.
- Its one-off macOS Seatbelt collector denies network for that local invocation only. It has no filesystem-read
  allowlist and is not evidence of a production sandbox, deployment egress policy or verified credential/config
  non-access.
- JSON/TXT ingestion is a bounded fixture path, not a hardened document pipeline.
- The rules/formula set is incomplete and not expert-certified.
- The application performs no external side effects by design.

See [security and Human Gate design](docs/02_SECURITY_AND_HUMAN_GATE.md) for the control matrix.
