# Security policy

## Current support boundary

ProofFlow is an alpha, synthetic-data-only reference implementation. It is not approved for real cases,
personal information, employment decisions, payments, signatures, submissions or production systems.

Only the latest `main` and the most recent tagged alpha release, when one exists, receive security fixes.

## Reporting

Use GitHub's private vulnerability reporting/security advisory feature for the repository when available. Do
not open a public issue containing an exploit, secret, personal information, customer material or a real case.

Include the affected Git SHA, environment, minimal synthetic reproduction, expected/actual control, and whether
any external side effect occurred. Never attach production credentials or restricted data.

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
- JSON/TXT ingestion is a bounded fixture path, not a hardened document pipeline.
- The rules/formula set is incomplete and not expert-certified.
- The application performs no external side effects by design.

See [security and Human Gate design](docs/02_SECURITY_AND_HUMAN_GATE.md) for the control matrix.
