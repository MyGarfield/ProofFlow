# Contributing

ProofFlow accepts focused contributions that preserve evidence boundaries and do not overstate validation.

## Setup

```bash
uv sync --dev
uv run ruff format --check .
uv run ruff check .
uv run mypy
uv run pytest
```

## Requirements

- Use a focused feature branch and explain the behavior/evidence contract being changed.
- Add tests for success, failure, authorization and tamper/replay behavior where applicable.
- Keep amounts as `Decimal`; floats are forbidden in canonical business payloads.
- Preserve tenant/case, source refs, schema version, producer identity, trace ID and hashes.
- Do not add a default approval path or allow an Agent to act as Human.
- Do not add external side effects without a separate threat model, authorization, idempotency, reconciliation,
  approval and rollback/stop design.
- Mark mocks, synthetic data, plans and unverified integrations explicitly.
- Never commit secrets, personal information, customer materials, real cases or restricted rule content.

Changes to Identity/Skill behavior must update the Python contract, `specs/`, AgentTeams `SKILL.md`, tests and
documentation together.
