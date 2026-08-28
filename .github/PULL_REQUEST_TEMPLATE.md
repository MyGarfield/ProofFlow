## Purpose

Describe the user or security outcome and why this belongs in ProofFlow Core.

## Evidence boundary

- What is verified?
- What remains synthetic, planned, unknown or not executed?
- Does this change authorization, approval, tenant, replay, receipt or external-effect behavior?

## Verification

List exact commands, test counts and any independent review. Include negative and tamper/replay tests when the
change affects a high-risk boundary.

## Safety checklist

- [ ] No secret, personal information, real case, customer material or workstation path is committed.
- [ ] Missing evidence fails closed and remains `UNKNOWN` where appropriate.
- [ ] No Agent is treated as a Human approver.
- [ ] External effects have authorization, idempotency, reconciliation and rollback/stop analysis.
- [ ] Public claims match the exact commit and machine evidence.
- [ ] Documentation, schemas, fixtures and compatibility notes are updated.
