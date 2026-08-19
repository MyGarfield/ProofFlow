---
name: human_approval
description: Request and record an explicit human decision bound to one immutable approval-subject hash and role.
assign_when: Assign only to the ProofFlow Case Manager (PF-A1) after a sealed PASS audit; execution requires a real Human actor.
---

# Human approval

Integration status: `LOCAL_DEMO_IMPLEMENTED / PRODUCTION_IDENTITY_AND_AGENTTEAMS_UNVERIFIED`.

The Agent may create an ApprovalRequest but must never create or simulate the HumanDecision. Validate tenant,
case, required role, expiry, exact artifact hash and current audit. Record APPROVE, REJECT or REVISE with actor,
role, reason, time, scope and approval method.

Any governed artifact change invalidates the old approval. Default approval, self-approval, expired approval,
wrong role and an Agent acting as Human must fail closed. Current `LOCAL_DEMO` approval is not a digital signature,
MFA or production identity proof.
