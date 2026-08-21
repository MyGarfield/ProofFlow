---
name: decision_audit
description: Perform a read-only structural audit of proposal support, conflicts, deterministic calculation, permissions, and trace completeness.
assign_when: Assign only to the ProofFlow Audit Agent (PF-A6) after proposals and a ConflictReport exist.
---

# Decision audit

Integration status: `REFERENCE_CORE_IMPLEMENTED / AGENTTEAMS_UNVERIFIED`.

Return exactly one verdict: `PASS`, `REVISE` or `BLOCK`, plus immutable object refs, findings, unsupported claims,
required actions, policy version and audit hash. Missing required trace, invalid hashes/references, permission
violations, incomplete conflict input or unresolved blocker conflicts forbid PASS.

Never modify audited objects, generate ApprovalRecord, approve your own result or treat chain-of-thought as
formal evidence.
