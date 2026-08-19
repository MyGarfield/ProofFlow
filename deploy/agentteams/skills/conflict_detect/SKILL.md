---
name: conflict_detect
description: Detect structural conflicts across evidence, rules, and calculations without resolving truth or mutating source artifacts.
assign_when: Assign only to the ProofFlow Audit Agent (PF-A6) before decision audit and whenever a governed artifact changes.
---

# Conflict detect

Integration status: `REFERENCE_CORE_IMPLEMENTED / AGENTTEAMS_UNVERIFIED`.

Inputs must reference the complete current evidence, rules, calculation and conflict-policy version. Output a
sealed ConflictReport with object references, severity, blocker IDs, required actions, coverage and trace.

Do not choose a winning fact or modify upstream objects. Incomplete input returns `INCOMPLETE_INPUT`; absence
of a detected conflict must never be represented as proof that no conflict exists.
