---
name: timeline_build
description: Build source-linked timeline events while preserving ambiguous dates and unresolved facts.
assign_when: Assign only to the ProofFlow Evidence Agent (PF-A2) after EvidenceObject artifacts have passed integrity checks.
---

# Timeline build

Integration status: `REFERENCE_CORE_IMPLEMENTED / AGENTTEAMS_UNVERIFIED`.

Inputs must belong to the active tenant/case and contain immutable EvidenceObject references. Each emitted
TimelineEvent must have source references or an explicit `UNRESOLVED` status and reason. Preserve date ranges;
do not turn ambiguous dates into exact timestamps.

Return events, unresolved items, temporal conflicts, input/output hashes and trace reference. Fail closed on
missing/cross-tenant source references. Never mutate upstream evidence or choose which conflicting fact is true.
