---
name: document_package
description: Render a controlled local draft and hash-verifiable PackageManifest only after a current PASS audit and matching human approval.
assign_when: Assign only to the ProofFlow Case Manager (PF-A1) after Human Gate success for the unchanged approval subject.
---

# Document package

Integration status: `REFERENCE_CORE_IMPLEMENTED / AGENTTEAMS_UNVERIFIED`.

Inputs: sealed proposal, calculation, PASS audit, APPROVE record, current subject hash, template ID/version and
controlled-draft destination policy. Recompute all hashes before rendering. Output local Markdown/JSON files,
their byte hashes, included artifact refs and a sealed PackageManifest.

No approval, expired approval, stale subject, failed audit, invalid calculation or render error must leave a
package that can be mistaken for valid. Never send, sign, submit, terminate employment, make payment or write to
an external system. The current implementation generates local controlled drafts only.
