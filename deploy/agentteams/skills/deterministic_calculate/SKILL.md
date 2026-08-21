---
name: deterministic_calculate
description: Produce a versioned Decimal-only CalculationSheet from verified facts and rule references.
assign_when: Assign only to the ProofFlow Calculation Agent (PF-A4) after required facts and calculation rules are available without blocker conflicts.
---

# Deterministic calculate

Integration status: `REFERENCE_CORE_IMPLEMENTED / MCP_AND_AGENTTEAMS_UNVERIFIED`.

Inputs: immutable verified fact refs, rule refs, explicit parameters, formula version, `trace_id` and idempotency
key. Output line items, formula ID/version, parameters, intermediate values, amount, missing parameters and a
reproducibility hash.

Use `Decimal`; floats, dynamic `eval`, LLM arithmetic and guessed parameters are forbidden. Missing/invalid
parameters, unknown formulas, conflicting facts or missing rules must block without a total. A calculation is a
reference amount and never proves legal eligibility or a final decision.
