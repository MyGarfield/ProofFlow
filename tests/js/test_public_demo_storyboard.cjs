"use strict";

const assert = require("node:assert/strict");
const test = require("node:test");

const snapshot = require("../../public-demo/evidence-snapshot.json");
const {
  EXPECTED_SOURCE_COMMIT,
  hasExactStaticBoundary,
  hasHorizontalOverflow,
} = require("../../public-demo/app.js");

test("static snapshot is pinned to the reviewed product source", () => {
  assert.equal(EXPECTED_SOURCE_COMMIT, "2edfe55d88abac3cc4d56dc74375b698dce7a476");
  assert.equal(hasExactStaticBoundary(snapshot), true);
  assert.equal(snapshot.non_claims.execution_receipt_implemented, true);
  assert.equal(snapshot.non_claims.outcome_closure_implemented, true);
});

test("static boundary rejects runtime, evaluation, and supply escalation", () => {
  const attacks = [
    { ...snapshot, source: { ...snapshot.source, commit: "0".repeat(40) } },
    {
      ...snapshot,
      runtime_boundary: { ...snapshot.runtime_boundary, readyWorkers: 6 },
    },
    {
      ...snapshot,
      runtime_boundary: { ...snapshot.runtime_boundary, llm_enabled: true },
    },
    {
      ...snapshot,
      evaluation_boundary: { ...snapshot.evaluation_boundary, status: "EXECUTED" },
    },
    {
      ...snapshot,
      supply_chain_boundary: {
        ...snapshot.supply_chain_boundary,
        release_eligible: true,
      },
    },
    {
      ...snapshot,
      non_claims: { ...snapshot.non_claims, operator_handoff_signed: true },
    },
    {
      ...snapshot,
      non_claims: {
        ...snapshot.non_claims,
        same_process_observer_is_independent_truth: true,
      },
    },
    {
      ...snapshot,
      non_claims: { ...snapshot.non_claims, indexes_process_local_only: false },
    },
  ];

  for (const attack of attacks) {
    assert.equal(hasExactStaticBoundary(attack), false);
  }
});

test("horizontal overflow check exposes the exact browser geometry predicate", () => {
  assert.equal(hasHorizontalOverflow({ clientWidth: 375, scrollWidth: 375 }), false);
  assert.equal(hasHorizontalOverflow({ clientWidth: 375, scrollWidth: 376 }), true);
});
