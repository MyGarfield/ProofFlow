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
  assert.equal(EXPECTED_SOURCE_COMMIT, "610f5d87006567055c658ca8adb66b61284f7603");
  assert.equal(hasExactStaticBoundary(snapshot), true);
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
  ];

  for (const attack of attacks) {
    assert.equal(hasExactStaticBoundary(attack), false);
  }
});

test("horizontal overflow check exposes the exact browser geometry predicate", () => {
  assert.equal(hasHorizontalOverflow({ clientWidth: 375, scrollWidth: 375 }), false);
  assert.equal(hasHorizontalOverflow({ clientWidth: 375, scrollWidth: 376 }), true);
});
