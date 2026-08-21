"use strict";

const assert = require("node:assert/strict");
const test = require("node:test");

const {
  applyStepPresentation,
  gatePresentation,
  verificationPresentation,
} = require("../../demo/app.js");

function createStep() {
  const classes = new Set(["chain-step", "gate-step"]);
  return {
    item: {
      classList: {
        add: (...names) => names.forEach((name) => classes.add(name)),
        contains: (name) => classes.has(name),
        remove: (...names) => names.forEach((name) => classes.delete(name)),
      },
    },
    output: { textContent: "" },
  };
}

function render(step, presentation) {
  applyStepPresentation(step.item, step.output, presentation);
  return {
    active: step.item.classList.contains("is-active"),
    blocked: step.item.classList.contains("is-blocked"),
    complete: step.item.classList.contains("is-complete"),
    label: step.output.textContent,
    verified: step.item.classList.contains("is-verified"),
  };
}

test("gate renders a historical block separately from current satisfaction", () => {
  const step = createStep();

  assert.deepEqual(render(step, gatePresentation("NOT_PREPARED", false)), {
    active: false,
    blocked: false,
    complete: false,
    label: "LOCKED",
    verified: false,
  });
  assert.deepEqual(render(step, gatePresentation("AWAITING_APPROVAL", false)), {
    active: true,
    blocked: false,
    complete: false,
    label: "WAITING",
    verified: false,
  });
  assert.deepEqual(render(step, gatePresentation("AWAITING_APPROVAL", true)), {
    active: false,
    blocked: true,
    complete: false,
    label: "409 BLOCKED",
    verified: false,
  });
  assert.deepEqual(render(step, gatePresentation("APPROVED", true)), {
    active: false,
    blocked: false,
    complete: true,
    label: "SATISFIED / BLOCK PASS",
    verified: false,
  });
  assert.deepEqual(render(step, gatePresentation("PACKAGED", true)), {
    active: false,
    blocked: false,
    complete: true,
    label: "SATISFIED / BLOCK PASS",
    verified: false,
  });
  assert.deepEqual(render(step, gatePresentation("APPROVED", false)), {
    active: false,
    blocked: false,
    complete: true,
    label: "SATISFIED",
    verified: false,
  });
});

test("verification renders ready, valid, and failed states without stale classes", () => {
  const step = createStep();

  assert.deepEqual(render(step, verificationPresentation("PACKAGED", null)), {
    active: true,
    blocked: false,
    complete: false,
    label: "READY",
    verified: false,
  });
  assert.deepEqual(render(step, verificationPresentation("PACKAGED", { valid: true })), {
    active: false,
    blocked: false,
    complete: false,
    label: "VALID",
    verified: true,
  });
  assert.deepEqual(
    render(step, verificationPresentation("PACKAGED", { valid: false, errors: ["a", "b"] })),
    {
      active: false,
      blocked: true,
      complete: false,
      label: "FAILED / 2",
      verified: false,
    },
  );
});
