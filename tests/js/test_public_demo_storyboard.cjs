"use strict";

const assert = require("node:assert/strict");
const test = require("node:test");

const {
  formatClock,
  hasHorizontalOverflow,
  selectSegment,
} = require("../../public-demo/app.js");

const segments = [
  { end: 12, heading: "boundary", start: 0 },
  { end: 28, heading: "prepare", start: 12 },
  { end: 40, heading: "block", start: 28 },
  { end: 58, heading: "approve", start: 40 },
  { end: 75, heading: "verify", start: 58 },
  { end: 91, heading: "contracts", start: 75 },
];

test("clock formatting clamps the storyboard to its 90 second contract", () => {
  assert.equal(formatClock(-5), "00:00");
  assert.equal(formatClock(0), "00:00");
  assert.equal(formatClock(59), "00:59");
  assert.equal(formatClock(75), "01:15");
  assert.equal(formatClock(999), "01:30");
});

test("segment selection changes exactly at each subtitle boundary", () => {
  assert.equal(selectSegment(segments, 0).heading, "boundary");
  assert.equal(selectSegment(segments, 11.999).heading, "boundary");
  assert.equal(selectSegment(segments, 12).heading, "prepare");
  assert.equal(selectSegment(segments, 28).heading, "block");
  assert.equal(selectSegment(segments, 40).heading, "approve");
  assert.equal(selectSegment(segments, 58).heading, "verify");
  assert.equal(selectSegment(segments, 75).heading, "contracts");
  assert.equal(selectSegment(segments, 90).heading, "contracts");
  assert.equal(selectSegment([], 0), null);
});

test("horizontal overflow check exposes the exact browser geometry predicate", () => {
  assert.equal(hasHorizontalOverflow({ clientWidth: 375, scrollWidth: 375 }), false);
  assert.equal(hasHorizontalOverflow({ clientWidth: 375, scrollWidth: 376 }), true);
});
