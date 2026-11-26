import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { classifyPatchFreshness, withPatchFreshness } from "./patch-freshness.ts";

const NOW = Date.parse("2026-12-30T00:00:00Z");
const daysAgo = (d: number) => new Date(NOW - d * 86_400_000).toISOString();

describe("classifyPatchFreshness", () => {
  it("is unknown when never reported or invalid", () => {
    assert.equal(classifyPatchFreshness(null, NOW).state, "unknown");
    assert.equal(classifyPatchFreshness(undefined, NOW).state, "unknown");
    assert.equal(classifyPatchFreshness("not-a-date", NOW).state, "unknown");
    // A report from the future (clock skew) must not look fresh.
    assert.equal(classifyPatchFreshness(daysAgo(-1), NOW).state, "unknown");
  });

  it("follows the 3-day and 7-day thresholds for daily automatic updates", () => {
    assert.deepEqual(classifyPatchFreshness(daysAgo(0), NOW), {
      state: "current",
      ageDays: 0,
      label: "Current (0 days)",
    });
    assert.equal(classifyPatchFreshness(daysAgo(3), NOW).state, "current");
    assert.equal(classifyPatchFreshness(daysAgo(3.5), NOW).state, "due");
    assert.equal(classifyPatchFreshness(daysAgo(7), NOW).state, "due");
    const overdue = classifyPatchFreshness(daysAgo(10), NOW);
    assert.equal(overdue.state, "overdue");
    assert.equal(overdue.label, "Overdue (10 days)");
  });

  it("attaches freshness to each sensor row", () => {
    const rows = withPatchFreshness(
      [
        { id: "a", last_patch_success_at: daysAgo(1) },
        { id: "b", last_patch_success_at: null },
      ],
      NOW,
    );
    assert.deepEqual(
      rows.map((r) => [r.id, r.freshness.state]),
      [
        ["a", "current"],
        ["b", "unknown"],
      ],
    );
  });
});
