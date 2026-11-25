import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { formatUtcDateTime, formatUtcShort, normalizeTimestamp } from "./format.ts";

describe("timestamp parsing for PostgreSQL shapes", () => {
  it("normalizes a bare +HH offset and a space separator", () => {
    assert.equal(normalizeTimestamp("2026-01-01T12:00:00+00"), "2026-01-01T12:00:00+00:00");
    assert.equal(normalizeTimestamp("2026-01-01 12:00:00+00"), "2026-01-01T12:00:00+00:00");
    assert.equal(normalizeTimestamp("2026-01-01T12:00:00-05"), "2026-01-01T12:00:00-05:00");
    assert.equal(normalizeTimestamp("2026-01-01T12:00:00+00:00"), "2026-01-01T12:00:00+00:00");
    assert.equal(normalizeTimestamp("2026-01-01T12:00:00Z"), "2026-01-01T12:00:00Z");
    assert.equal(normalizeTimestamp("2026-01-01T12:00:00.5+00"), "2026-01-01T12:00:00.5+00:00");
    // Date-only values are not offsets.
    assert.equal(normalizeTimestamp("2026-01-01"), "2026-01-01");
    assert.notEqual(formatUtcDateTime("2026-01-01"), "—");
  });

  it("formats every shape PostgreSQL/PostgREST can return", () => {
    for (const value of [
      "2026-01-01T12:00:00+00",
      "2026-01-01 12:00:00+00",
      "2026-01-01T12:00:00+00:00",
      "2026-01-01T12:00:00.123456+00:00",
      "2026-01-01T21:00:00+09",
    ]) {
      assert.equal(formatUtcDateTime(value), "2026-01-01 12:00:00 UTC", value);
    }
    assert.equal(formatUtcShort("2026-01-01T12:00:00+00"), formatUtcShort("2026-01-01T12:00:00Z"));
  });

  it("still returns the fallback for garbage", () => {
    assert.equal(formatUtcDateTime("not a date"), "—");
    assert.equal(formatUtcDateTime(null), "—");
  });
});
