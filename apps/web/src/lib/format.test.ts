import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  formatEvidenceBasis,
  formatMatchStrength,
  formatUtcDateTime,
  formatUtcShort,
  matchStrengthRank,
  normalizeTimestamp,
  parseCveId,
  UNCOMMON_PATH_LABEL,
  displayEventHttpPath,
} from "./format.ts";

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

describe("match strength and CVE ids (#84)", () => {
  it("shows a graded label, never a percentage", () => {
    assert.equal(formatMatchStrength("high"), "High");
    assert.equal(formatMatchStrength("medium"), "Medium");
    assert.equal(formatMatchStrength("low"), "Low");
    for (const v of [null, undefined, "", "0.7", "HIGH", "70%"]) {
      assert.equal(formatMatchStrength(v), "Ungraded");
    }
    assert.ok(matchStrengthRank("high") > matchStrengthRank("medium"));
    assert.ok(matchStrengthRank("low") > matchStrengthRank(null));
  });

  it("formats the evidence basis", () => {
    assert.equal(formatEvidenceBasis("sap_path", "url"), "sap_path in url");
    assert.equal(formatEvidenceBasis(null, "url"), "in url");
    assert.equal(formatEvidenceBasis(null, null), null);
  });

  it("accepts only well-formed CVE ids", () => {
    assert.equal(parseCveId("CVE-2025-31324"), "CVE-2025-31324");
    assert.equal(parseCveId(" cve-2021-44228 "), "CVE-2021-44228");
    assert.equal(parseCveId("CVE-2021-1234567"), "CVE-2021-1234567");
    assert.equal(parseCveId("CVE-2026-12345678"), "CVE-2026-12345678");
    for (const bad of ["CVE-21-1234", "CVE-2021-123", `CVE-2021-${"9".repeat(40)}`, "CVE-2021-1234;drop", null, undefined]) {
      assert.equal(parseCveId(bad), null, String(bad));
    }
  });
});

describe("displayEventHttpPath (#88)", () => {
  it("labels a withheld path as uncommon instead of showing '/'", () => {
    assert.equal(displayEventHttpPath(null), UNCOMMON_PATH_LABEL);
    assert.equal(displayEventHttpPath(""), UNCOMMON_PATH_LABEL);
    assert.equal(displayEventHttpPath("/wp-login.php"), "/wp-login.php");
  });
});
