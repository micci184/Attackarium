import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { evaluatePatchFreshness, fetchSensorPatchRows } from "./core.ts";

const NOW = Date.parse("2026-12-10T00:00:00Z");
const daysAgo = (d: number) => new Date(NOW - d * 86_400_000).toISOString();

describe("evaluatePatchFreshness", () => {
  it("passes when every active sensor is current", () => {
    const report = evaluatePatchFreshness(
      [
        { id: "a", is_active: true, last_patch_success_at: daysAgo(1) },
        { id: "old-inactive", is_active: false, last_patch_success_at: null },
      ],
      NOW,
    );
    assert.equal(report.ok, true);
    assert.equal(report.activeSensors, 1);
  });

  it("fails for stale, never-reported, or no active sensors", () => {
    assert.equal(
      evaluatePatchFreshness([{ id: "a", is_active: true, last_patch_success_at: daysAgo(5) }], NOW).ok,
      false,
    );
    assert.equal(
      evaluatePatchFreshness([{ id: "a", is_active: true, last_patch_success_at: null }], NOW).ok,
      false,
    );
    assert.equal(evaluatePatchFreshness([], NOW).ok, false);
  });

  it("never puts identifiers or timestamps in the message (public logs)", () => {
    const report = evaluatePatchFreshness(
      [{ id: "sensor-secret-name", is_active: true, last_patch_success_at: daysAgo(40) }],
      NOW,
    );
    assert.equal(report.ok, false);
    assert.doesNotMatch(report.message, /sensor-secret-name/);
    assert.doesNotMatch(report.message, /\d{4}-\d{2}-\d{2}/);
    assert.doesNotMatch(report.message, /40/);
  });
});

describe("fetchSensorPatchRows", () => {
  it("queries only the needed columns with service-role headers", async () => {
    let seen: { url: string; headers: Headers } | null = null;
    const fakeFetch = (async (input: URL | RequestInfo, init?: RequestInit) => {
      seen = { url: String(input), headers: new Headers(init?.headers) };
      return new Response(JSON.stringify([{ id: "a", is_active: true, last_patch_success_at: null }]), {
        status: 200,
        headers: { "content-range": "0-0/1" },
      });
    }) as typeof fetch;
    const rows = await fetchSensorPatchRows("https://example.supabase.co", "svc-key", fakeFetch);
    assert.deepEqual(rows, [{ id: "a", is_active: true, last_patch_success_at: null }]);
    assert.ok(seen);
    assert.match(seen!.url, /\/rest\/v1\/sensors\?select=id%2Cis_active%2Clast_patch_success_at&is_active=eq.true$/);
    assert.equal(seen!.headers.get("apikey"), "svc-key");
    assert.equal(seen!.headers.get("prefer"), "count=exact");
  });

  it("throws when the response may be truncated or the count is missing", async () => {
    const rows = JSON.stringify([{ id: "a", is_active: true, last_patch_success_at: null }]);
    for (const range of ["0-0/2", "0-0/*", ""]) {
      const fakeFetch = (async () =>
        new Response(rows, { status: 200, headers: range ? { "content-range": range } : {} })) as typeof fetch;
      await assert.rejects(
        fetchSensorPatchRows("https://example.supabase.co", "k", fakeFetch),
        /truncated/,
        range,
      );
    }
  });

  it("throws on HTTP errors instead of reporting success", async () => {
    const fakeFetch = (async () => new Response("nope", { status: 500 })) as typeof fetch;
    await assert.rejects(fetchSensorPatchRows("https://example.supabase.co", "k", fakeFetch), /HTTP 500/);
  });
});
