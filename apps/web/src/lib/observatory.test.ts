import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { formatJstDateTime, safeDisplayText } from "./format.ts";
import {
  buildDailySeries,
  buildHourlySeries,
  parseTrendPeriod,
  seriesHasLeadingGap,
  topHttpPaths,
  topPatterns,
} from "./dashboard-metrics.ts";
import {
  evaluateSensorHealth,
  getEventDetail,
  getOverviewData,
  getPaginatedEvents,
  getTrendsData,
} from "./observatory.ts";
import { buildWorldMapData } from "./world-map.ts";

describe("observatory data layer (mock mode)", () => {
  it("returns sanitized overview data without sensitive fields", async () => {
    process.env.USE_MOCK = "true";
    const overview = await getOverviewData();
    assert.equal(overview.sourceMode, "mock");
    assert.equal(overview.totalEvents24h, 36);
    assert.equal(overview.priorEvents24h, 0);
    assert.ok(overview.patterns24h.length > 0);
    assert.ok(overview.httpPaths24h.length > 0);
    assert.ok(overview.dataUpdatedAt);
    assert.ok(overview.recentEvents.length > 0);

    for (const ev of overview.recentEvents) {
      const record = ev as unknown as Record<string, unknown>;
      assert.equal("src_ip" in record, false);
      assert.equal("src_ip_hash" in record, false);
      assert.equal("raw_object_key" in record, false);
      assert.equal("metadata" in record, false);
    }
  });

  it("paginates and filters events by protocol deterministically", async () => {
    process.env.USE_MOCK = "true";
    const page1 = await getPaginatedEvents({ page: 1, pageSize: 10, protocol: "all" });
    assert.equal(page1.items.length, 10);
    assert.equal(page1.totalCount, 36);
    assert.equal(page1.totalPages, 4);

    const httpOnly = await getPaginatedEvents({ page: 1, pageSize: 20, protocol: "http" });
    assert.ok(httpOnly.items.length > 0);
    for (const item of httpOnly.items) {
      assert.equal(item.protocol, "http");
    }
  });

  it("loads candidate CVE match detail with rule metadata and handles invalid IDs safely", async () => {
    process.env.USE_MOCK = "true";
    const invalid = await getEventDetail("not-a-uuid");
    assert.equal(invalid.event, null);

    const detail = await getEventDetail("10000000-0000-4000-8000-000000000004");
    assert.ok(detail.event);
    assert.equal(detail.detections.length, 1);
    assert.equal(detail.cveMatches.length, 1);
    assert.equal(detail.cveMatches[0].match_type, "candidate_cve");
  });

  it("aggregates trends series and formats JST / strips control chars", async () => {
    process.env.USE_MOCK = "true";
    const trends = await getTrendsData();
    assert.equal(trends.period, "30d");
    assert.equal(trends.series.length, 30);
    assert.equal(trends.seriesSource, "daily_stats");
    assert.ok(trends.protocolTotals.length > 0);
    assert.ok(trends.patterns.length > 0);
    assert.ok(trends.httpPaths.length > 0);
    for (const day of trends.series) {
      assert.equal("uniqueSources" in day, false);
    }

    const hourly = await getTrendsData("24h");
    assert.equal(hourly.series.length, 24);
    assert.equal(hourly.seriesSource, "events");
    assert.equal(
      hourly.series.reduce((sum, bucket) => sum + bucket.totalEvents, 0),
      36,
    );

    assert.match(formatJstDateTime("2026-11-21T00:00:00.000Z"), /2026\/11\/21 09:00:00 JST/);
    assert.equal(safeDisplayText("abc\u0000\u202edef"), "abcdef");
    assert.equal(parseTrendPeriod("7d"), "7d");
    assert.equal(parseTrendPeriod("nope"), "30d");
  });

  it("builds flat world map data covering both polygons (JP) and small-territory markers (SG)", () => {
    const map = buildWorldMapData([
      { country: "JP", count: 10 },
      { country: "US", count: 5 },
      { country: "SG", count: 3 },
      { country: "UNKNOWN", count: 99 },
    ]);
    assert.equal(map.maxCount, 10);
    assert.equal(map.totalMapped, 18);
    assert.equal(map.countries.some((c) => c.id === "010"), false); // Antarctica excluded
    const jp = map.countries.find((c) => c.code === "JP");
    assert.ok(jp && jp.count === 10 && jp.d.length > 10);
    const sg = map.markers.find((m) => m.code === "SG");
    assert.ok(sg && sg.count === 3);
  });

  it("evaluates sensor health using heartbeat freshness to separate healthy, stale, and inactive nodes", () => {
    const now = Date.parse("2026-11-21T10:00:00.000Z");
    assert.equal(
      evaluateSensorHealth({ is_active: true, last_heartbeat_at: "2026-11-21T09:55:00.000Z" }, now),
      "healthy",
    );
    assert.equal(
      evaluateSensorHealth({ is_active: true, last_heartbeat_at: "2026-11-21T09:30:00.000Z" }, now),
      "stale",
    );
    assert.equal(
      evaluateSensorHealth({ is_active: true, last_heartbeat_at: null }, now),
      "stale",
    );
    assert.equal(
      evaluateSensorHealth({ is_active: false, last_heartbeat_at: "2026-11-21T09:59:00.000Z" }, now),
      "inactive",
    );
  });

  it("handles empty series, leading history gaps, attack categories, and HTTP path filtering", () => {
    const nowMs = Date.parse("2026-11-22T00:00:00.000Z");

    const emptyDaily = buildDailySeries([], nowMs, 7);
    assert.equal(emptyDaily.length, 7);
    assert.equal(seriesHasLeadingGap(emptyDaily), false);

    const gappedDaily = buildDailySeries([{ dateUtc: "2026-11-22", eventCount: 5 }], nowMs, 7);
    assert.equal(seriesHasLeadingGap(gappedDaily), true);

    const hourly = buildHourlySeries(["2026-11-21T23:30:00.000Z", "invalid-date"], nowMs);
    assert.equal(hourly.length, 24);
    assert.equal(
      hourly.reduce((sum, bucket) => sum + bucket.totalEvents, 0),
      1,
    );

    const patterns = topPatterns([
      { protocol: "http", event_type: "http_probe", attack_category: "http_path_probe" },
      { protocol: "http", event_type: "http_probe", attack_category: "http_path_probe" },
      { protocol: "ssh", event_type: "ssh_new_connection", attack_category: null },
    ]);
    assert.equal(patterns[0]?.label, "HTTP path probe");
    assert.equal(patterns[0]?.count, 2);
    assert.equal(patterns[1]?.label, "ssh_new_connection");

    const paths = topHttpPaths([
      { protocol: "http", http_method: "GET", http_path_redacted: "/.env" },
      { protocol: "http", http_method: null, http_path_redacted: "/.env" },
      { protocol: "ssh", http_method: "GET", http_path_redacted: "/ignored" },
      { protocol: "https", http_method: "POST", http_path_redacted: null },
    ]);
    assert.deepEqual(paths, [{ method: "GET", path: "/.env", count: 2 }]);
  });
});
