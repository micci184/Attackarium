import type {
  AttackCategory,
  HttpPathTotal,
  PatternTotal,
  Protocol,
  TrendBucket,
  TrendPeriod,
} from "./types.ts";
import { TREND_PERIODS } from "./types.ts";

const HOUR_MS = 60 * 60 * 1000;
const DAY_MS = 24 * HOUR_MS;

const CATEGORY_LABELS: Record<AttackCategory, string> = {
  port_scan: "Port scan",
  auth_attempt: "Authentication attempt",
  http_path_probe: "HTTP path probe",
  web_attack_attempt: "Web attack attempt",
  suspected_cve_probe: "Suspected CVE probe",
};

export function parseTrendPeriod(value: string | undefined): TrendPeriod {
  if (value === "24h" || value === "7d" || value === "30d") return value;
  return "30d";
}

export function periodLengthMs(period: TrendPeriod): number {
  if (period === "24h") return DAY_MS;
  if (period === "7d") return 7 * DAY_MS;
  return 30 * DAY_MS;
}

export function periodDayCount(period: TrendPeriod): number {
  if (period === "7d") return 7;
  return 30;
}

export function utcDateString(ms: number): string {
  return new Date(ms).toISOString().slice(0, 10);
}

function addUtcDays(dateUtc: string, days: number): string {
  const ms = Date.parse(`${dateUtc}T00:00:00.000Z`) + days * DAY_MS;
  return new Date(ms).toISOString().slice(0, 10);
}

export function countEventsInWindow(
  observedAt: Iterable<string>,
  startMs: number,
  endMs: number,
): number {
  let count = 0;
  for (const iso of observedAt) {
    const ms = Date.parse(iso);
    if (!Number.isNaN(ms) && ms >= startMs && ms < endMs) count += 1;
  }
  return count;
}

export function latestTimestamp(values: Iterable<string | null | undefined>): string | null {
  let latestMs = Number.NEGATIVE_INFINITY;
  let latest: string | null = null;
  for (const value of values) {
    if (!value) continue;
    const ms = Date.parse(value);
    if (!Number.isNaN(ms) && ms > latestMs) {
      latestMs = ms;
      latest = value;
    }
  }
  return latest;
}

export function earliestTimestamp(values: Iterable<string | null | undefined>): string | null {
  let earliestMs = Number.POSITIVE_INFINITY;
  let earliest: string | null = null;
  for (const value of values) {
    if (!value) continue;
    const ms = Date.parse(value);
    if (!Number.isNaN(ms) && ms < earliestMs) {
      earliestMs = ms;
      earliest = value;
    }
  }
  return earliest;
}

export function buildHourlySeries(
  observedAt: Iterable<string>,
  nowMs: number,
): TrendBucket[] {
  const windowStart = nowMs - DAY_MS;
  const counts = new Array<number>(24).fill(0);
  for (const iso of observedAt) {
    const ms = Date.parse(iso);
    if (Number.isNaN(ms) || ms < windowStart || ms > nowMs) continue;
    const index = Math.min(23, Math.floor((ms - windowStart) / HOUR_MS));
    counts[index] += 1;
  }
  return counts.map((totalEvents, index) => {
    const iso = new Date(windowStart + index * HOUR_MS).toISOString();
    return { bucketStart: iso, label: iso.slice(11, 16), totalEvents };
  });
}

export function buildDailySeries(
  rows: Iterable<{ dateUtc: string; eventCount: number }>,
  nowMs: number,
  days: number,
): TrendBucket[] {
  const endDate = utcDateString(nowMs);
  const totals = new Map<string, number>();
  for (const row of rows) {
    totals.set(row.dateUtc, (totals.get(row.dateUtc) ?? 0) + row.eventCount);
  }
  const series: TrendBucket[] = [];
  for (let offset = days - 1; offset >= 0; offset -= 1) {
    const dateUtc = addUtcDays(endDate, -offset);
    series.push({
      bucketStart: dateUtc,
      label: dateUtc.slice(5),
      totalEvents: totals.get(dateUtc) ?? 0,
    });
  }
  return series;
}

export function eventsToDailyRows(
  observedAt: Iterable<string>,
  startMs: number,
  endMs: number,
): Array<{ dateUtc: string; eventCount: number }> {
  const totals = new Map<string, number>();
  for (const iso of observedAt) {
    const ms = Date.parse(iso);
    if (Number.isNaN(ms) || ms < startMs || ms > endMs) continue;
    const dateUtc = utcDateString(ms);
    totals.set(dateUtc, (totals.get(dateUtc) ?? 0) + 1);
  }
  return Array.from(totals, ([dateUtc, eventCount]) => ({ dateUtc, eventCount }));
}

interface PatternInput {
  protocol: Protocol;
  event_type: string;
  attack_category?: AttackCategory | null;
}

export function topPatterns(events: PatternInput[], limit = 8): PatternTotal[] {
  const totals = new Map<string, PatternTotal>();
  for (const event of events) {
    const category = event.attack_category;
    const key = category ? `${event.protocol}:${category}` : `${event.protocol}:${event.event_type}`;
    const current = totals.get(key);
    if (current) {
      current.count += 1;
      continue;
    }
    totals.set(key, {
      key,
      label: category ? CATEGORY_LABELS[category] : event.event_type,
      protocol: event.protocol,
      count: 1,
    });
  }
  return Array.from(totals.values())
    .toSorted((a, b) => b.count - a.count || a.label.localeCompare(b.label))
    .slice(0, limit);
}

interface HttpPathInput {
  protocol: Protocol;
  http_method: string | null;
  http_path_redacted: string | null;
}

export function topHttpPaths(events: HttpPathInput[], limit = 8): HttpPathTotal[] {
  const totals = new Map<string, HttpPathTotal>();
  for (const event of events) {
    if (event.protocol !== "http" && event.protocol !== "https") continue;
    if (!event.http_path_redacted) continue;
    const method = event.http_method ?? "GET";
    const key = `${method} ${event.http_path_redacted}`;
    const current = totals.get(key);
    if (current) {
      current.count += 1;
      continue;
    }
    totals.set(key, { method, path: event.http_path_redacted, count: 1 });
  }
  return Array.from(totals.values())
    .toSorted((a, b) => b.count - a.count || a.path.localeCompare(b.path))
    .slice(0, limit);
}

export function seriesHasLeadingGap(series: TrendBucket[]): boolean {
  const firstWithData = series.findIndex((bucket) => bucket.totalEvents > 0);
  return firstWithData > 0;
}

export function trendPeriodLabel(period: TrendPeriod): string {
  if (period === "24h") return "Past 24 hours";
  if (period === "7d") return "Past 7 days";
  return "Past 30 days";
}

export { TREND_PERIODS };
