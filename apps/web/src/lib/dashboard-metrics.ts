import type {
  AttackCategory,
  EventCategoryFilter,
  EventPeriodFilter,
  HttpPathTotal,
  NoteworthyObservation,
  PatternTotal,
  Protocol,
  PublicSensorStatusEvent,
  SensorStatusEventType,
  TrendBucket,
  TrendPeriod,
} from "./types.ts";
import { safeDisplayHttpPath } from "./format.ts";
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
  return "7d";
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

export function dailyWindowStartDate(nowMs: number, days: number): string {
  return addUtcDays(utcDateString(nowMs), -(days - 1));
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

export const AGGREGATE_PAGE_SIZE = 1000;
export const AGGREGATE_MAX_ROWS = 100_000;

/** Read every page. `complete` is false when the safety cap stops the read early. */
export async function collectPages<T>(
  fetchPage: (from: number, to: number) => Promise<T[]>,
  pageSize = AGGREGATE_PAGE_SIZE,
  maxRows = AGGREGATE_MAX_ROWS,
): Promise<{ rows: T[]; complete: boolean }> {
  const rows: T[] = [];
  let from = 0;
  while (from < maxRows) {
    const to = Math.min(from + pageSize - 1, maxRows - 1);
    const expected = to - from + 1;
    const page = await fetchPage(from, to);
    rows.push(...page);
    if (page.length < expected) return { rows, complete: true };
    from += expected;
  }
  return { rows, complete: false };
}

export function utcHourBucketStart(ms: number): number {
  const date = new Date(ms);
  return Date.UTC(
    date.getUTCFullYear(),
    date.getUTCMonth(),
    date.getUTCDate(),
    date.getUTCHours(),
  );
}

/**
 * 24 UTC hour buckets ending at the hour that contains `nowMs`.
 * The period total is the sum of these buckets, not a rolling minute window.
 */
export function buildUtcHourlySeries(
  rows: Iterable<{ bucketStart: string; eventCount: number }>,
  nowMs: number,
): TrendBucket[] {
  const end = utcHourBucketStart(nowMs);
  const start = end - 23 * HOUR_MS;
  const counts = new Map<number, number>();
  for (const row of rows) {
    const ms = Date.parse(row.bucketStart);
    if (Number.isNaN(ms)) continue;
    const bucket = utcHourBucketStart(ms);
    if (bucket < start || bucket > end) continue;
    counts.set(bucket, (counts.get(bucket) ?? 0) + row.eventCount);
  }
  return Array.from({ length: 24 }, (_, index) => {
    const bucketMs = start + index * HOUR_MS;
    const iso = new Date(bucketMs).toISOString();
    return { bucketStart: iso, label: iso.slice(11, 16), totalEvents: counts.get(bucketMs) ?? 0 };
  });
}

export function sumTrendBuckets(series: Iterable<{ totalEvents: number }>): number {
  let total = 0;
  for (const bucket of series) total += bucket.totalEvents;
  return total;
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

export function topPatternsFromCounts(
  rows: Iterable<{ protocol: Protocol; attack_category: AttackCategory; eventCount: number }>,
  limit = 8,
): PatternTotal[] {
  const totals = new Map<string, PatternTotal>();
  for (const row of rows) {
    const key = `${row.protocol}:${row.attack_category}`;
    const current = totals.get(key);
    if (current) {
      current.count += row.eventCount;
      continue;
    }
    totals.set(key, {
      key,
      label: CATEGORY_LABELS[row.attack_category],
      protocol: row.protocol,
      count: row.eventCount,
    });
  }
  return Array.from(totals.values())
    .toSorted((a, b) => b.count - a.count || a.label.localeCompare(b.label))
    .slice(0, limit);
}

const MIN_NOTEWORTHY_COUNT = 5;
const MIN_PRIOR_FOR_PERCENT = 10;

export function eventsFilterHref(protocol: Protocol, category?: string): string {
  const params = new URLSearchParams({ protocol, period: "24h" });
  if (category) params.set("category", category);
  return `/events?${params.toString()}`;
}

interface CountRow {
  protocol: Protocol;
  attack_category: AttackCategory;
  eventCount: number;
}

function addCounts(rows: Iterable<CountRow>): Map<string, CountRow> {
  const totals = new Map<string, CountRow>();
  for (const row of rows) {
    const key = `${row.protocol}:${row.attack_category}`;
    const current = totals.get(key);
    if (current) {
      current.eventCount += row.eventCount;
      continue;
    }
    totals.set(key, { ...row });
  }
  return totals;
}

const PROTOCOL_DISPLAY: Record<Protocol, string> = {
  ssh: "SSH",
  http: "HTTP",
  https: "HTTPS",
  telnet: "Telnet",
  ftp: "FTP",
  mysql: "MySQL",
  redis: "Redis",
  other: "Other",
};

const CATEGORY_PLURAL: Record<AttackCategory, string> = {
  port_scan: "connection and scan probes",
  auth_attempt: "authentication attempts",
  http_path_probe: "HTTP path probes",
  web_attack_attempt: "web attack attempts",
  suspected_cve_probe: "suspected CVE probes",
};

/**
 * Explainable 24h observation highlights.
 * - When the prior 24h window precedes observation start (baseline building),
 *   increase/decrease claims are suppressed and factual summaries of current
 *   observed activity are returned instead.
 * - When a full prior 24h baseline exists, small samples stay out and
 *   percentages are shown only when the prior window supports them.
 */
export function selectNoteworthyObservations(input: {
  current: Iterable<CountRow>;
  prior: Iterable<CountRow>;
  firstSeen?: Iterable<{
    patternType: string;
    patternKey: string;
    protocol: Protocol;
    totalCount: number;
  }>;
  comparisonReliable: boolean;
  hasPriorWindowBaseline?: boolean;
  limit?: number;
}): NoteworthyObservation[] {
  const current = addCounts(input.current);
  const prior = addCounts(input.prior);
  const hasBaseline = input.hasPriorWindowBaseline ?? true;
  const maxItems = input.limit ?? 3;

  // Baseline building: never treat pre-observation empty time as 0 measured events.
  if (!hasBaseline) {
    const byProtocol = new Map<Protocol, number>();
    let totalCurrent = 0;
    for (const row of current.values()) {
      byProtocol.set(row.protocol, (byProtocol.get(row.protocol) ?? 0) + row.eventCount);
      totalCurrent += row.eventCount;
    }
    if (totalCurrent < MIN_NOTEWORTHY_COUNT) return [];

    const rankedProtocols = Array.from(byProtocol.entries()).toSorted(
      (a, b) => b[1] - a[1] || a[0].localeCompare(b[0]),
    );
    const summaries: NoteworthyObservation[] = [];

    const top1 = rankedProtocols[0];
    const top2 = rankedProtocols[1];
    if (top1 && top2 && (top1[1] + top2[1]) / totalCurrent >= 0.65) {
      const combined = top1[1] + top2[1];
      const share = Math.round((combined / totalCurrent) * 100);
      summaries.push({
        id: `summary:dominant:${top1[0]}:${top2[0]}`,
        kind: "summary",
        severity: "primary",
        title: `${PROTOCOL_DISPLAY[top1[0]]} and ${PROTOCOL_DISPLAY[top2[0]]} probes account for ${share}% of observed activity`,
        detail: `${PROTOCOL_DISPLAY[top1[0]]}: ${top1[1]} events · ${PROTOCOL_DISPLAY[top2[0]]}: ${top2[1]} events (last 24 UTC hours)`,
        rationale: "Baseline building — 24h increase/decrease comparison activates after 48h of stored history.",
        protocol: top1[0],
        currentCount: combined,
        priorCount: 0,
        delta: combined,
        showPercent: false,
        comparisonReliable: input.comparisonReliable,
        href: eventsFilterHref(top1[0]),
      });
    } else if (top1) {
      const share = Math.round((top1[1] / totalCurrent) * 100);
      summaries.push({
        id: `summary:dominant:${top1[0]}`,
        kind: "summary",
        severity: "primary",
        title: `${PROTOCOL_DISPLAY[top1[0]]} traffic leads current observations (${share}%)`,
        detail: `${PROTOCOL_DISPLAY[top1[0]]}: ${top1[1]} of ${totalCurrent} stored events (last 24 UTC hours)`,
        rationale: "Baseline building — 24h increase/decrease comparison activates after 48h of stored history.",
        protocol: top1[0],
        currentCount: top1[1],
        priorCount: 0,
        delta: top1[1],
        showPercent: false,
        comparisonReliable: input.comparisonReliable,
        href: eventsFilterHref(top1[0]),
      });
    }

    const httpTotal = (byProtocol.get("http") ?? 0) + (byProtocol.get("https") ?? 0);
    if (httpTotal >= MIN_NOTEWORTHY_COUNT && top1?.[0] !== "http" && top2?.[0] !== "http") {
      summaries.push({
        id: "summary:http:probes",
        kind: "summary",
        severity: "secondary",
        title: "Unsolicited HTTP requests targeted web and router endpoints",
        detail: `HTTP/HTTPS: ${httpTotal} events recorded in the last 24 UTC hours`,
        rationale: "Inspect sanitized request paths to see which endpoints were probed.",
        protocol: "http",
        currentCount: httpTotal,
        priorCount: 0,
        delta: httpTotal,
        showPercent: false,
        comparisonReliable: input.comparisonReliable,
        href: eventsFilterHref("http"),
      });
    }

    const dbTotal = (byProtocol.get("redis") ?? 0) + (byProtocol.get("mysql") ?? 0);
    if (dbTotal >= MIN_NOTEWORTHY_COUNT && summaries.length < maxItems) {
      const primaryDb: Protocol = (byProtocol.get("redis") ?? 0) >= (byProtocol.get("mysql") ?? 0) ? "redis" : "mysql";
      const parts: string[] = [];
      if (byProtocol.get("redis")) parts.push(`Redis: ${byProtocol.get("redis")}`);
      if (byProtocol.get("mysql")) parts.push(`MySQL: ${byProtocol.get("mysql")}`);
      summaries.push({
        id: "summary:db:probes",
        kind: "summary",
        severity: "secondary",
        title: "Database and datastore ports received automated probing",
        detail: `${parts.join(" · ")} events in the last 24 UTC hours`,
        rationale: "Exposed service decoys capture unsolicited connection and command attempts.",
        protocol: primaryDb,
        currentCount: dbTotal,
        priorCount: 0,
        delta: dbTotal,
        showPercent: false,
        comparisonReliable: input.comparisonReliable,
        href: eventsFilterHref(primaryDb),
      });
    }

    return summaries.slice(0, maxItems);
  }

  const allKeys = new Set([...current.keys(), ...prior.keys()]);
  const notes: NoteworthyObservation[] = [];

  for (const key of allKeys) {
    const currRow = current.get(key);
    const priorRow = prior.get(key);
    const protocol = currRow?.protocol ?? priorRow!.protocol;
    const category = currRow?.attack_category ?? priorRow!.attack_category;
    const currentCount = currRow?.eventCount ?? 0;
    const previous = priorRow?.eventCount ?? 0;
    const delta = currentCount - previous;
    const larger = Math.max(currentCount, previous);
    if (larger < MIN_NOTEWORTHY_COUNT || Math.abs(delta) < MIN_NOTEWORTHY_COUNT) continue;
    if (previous > 0 && Math.abs(delta) / previous < 0.5) continue;
    const direction = delta > 0 ? "increased" : "decreased";
    notes.push({
      id: `category:${key}`,
      kind: "change",
      severity: Math.abs(delta) >= 50 ? "primary" : "secondary",
      title: `${PROTOCOL_DISPLAY[protocol]} ${CATEGORY_PLURAL[category]} ${direction}`,
      detail: formatWindowDelta(currentCount, previous),
      rationale: previous >= MIN_PRIOR_FOR_PERCENT
        ? "Exceeded 50% shift threshold with sufficient prior baseline."
        : "Absolute change only — prior 24h count is below 10 for percentage claims.",
      protocol,
      currentCount,
      priorCount: previous,
      delta,
      showPercent: previous >= MIN_PRIOR_FOR_PERCENT,
      comparisonReliable: input.comparisonReliable,
      href: eventsFilterHref(protocol, category),
    });
  }

  for (const pattern of input.firstSeen ?? []) {
    if (pattern.totalCount < MIN_NOTEWORTHY_COUNT) continue;
    if (pattern.patternType === "attack_category") continue;
    notes.push({
      id: `first:${pattern.patternType}:${pattern.protocol}:${pattern.patternKey}`,
      kind: "first_seen",
      severity: "secondary",
      title: `New ${PROTOCOL_DISPLAY[pattern.protocol]} pattern observed (${pattern.patternKey})`,
      detail: `${pattern.totalCount} stored events in the last 24 UTC hours`,
      rationale: "First appearance of this pattern key in stored observatory history.",
      protocol: pattern.protocol,
      currentCount: pattern.totalCount,
      priorCount: 0,
      delta: pattern.totalCount,
      showPercent: false,
      comparisonReliable: input.comparisonReliable,
      href: eventsFilterHref(pattern.protocol),
    });
  }

  return notes
    .toSorted((a, b) => Math.abs(b.delta) - Math.abs(a.delta) || a.title.localeCompare(b.title))
    .slice(0, maxItems);
}

function formatWindowDelta(current: number, prior: number): string {
  const delta = current - prior;
  const signed = `${delta > 0 ? "+" : ""}${delta}`;
  return `${current} in the latest 24 UTC hours, ${prior} in the previous 24 (${signed})`;
}

interface HttpPathInput {
  protocol: Protocol;
  http_method: string | null;
  http_path_redacted: string | null;
}

/** Top HTTP paths from event rows (mock mode). Withheld paths (NULL) are skipped. */
export function topHttpPaths(events: HttpPathInput[], limit = 8): HttpPathTotal[] {
  const totals = new Map<string, HttpPathTotal>();
  for (const event of events) {
    if (event.protocol !== "http" && event.protocol !== "https") continue;
    const maskedPath = safeDisplayHttpPath(event.http_path_redacted, "");
    if (!maskedPath) continue;
    const method = event.http_method ?? "GET";
    const key = `${method} ${maskedPath}`;
    const current = totals.get(key);
    if (current) {
      current.count += 1;
      continue;
    }
    totals.set(key, { method, path: maskedPath, count: 1 });
  }
  return Array.from(totals.values())
    .toSorted((a, b) => b.count - a.count || a.path.localeCompare(b.path))
    .slice(0, limit);
}

export interface PublicHttpPathPatternRow {
  pattern_key: string;
  total_count: number;
  unique_source_count: number | null;
}

/**
 * Top public HTTP paths (#88 L5): built from public_observed_patterns, which
 * lists only paths sent by at least 3 distinct sources, and ranked by distinct
 * sources, then events. It does not use a capped event sample, so a source
 * flooding one path cannot crowd out others or buy a higher rank.
 * Rows without a source count are dropped rather than ranked by events.
 */
export function rankPublicHttpPaths(rows: readonly PublicHttpPathPatternRow[], limit = 8): HttpPathTotal[] {
  return rows
    .filter((row) => typeof row.unique_source_count === "number" && Number.isFinite(row.unique_source_count))
    .map((row) => ({
      method: "",
      path: safeDisplayHttpPath(row.pattern_key, ""),
      count: row.total_count,
      sources: row.unique_source_count as number,
    }))
    .filter((row) => row.path.length > 0)
    .toSorted((a, b) => b.sources - a.sources || b.count - a.count || a.path.localeCompare(b.path))
    .slice(0, limit);
}

export function seriesHasLeadingGap(
  series: TrendBucket[],
  historyStartedAt: string | null,
): boolean {
  if (series.length === 0 || !historyStartedAt) return false;
  const historyMs = Date.parse(historyStartedAt);
  if (Number.isNaN(historyMs)) return false;
  const firstBucket = series[0];
  const firstBucketMs = firstBucket.bucketStart.includes("T")
    ? Date.parse(firstBucket.bucketStart)
    : Date.parse(`${firstBucket.bucketStart}T00:00:00.000Z`);
  if (Number.isNaN(firstBucketMs)) return false;
  return historyMs > firstBucketMs;
}

export function attackCategoryLabel(category: AttackCategory | null | undefined): string {
  if (!category) return "Unclassified";
  return CATEGORY_LABELS[category];
}

export function parseEventPeriod(value: string | undefined): EventPeriodFilter {
  if (value === "24h" || value === "7d" || value === "30d") return value;
  return "all";
}

export function parseEventCategory(value: string | undefined): EventCategoryFilter {
  if (value === "unclassified") return "unclassified";
  if (
    value === "port_scan" ||
    value === "auth_attempt" ||
    value === "http_path_probe" ||
    value === "web_attack_attempt" ||
    value === "suspected_cve_probe"
  ) {
    return value;
  }
  return "all";
}

export function eventMatchesExplorerFilters(
  event: { observed_at: string; attack_category?: AttackCategory | null },
  period: EventPeriodFilter,
  category: EventCategoryFilter,
  nowMs: number,
): boolean {
  if (period !== "all") {
    const observedMs = Date.parse(event.observed_at);
    if (Number.isNaN(observedMs) || observedMs < nowMs - periodLengthMs(period) || observedMs > nowMs) {
      return false;
    }
  }
  if (category === "unclassified") return event.attack_category == null;
  if (category !== "all") return event.attack_category === category;
  return true;
}

export function isCoverageGapStatus(status: SensorStatusEventType): boolean {
  return status !== "healthy";
}

export function intervalOverlapsWindow(
  event: Pick<PublicSensorStatusEvent, "started_at" | "ended_at">,
  windowStartMs: number,
  windowEndMs: number,
  nowMs: number,
): boolean {
  const startMs = Date.parse(event.started_at);
  if (Number.isNaN(startMs)) return false;
  const endMs = event.ended_at ? Date.parse(event.ended_at) : nowMs;
  if (Number.isNaN(endMs) || endMs < startMs) return false;
  if (endMs === startMs) {
    return startMs >= windowStartMs && startMs <= windowEndMs;
  }
  return startMs < windowEndMs && endMs > windowStartMs;
}

export function filterCoverageGapsInWindow(
  events: PublicSensorStatusEvent[],
  windowStartMs: number,
  windowEndMs: number,
  nowMs: number,
): PublicSensorStatusEvent[] {
  return events.filter(
    (event) =>
      isCoverageGapStatus(event.status) &&
      intervalOverlapsWindow(event, windowStartMs, windowEndMs, nowMs),
  );
}

export function annotateSeriesCoverage(
  series: TrendBucket[],
  statusEvents: PublicSensorStatusEvent[],
  nowMs: number,
): TrendBucket[] {
  const gapEvents = statusEvents.filter((event) => isCoverageGapStatus(event.status));
  if (gapEvents.length === 0) return series;

  return series.map((bucket) => {
    const isHourly = bucket.bucketStart.includes("T");
    const bucketStartMs = isHourly
      ? Date.parse(bucket.bucketStart)
      : Date.parse(`${bucket.bucketStart}T00:00:00.000Z`);
    if (Number.isNaN(bucketStartMs)) return bucket;
    const bucketEndMs = bucketStartMs + (isHourly ? HOUR_MS : DAY_MS);

    const matchedStatuses = new Set<SensorStatusEventType>();
    for (const ev of gapEvents) {
      if (intervalOverlapsWindow(ev, bucketStartMs, bucketEndMs, nowMs)) {
        matchedStatuses.add(ev.status);
      }
    }
    if (matchedStatuses.size === 0) return bucket;
    return {
      ...bucket,
      hasCoverageGap: true,
      gapStatuses: Array.from(matchedStatuses),
    };
  });
}

export function formatOutageDuration(startedAt: string, endedAt: string | null, nowMs: number): string {
  const startMs = Date.parse(startedAt);
  const endMs = endedAt ? Date.parse(endedAt) : nowMs;
  if (Number.isNaN(startMs) || Number.isNaN(endMs) || endMs < startMs) return "—";
  const totalMinutes = Math.max(1, Math.round((endMs - startMs) / 60_000));
  if (totalMinutes < 60) return `${totalMinutes}m`;
  const hours = Math.floor(totalMinutes / 60);
  const minutes = totalMinutes % 60;
  return minutes > 0 ? `${hours}h ${minutes}m` : `${hours}h`;
}

export function annotateSeriesPreHistory(
  series: TrendBucket[],
  historyStartedAt: string | null,
): TrendBucket[] {
  if (series.length === 0 || !historyStartedAt) return series;
  const historyMs = Date.parse(historyStartedAt);
  if (Number.isNaN(historyMs)) return series;

  let startMarked = false;
  return series.map((bucket, idx) => {
    const startMs = Date.parse(bucket.bucketStart);
    if (Number.isNaN(startMs)) return bucket;
    const nextMs =
      idx + 1 < series.length
        ? Date.parse(series[idx + 1].bucketStart)
        : startMs + (bucket.label.includes(":") ? HOUR_MS : DAY_MS);
    const endMs = Number.isNaN(nextMs) ? startMs + DAY_MS : nextMs;

    if (endMs <= historyMs && bucket.totalEvents === 0) {
      return { ...bucket, isPreHistory: true };
    }
    if (!startMarked && startMs <= historyMs && historyMs < endMs) {
      startMarked = true;
      return { ...bucket, isObservationStart: true };
    }
    return bucket;
  });
}

export function trendPeriodLabel(period: TrendPeriod): string {
  if (period === "24h") return "Past 24 hours";
  if (period === "7d") return "Past 7 days";
  return "Past 30 days";
}

export { TREND_PERIODS };
