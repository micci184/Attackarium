import { createClient, type SupabaseClient } from "@supabase/supabase-js";
import { z } from "zod";
import {
  MOCK_CVE_MATCHES,
  MOCK_DAILY_STATS,
  MOCK_DETECTIONS,
  MOCK_EVENTS,
  MOCK_REFERENCE_NOW_MS,
  MOCK_SENSORS,
  MOCK_SENSOR_STATUS_EVENTS,
} from "./mock-data.ts";
import {
  annotateSeriesCoverage,
  buildDailySeries,
  buildHourlySeries,
  buildUtcHourlySeries,
  collectPages,
  countEventsInWindow,
  dailyWindowStartDate,
  earliestTimestamp,
  eventMatchesExplorerFilters,
  eventsToDailyRows,
  filterCoverageGapsInWindow,
  isCoverageGapStatus,
  latestTimestamp,
  parseEventCategory,
  parseEventPeriod,
  periodDayCount,
  periodLengthMs,
  sumTrendBuckets,
  topHttpPaths,
  topPatterns,
  topPatternsFromCounts,
  utcDateString,
  utcHourBucketStart,
} from "./dashboard-metrics.ts";
import {
  AttackCategorySchema,
  type EventDetailData,
  type OverviewData,
  type OverviewSensor,
  type PaginatedEventsResult,
  type Protocol,
  ProtocolSchema,
  PublicDailyStatSchema,
  PublicDetectionSchema,
  PublicEventCveMatchSchema,
  PublicEventSchema,
  type PublicSensor,
  PublicSensorSchema,
  type PublicSensorStatusEvent,
  PublicSensorStatusEventSchema,
  type SensorHealthStatus,
  type SensorsPageData,
  type TrendPeriod,
  type TrendsData,
} from "./types.ts";

export const HEARTBEAT_STALE_THRESHOLD_MS = 15 * 60 * 1000;
export function evaluateSensorHealth(
  sensor: Pick<PublicSensor, "is_active" | "last_heartbeat_at">,
  nowMs: number,
  staleThresholdMs: number = HEARTBEAT_STALE_THRESHOLD_MS,
): SensorHealthStatus {
  if (!sensor.is_active) {
    return "inactive";
  }
  if (!sensor.last_heartbeat_at) {
    return "stale";
  }
  const hbMs = Date.parse(sensor.last_heartbeat_at);
  if (Number.isNaN(hbMs) || nowMs - hbMs > staleThresholdMs) {
    return "stale";
  }
  return "healthy";
}

const SAMPLE_EVENT_LIMIT = 1000;

function protocolShare(
  rows: Iterable<{ protocol: Protocol; eventCount: number }>,
): Array<{ protocol: Protocol; count: number; sharePct: number }> {
  const counts = new Map<Protocol, number>();
  let total = 0;
  for (const row of rows) {
    counts.set(row.protocol, (counts.get(row.protocol) ?? 0) + row.eventCount);
    total += row.eventCount;
  }
  return Array.from(counts, ([protocol, count]) => ({
    protocol,
    count,
    sharePct: total === 0 ? 0 : Math.round((count / total) * 1000) / 10,
  })).toSorted((a, b) => b.count - a.count || a.protocol.localeCompare(b.protocol));
}
const HOUR_MS = 60 * 60 * 1000;

const HourAggregateSchema = z.object({
  bucket_start: z.string(),
  protocol: ProtocolSchema,
  attack_category: AttackCategorySchema,
  event_count: z.coerce.number().int().nonnegative(),
  updated_at: z.string(),
});

function mockModeRequested(): boolean {
  return process.env.USE_MOCK === "true";
}

function assertMockAllowed(): void {
  if (!mockModeRequested()) return;
  if (process.env.VERCEL_ENV === "production" || process.env.NODE_ENV === "production") {
    throw new Error(
      "USE_MOCK is set in production. Refusing to show synthetic observations.",
    );
  }
}

function getPublicSupabaseClient(): SupabaseClient | null {
  assertMockAllowed();
  if (mockModeRequested()) return null;
  const url = process.env.NEXT_PUBLIC_SUPABASE_URL;
  const anonKey = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY;
  if (!url || !anonKey) {
    throw new Error(
      "Supabase public configuration is missing. Synthetic observations are shown only when USE_MOCK=true in development or tests.",
    );
  }
  return createClient(url, anonKey, {
    auth: { persistSession: false, autoRefreshToken: false },
  });
}

async function fetchAllRows<T>(
  fetchPage: (from: number, to: number) => PromiseLike<{ data: T[] | null; error: { message: string } | null }>,
  label: string,
): Promise<{ rows: T[]; complete: boolean }> {
  const collected = await collectPages(async (from, to) => {
    const { data, error } = await fetchPage(from, to);
    if (error) throw new Error(`${label} query failed: ${error.message}`);
    return data ?? [];
  });
  return collected;
}

function summarize24hRows(
  rows: Array<{ protocol: Protocol; src_country: string | null }>,
): {
  uniqueCountries: number;
  protocolBreakdown: Array<{ protocol: Protocol; count: number; sharePct: number }>;
  regionTotals: Array<{ country: string; count: number }>;
} {
  const protocolCounts = new Map<Protocol, number>();
  const regionCounts = new Map<string, number>();
  const countries = new Set<string>();

  for (const row of rows) {
    protocolCounts.set(row.protocol, (protocolCounts.get(row.protocol) ?? 0) + 1);
    if (row.src_country) {
      countries.add(row.src_country);
    }
    const region = row.src_country ?? "UNKNOWN";
    regionCounts.set(region, (regionCounts.get(region) ?? 0) + 1);
  }

  const total = rows.length || 1;
  const protocolBreakdown = Array.from(protocolCounts.entries())
    .map(([protocol, count]) => ({
      protocol,
      count,
      sharePct: Math.round((count / total) * 1000) / 10,
    }))
    .toSorted((a, b) => b.count - a.count);

  const regionTotals = Array.from(regionCounts.entries())
    .map(([country, count]) => ({ country, count }))
    .toSorted((a, b) => b.count - a.count);

  return {
    uniqueCountries: countries.size,
    protocolBreakdown,
    regionTotals,
  };
}

export async function getOverviewData(): Promise<OverviewData> {
  const client = getPublicSupabaseClient();

  if (!client) {
    const recentEvents = MOCK_EVENTS.slice(0, 12);
    const summary = summarize24hRows(MOCK_EVENTS);
    const sensors: OverviewSensor[] = MOCK_SENSORS.map((sensor) => ({
      ...sensor,
      healthStatus: evaluateSensorHealth(sensor, MOCK_REFERENCE_NOW_MS),
    }));
    const windowStart = MOCK_REFERENCE_NOW_MS - 24 * 60 * 60 * 1000;
    const priorStart = windowStart - 24 * 60 * 60 * 1000;
    const coverageGapIn24h =
      filterCoverageGapsInWindow(
        MOCK_SENSOR_STATUS_EVENTS,
        windowStart,
        MOCK_REFERENCE_NOW_MS,
        MOCK_REFERENCE_NOW_MS,
      ).length > 0;
    const coverageGapInPrior24h =
      filterCoverageGapsInWindow(
        MOCK_SENSOR_STATUS_EVENTS,
        priorStart,
        windowStart,
        MOCK_REFERENCE_NOW_MS,
      ).length > 0;
    const activeOutages = MOCK_SENSOR_STATUS_EVENTS.filter(
      (event) => isCoverageGapStatus(event.status) && event.ended_at === null,
    );
    return {
      sourceMode: "mock",
      totalEvents24h: MOCK_EVENTS.length,
      priorEvents24h: countEventsInWindow(
        MOCK_EVENTS.map((event) => event.observed_at),
        priorStart,
        windowStart,
      ),
      coverageGapIn24h,
      coverageGapInPrior24h,
      activeOutages,
      sampled24hCount: MOCK_EVENTS.length,
      is24hBreakdownSampled: false,
      aggregateComplete: true,
      rollupPendingEvents24h: 0,
      uniqueCountries24h: summary.uniqueCountries,
      activeSensorCount: sensors.filter((s) => s.is_active).length,
      healthySensorCount: sensors.filter((s) => s.healthStatus === "healthy").length,
      sensors,
      protocolBreakdown: summary.protocolBreakdown,
      regionTotals24h: summary.regionTotals,
      patterns24h: topPatterns(MOCK_EVENTS),
      httpPaths24h: topHttpPaths(MOCK_EVENTS),
      dataUpdatedAt: latestTimestamp(MOCK_EVENTS.map((event) => event.received_at)),
      recentEvents,
    };
  }

  const nowMs = Date.now();
  const currentHourMs = utcHourBucketStart(nowMs);
  const window24hStartMs = currentHourMs - 23 * HOUR_MS;
  const window48hStartMs = window24hStartMs - 24 * HOUR_MS;
  const since48h = new Date(window48hStartMs).toISOString();
  const untilHour = new Date(currentHourMs).toISOString();

  const [sensorsRes, recentRes, statusRes, sampleRes, aggregatePage] = await Promise.all([
    client.from("public_sensors").select("*").order("created_at", { ascending: true }),
    client
      .from("public_events")
      .select("*")
      .order("observed_at", { ascending: false })
      .limit(12),
    client
      .from("public_sensor_status_events")
      .select("id, sensor_id, status, started_at, ended_at")
      .or(`ended_at.is.null,ended_at.gte.${since48h}`)
      .order("started_at", { ascending: false })
      .limit(100),
    client
      .from("public_events")
      .select(
        "protocol, src_country, http_method, http_path_redacted, received_at",
        { count: "exact" },
      )
      .gte("observed_at", new Date(window24hStartMs).toISOString())
      .lte("observed_at", new Date(currentHourMs + HOUR_MS - 1).toISOString())
      .order("observed_at", { ascending: false })
      .limit(SAMPLE_EVENT_LIMIT),
    fetchAllRows(
      (from, to) =>
        client
          .from("public_event_aggregates")
          .select("bucket_start, protocol, attack_category, event_count, updated_at")
          .eq("granularity", "hour")
          .gte("bucket_start", since48h)
          .lte("bucket_start", untilHour)
          .order("bucket_start", { ascending: true })
          .order("sensor_id", { ascending: true })
          .order("protocol", { ascending: true })
          .order("attack_category", { ascending: true })
          .range(from, to),
      "public_event_aggregates",
    ),
  ]);

  if (sensorsRes.error) throw new Error(`public_sensors query failed: ${sensorsRes.error.message}`);
  if (recentRes.error) throw new Error(`public_events recent query failed: ${recentRes.error.message}`);
  if (statusRes.error) throw new Error(`public_sensor_status_events query failed: ${statusRes.error.message}`);
  if (sampleRes.error) throw new Error(`public_events sample query failed: ${sampleRes.error.message}`);

  const parsedSensors = z.array(PublicSensorSchema).parse(sensorsRes.data ?? []);
  const statusEvents = z.array(PublicSensorStatusEventSchema).parse(statusRes.data ?? []);
  const sensors: OverviewSensor[] = parsedSensors.map((sensor) => ({
    ...sensor,
    healthStatus: evaluateSensorHealth(sensor, nowMs),
  }));
  const recentEvents = z.array(PublicEventSchema).parse(recentRes.data ?? []);
  const sampleRows = z
    .array(
      z.object({
        protocol: ProtocolSchema,
        src_country: z.string().nullable(),
        http_method: z.string().nullable(),
        http_path_redacted: z.string().nullable(),
        received_at: z.string(),
      }),
    )
    .parse(sampleRes.data ?? []);
  const hourRows = z.array(HourAggregateSchema).parse(aggregatePage.rows);
  const currentRows = hourRows.filter((row) => Date.parse(row.bucket_start) >= window24hStartMs);
  const priorRows = hourRows.filter((row) => Date.parse(row.bucket_start) < window24hStartMs);
  const currentSeries = buildUtcHourlySeries(
    currentRows.map((row) => ({ bucketStart: row.bucket_start, eventCount: row.event_count })),
    nowMs,
  );
  const summary = summarize24hRows(sampleRows);
  const sampleCount = sampleRes.count ?? sampleRows.length;

  const coverageGapIn24h =
    filterCoverageGapsInWindow(statusEvents, window24hStartMs, currentHourMs + HOUR_MS, nowMs).length > 0;
  const coverageGapInPrior24h =
    filterCoverageGapsInWindow(statusEvents, window48hStartMs, window24hStartMs, nowMs).length > 0;
  const activeOutages = statusEvents.filter(
    (event) => isCoverageGapStatus(event.status) && event.ended_at === null,
  );

  const totalEvents24h = sumTrendBuckets(currentSeries);

  return {
    sourceMode: "supabase",
    totalEvents24h,
    priorEvents24h: priorRows.reduce((sum, row) => sum + row.event_count, 0),
    coverageGapIn24h,
    coverageGapInPrior24h,
    activeOutages,
    sampled24hCount: sampleRows.length,
    is24hBreakdownSampled: sampleCount > sampleRows.length,
    aggregateComplete: aggregatePage.complete,
    rollupPendingEvents24h: Math.max(0, sampleCount - totalEvents24h),
    uniqueCountries24h: summary.uniqueCountries,
    activeSensorCount: sensors.filter((s) => s.is_active).length,
    healthySensorCount: sensors.filter((s) => s.healthStatus === "healthy").length,
    sensors,
    protocolBreakdown: protocolShare(
      currentRows.map((row) => ({ protocol: row.protocol, eventCount: row.event_count })),
    ),
    regionTotals24h: summary.regionTotals,
    patterns24h: topPatternsFromCounts(
      currentRows.map((row) => ({
        protocol: row.protocol,
        attack_category: row.attack_category,
        eventCount: row.event_count,
      })),
    ),
    httpPaths24h: topHttpPaths(sampleRows),
    dataUpdatedAt: latestTimestamp([
      ...hourRows.map((row) => row.updated_at),
      ...sampleRows.map((row) => row.received_at),
    ]),
    recentEvents,
  };
}

export async function getTrendsData(period: TrendPeriod = "30d"): Promise<TrendsData> {
  const client = getPublicSupabaseClient();
  const nowMs = client ? Date.now() : MOCK_REFERENCE_NOW_MS;
  const windowStartMs = nowMs - periodLengthMs(period);

  const days = periodDayCount(period);
  const sinceDate = dailyWindowStartDate(nowMs, days);
  const endDate = utcDateString(nowMs);
  const hourWindowStartMs = utcHourBucketStart(nowMs) - 23 * HOUR_MS;
  const hourWindowEndMs = utcHourBucketStart(nowMs);
  const seriesStartMs =
    period === "24h"
      ? client
        ? hourWindowStartMs
        : windowStartMs
      : Date.parse(`${sinceDate}T00:00:00.000Z`);

  let dailyStats = MOCK_DAILY_STATS;
  let recentEvents = MOCK_EVENTS;
  let statusEvents: PublicSensorStatusEvent[] = MOCK_SENSOR_STATUS_EVENTS;
  let registeredSensorCount = MOCK_SENSORS.length;
  let historyStartedAt = earliestTimestamp([
    ...MOCK_EVENTS.map((event) => event.observed_at),
    ...MOCK_DAILY_STATS.map((row) => `${row.date_utc}T00:00:00.000Z`),
  ]);
  let eventMatchCount = MOCK_EVENTS.length;
  let sourceMode: "mock" | "supabase" = "mock";
  let aggregateComplete = true;
  let hourAggregates: Array<z.infer<typeof HourAggregateSchema>> = [];

  if (client) {
    sourceMode = "supabase";
    const sinceIso = new Date(seriesStartMs).toISOString();
    const statusSinceIso = new Date(seriesStartMs).toISOString();
    const hourStart = new Date(hourWindowStartMs).toISOString();
    const hourEnd = new Date(hourWindowEndMs).toISOString();
    const [statsPage, hourPage, eventsRes, sensorsRes, oldestRes, statusRes] = await Promise.all([
      period === "24h"
        ? Promise.resolve({ rows: [] as Array<z.infer<typeof PublicDailyStatSchema>>, complete: true })
        : fetchAllRows(
            (from, to) =>
              client
                .from("public_daily_stats")
                .select("date_utc, sensor_id, protocol, event_type, event_count, unique_source_count")
                .gte("date_utc", sinceDate)
                .lte("date_utc", endDate)
                .order("date_utc", { ascending: true })
                .order("sensor_id", { ascending: true })
                .order("protocol", { ascending: true })
                .order("event_type", { ascending: true })
                .range(from, to),
            "public_daily_stats",
          ),
      period === "24h"
        ? fetchAllRows(
            (from, to) =>
              client
                .from("public_event_aggregates")
                .select("bucket_start, protocol, attack_category, event_count, updated_at")
                .eq("granularity", "hour")
                .gte("bucket_start", hourStart)
                .lte("bucket_start", hourEnd)
                .order("bucket_start", { ascending: true })
                .order("sensor_id", { ascending: true })
                .order("protocol", { ascending: true })
                .order("attack_category", { ascending: true })
                .range(from, to),
            "public_event_aggregates",
          )
        : Promise.resolve({ rows: [] as Array<z.infer<typeof HourAggregateSchema>>, complete: true }),
      client
        .from("public_events")
        .select("*", { count: "exact" })
        .gte("observed_at", sinceIso)
        .order("observed_at", { ascending: false })
        .limit(SAMPLE_EVENT_LIMIT),
      client.from("public_sensors").select("id", { count: "exact", head: true }),
      client
        .from("public_events")
        .select("observed_at")
        .order("observed_at", { ascending: true })
        .limit(1),
      client
        .from("public_sensor_status_events")
        .select("id, sensor_id, status, started_at, ended_at")
        .or(`ended_at.is.null,ended_at.gte.${statusSinceIso}`)
        .order("started_at", { ascending: false })
        .limit(200),
    ]);

    if (eventsRes.error) throw new Error(`public_events trends query failed: ${eventsRes.error.message}`);
    if (sensorsRes.error) throw new Error(`public_sensors count failed: ${sensorsRes.error.message}`);
    if (oldestRes.error) throw new Error(`public_events history query failed: ${oldestRes.error.message}`);
    if (statusRes.error) throw new Error(`public_sensor_status_events query failed: ${statusRes.error.message}`);

    dailyStats = z.array(PublicDailyStatSchema).parse(statsPage.rows);
    hourAggregates = z.array(HourAggregateSchema).parse(hourPage.rows);
    aggregateComplete = statsPage.complete && hourPage.complete;
    recentEvents = z.array(PublicEventSchema).parse(eventsRes.data ?? []);
    statusEvents = z.array(PublicSensorStatusEventSchema).parse(statusRes.data ?? []);
    registeredSensorCount = sensorsRes.count ?? 0;
    eventMatchCount = eventsRes.count ?? recentEvents.length;
    const oldest = z
      .array(z.object({ observed_at: z.string() }))
      .parse(oldestRes.data ?? []);
    historyStartedAt = earliestTimestamp([
      oldest[0]?.observed_at,
      dailyStats[0] ? `${dailyStats[0].date_utc}T00:00:00.000Z` : null,
    ]);
  }

  const windowEvents =
    sourceMode === "mock"
      ? recentEvents.filter((event) => {
          const ms = Date.parse(event.observed_at);
          return ms >= windowStartMs && ms <= nowMs;
        })
      : recentEvents;
  const windowStats = dailyStats.filter((row) => row.date_utc >= sinceDate && row.date_utc <= endDate);
  const useAggregateSeries = sourceMode === "supabase";
  const series = useAggregateSeries
    ? period === "24h"
      ? buildUtcHourlySeries(
          hourAggregates.map((row) => ({ bucketStart: row.bucket_start, eventCount: row.event_count })),
          nowMs,
        )
      : buildDailySeries(
          windowStats.map((row) => ({ dateUtc: row.date_utc, eventCount: row.event_count })),
          nowMs,
          days,
        )
    : period === "24h"
      ? buildHourlySeries(
          windowEvents.map((event) => event.observed_at),
          nowMs,
        )
      : buildDailySeries(
          windowStats.length > 0
            ? windowStats.map((row) => ({ dateUtc: row.date_utc, eventCount: row.event_count }))
            : eventsToDailyRows(
                windowEvents.map((event) => event.observed_at),
                windowStartMs,
                nowMs,
              ),
          nowMs,
          days,
        );

  const protocolMap = new Map<Protocol, number>();
  if (useAggregateSeries && period === "24h") {
    for (const row of hourAggregates) {
      protocolMap.set(row.protocol, (protocolMap.get(row.protocol) ?? 0) + row.event_count);
    }
  } else if (useAggregateSeries || (period !== "24h" && windowStats.length > 0 && sourceMode === "mock")) {
    for (const row of windowStats) {
      protocolMap.set(row.protocol, (protocolMap.get(row.protocol) ?? 0) + row.event_count);
    }
  } else {
    for (const event of windowEvents) {
      protocolMap.set(event.protocol, (protocolMap.get(event.protocol) ?? 0) + 1);
    }
  }

  // unique_source_count is not additive across daily_stats buckets, so the series
  // sums event_count only.
  const portMap = new Map<string, { dstPort: number; protocol: Protocol; count: number }>();
  const regionMap = new Map<string, number>();
  const asnMap = new Map<string, number>();

  for (const ev of windowEvents) {
    const portKey = `${ev.protocol}:${ev.dst_port}`;
    const portEntry = portMap.get(portKey) ?? {
      dstPort: ev.dst_port,
      protocol: ev.protocol,
      count: 0,
    };
    portEntry.count += 1;
    portMap.set(portKey, portEntry);

    const country = ev.src_country ?? "UNKNOWN";
    regionMap.set(country, (regionMap.get(country) ?? 0) + 1);

    const asn = ev.src_asn ?? "UNKNOWN";
    asnMap.set(asn, (asnMap.get(asn) ?? 0) + 1);
  }

  const coverageGaps = filterCoverageGapsInWindow(statusEvents, seriesStartMs, nowMs, nowMs);
  const annotatedSeries = annotateSeriesCoverage(series, coverageGaps, nowMs);

  return {
    sourceMode,
    period,
    series: annotatedSeries,
    seriesSource: useAggregateSeries
      ? period === "24h"
        ? "event_aggregates"
        : "daily_stats"
      : period === "24h" || windowStats.length === 0
        ? "events"
        : "daily_stats",
    aggregateComplete,
    rollupPendingEvents:
      useAggregateSeries && period === "24h"
        ? Math.max(0, eventMatchCount - sumTrendBuckets(annotatedSeries))
        : 0,
    historyStartedAt,
    dataUpdatedAt: latestTimestamp([
      ...hourAggregates.map((row) => row.updated_at),
      ...windowEvents.map((event) => event.received_at),
    ]),
    registeredSensorCount,
    isEventSampled: eventMatchCount > windowEvents.length,
    coverageGaps,
    protocolTotals: Array.from(protocolMap.entries())
      .map(([protocol, count]) => ({ protocol, count }))
      .toSorted((a, b) => b.count - a.count),
    portTotals: Array.from(portMap.values())
      .toSorted((a, b) => b.count - a.count)
      .slice(0, 10),
    regionTotals: Array.from(regionMap.entries())
      .map(([country, count]) => ({ country, count }))
      .toSorted((a, b) => b.count - a.count)
      .slice(0, 10),
    asnTotals: Array.from(asnMap.entries())
      .map(([asn, count]) => ({ asn, count }))
      .toSorted((a, b) => b.count - a.count)
      .slice(0, 10),
    patterns:
      useAggregateSeries && period === "24h"
        ? topPatternsFromCounts(
            hourAggregates.map((row) => ({
              protocol: row.protocol,
              attack_category: row.attack_category,
              eventCount: row.event_count,
            })),
          )
        : topPatterns(windowEvents),
    httpPaths: topHttpPaths(windowEvents),
  };
}

export async function getPaginatedEvents(options: {
  page?: number;
  pageSize?: number;
  protocol?: string;
  period?: string;
  category?: string;
}): Promise<PaginatedEventsResult> {
  const pageSize = Math.min(Math.max(options.pageSize ?? 12, 1), 50);
  const requestedPage = Math.max(options.page ?? 1, 1);
  const parsedProtocol = ProtocolSchema.safeParse(options.protocol);
  const protocolFilter: Protocol | "all" = parsedProtocol.success ? parsedProtocol.data : "all";
  const periodFilter = parseEventPeriod(options.period);
  const categoryFilter = parseEventCategory(options.category);

  const client = getPublicSupabaseClient();
  const nowMs = client ? Date.now() : MOCK_REFERENCE_NOW_MS;

  if (!client) {
    const filtered = MOCK_EVENTS.filter(
      (event) =>
        (protocolFilter === "all" || event.protocol === protocolFilter) &&
        eventMatchesExplorerFilters(event, periodFilter, categoryFilter, nowMs),
    );
    const totalCount = filtered.length;
    const totalPages = Math.max(1, Math.ceil(totalCount / pageSize));
    const page = Math.min(requestedPage, totalPages);
    const offset = (page - 1) * pageSize;

    return {
      sourceMode: "mock",
      items: filtered.slice(offset, offset + pageSize),
      page,
      pageSize,
      totalCount,
      totalPages,
      protocolFilter,
      periodFilter,
      categoryFilter,
    };
  }

  const offset = (requestedPage - 1) * pageSize;
  let query = client
    .from("public_events")
    .select("*", { count: "exact" })
    .order("observed_at", { ascending: false })
    .range(offset, offset + pageSize - 1);

  if (protocolFilter !== "all") {
    query = query.eq("protocol", protocolFilter);
  }
  if (periodFilter !== "all") {
    query = query
      .gte("observed_at", new Date(nowMs - periodLengthMs(periodFilter)).toISOString())
      .lte("observed_at", new Date(nowMs).toISOString());
  }
  if (categoryFilter === "unclassified") {
    query = query.is("attack_category", null);
  } else if (categoryFilter !== "all") {
    query = query.eq("attack_category", categoryFilter);
  }

  const { data, count, error } = await query;
  if (error) throw new Error(`public_events paginated query failed: ${error.message}`);

  const totalCount = count ?? 0;
  const totalPages = Math.max(1, Math.ceil(totalCount / pageSize));

  return {
    sourceMode: "supabase",
    items: z.array(PublicEventSchema).parse(data ?? []),
    page: Math.min(requestedPage, totalPages),
    pageSize,
    totalCount,
    totalPages,
    protocolFilter,
    periodFilter,
    categoryFilter,
  };
}

const UUID_CHECK = z.uuid();

export async function getEventDetail(id: string): Promise<EventDetailData> {
  const client = getPublicSupabaseClient();

  if (!UUID_CHECK.safeParse(id).success) {
    return {
      sourceMode: client ? "supabase" : "mock",
      event: null,
      detections: [],
      cveMatches: [],
    };
  }

  if (!client) {
    const event = MOCK_EVENTS.find((e) => e.id === id) ?? null;
    if (!event) {
      return { sourceMode: "mock", event: null, detections: [], cveMatches: [] };
    }
    return {
      sourceMode: "mock",
      event,
      detections: MOCK_DETECTIONS.filter((d) => d.event_id === id),
      cveMatches: MOCK_CVE_MATCHES.filter((m) => m.event_id === id),
    };
  }

  const [eventRes, detectionsRes, matchesRes] = await Promise.all([
    client.from("public_events").select("*").eq("id", id).maybeSingle(),
    client.from("public_detections").select("*").eq("event_id", id),
    client.from("public_event_cve_matches").select("*").eq("event_id", id),
  ]);

  if (eventRes.error) throw new Error(`public_events detail failed: ${eventRes.error.message}`);
  if (detectionsRes.error) throw new Error(`public_detections query failed: ${detectionsRes.error.message}`);
  if (matchesRes.error) throw new Error(`public_event_cve_matches query failed: ${matchesRes.error.message}`);

  if (!eventRes.data) {
    return { sourceMode: "supabase", event: null, detections: [], cveMatches: [] };
  }

  return {
    sourceMode: "supabase",
    event: PublicEventSchema.parse(eventRes.data),
    detections: z.array(PublicDetectionSchema).parse(detectionsRes.data ?? []),
    cveMatches: z.array(PublicEventCveMatchSchema).parse(matchesRes.data ?? []),
  };
}

export async function getSensorsData(): Promise<SensorsPageData> {
  const client = getPublicSupabaseClient();
  const nowMs = client ? Date.now() : MOCK_REFERENCE_NOW_MS;

  if (!client) {
    const sensors: OverviewSensor[] = MOCK_SENSORS.map((sensor) => ({
      ...sensor,
      healthStatus: evaluateSensorHealth(sensor, nowMs),
    }));
    const activeOutages = MOCK_SENSOR_STATUS_EVENTS.filter(
      (event) => isCoverageGapStatus(event.status) && event.ended_at === null,
    );
    const hasAnyGap = MOCK_SENSOR_STATUS_EVENTS.some((event) => isCoverageGapStatus(event.status));
    return {
      sourceMode: "mock",
      evaluatedAt: new Date(nowMs).toISOString(),
      sensors,
      statusEvents: MOCK_SENSOR_STATUS_EVENTS,
      activeOutages,
      hasAnyGap,
    };
  }

  const since30d = new Date(nowMs - 30 * 24 * 60 * 60 * 1000).toISOString();
  const [sensorsRes, statusRes] = await Promise.all([
    client.from("public_sensors").select("*").order("created_at", { ascending: true }),
    client
      .from("public_sensor_status_events")
      .select("id, sensor_id, status, started_at, ended_at")
      .or(`ended_at.is.null,ended_at.gte.${since30d}`)
      .order("started_at", { ascending: false })
      .limit(100),
  ]);

  if (sensorsRes.error) throw new Error(`public_sensors query failed: ${sensorsRes.error.message}`);
  if (statusRes.error) throw new Error(`public_sensor_status_events query failed: ${statusRes.error.message}`);

  const parsedSensors = z.array(PublicSensorSchema).parse(sensorsRes.data ?? []);
  const sensors: OverviewSensor[] = parsedSensors.map((sensor) => ({
    ...sensor,
    healthStatus: evaluateSensorHealth(sensor, nowMs),
  }));
  const statusEvents = z.array(PublicSensorStatusEventSchema).parse(statusRes.data ?? []);
  const activeOutages = statusEvents.filter(
    (event) => isCoverageGapStatus(event.status) && event.ended_at === null,
  );
  const hasAnyGap = statusEvents.some((event) => isCoverageGapStatus(event.status));

  return {
    sourceMode: "supabase",
    evaluatedAt: new Date(nowMs).toISOString(),
    sensors,
    statusEvents,
    activeOutages,
    hasAnyGap,
  };
}
