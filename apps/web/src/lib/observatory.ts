import { createClient, type SupabaseClient } from "@supabase/supabase-js";
import { z } from "zod";
import {
  MOCK_CVE_MATCHES,
  MOCK_DAILY_STATS,
  MOCK_DETECTIONS,
  MOCK_EVENTS,
  MOCK_REFERENCE_NOW_MS,
  MOCK_SENSORS,
} from "./mock-data.ts";
import {
  buildDailySeries,
  buildHourlySeries,
  countEventsInWindow,
  dailyWindowStartDate,
  earliestTimestamp,
  eventMatchesExplorerFilters,
  eventsToDailyRows,
  latestTimestamp,
  parseEventCategory,
  parseEventPeriod,
  periodDayCount,
  periodLengthMs,
  topHttpPaths,
  topPatterns,
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
  type SensorHealthStatus,
  type TrendPeriod,
  type TrendsData,
} from "./types.ts";

export const HEARTBEAT_STALE_THRESHOLD_MS = 15 * 60 * 1000;
const OVERVIEW_SAMPLE_LIMIT = 5000;

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

function getPublicSupabaseClient(): SupabaseClient | null {
  if (process.env.USE_MOCK === "true") {
    return null;
  }
  const url = process.env.NEXT_PUBLIC_SUPABASE_URL;
  const anonKey = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY;
  if (!url || !anonKey) {
    return null;
  }
  return createClient(url, anonKey, {
    auth: { persistSession: false, autoRefreshToken: false },
  });
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
    return {
      sourceMode: "mock",
      totalEvents24h: MOCK_EVENTS.length,
      priorEvents24h: countEventsInWindow(
        MOCK_EVENTS.map((event) => event.observed_at),
        windowStart - 24 * 60 * 60 * 1000,
        windowStart,
      ),
      sampled24hCount: MOCK_EVENTS.length,
      is24hBreakdownSampled: false,
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
  const since24h = new Date(nowMs - 24 * 60 * 60 * 1000).toISOString();

  const since48h = new Date(nowMs - 48 * 60 * 60 * 1000).toISOString();
  const [sensorsRes, events24hRes, priorRes, recentRes] = await Promise.all([
    client.from("public_sensors").select("*").order("created_at", { ascending: true }),
    client
      .from("public_events")
      .select(
        "protocol, src_country, event_type, attack_category, http_method, http_path_redacted, received_at",
        { count: "exact" },
      )
      .gte("observed_at", since24h)
      .order("observed_at", { ascending: false })
      .limit(OVERVIEW_SAMPLE_LIMIT),
    client
      .from("public_events")
      .select("id", { count: "exact", head: true })
      .gte("observed_at", since48h)
      .lt("observed_at", since24h),
    client
      .from("public_events")
      .select("*")
      .order("observed_at", { ascending: false })
      .limit(12),
  ]);

  if (sensorsRes.error) throw new Error(`public_sensors query failed: ${sensorsRes.error.message}`);
  if (events24hRes.error) throw new Error(`public_events 24h query failed: ${events24hRes.error.message}`);
  if (priorRes.error) throw new Error(`public_events prior 24h query failed: ${priorRes.error.message}`);
  if (recentRes.error) throw new Error(`public_events recent query failed: ${recentRes.error.message}`);

  const parsedSensors = z.array(PublicSensorSchema).parse(sensorsRes.data ?? []);
  const sensors: OverviewSensor[] = parsedSensors.map((sensor) => ({
    ...sensor,
    healthStatus: evaluateSensorHealth(sensor, nowMs),
  }));
  const recentEvents = z.array(PublicEventSchema).parse(recentRes.data ?? []);
  const rows24h = z
    .array(
      z.object({
        protocol: ProtocolSchema,
        src_country: z.string().nullable(),
        event_type: z.string(),
        attack_category: AttackCategorySchema.nullable(),
        http_method: z.string().nullable(),
        http_path_redacted: z.string().nullable(),
        received_at: z.string(),
      }),
    )
    .parse(events24hRes.data ?? []);

  const summary = summarize24hRows(rows24h);
  const totalEvents24h = events24hRes.count ?? rows24h.length;

  return {
    sourceMode: "supabase",
    totalEvents24h,
    priorEvents24h: priorRes.count ?? 0,
    sampled24hCount: rows24h.length,
    is24hBreakdownSampled: totalEvents24h > rows24h.length,
    uniqueCountries24h: summary.uniqueCountries,
    activeSensorCount: sensors.filter((s) => s.is_active).length,
    healthySensorCount: sensors.filter((s) => s.healthStatus === "healthy").length,
    sensors,
    protocolBreakdown: summary.protocolBreakdown,
    regionTotals24h: summary.regionTotals,
    patterns24h: topPatterns(rows24h),
    httpPaths24h: topHttpPaths(rows24h),
    dataUpdatedAt: latestTimestamp(rows24h.map((row) => row.received_at)),
    recentEvents,
  };
}

export async function getTrendsData(period: TrendPeriod = "30d"): Promise<TrendsData> {
  const client = getPublicSupabaseClient();
  const nowMs = client ? Date.now() : MOCK_REFERENCE_NOW_MS;
  const windowStartMs = nowMs - periodLengthMs(period);

  const days = periodDayCount(period);
  const sinceDate = dailyWindowStartDate(nowMs, days);

  let dailyStats = MOCK_DAILY_STATS;
  let recentEvents = MOCK_EVENTS;
  let registeredSensorCount = MOCK_SENSORS.length;
  let historyStartedAt = earliestTimestamp([
    ...MOCK_EVENTS.map((event) => event.observed_at),
    ...MOCK_DAILY_STATS.map((row) => `${row.date_utc}T00:00:00.000Z`),
  ]);
  let eventMatchCount = MOCK_EVENTS.length;
  let sourceMode: "mock" | "supabase" = "mock";

  if (client) {
    sourceMode = "supabase";
    const sinceIso = new Date(windowStartMs).toISOString();
    const [statsRes, eventsRes, sensorsRes, oldestRes] = await Promise.all([
      client
        .from("public_daily_stats")
        .select("date_utc, sensor_id, protocol, event_type, event_count, unique_source_count")
        .gte("date_utc", sinceDate)
        .order("date_utc", { ascending: true })
        .limit(2000),
      client
        .from("public_events")
        .select("*", { count: "exact" })
        .gte("observed_at", sinceIso)
        .order("observed_at", { ascending: false })
        .limit(OVERVIEW_SAMPLE_LIMIT),
      client.from("public_sensors").select("id", { count: "exact", head: true }),
      client
        .from("public_events")
        .select("observed_at")
        .order("observed_at", { ascending: true })
        .limit(1),
    ]);

    if (statsRes.error) throw new Error(`public_daily_stats query failed: ${statsRes.error.message}`);
    if (eventsRes.error) throw new Error(`public_events trends query failed: ${eventsRes.error.message}`);
    if (sensorsRes.error) throw new Error(`public_sensors count failed: ${sensorsRes.error.message}`);
    if (oldestRes.error) throw new Error(`public_events history query failed: ${oldestRes.error.message}`);

    dailyStats = z.array(PublicDailyStatSchema).parse(statsRes.data ?? []);
    recentEvents = z.array(PublicEventSchema).parse(eventsRes.data ?? []);
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
  const windowStats = dailyStats.filter((row) => row.date_utc >= sinceDate);
  const useDailyStats = period !== "24h" && windowStats.length > 0;
  const series = useDailyStats
    ? buildDailySeries(
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
          eventsToDailyRows(
            windowEvents.map((event) => event.observed_at),
            windowStartMs,
            nowMs,
          ),
          nowMs,
          days,
        );

  const protocolMap = new Map<Protocol, number>();
  if (useDailyStats) {
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

  return {
    sourceMode,
    period,
    series,
    seriesSource: useDailyStats ? "daily_stats" : "events",
    historyStartedAt,
    dataUpdatedAt: latestTimestamp(windowEvents.map((event) => event.received_at)),
    registeredSensorCount,
    isEventSampled: eventMatchCount > windowEvents.length,
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
    patterns: topPatterns(windowEvents),
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
  if (!UUID_CHECK.safeParse(id).success) {
    return { sourceMode: getPublicSupabaseClient() ? "supabase" : "mock", event: null, detections: [], cveMatches: [] };
  }

  const client = getPublicSupabaseClient();

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
