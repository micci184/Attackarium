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
    return {
      sourceMode: "mock",
      totalEvents24h: MOCK_EVENTS.length,
      sampled24hCount: MOCK_EVENTS.length,
      is24hBreakdownSampled: false,
      uniqueCountries24h: summary.uniqueCountries,
      activeSensorCount: sensors.filter((s) => s.is_active).length,
      healthySensorCount: sensors.filter((s) => s.healthStatus === "healthy").length,
      sensors,
      protocolBreakdown: summary.protocolBreakdown,
      regionTotals24h: summary.regionTotals,
      recentEvents,
    };
  }

  const nowMs = Date.now();
  const since24h = new Date(nowMs - 24 * 60 * 60 * 1000).toISOString();

  const [sensorsRes, events24hRes, recentRes] = await Promise.all([
    client.from("public_sensors").select("*").order("created_at", { ascending: true }),
    client
      .from("public_events")
      .select("protocol, src_country", { count: "exact" })
      .gte("observed_at", since24h)
      .order("observed_at", { ascending: false })
      .limit(OVERVIEW_SAMPLE_LIMIT),
    client
      .from("public_events")
      .select("*")
      .order("observed_at", { ascending: false })
      .limit(12),
  ]);

  if (sensorsRes.error) throw new Error(`public_sensors query failed: ${sensorsRes.error.message}`);
  if (events24hRes.error) throw new Error(`public_events 24h query failed: ${events24hRes.error.message}`);
  if (recentRes.error) throw new Error(`public_events recent query failed: ${recentRes.error.message}`);

  const parsedSensors = z.array(PublicSensorSchema).parse(sensorsRes.data ?? []);
  const sensors: OverviewSensor[] = parsedSensors.map((sensor) => ({
    ...sensor,
    healthStatus: evaluateSensorHealth(sensor, nowMs),
  }));
  const recentEvents = z.array(PublicEventSchema).parse(recentRes.data ?? []);
  const rows24h = z
    .array(z.object({ protocol: ProtocolSchema, src_country: z.string().nullable() }))
    .parse(events24hRes.data ?? []);

  const summary = summarize24hRows(rows24h);
  const totalEvents24h = events24hRes.count ?? rows24h.length;

  return {
    sourceMode: "supabase",
    totalEvents24h,
    sampled24hCount: rows24h.length,
    is24hBreakdownSampled: totalEvents24h > rows24h.length,
    uniqueCountries24h: summary.uniqueCountries,
    activeSensorCount: sensors.filter((s) => s.is_active).length,
    healthySensorCount: sensors.filter((s) => s.healthStatus === "healthy").length,
    sensors,
    protocolBreakdown: summary.protocolBreakdown,
    regionTotals24h: summary.regionTotals,
    recentEvents,
  };
}

export async function getTrendsData(): Promise<TrendsData> {
  const client = getPublicSupabaseClient();

  let dailyStats = MOCK_DAILY_STATS;
  let recentEvents = MOCK_EVENTS;
  let sourceMode: "mock" | "supabase" = "mock";

  if (client) {
    sourceMode = "supabase";
    const [statsRes, eventsRes] = await Promise.all([
      client
        .from("public_daily_stats")
        .select("*")
        .order("date_utc", { ascending: true })
        .limit(500),
      client
        .from("public_events")
        .select("*")
        .order("observed_at", { ascending: false })
        .limit(1000),
    ]);

    if (statsRes.error) throw new Error(`public_daily_stats query failed: ${statsRes.error.message}`);
    if (eventsRes.error) throw new Error(`public_events trends query failed: ${eventsRes.error.message}`);

    dailyStats = z.array(PublicDailyStatSchema).parse(statsRes.data ?? []);
    recentEvents = z.array(PublicEventSchema).parse(eventsRes.data ?? []);
  }

  // Note: daily_stats rows are keyed by (date_utc, sensor_id, protocol, event_type).
  // Event counts are additive across buckets, whereas unique_source_count is NOT
  // additive across buckets (a single source can appear in multiple buckets), so
  // dailySeries aggregates totalEvents only.
  const dailyMap = new Map<string, number>();
  const protocolMap = new Map<Protocol, number>();

  for (const row of dailyStats) {
    dailyMap.set(row.date_utc, (dailyMap.get(row.date_utc) ?? 0) + row.event_count);
    protocolMap.set(row.protocol, (protocolMap.get(row.protocol) ?? 0) + row.event_count);
  }

  const portMap = new Map<string, { dstPort: number; protocol: Protocol; count: number }>();
  const regionMap = new Map<string, number>();
  const asnMap = new Map<string, number>();

  for (const ev of recentEvents) {
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
    dailySeries: Array.from(dailyMap.entries())
      .map(([dateUtc, totalEvents]) => ({ dateUtc, totalEvents }))
      .toSorted((a, b) => a.dateUtc.localeCompare(b.dateUtc)),
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
  };
}

export async function getPaginatedEvents(options: {
  page?: number;
  pageSize?: number;
  protocol?: string;
}): Promise<PaginatedEventsResult> {
  const pageSize = Math.min(Math.max(options.pageSize ?? 12, 1), 50);
  const requestedPage = Math.max(options.page ?? 1, 1);
  const parsedProtocol = ProtocolSchema.safeParse(options.protocol);
  const protocolFilter: Protocol | "all" = parsedProtocol.success ? parsedProtocol.data : "all";

  const client = getPublicSupabaseClient();

  if (!client) {
    const filtered =
      protocolFilter === "all"
        ? MOCK_EVENTS
        : MOCK_EVENTS.filter((ev) => ev.protocol === protocolFilter);
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
