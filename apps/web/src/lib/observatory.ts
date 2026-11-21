import { createClient, type SupabaseClient } from "@supabase/supabase-js";
import { z } from "zod";
import {
  MOCK_CVE_MATCHES,
  MOCK_DAILY_STATS,
  MOCK_DETECTIONS,
  MOCK_EVENTS,
  MOCK_SENSORS,
} from "./mock-data.ts";
import {
  type EventDetailData,
  type OverviewData,
  type PaginatedEventsResult,
  type Protocol,
  ProtocolSchema,
  PublicDailyStatSchema,
  PublicDetectionSchema,
  PublicEventCveMatchSchema,
  PublicEventSchema,
  PublicSensorSchema,
  type TrendsData,
} from "./types.ts";

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

function summarizeProtocols(
  events: Array<{ protocol: Protocol }>,
): Array<{ protocol: Protocol; count: number; sharePct: number }> {
  const counts = new Map<Protocol, number>();
  for (const ev of events) {
    counts.set(ev.protocol, (counts.get(ev.protocol) ?? 0) + 1);
  }
  const total = events.length || 1;
  return Array.from(counts.entries())
    .map(([protocol, count]) => ({
      protocol,
      count,
      sharePct: Math.round((count / total) * 1000) / 10,
    }))
    .sort((a, b) => b.count - a.count);
}

function summarizeRegions(
  events: Array<{ src_country: string | null }>,
): Array<{ country: string; count: number }> {
  const counts = new Map<string, number>();
  for (const ev of events) {
    const code = ev.src_country ?? "UNKNOWN";
    counts.set(code, (counts.get(code) ?? 0) + 1);
  }
  return Array.from(counts.entries())
    .map(([country, count]) => ({ country, count }))
    .sort((a, b) => b.count - a.count);
}

export async function getOverviewData(): Promise<OverviewData> {
  const client = getPublicSupabaseClient();

  if (!client) {
    const recentEvents = MOCK_EVENTS.slice(0, 12);
    const regionTotals24h = summarizeRegions(MOCK_EVENTS);
    const countries = new Set(
      MOCK_EVENTS.map((e) => e.src_country).filter((c): c is string => Boolean(c)),
    );
    return {
      sourceMode: "mock",
      totalEvents24h: MOCK_EVENTS.length,
      uniqueCountries24h: countries.size,
      activeSensorCount: MOCK_SENSORS.filter((s) => s.is_active).length,
      sensors: MOCK_SENSORS,
      protocolBreakdown: summarizeProtocols(MOCK_EVENTS),
      regionTotals24h,
      recentEvents,
    };
  }

  const since24h = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString();

  const [sensorsRes, events24hRes, recentRes] = await Promise.all([
    client.from("public_sensors").select("*").order("created_at", { ascending: true }),
    client
      .from("public_events")
      .select("protocol, src_country")
      .gte("observed_at", since24h)
      .limit(5000),
    client
      .from("public_events")
      .select("*")
      .order("observed_at", { ascending: false })
      .limit(12),
  ]);

  if (sensorsRes.error) throw new Error(`public_sensors query failed: ${sensorsRes.error.message}`);
  if (events24hRes.error) throw new Error(`public_events 24h query failed: ${events24hRes.error.message}`);
  if (recentRes.error) throw new Error(`public_events recent query failed: ${recentRes.error.message}`);

  const sensors = z.array(PublicSensorSchema).parse(sensorsRes.data ?? []);
  const recentEvents = z.array(PublicEventSchema).parse(recentRes.data ?? []);
  const rows24h = z
    .array(z.object({ protocol: ProtocolSchema, src_country: z.string().nullable() }))
    .parse(events24hRes.data ?? []);

  const countries = new Set(
    rows24h.map((r) => r.src_country).filter((c): c is string => Boolean(c)),
  );

  return {
    sourceMode: "supabase",
    totalEvents24h: rows24h.length,
    uniqueCountries24h: countries.size,
    activeSensorCount: sensors.filter((s) => s.is_active).length,
    sensors,
    protocolBreakdown: summarizeProtocols(rows24h),
    regionTotals24h: summarizeRegions(rows24h),
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

  const dailyMap = new Map<string, { totalEvents: number; uniqueSources: number }>();
  const protocolMap = new Map<Protocol, number>();

  for (const row of dailyStats) {
    const existing = dailyMap.get(row.date_utc) ?? { totalEvents: 0, uniqueSources: 0 };
    existing.totalEvents += row.event_count;
    existing.uniqueSources += row.unique_source_count;
    dailyMap.set(row.date_utc, existing);

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
      .map(([dateUtc, v]) => ({ dateUtc, ...v }))
      .sort((a, b) => a.dateUtc.localeCompare(b.dateUtc)),
    protocolTotals: Array.from(protocolMap.entries())
      .map(([protocol, count]) => ({ protocol, count }))
      .sort((a, b) => b.count - a.count),
    portTotals: Array.from(portMap.values())
      .sort((a, b) => b.count - a.count)
      .slice(0, 10),
    regionTotals: Array.from(regionMap.entries())
      .map(([country, count]) => ({ country, count }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 10),
    asnTotals: Array.from(asnMap.entries())
      .map(([asn, count]) => ({ asn, count }))
      .sort((a, b) => b.count - a.count)
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

const UUID_CHECK = z.string().uuid();

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
