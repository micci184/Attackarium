import { z } from "zod";

export const ProtocolSchema = z.enum([
  "ssh",
  "telnet",
  "ftp",
  "mysql",
  "redis",
  "http",
  "https",
  "other",
]);

export type Protocol = z.infer<typeof ProtocolSchema>;

export const PublicSensorSchema = z.object({
  id: z.string(),
  name: z.string(),
  type: z.enum(["opencanary", "http_collector", "combined"]),
  region: z.string(),
  is_active: z.boolean(),
  last_heartbeat_at: z.string().nullable(),
  last_event_at: z.string().nullable(),
  created_at: z.string(),
});

export type PublicSensor = z.infer<typeof PublicSensorSchema>;

/**
 * Strictly sanitized public projection of an observed event.
 * Never includes src_ip, src_ip_hash, credentials, raw_object_key, or raw metadata.
 */
export const PublicEventSchema = z.object({
  id: z.string().uuid(),
  sensor_id: z.string(),
  observed_at: z.string(),
  received_at: z.string(),
  protocol: ProtocolSchema,
  dst_port: z.number().int().min(1).max(65535),
  event_type: z.string(),
  src_country: z.string().nullable(),
  src_asn: z.string().nullable(),
  http_method: z.string().nullable(),
  http_path_redacted: z.string().nullable(),
  fingerprint: z.string().nullable(),
});

export type PublicEvent = z.infer<typeof PublicEventSchema>;

export const PublicDetectionSchema = z.object({
  id: z.string().uuid(),
  event_id: z.string().uuid(),
  rule_id: z.string(),
  rule_version: z.string(),
  classification: z.enum(["observed", "indicator_match", "candidate_cve"]),
  confidence: z.coerce.number().min(0).max(1),
  evidence_redacted: z.record(z.unknown()),
  created_at: z.string(),
});

export type PublicDetection = z.infer<typeof PublicDetectionSchema>;

export const PublicEventCveMatchSchema = z.object({
  id: z.string().uuid(),
  event_id: z.string().uuid(),
  cve_id: z.string(),
  detection_id: z.string().uuid(),
  match_type: z.enum(["candidate_cve", "indicator_match"]),
  confidence: z.coerce.number().min(0).max(1),
  reason: z.string(),
  created_at: z.string(),
  rule_id: z.string(),
  rule_version: z.string(),
  kev_present: z.boolean(),
  epss_score: z.coerce.number().nullable(),
  epss_percentile: z.coerce.number().nullable(),
  epss_date: z.string().nullable(),
});

export type PublicEventCveMatch = z.infer<typeof PublicEventCveMatchSchema>;

export const PublicDailyStatSchema = z.object({
  date_utc: z.string(),
  sensor_id: z.string(),
  protocol: ProtocolSchema,
  event_type: z.string(),
  event_count: z.number().int().min(0),
  unique_source_count: z.number().int().min(0),
});

export type PublicDailyStat = z.infer<typeof PublicDailyStatSchema>;

export interface OverviewData {
  sourceMode: "mock" | "supabase";
  totalEvents24h: number;
  uniqueCountries24h: number;
  activeSensorCount: number;
  sensors: PublicSensor[];
  protocolBreakdown: Array<{ protocol: Protocol; count: number; sharePct: number }>;
  regionTotals24h: Array<{ country: string; count: number }>;
  recentEvents: PublicEvent[];
}

export interface TrendsData {
  sourceMode: "mock" | "supabase";
  dailySeries: Array<{ dateUtc: string; totalEvents: number; uniqueSources: number }>;
  protocolTotals: Array<{ protocol: Protocol; count: number }>;
  portTotals: Array<{ dstPort: number; protocol: Protocol; count: number }>;
  regionTotals: Array<{ country: string; count: number }>;
  asnTotals: Array<{ asn: string; count: number }>;
}

export interface PaginatedEventsResult {
  sourceMode: "mock" | "supabase";
  items: PublicEvent[];
  page: number;
  pageSize: number;
  totalCount: number;
  totalPages: number;
  protocolFilter: Protocol | "all";
}

export interface EventDetailData {
  sourceMode: "mock" | "supabase";
  event: PublicEvent | null;
  detections: PublicDetection[];
  cveMatches: PublicEventCveMatch[];
}
