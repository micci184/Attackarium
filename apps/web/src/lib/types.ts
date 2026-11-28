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

export const AttackCategorySchema = z.enum([
  "port_scan",
  "auth_attempt",
  "http_path_probe",
  "web_attack_attempt",
  "suspected_cve_probe",
]);

export type AttackCategory = z.infer<typeof AttackCategorySchema>;

export const TREND_PERIODS = ["24h", "7d", "30d"] as const;

export type TrendPeriod = (typeof TREND_PERIODS)[number];

export const SensorStatusEventTypeSchema = z.enum([
  "healthy",
  "degraded",
  "offline",
  "error",
]);

export type SensorStatusEventType = z.infer<typeof SensorStatusEventTypeSchema>;

export const PublicSensorSchema = z.object({
  id: z.string(),
  name: z.string(),
  type: z.enum(["opencanary", "http_collector", "combined"]),
  region: z.string(),
  is_active: z.boolean(),
  last_heartbeat_at: z.string().nullable(),
  last_event_at: z.string().nullable(),
  created_at: z.string(),
  monitored_services: z.array(ProtocolSchema).optional().default([]),
  last_error_at: z.string().nullable().optional().default(null),
});

export type PublicSensor = z.infer<typeof PublicSensorSchema>;

export const PublicSensorStatusEventSchema = z.object({
  id: z.uuid(),
  sensor_id: z.string(),
  status: SensorStatusEventTypeSchema,
  started_at: z.string(),
  ended_at: z.string().nullable(),
});

export type PublicSensorStatusEvent = z.infer<typeof PublicSensorStatusEventSchema>;

/**
 * Strictly sanitized public projection of an observed event.
 * Never includes src_ip, src_ip_hash, credentials, raw_object_key, or raw metadata.
 */
export const PublicEventSchema = z.object({
  id: z.uuid(),
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
  attack_category: AttackCategorySchema.nullable().optional(),
});

export type PublicEvent = z.infer<typeof PublicEventSchema>;

/** Rule-defined evidence grade (not a probability). */
export const MatchStrengthSchema = z.enum(["high", "medium", "low"]);
export type MatchStrength = z.infer<typeof MatchStrengthSchema>;

export const PublicDetectionSchema = z.object({
  id: z.uuid(),
  event_id: z.uuid(),
  rule_id: z.string(),
  rule_version: z.string(),
  classification: z.enum(["observed", "indicator_match", "candidate_cve"]),
  confidence: z.coerce.number().min(0).max(1),
  evidence_redacted: z.record(z.string(), z.unknown()),
  created_at: z.string(),
});

export type PublicDetection = z.infer<typeof PublicDetectionSchema>;

export const PublicEventCveMatchSchema = z.object({
  id: z.uuid(),
  event_id: z.uuid(),
  cve_id: z.string(),
  detection_id: z.uuid(),
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
  evaluated_at: z.string().nullable().optional().default(null),
  // #84: when the probe was observed (time-series basis), the rule-defined
  // evidence grade, and the evidence basis. Defaults keep older rows parsing.
  observed_at: z.string().nullable().optional().default(null),
  match_strength: MatchStrengthSchema.nullable().optional().default(null),
  indicator: z.string().nullable().optional().default(null),
  matched_location: z.string().nullable().optional().default(null),
});

export type PublicEventCveMatch = z.infer<typeof PublicEventCveMatchSchema>;

export const PublicVulnerabilitySchema = z.object({
  cve_id: z.string(),
  description: z.string().nullable(),
  vendor: z.string().nullable(),
  product: z.string().nullable(),
  kev_present: z.boolean(),
  kev_updated_at: z.string().nullable(),
  epss_score: z.coerce.number().nullable(),
  epss_percentile: z.coerce.number().nullable(),
  epss_date: z.string().nullable(),
  source_updated_at: z.string().nullable(),
  matched_event_count: z.coerce.number().int().nonnegative(),
  max_confidence: z.coerce.number().min(0).max(1).nullable(),
  last_matched_at: z.string().nullable(),
  published_at: z.string().nullable().optional().default(null),
  cvss_score: z.coerce.number().nullable().optional().default(null),
  cvss_vector: z.string().nullable().optional().default(null),
  kev_added_at: z.string().nullable().optional().default(null),
  last_observed_at: z.string().nullable().optional().default(null),
});

export type PublicVulnerability = z.infer<typeof PublicVulnerabilitySchema>;

export interface EnrichedEventCveMatch extends PublicEventCveMatch {
  description: string | null;
  vendor: string | null;
  product: string | null;
  published_at: string | null;
  cvss_score: number | null;
  cvss_vector: string | null;
  kev_added_at: string | null;
  kev_updated_at: string | null;
  source_updated_at: string | null;
}

export interface PatternCveContext {
  cveId: string;
  ruleId: string;
  ruleVersion: string;
  /** Strongest rule-defined evidence grade among the matches (null = ungraded). */
  matchStrength: MatchStrength | null;
  /** Evidence basis of that strongest match. */
  indicator: string | null;
  matchedLocation: string | null;
  /** Internal rule score (0-1). Not a probability; kept for ordering and MCP. */
  maxConfidence: number;
  matchedEventCount: number;
  /** Latest OBSERVATION time of a matched event (not the matcher write time). */
  lastObservedAt: string;
  kevPresent: boolean;
  kevAddedAt: string | null;
  kevUpdatedAt: string | null;
  epssScore: number | null;
  epssPercentile: number | null;
  epssDate: string | null;
  cvssScore: number | null;
  vendor: string | null;
  product: string | null;
  description: string | null;
  reason: string;
  eventsHref: string;
}

export const PublicDailyStatSchema = z.object({
  date_utc: z.string(),
  sensor_id: z.string(),
  protocol: ProtocolSchema,
  event_type: z.string(),
  event_count: z.number().int().min(0),
  unique_source_count: z.number().int().min(0),
});

export type PublicDailyStat = z.infer<typeof PublicDailyStatSchema>;

export type SensorHealthStatus = "healthy" | "stale" | "inactive";

export interface OverviewSensor extends PublicSensor {
  healthStatus: SensorHealthStatus;
}

export interface PatternTotal {
  key: string;
  label: string;
  protocol: Protocol;
  count: number;
  eventsHref?: string;
}

export interface NoteworthyObservation {
  id: string;
  kind: "change" | "first_seen" | "summary";
  title: string;
  detail: string;
  rationale?: string;
  severity?: "primary" | "secondary";
  protocol: Protocol;
  currentCount: number;
  priorCount: number;
  delta: number;
  showPercent: boolean;
  comparisonReliable: boolean;
  href: string;
}

export interface HttpPathTotal {
  method: string;
  path: string;
  count: number;
  /** Distinct sources that sent this path (30-day window), when known (#88). */
  sources?: number;
}

export interface TrendBucket {
  bucketStart: string;
  label: string;
  totalEvents: number;
  hasCoverageGap?: boolean;
  gapStatuses?: SensorStatusEventType[];
  isPreHistory?: boolean;
  isObservationStart?: boolean;
}

export interface OverviewData {
  sourceMode: "mock" | "supabase";
  totalEvents24h: number;
  priorEvents24h: number;
  historyStartedAt: string | null;
  hasPriorWindowBaseline: boolean;
  coverageGapIn24h: boolean;
  coverageGapInPrior24h: boolean;
  activeOutages: PublicSensorStatusEvent[];
  sampled24hCount: number;
  is24hBreakdownSampled: boolean;
  /** False when an aggregate read stopped at the safety cap. Totals are then partial. */
  aggregateComplete: boolean;
  /** Events in the 24h UTC window not yet reflected in hourly rollups (e.g. recent <15m or unclassified). */
  rollupPendingEvents24h: number;
  hourlySeries: TrendBucket[];
  noteworthy: NoteworthyObservation[];
  uniqueCountries24h: number;
  activeSensorCount: number;
  healthySensorCount: number;
  sensors: OverviewSensor[];
  protocolBreakdown: Array<{ protocol: Protocol; count: number; sharePct: number }>;
  regionTotals24h: Array<{ country: string; count: number }>;
  patterns24h: PatternTotal[];
  patternCveContext24h: PatternCveContext[];
  httpPaths24h: HttpPathTotal[];
  dataUpdatedAt: string | null;
  recentEvents: PublicEvent[];
}

export interface TrendsData {
  sourceMode: "mock" | "supabase";
  period: TrendPeriod;
  series: TrendBucket[];
  seriesSource: "events" | "daily_stats" | "event_aggregates";
  aggregateComplete: boolean;
  /** Events in the active 24h UTC window not yet reflected in hourly rollups. */
  rollupPendingEvents: number;
  historyStartedAt: string | null;
  dataUpdatedAt: string | null;
  registeredSensorCount: number;
  isEventSampled: boolean;
  coverageGaps: PublicSensorStatusEvent[];
  protocolTotals: Array<{ protocol: Protocol; count: number }>;
  portTotals: Array<{ dstPort: number; protocol: Protocol; count: number }>;
  regionTotals: Array<{ country: string; count: number }>;
  asnTotals: Array<{ asn: string; count: number }>;
  patterns: PatternTotal[];
  patternCveContext: PatternCveContext[];
  httpPaths: HttpPathTotal[];
}

export interface SensorsPageData {
  sourceMode: "mock" | "supabase";
  evaluatedAt: string;
  sensors: OverviewSensor[];
  statusEvents: PublicSensorStatusEvent[];
  activeOutages: PublicSensorStatusEvent[];
  hasAnyGap: boolean;
}

export type EventPeriodFilter = TrendPeriod | "all";

export type EventCategoryFilter = AttackCategory | "unclassified" | "all";

export interface PaginatedEventsResult {
  sourceMode: "mock" | "supabase";
  items: PublicEvent[];
  page: number;
  pageSize: number;
  totalCount: number;
  totalPages: number;
  protocolFilter: Protocol | "all";
  periodFilter: EventPeriodFilter;
  categoryFilter: EventCategoryFilter;
  /** Candidate CVE filter (validated CVE id) or null. */
  cveFilter: string | null;
}

export interface EventDetailData {
  sourceMode: "mock" | "supabase";
  event: PublicEvent | null;
  detections: PublicDetection[];
  cveMatches: EnrichedEventCveMatch[];
}
