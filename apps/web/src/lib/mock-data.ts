import type {
  AttackCategory,
  Protocol,
  PublicDailyStat,
  PublicDetection,
  PublicEvent,
  PublicEventCveMatch,
  PublicSensor,
  PublicSensorStatusEvent,
  PublicVulnerability,
} from "./types.ts";

// Deterministic synthetic fixtures for local/preview UI verification.
// Never contains real attacker IPs, real credentials, or raw payloads.

export const MOCK_REFERENCE_NOW_MS = Date.parse("2026-11-21T09:50:00.000Z");
const BASE_MS = MOCK_REFERENCE_NOW_MS;

export const MOCK_SENSORS: PublicSensor[] = [
  {
    id: "sensor-synthetic-01",
    name: "Synthetic Observatory Node 01",
    type: "combined",
    region: "us-east-1 (synthetic)",
    is_active: true,
    last_heartbeat_at: new Date(BASE_MS - 35_000).toISOString(),
    last_event_at: new Date(BASE_MS - 42_000).toISOString(),
    created_at: "2026-11-01T00:00:00.000Z",
    monitored_services: ["ssh", "telnet", "ftp", "mysql", "redis", "http", "https"],
    last_error_at: null,
  },
];

export const MOCK_SENSOR_STATUS_EVENTS: PublicSensorStatusEvent[] = [
  {
    id: "40000000-0000-4000-8000-000000000001",
    sensor_id: "sensor-synthetic-01",
    status: "offline",
    started_at: "2026-11-19T03:00:00.000Z",
    ended_at: "2026-11-19T05:30:00.000Z",
  },
];

const EVENT_TEMPLATES: Array<{
  protocol: Protocol;
  dst_port: number;
  event_type: string;
  src_country: string;
  src_asn: string;
  http_method: string | null;
  http_path_redacted: string | null;
  fingerprint: string;
}> = [
  {
    protocol: "ssh",
    dst_port: 22,
    event_type: "ssh_login_attempt",
    src_country: "JP",
    src_asn: "AS64512",
    http_method: null,
    http_path_redacted: null,
    fingerprint: "ssh-openssh-synth-01",
  },
  {
    protocol: "http",
    dst_port: 80,
    event_type: "http_cms_probe",
    src_country: "US",
    src_asn: "AS64513",
    http_method: "GET",
    http_path_redacted: "/wp-login.php?user=admin&password=[REDACTED]",
    fingerprint: "http-wp-probe-02",
  },
  {
    protocol: "https",
    dst_port: 443,
    event_type: "http_env_probe",
    src_country: "DE",
    src_asn: "AS64514",
    http_method: "GET",
    http_path_redacted: "/.env?api_key=[REDACTED]",
    fingerprint: "https-dotenv-03",
  },
  {
    protocol: "http",
    dst_port: 80,
    event_type: "http_router_probe",
    src_country: "SG",
    src_asn: "AS64515",
    http_method: "POST",
    http_path_redacted: "/cgi-bin/luci/;stok=[REDACTED]/admin/sysauth",
    fingerprint: "http-luci-probe-04",
  },
  {
    protocol: "telnet",
    dst_port: 23,
    event_type: "telnet_login_attempt",
    src_country: "NL",
    src_asn: "AS64516",
    http_method: null,
    http_path_redacted: null,
    fingerprint: "telnet-mirai-like-05",
  },
  {
    protocol: "mysql",
    dst_port: 3306,
    event_type: "mysql_handshake",
    src_country: "FR",
    src_asn: "AS64517",
    http_method: null,
    http_path_redacted: null,
    fingerprint: "mysql-proto10-06",
  },
  {
    protocol: "redis",
    dst_port: 6379,
    event_type: "redis_command_probe",
    src_country: "GB",
    src_asn: "AS64518",
    http_method: null,
    http_path_redacted: null,
    fingerprint: "redis-info-07",
  },
  {
    protocol: "ftp",
    dst_port: 21,
    event_type: "ftp_anonymous_probe",
    src_country: "US",
    src_asn: "AS64519",
    http_method: null,
    http_path_redacted: null,
    fingerprint: "ftp-anon-08",
  },
  {
    // Hostile-input rendering test case: XSS / prompt-injection-like string
    protocol: "https",
    dst_port: 443,
    event_type: "http_suspicious_query",
    src_country: "KR",
    src_asn: "AS64520",
    http_method: "GET",
    http_path_redacted:
      "/search?q=<script>alert(1)</script>&note=Ignore+previous+instructions",
    fingerprint: "https-hostile-text-09",
  },
];

function synthUuid(n: number): string {
  return `10000000-0000-4000-8000-${n.toString(16).padStart(12, "0")}`;
}

function mockAttackCategory(protocol: Protocol): AttackCategory | null {
  if (protocol === "http" || protocol === "https") return "http_path_probe";
  if (protocol === "redis") return null;
  return "auth_attempt";
}

export const MOCK_EVENTS: PublicEvent[] = Array.from({ length: 36 }, (_, idx) => {
  const tpl = EVENT_TEMPLATES[idx % EVENT_TEMPLATES.length];
  const observedMs = BASE_MS - idx * 14 * 60 * 1000;
  return {
    id: synthUuid(idx + 1),
    sensor_id: "sensor-synthetic-01",
    observed_at: new Date(observedMs).toISOString(),
    received_at: new Date(observedMs + 2_000).toISOString(),
    protocol: tpl.protocol,
    dst_port: tpl.dst_port,
    event_type: tpl.event_type,
    src_country: tpl.src_country,
    src_asn: tpl.src_asn,
    http_method: tpl.http_method,
    http_path_redacted: tpl.http_path_redacted,
    fingerprint: tpl.fingerprint,
    attack_category: mockAttackCategory(tpl.protocol),
  };
});

export const MOCK_DETECTIONS: PublicDetection[] = [
  {
    id: "20000000-0000-4000-8000-000000000001",
    event_id: synthUuid(4),
    rule_id: "http-cgi-luci-probe",
    rule_version: "1.0.0",
    classification: "candidate_cve",
    confidence: 0.62,
    evidence_redacted: {
      indicator: "luci_cgi_path",
      matched_location: "url",
      match_strength: "medium",
      summary: "URI pattern matches common router probing; does NOT prove exploit success.",
    },
    created_at: new Date(BASE_MS - 3 * 14 * 60 * 1000 + 5_000).toISOString(),
  },
  {
    id: "20000000-0000-4000-8000-000000000002",
    event_id: synthUuid(2),
    rule_id: "http-wp-login-scan",
    rule_version: "1.0.0",
    classification: "indicator_match",
    confidence: 0.85,
    evidence_redacted: {
      indicator: "wp_login_path",
      matched_location: "url",
      match_strength: "high",
      summary: "WordPress login path probe.",
    },
    created_at: new Date(BASE_MS - 14 * 60 * 1000 + 5_000).toISOString(),
  },
];

export const MOCK_CVE_MATCHES: PublicEventCveMatch[] = [
  {
    id: "30000000-0000-4000-8000-000000000001",
    event_id: synthUuid(4),
    cve_id: "CVE-2023-1389",
    detection_id: "20000000-0000-4000-8000-000000000001",
    match_type: "candidate_cve",
    confidence: 0.62,
    reason:
      "Observed HTTP probe path resembles router command-injection scanning patterns. Candidate hypothesis only (not proof of exploitation).",
    created_at: new Date(BASE_MS - 3 * 14 * 60 * 1000 + 8_000).toISOString(),
    rule_id: "http-cgi-luci-probe",
    rule_version: "1.0.0",
    kev_present: true,
    epss_score: 0.9412,
    epss_percentile: 0.996,
    epss_date: "2026-11-21",
    evaluated_at: new Date(BASE_MS - 3 * 14 * 60 * 1000 + 8_000).toISOString(),
    // The event behind this match (synthUuid(4)) was observed 3 * 14 minutes ago.
    observed_at: new Date(BASE_MS - 3 * 14 * 60 * 1000).toISOString(),
    match_strength: "medium",
    indicator: "luci_cgi_path",
    matched_location: "url",
  },
];

export const MOCK_VULNERABILITIES: PublicVulnerability[] = [
  {
    cve_id: "CVE-2023-1389",
    description:
      "Synthetic NVD summary: command-injection pattern associated with router web management interfaces.",
    vendor: "tp-link",
    product: "archer_ax21",
    kev_present: true,
    kev_added_at: "2023-05-01T00:00:00.000Z",
    kev_updated_at: "2026-11-21T08:15:00.000Z",
    epss_score: 0.9412,
    epss_percentile: 0.996,
    epss_date: "2026-11-21",
    source_updated_at: "2026-11-21T08:20:00.000Z",
    matched_event_count: 1,
    max_confidence: 0.62,
    last_matched_at: new Date(BASE_MS - 3 * 14 * 60 * 1000 + 8_000).toISOString(),
    last_observed_at: new Date(BASE_MS - 3 * 14 * 60 * 1000).toISOString(),
    published_at: "2023-04-27T17:15:00.000Z",
    cvss_score: 8.8,
    cvss_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
  },
  {
    // Unmatched catalog entry: must never surface in evidence-gated views.
    cve_id: "CVE-2024-99999",
    description: "Unmatched synthetic vulnerability that should never be displayed.",
    vendor: "example",
    product: "unmatched",
    kev_present: true,
    kev_added_at: "2024-01-01T00:00:00.000Z",
    kev_updated_at: "2026-11-21T08:15:00.000Z",
    epss_score: 0.99,
    epss_percentile: 0.999,
    epss_date: "2026-11-21",
    source_updated_at: "2026-11-21T08:20:00.000Z",
    matched_event_count: 0,
    max_confidence: null,
    last_matched_at: null,
    last_observed_at: null,
    published_at: "2024-01-01T00:00:00.000Z",
    cvss_score: 9.8,
    cvss_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
  },
];

export const MOCK_DAILY_STATS: PublicDailyStat[] = [
  { date_utc: "2026-11-15", sensor_id: "sensor-synthetic-01", protocol: "ssh", event_type: "ssh_login_attempt", event_count: 142, unique_source_count: 38 },
  { date_utc: "2026-11-15", sensor_id: "sensor-synthetic-01", protocol: "http", event_type: "http_cms_probe", event_count: 96, unique_source_count: 29 },
  { date_utc: "2026-11-15", sensor_id: "sensor-synthetic-01", protocol: "telnet", event_type: "telnet_login_attempt", event_count: 54, unique_source_count: 17 },
  { date_utc: "2026-11-16", sensor_id: "sensor-synthetic-01", protocol: "ssh", event_type: "ssh_login_attempt", event_count: 168, unique_source_count: 44 },
  { date_utc: "2026-11-16", sensor_id: "sensor-synthetic-01", protocol: "http", event_type: "http_cms_probe", event_count: 112, unique_source_count: 35 },
  { date_utc: "2026-11-16", sensor_id: "sensor-synthetic-01", protocol: "https", event_type: "http_env_probe", event_count: 48, unique_source_count: 19 },
  { date_utc: "2026-11-17", sensor_id: "sensor-synthetic-01", protocol: "ssh", event_type: "ssh_login_attempt", event_count: 129, unique_source_count: 33 },
  { date_utc: "2026-11-17", sensor_id: "sensor-synthetic-01", protocol: "http", event_type: "http_router_probe", event_count: 134, unique_source_count: 41 },
  { date_utc: "2026-11-17", sensor_id: "sensor-synthetic-01", protocol: "redis", event_type: "redis_command_probe", event_count: 27, unique_source_count: 11 },
  { date_utc: "2026-11-18", sensor_id: "sensor-synthetic-01", protocol: "ssh", event_type: "ssh_login_attempt", event_count: 185, unique_source_count: 51 },
  { date_utc: "2026-11-18", sensor_id: "sensor-synthetic-01", protocol: "http", event_type: "http_cms_probe", event_count: 120, unique_source_count: 39 },
  { date_utc: "2026-11-18", sensor_id: "sensor-synthetic-01", protocol: "mysql", event_type: "mysql_handshake", event_count: 31, unique_source_count: 14 },
  { date_utc: "2026-11-19", sensor_id: "sensor-synthetic-01", protocol: "ssh", event_type: "ssh_login_attempt", event_count: 158, unique_source_count: 42 },
  { date_utc: "2026-11-19", sensor_id: "sensor-synthetic-01", protocol: "https", event_type: "http_env_probe", event_count: 89, unique_source_count: 28 },
  { date_utc: "2026-11-19", sensor_id: "sensor-synthetic-01", protocol: "telnet", event_type: "telnet_login_attempt", event_count: 73, unique_source_count: 24 },
  { date_utc: "2026-11-20", sensor_id: "sensor-synthetic-01", protocol: "ssh", event_type: "ssh_login_attempt", event_count: 204, unique_source_count: 58 },
  { date_utc: "2026-11-20", sensor_id: "sensor-synthetic-01", protocol: "http", event_type: "http_router_probe", event_count: 147, unique_source_count: 45 },
  { date_utc: "2026-11-20", sensor_id: "sensor-synthetic-01", protocol: "ftp", event_type: "ftp_anonymous_probe", event_count: 22, unique_source_count: 9 },
  { date_utc: "2026-11-21", sensor_id: "sensor-synthetic-01", protocol: "ssh", event_type: "ssh_login_attempt", event_count: 176, unique_source_count: 49 },
  { date_utc: "2026-11-21", sensor_id: "sensor-synthetic-01", protocol: "http", event_type: "http_cms_probe", event_count: 138, unique_source_count: 40 },
  { date_utc: "2026-11-21", sensor_id: "sensor-synthetic-01", protocol: "https", event_type: "http_env_probe", event_count: 64, unique_source_count: 23 },
];
