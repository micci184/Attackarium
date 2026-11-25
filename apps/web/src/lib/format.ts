const JST_DATETIME_FORMATTER = new Intl.DateTimeFormat("ja-JP", {
  timeZone: "Asia/Tokyo",
  year: "numeric",
  month: "2-digit",
  day: "2-digit",
  hour: "2-digit",
  minute: "2-digit",
  second: "2-digit",
  hour12: false,
});

const JST_SHORT_FORMATTER = new Intl.DateTimeFormat("ja-JP", {
  timeZone: "Asia/Tokyo",
  month: "2-digit",
  day: "2-digit",
  hour: "2-digit",
  minute: "2-digit",
  hour12: false,
});

const NUMBER_FORMATTER = new Intl.NumberFormat("en-US");

export function formatCount(value: number): string {
  return NUMBER_FORMATTER.format(value);
}

/**
 * Normalize PostgreSQL-style timestamps for `Date` parsing: a bare `±HH`
 * offset (as psql prints `+00`) becomes `±HH:00`, and a space separator
 * becomes `T`. `2026-01-01T12:00:00+00` is otherwise an Invalid Date in V8.
 */
export function normalizeTimestamp(isoString: string): string {
  return isoString
    .trim()
    .replace(/^(\d{4}-\d{2}-\d{2}) (\d{2}:)/, "$1T$2")
    // Only a time-bearing value can carry an offset; "2026-01-01" must not
    // be read as a "-01" offset.
    .replace(/(T\d{2}:\d{2}(?::\d{2}(?:\.\d+)?)?)([+-]\d{2})$/, "$1$2:00");
}

/** Parse a timestamp string into a Date (possibly invalid). */
export function parseTimestamp(isoString: string): Date {
  return new Date(normalizeTimestamp(isoString));
}

export function formatUtcDateTime(isoString: string | null | undefined): string {
  if (!isoString) return "—";
  const date = parseTimestamp(isoString);
  if (Number.isNaN(date.getTime())) return "—";
  return `${date.toISOString().slice(0, 19).replace("T", " ")} UTC`;
}

export function formatUtcShort(isoString: string | null | undefined): string {
  if (!isoString) return "—";
  const date = parseTimestamp(isoString);
  if (Number.isNaN(date.getTime())) return "—";
  return `${date.toISOString().slice(5, 16).replace("T", " ")} UTC`;
}

export function formatJstDateTime(isoString: string | null | undefined): string {
  if (!isoString) return "—";
  const date = parseTimestamp(isoString);
  if (Number.isNaN(date.getTime())) return "—";
  return `${JST_DATETIME_FORMATTER.format(date)} JST`;
}

export function formatJstShort(isoString: string | null | undefined): string {
  if (!isoString) return "—";
  const date = parseTimestamp(isoString);
  if (Number.isNaN(date.getTime())) return "—";
  return `${JST_SHORT_FORMATTER.format(date)} JST`;
}

export function formatConfidence(confidence: number): string {
  return `${Math.round(confidence * 100)}%`;
}

export function formatEpss(score: number | null | undefined): string {
  if (score === null || score === undefined || Number.isNaN(score)) return "N/A";
  return `${(score * 100).toFixed(2)}%`;
}

export function formatEpssPercentile(percentile: number | null | undefined): string {
  if (percentile === null || percentile === undefined || Number.isNaN(percentile)) return "N/A";
  return `${(percentile * 100).toFixed(1)}th pct`;
}

export function formatCvss(score: number | null | undefined): string {
  if (score === null || score === undefined || Number.isNaN(score)) return "N/A";
  return `${score.toFixed(1)} / 10`;
}

export function formatUtcDate(isoString: string | null | undefined): string {
  if (!isoString) return "—";
  if (/^\d{4}-\d{2}-\d{2}$/.test(isoString)) return isoString;
  const date = parseTimestamp(isoString);
  if (Number.isNaN(date.getTime())) return "—";
  return date.toISOString().slice(0, 10);
}

/**
 * Strips non-printable control chars before rendering untrusted strings as text.
 * React already escapes HTML entities; this additionally guards against
 * bidirectional overrides and control characters in logs.
 */
export function safeDisplayText(value: string | null | undefined, fallback = "—"): string {
  if (!value) return fallback;
  const cleaned = value.replace(/[\u0000-\u001f\u007f\u202a-\u202e\u2066-\u2069]/g, "");
  return cleaned.length > 0 ? cleaned : fallback;
}

const DISPLAY_SENSITIVE_KEY_RE =
  /(pass(word|wd|phrase)?|pwd|secret|token|auth(orization)?|cookie|session|jsessionid|stok|api[_-]?key|private[_-]?key|cred(ential)?s?|jwt|bearer|access[_-]?key|sig(nature)?|otp|pin)/i;
const DISPLAY_EMBEDDED_CREDS_RE = /([a-zA-Z][a-zA-Z0-9+.-]*:\/\/)([^/\s@]+)@/g;
const DISPLAY_PATH_PARAM_SECRET_RE =
  /(;[A-Za-z0-9_.-]*(?:stok|jsessionid|session|token|auth|pass|secret|key|sig)[A-Za-z0-9_.-]*=)([^/;?#]+)/gi;
const DISPLAY_SENSITIVE_VALUE_PATTERNS: readonly RegExp[] = [
  /eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/g,
  /\b(?:AKIA|ASIA|AIDA|AROA)[0-9A-Z]{16}\b/g,
  /\b(?:ghp|gho|ghu|ghs|ghr|github_pat|xox[baprs]|sk|pk|rk)_[A-Za-z0-9_-]{12,}\b/g,
  /\bsk-[A-Za-z0-9_-]{16,}\b/g,
  /[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g,
];

function safeDecode(input: string): string {
  try {
    return decodeURIComponent(input);
  } catch {
    return input;
  }
}

function hasSensitiveToken(input: string): boolean {
  DISPLAY_EMBEDDED_CREDS_RE.lastIndex = 0;
  if (DISPLAY_EMBEDDED_CREDS_RE.test(input)) return true;
  for (const re of DISPLAY_SENSITIVE_VALUE_PATTERNS) {
    re.lastIndex = 0;
    if (re.test(input)) return true;
  }
  return false;
}

function maskPathBase(segment: string): string {
  let out = segment
    .replace(DISPLAY_EMBEDDED_CREDS_RE, "$1[REDACTED]@")
    .replace(DISPLAY_PATH_PARAM_SECRET_RE, "$1[REDACTED]");
  for (const re of DISPLAY_SENSITIVE_VALUE_PATTERNS) {
    out = out.replace(re, "[REDACTED]");
  }
  return out;
}

/**
 * Defense-in-depth display formatter for public HTTP paths.
 * Masks query values by default and scrubs embedded credentials/tokens so even
 * historical rows ingested under older rules never expose query values in the UI.
 */
export function safeDisplayHttpPath(value: string | null | undefined, fallback = "—"): string {
  const cleaned = safeDisplayText(value, "");
  if (!cleaned) return fallback;

  const qIdx = cleaned.indexOf("?");
  if (qIdx === -1) {
    return maskPathBase(cleaned);
  }

  const base = maskPathBase(cleaned.slice(0, qIdx));
  const query = cleaned.slice(qIdx + 1);
  const maskedPairs = query.split("&").map((pair) => {
    if (!pair) return "";
    const eqIdx = pair.indexOf("=");
    if (eqIdx === -1) {
      const decoded = safeDecode(pair);
      if (decoded.length > 64 || DISPLAY_SENSITIVE_KEY_RE.test(decoded) || hasSensitiveToken(decoded)) {
        return "[REDACTED]";
      }
      return pair;
    }
    const rawKey = pair.slice(0, eqIdx);
    const decodedKey = safeDecode(rawKey);
    if (!decodedKey || decodedKey.length > 64 || hasSensitiveToken(decodedKey)) {
      return "[REDACTED]=[REDACTED]";
    }
    return `${rawKey}=[REDACTED]`;
  });

  const joined = maskedPairs.filter(Boolean).join("&");
  return joined ? `${base}?${joined}` : base;
}

const EVENT_TYPE_LABELS: Record<string, string> = {
  ssh_new_connection: "SSH connection",
  ssh_remote_version: "SSH client banner",
  ssh_login_attempt: "SSH login attempt",
  telnet_login_attempt: "Telnet login attempt",
  ftp_login_attempt: "FTP login attempt",
  mysql_login_attempt: "MySQL login attempt",
  redis_command_probe: "Redis command probe",
  http_probe: "HTTP request probe",
  http_secret_file_probe: "Sensitive file probe",
  http_cms_probe: "CMS login probe",
  http_router_probe: "Router / CGI probe",
  http_payload_probe: "HTTP payload probe",
  port_scan: "Port scan",
};

const FINGERPRINT_LABELS: Record<string, string> = {
  "oc-2000": "FTP login attempt",
  "oc-4000": "SSH connection",
  "oc-4001": "SSH client banner",
  "oc-4002": "SSH login attempt",
  "oc-6001": "Telnet login attempt",
  "oc-8001": "MySQL login attempt",
  "oc-17001": "Redis command",
};

/**
 * Converts internal snake_case event identifiers into readable labels
 * while never inventing claims beyond what the sensor recorded.
 */
export function formatEventTypeLabel(eventType: string | null | undefined): string {
  const cleaned = safeDisplayText(eventType, "");
  if (!cleaned) return "Unknown event";
  const mapped = EVENT_TYPE_LABELS[cleaned];
  if (mapped) return mapped;
  const words = cleaned.replace(/_/g, " ");
  return words.charAt(0).toUpperCase() + words.slice(1);
}

/**
 * Adds a concise factual description for known OpenCanary logtype fingerprints
 * (e.g. oc-6001 -> "Telnet login attempt (oc-6001)").
 */
export function formatFingerprintLabel(fingerprint: string | null | undefined): string {
  const cleaned = safeDisplayText(fingerprint, "");
  if (!cleaned) return "Inspect";
  const desc = FINGERPRINT_LABELS[cleaned];
  return desc ? `${desc} (${cleaned})` : cleaned;
}

import type { AttackCategory } from "./types.ts";

/**
 * Reconciles legacy stored categories for display so plain connections and
 * Redis command probes are not presented as confirmed authentication attempts.
 */
export function resolveDisplayCategory(
  eventType: string | null | undefined,
  storedCategory: AttackCategory | null | undefined,
): AttackCategory | null {
  if (storedCategory === "suspected_cve_probe" || storedCategory === "web_attack_attempt") {
    return storedCategory;
  }
  const normalized = (eventType ?? "").toLowerCase();
  if (
    normalized === "ssh_new_connection" ||
    normalized === "ssh_remote_version" ||
    normalized.endsWith("_connection") ||
    normalized === "port_scan"
  ) {
    return "port_scan";
  }
  if (normalized === "redis_command_probe" || normalized.endsWith("_command_probe")) {
    return null;
  }
  return storedCategory ?? null;
}
