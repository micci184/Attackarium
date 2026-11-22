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

export function formatJstDateTime(isoString: string | null | undefined): string {
  if (!isoString) return "—";
  const date = new Date(isoString);
  if (Number.isNaN(date.getTime())) return "—";
  return `${JST_DATETIME_FORMATTER.format(date)} JST`;
}

export function formatJstShort(isoString: string | null | undefined): string {
  if (!isoString) return "—";
  const date = new Date(isoString);
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
  const date = new Date(isoString);
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
