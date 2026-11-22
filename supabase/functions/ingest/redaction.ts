// Sanitization & redaction utilities for attacker-controlled telemetry.
// Treat all incoming headers, paths, query strings, and metadata as hostile.

const SENSITIVE_KEY_PATTERN =
  /(pass(word|wd|phrase)?|pwd|secret|token|auth(orization)?|cookie|session|jsessionid|stok|api[_-]?key|private[_-]?key|cred(ential)?s?|jwt|bearer|access[_-]?key|\botp\b|\bpin\b)/i;

const SENSITIVE_QUERY_FLAG_PATTERN =
  /(pass(word|wd|phrase)?|pwd|secret|token|auth(orization)?|cookie|session|jsessionid|stok|api[_-]?key|private[_-]?key|cred(ential)?s?|jwt|bearer|access[_-]?key|\bsig(nature)?\b|\botp\b|\bpin\b)/i;

const CONTROL_CHARS_PATTERN = /[\u0000-\u001f\u007f]/g;
const EMBEDDED_URL_CREDS_PATTERN = /([a-zA-Z][a-zA-Z0-9+.-]*:\/\/)([^/\s@]+)@/g;
const PATH_PARAM_SECRET_PATTERN =
  /(;[A-Za-z0-9_.-]*(?:stok|jsessionid|session|token|auth|pass|secret|key|sig)[A-Za-z0-9_.-]*=)([^/;?#]+)/gi;
const SENSITIVE_VALUE_PATTERNS: readonly RegExp[] = [
  /eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/g,
  /\b(?:AKIA|ASIA|AIDA|AROA)[0-9A-Z]{16}\b/g,
  /\b(?:ghp|gho|ghu|ghs|ghr|github_pat|xox[baprs]|sk|pk|rk)_[A-Za-z0-9_-]{12,}\b/g,
  /\bsk-[A-Za-z0-9_-]{16,}\b/g,
  /[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g,
];

export const MAX_HTTP_PATH_LENGTH = 512;
export const MAX_QUERY_KEY_LENGTH = 64;
export const MAX_METADATA_DEPTH = 4;
export const MAX_METADATA_KEYS = 32;
export const MAX_METADATA_STRING_LENGTH = 512;

export function stripControlChars(input: string): string {
  return input.replace(CONTROL_CHARS_PATTERN, "");
}

function safeDecodeURIComponent(input: string): string {
  try {
    return decodeURIComponent(input);
  } catch {
    return input;
  }
}

function containsSensitiveValue(input: string): boolean {
  EMBEDDED_URL_CREDS_PATTERN.lastIndex = 0;
  if (EMBEDDED_URL_CREDS_PATTERN.test(input)) return true;
  for (const pattern of SENSITIVE_VALUE_PATTERNS) {
    pattern.lastIndex = 0;
    if (pattern.test(input)) return true;
  }
  return false;
}

function redactPathSegment(segment: string): string {
  let redacted = segment
    .replace(EMBEDDED_URL_CREDS_PATTERN, "$1[REDACTED]@")
    .replace(PATH_PARAM_SECRET_PATTERN, "$1[REDACTED]");
  for (const pattern of SENSITIVE_VALUE_PATTERNS) {
    redacted = redacted.replace(pattern, "[REDACTED]");
  }
  return redacted;
}

/**
 * Sanitizes and redacts an attacker-supplied HTTP path + query string.
 * Redacts query parameter values by default so tokens, credentials, PII,
 * and arbitrary attacker payloads cannot leak into public views while
 * preserving parameter key structure for pattern analysis.
 * Never executes, fetches, or redirects based on the input.
 */
export function redactHttpPath(rawPath: string): string {
  const cleaned = stripControlChars(rawPath).trim();
  if (!cleaned) return "/";

  const queryIndex = cleaned.indexOf("?");
  if (queryIndex === -1) {
    return redactPathSegment(cleaned).slice(0, MAX_HTTP_PATH_LENGTH);
  }

  const basePath = redactPathSegment(cleaned.slice(0, queryIndex));
  const rawQuery = cleaned.slice(queryIndex + 1);
  const redactedPairs = rawQuery.split("&").map((pair) => {
    if (!pair) return "";
    const eqIndex = pair.indexOf("=");
    if (eqIndex === -1) {
      const decodedPart = safeDecodeURIComponent(pair);
      if (
        decodedPart.length > MAX_QUERY_KEY_LENGTH ||
        SENSITIVE_QUERY_FLAG_PATTERN.test(decodedPart) ||
        containsSensitiveValue(decodedPart)
      ) {
        return "[REDACTED]";
      }
      return pair;
    }
    const rawKey = pair.slice(0, eqIndex);
    const decodedKey = safeDecodeURIComponent(rawKey);
    if (
      !decodedKey ||
      decodedKey.length > MAX_QUERY_KEY_LENGTH ||
      containsSensitiveValue(decodedKey)
    ) {
      return "[REDACTED]=[REDACTED]";
    }
    return `${rawKey}=[REDACTED]`;
  });

  const combined = `${basePath}?${redactedPairs.filter(Boolean).join("&")}`;
  return combined.slice(0, MAX_HTTP_PATH_LENGTH);
}

/**
 * Recursively strips/redacts sensitive keys and enforces depth/size bounds on
 * arbitrary attacker-influenced metadata objects.
 */
export function sanitizeMetadata(
  value: unknown,
  depth = 0,
): Record<string, unknown> {
  if (
    value === null ||
    typeof value !== "object" ||
    Array.isArray(value)
  ) {
    return {};
  }
  return sanitizeObject(value as Record<string, unknown>, depth);
}

function sanitizeValue(value: unknown, depth: number): unknown {
  if (value === null || typeof value === "boolean" || typeof value === "number") {
    return Number.isNaN(value) ? null : value;
  }
  if (typeof value === "string") {
    const cleaned = stripControlChars(value);
    if (SENSITIVE_KEY_PATTERN.test(cleaned) && /[:=]/.test(cleaned)) {
      return "[REDACTED]";
    }
    return cleaned.slice(0, MAX_METADATA_STRING_LENGTH);
  }
  if (depth >= MAX_METADATA_DEPTH) {
    return "[TRUNCATED]";
  }
  if (Array.isArray(value)) {
    return value.slice(0, 20).map((item) => sanitizeValue(item, depth + 1));
  }
  if (typeof value === "object") {
    return sanitizeObject(value as Record<string, unknown>, depth + 1);
  }
  return null;
}

function sanitizeObject(
  obj: Record<string, unknown>,
  depth: number,
): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  let count = 0;

  for (const [rawKey, rawVal] of Object.entries(obj)) {
    if (count >= MAX_METADATA_KEYS) {
      out._truncated = true;
      break;
    }
    const key = stripControlChars(rawKey).slice(0, 64);
    if (!key || key === "__proto__" || key === "constructor" || key === "prototype") {
      continue;
    }
    if (SENSITIVE_KEY_PATTERN.test(key)) {
      out[key] = "[REDACTED]";
    } else {
      out[key] = sanitizeValue(rawVal, depth);
    }
    count += 1;
  }

  return out;
}
