// Sanitization & redaction utilities for attacker-controlled telemetry.
// Treat all incoming headers, paths, query strings, and metadata as hostile.

const SENSITIVE_KEY_PATTERN =
  /(pass(word|wd|phrase)?|pwd|secret|token|auth(orization)?|cookie|session|api[_-]?key|private[_-]?key|cred(ential)?s?|jwt|bearer|access[_-]?key)/i;

const CONTROL_CHARS_PATTERN = /[\u0000-\u001f\u007f]/g;

export const MAX_HTTP_PATH_LENGTH = 512;
export const MAX_METADATA_DEPTH = 4;
export const MAX_METADATA_KEYS = 32;
export const MAX_METADATA_STRING_LENGTH = 512;

export function stripControlChars(input: string): string {
  return input.replace(CONTROL_CHARS_PATTERN, "");
}

/**
 * Sanitizes and redacts an attacker-supplied HTTP path + query string.
 * Never executes, fetches, or redirects based on the input.
 */
export function redactHttpPath(rawPath: string): string {
  const cleaned = stripControlChars(rawPath).trim();
  if (!cleaned) return "/";

  const queryIndex = cleaned.indexOf("?");
  if (queryIndex === -1) {
    return cleaned.slice(0, MAX_HTTP_PATH_LENGTH);
  }

  const basePath = cleaned.slice(0, queryIndex);
  const rawQuery = cleaned.slice(queryIndex + 1);
  const redactedPairs = rawQuery.split("&").map((pair) => {
    if (!pair) return "";
    const eqIndex = pair.indexOf("=");
    if (eqIndex === -1) {
      return SENSITIVE_KEY_PATTERN.test(pair) ? "[REDACTED]" : pair;
    }
    const rawKey = pair.slice(0, eqIndex);
    if (SENSITIVE_KEY_PATTERN.test(rawKey)) {
      return `${rawKey}=[REDACTED]`;
    }
    const rawVal = pair.slice(eqIndex + 1);
    if (/^(bearer|basic)\s+/i.test(rawVal) || rawVal.length > 128) {
      return `${rawKey}=[REDACTED]`;
    }
    return `${rawKey}=${rawVal}`;
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
