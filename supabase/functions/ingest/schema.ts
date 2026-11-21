// Strict schema validation for incoming sensor event batches.
// Rejects unknown fields, oversize batches, and malformed timestamps/ports.

import { redactHttpPath, sanitizeMetadata, stripControlChars } from "./redaction.ts";

export const ALLOWED_PROTOCOLS = new Set([
  "ssh",
  "telnet",
  "ftp",
  "mysql",
  "redis",
  "http",
  "https",
  "other",
] as const);

export type AllowedProtocol =
  | "ssh"
  | "telnet"
  | "ftp"
  | "mysql"
  | "redis"
  | "http"
  | "https"
  | "other";

const ALLOWED_TOP_LEVEL_KEYS = new Set(["events"]);

const ALLOWED_EVENT_KEYS = new Set([
  "id",
  "observed_at",
  "protocol",
  "dst_port",
  "event_type",
  "src_ip",
  "src_country",
  "src_asn",
  "http_method",
  "http_path",
  "fingerprint",
  "raw_object_key",
  "metadata",
]);

const UUID_REGEX =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const COUNTRY_REGEX = /^[A-Z]{2}$/;
const HTTP_METHOD_REGEX = /^[A-Z]{2,16}$/;
const IPV4_REGEX =
  /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;
const IPV6_HEX_GROUP_REGEX = /^[0-9a-f]{1,4}$/i;
const RAW_OBJECT_KEY_REGEX = /^[A-Za-z0-9][A-Za-z0-9/_.-]{0,511}$/;

export interface NormalizedAttackEvent {
  id: string;
  sensor_id: string;
  observed_at: string;
  protocol: AllowedProtocol;
  dst_port: number;
  event_type: string;
  src_ip: string | null;
  src_ip_hash: string | null;
  src_country: string | null;
  src_asn: string | null;
  http_method: string | null;
  http_path_redacted: string | null;
  fingerprint: string | null;
  raw_object_key: string | null;
  metadata: Record<string, unknown>;
}

export type ValidationResult<T> =
  | { ok: true; value: T }
  | { ok: false; error: string };

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return v !== null && typeof v === "object" && !Array.isArray(v);
}

function isValidIpv6(value: string): boolean {
  if (value.length < 2 || value.length > 45 || !value.includes(":")) {
    return false;
  }
  const doubleColonParts = value.split("::");
  if (doubleColonParts.length > 2) {
    return false;
  }

  const expandPart = (part: string): string[] | null => {
    if (part === "") return [];
    const tokens = part.split(":");
    const groups: string[] = [];
    for (let i = 0; i < tokens.length; i += 1) {
      const token = tokens[i];
      if (i === tokens.length - 1 && token.includes(".")) {
        if (!IPV4_REGEX.test(token)) return null;
        groups.push("0", "0"); // IPv4 suffix counts as two 16-bit groups
      } else if (IPV6_HEX_GROUP_REGEX.test(token)) {
        groups.push(token);
      } else {
        return null;
      }
    }
    return groups;
  };

  if (doubleColonParts.length === 1) {
    const groups = expandPart(doubleColonParts[0]);
    return groups !== null && groups.length === 8;
  }

  // IPv4 suffix is only valid in the right-hand part of "::"
  if (doubleColonParts[0].includes(".")) {
    return false;
  }
  const left = expandPart(doubleColonParts[0]);
  const right = expandPart(doubleColonParts[1]);
  if (left === null || right === null) {
    return false;
  }
  return left.length + right.length < 8;
}

function isValidIp(value: string): boolean {
  return IPV4_REGEX.test(value) || isValidIpv6(value);
}

export function validateBatchPayload(
  payload: unknown,
  sensorId: string,
  options: {
    maxBatchEvents: number;
    nowMs: number;
    maxEventAgeMs?: number;
    maxFutureSkewMs?: number;
  },
): ValidationResult<NormalizedAttackEvent[]> {
  if (!isPlainObject(payload)) {
    return { ok: false, error: "Request body must be a JSON object" };
  }

  for (const key of Object.keys(payload)) {
    if (!ALLOWED_TOP_LEVEL_KEYS.has(key)) {
      return { ok: false, error: `Unexpected top-level field: ${key}` };
    }
  }

  const rawEvents = payload.events;
  if (!Array.isArray(rawEvents)) {
    return { ok: false, error: "'events' must be an array" };
  }
  if (rawEvents.length === 0) {
    return { ok: false, error: "'events' must contain at least 1 event" };
  }
  if (rawEvents.length > options.maxBatchEvents) {
    return {
      ok: false,
      error: `'events' exceeds maximum batch size of ${options.maxBatchEvents}`,
    };
  }

  const maxAgeMs = options.maxEventAgeMs ?? 7 * 24 * 60 * 60 * 1000;
  const maxFutureMs = options.maxFutureSkewMs ?? 5 * 60 * 1000;

  const normalized: NormalizedAttackEvent[] = [];

  for (let i = 0; i < rawEvents.length; i += 1) {
    const raw = rawEvents[i];
    if (!isPlainObject(raw)) {
      return { ok: false, error: `events[${i}] must be an object` };
    }

    for (const key of Object.keys(raw)) {
      if (!ALLOWED_EVENT_KEYS.has(key)) {
        return { ok: false, error: `events[${i}] contains unexpected field: ${key}` };
      }
    }

    if (typeof raw.id !== "string" || !UUID_REGEX.test(raw.id)) {
      return { ok: false, error: `events[${i}].id must be a valid UUID` };
    }

    if (typeof raw.observed_at !== "string") {
      return { ok: false, error: `events[${i}].observed_at must be an ISO timestamp string` };
    }
    const observedMs = Date.parse(raw.observed_at);
    if (Number.isNaN(observedMs)) {
      return { ok: false, error: `events[${i}].observed_at is not a valid timestamp` };
    }
    if (observedMs > options.nowMs + maxFutureMs) {
      return { ok: false, error: `events[${i}].observed_at is too far in the future` };
    }
    if (observedMs < options.nowMs - maxAgeMs) {
      return { ok: false, error: `events[${i}].observed_at is too old` };
    }

    if (
      typeof raw.protocol !== "string" ||
      !ALLOWED_PROTOCOLS.has(raw.protocol as AllowedProtocol)
    ) {
      return { ok: false, error: `events[${i}].protocol is invalid` };
    }

    if (
      typeof raw.dst_port !== "number" ||
      !Number.isInteger(raw.dst_port) ||
      raw.dst_port < 1 ||
      raw.dst_port > 65535
    ) {
      return { ok: false, error: `events[${i}].dst_port must be an integer between 1 and 65535` };
    }

    if (typeof raw.event_type !== "string") {
      return { ok: false, error: `events[${i}].event_type must be a string` };
    }
    const eventType = stripControlChars(raw.event_type).trim();
    if (eventType.length < 1 || eventType.length > 100) {
      return { ok: false, error: `events[${i}].event_type length must be 1..100` };
    }

    let srcIp: string | null = null;
    if (raw.src_ip !== undefined && raw.src_ip !== null) {
      if (typeof raw.src_ip !== "string" || !isValidIp(raw.src_ip.trim())) {
        return { ok: false, error: `events[${i}].src_ip is not a valid IP address` };
      }
      srcIp = raw.src_ip.trim();
    }

    let srcCountry: string | null = null;
    if (raw.src_country !== undefined && raw.src_country !== null) {
      if (typeof raw.src_country !== "string" || !COUNTRY_REGEX.test(raw.src_country)) {
        return { ok: false, error: `events[${i}].src_country must be an ISO-3166 alpha-2 code` };
      }
      srcCountry = raw.src_country;
    }

    let srcAsn: string | null = null;
    if (raw.src_asn !== undefined && raw.src_asn !== null) {
      if (typeof raw.src_asn !== "string" || raw.src_asn.length > 32) {
        return { ok: false, error: `events[${i}].src_asn must be a string <= 32 chars` };
      }
      srcAsn = stripControlChars(raw.src_asn).trim() || null;
    }

    let httpMethod: string | null = null;
    if (raw.http_method !== undefined && raw.http_method !== null) {
      if (typeof raw.http_method !== "string" || !HTTP_METHOD_REGEX.test(raw.http_method)) {
        return { ok: false, error: `events[${i}].http_method must be an uppercase HTTP verb` };
      }
      httpMethod = raw.http_method;
    }

    let httpPathRedacted: string | null = null;
    if (raw.http_path !== undefined && raw.http_path !== null) {
      if (typeof raw.http_path !== "string") {
        return { ok: false, error: `events[${i}].http_path must be a string` };
      }
      httpPathRedacted = redactHttpPath(raw.http_path);
    }

    let fingerprint: string | null = null;
    if (raw.fingerprint !== undefined && raw.fingerprint !== null) {
      if (typeof raw.fingerprint !== "string" || raw.fingerprint.length > 128) {
        return { ok: false, error: `events[${i}].fingerprint must be a string <= 128 chars` };
      }
      fingerprint = stripControlChars(raw.fingerprint).trim() || null;
    }

    let rawObjectKey: string | null = null;
    if (raw.raw_object_key !== undefined && raw.raw_object_key !== null) {
      if (
        typeof raw.raw_object_key !== "string" ||
        !RAW_OBJECT_KEY_REGEX.test(raw.raw_object_key) ||
        raw.raw_object_key.includes("..")
      ) {
        return { ok: false, error: `events[${i}].raw_object_key is invalid` };
      }
      rawObjectKey = raw.raw_object_key;
    }

    let metadata: Record<string, unknown> = {};
    if (raw.metadata !== undefined && raw.metadata !== null) {
      if (!isPlainObject(raw.metadata)) {
        return { ok: false, error: `events[${i}].metadata must be a JSON object` };
      }
      metadata = sanitizeMetadata(raw.metadata);
    }

    normalized.push({
      id: raw.id.toLowerCase(),
      sensor_id: sensorId,
      observed_at: new Date(observedMs).toISOString(),
      protocol: raw.protocol as AllowedProtocol,
      dst_port: raw.dst_port,
      event_type: eventType,
      src_ip: srcIp,
      src_ip_hash: null,
      src_country: srcCountry,
      src_asn: srcAsn,
      http_method: httpMethod,
      http_path_redacted: httpPathRedacted,
      fingerprint,
      raw_object_key: rawObjectKey,
      metadata,
    });
  }

  return { ok: true, value: normalized };
}
