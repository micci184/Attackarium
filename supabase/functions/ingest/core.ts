// Runtime-agnostic core logic for Attackarium Ingest Edge Function.
// Uses standard Web Crypto API + Fetch Request/Response so it runs identically
// in Supabase Edge Functions (Deno) and Node.js 22 unit/integration tests.

import {
  type NormalizedAttackEvent,
  validateBatchPayload,
} from "./schema.ts";

const SENSOR_ID_REGEX = /^[a-z0-9][a-z0-9_-]{1,63}$/;
const REQUEST_ID_REGEX = /^[A-Za-z0-9._-]{8,128}$/;
const SIGNATURE_PREFIX = "sha256=";

export interface IngestConfig {
  sensorSecrets: Record<string, string>;
  maxSkewSeconds: number;
  maxBodyBytes: number;
  maxBatchEvents: number;
  rateLimitPerMinute: number;
  ipHashSalt?: string;
}

export interface IngestRepository {
  countRecentReceipts(sensorId: string, sinceIso: string): Promise<number>;
  recordReceipt(
    sensorId: string,
    requestId: string,
    receivedAtIso: string,
    expiresAtIso: string,
  ): Promise<{ inserted: boolean }>;
  upsertEvents(events: NormalizedAttackEvent[]): Promise<{ inserted: number }>;
  touchSensorHeartbeat(sensorId: string, timestampIso: string): Promise<void>;
}

const encoder = new TextEncoder();

function toHex(buffer: ArrayBuffer): string {
  return Array.from(new Uint8Array(buffer))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

/**
 * Constant-time string comparison to avoid HMAC timing side channels.
 */
export function constantTimeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i += 1) {
    diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return diff === 0;
}

export function buildSignaturePayload(
  sensorId: string,
  timestamp: string,
  requestId: string,
  rawBody: string,
): string {
  return `${sensorId}\n${timestamp}\n${requestId}\n${rawBody}`;
}

export async function computeHmacSha256Hex(
  secret: string,
  message: string,
): Promise<string> {
  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const sig = await crypto.subtle.sign("HMAC", key, encoder.encode(message));
  return toHex(sig);
}

async function hashIpWithSalt(ip: string, salt: string): Promise<string> {
  return computeHmacSha256Hex(salt, ip);
}

function jsonResponse(
  status: number,
  body: Record<string, unknown>,
  extraHeaders: Record<string, string> = {},
): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store",
      ...extraHeaders,
    },
  });
}

async function readBoundedBody(
  request: Request,
  maxBytes: number,
): Promise<{ ok: true; text: string } | { ok: false; status: number; error: string }> {
  const contentLengthHeader = request.headers.get("content-length");
  if (contentLengthHeader !== null) {
    const declared = Number(contentLengthHeader);
    if (!Number.isFinite(declared) || declared < 0 || declared > maxBytes) {
      return { ok: false, status: 413, error: "Payload exceeds maximum allowed size" };
    }
  }

  const buffer = await request.arrayBuffer();
  if (buffer.byteLength === 0) {
    return { ok: false, status: 400, error: "Request body is empty" };
  }
  if (buffer.byteLength > maxBytes) {
    return { ok: false, status: 413, error: "Payload exceeds maximum allowed size" };
  }

  return { ok: true, text: new TextDecoder("utf-8", { fatal: false }).decode(buffer) };
}

export async function handleIngestRequest(
  request: Request,
  config: IngestConfig,
  repo: IngestRepository,
  nowMs: number = Date.now(),
): Promise<Response> {
  if (request.method !== "POST") {
    return jsonResponse(405, { error: "Method not allowed" }, { allow: "POST" });
  }

  const contentType = request.headers.get("content-type") ?? "";
  if (!contentType.toLowerCase().includes("application/json")) {
    return jsonResponse(415, { error: "Content-Type must be application/json" });
  }

  const sensorId = (request.headers.get("x-sensor-id") ?? "").trim();
  const timestampHeader = (request.headers.get("x-timestamp") ?? "").trim();
  const requestId = (request.headers.get("x-request-id") ?? "").trim();
  const signatureHeader = (request.headers.get("x-signature") ?? "").trim();

  if (!SENSOR_ID_REGEX.test(sensorId)) {
    return jsonResponse(401, { error: "Invalid or missing X-Sensor-Id" });
  }
  if (!REQUEST_ID_REGEX.test(requestId)) {
    return jsonResponse(400, { error: "Invalid or missing X-Request-Id" });
  }
  if (!/^\d{9,12}$/.test(timestampHeader)) {
    return jsonResponse(401, { error: "Invalid or missing X-Timestamp" });
  }

  const timestampSec = Number(timestampHeader);
  const nowSec = Math.floor(nowMs / 1000);
  if (Math.abs(nowSec - timestampSec) > config.maxSkewSeconds) {
    return jsonResponse(401, { error: "Request timestamp outside allowed window" });
  }

  const sensorSecret = config.sensorSecrets[sensorId];
  if (!sensorSecret) {
    return jsonResponse(401, { error: "Unknown sensor credentials" });
  }

  if (!signatureHeader.startsWith(SIGNATURE_PREFIX)) {
    return jsonResponse(401, { error: "Invalid X-Signature format" });
  }
  const providedHex = signatureHeader.slice(SIGNATURE_PREFIX.length).toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(providedHex)) {
    return jsonResponse(401, { error: "Invalid X-Signature digest" });
  }

  const bodyResult = await readBoundedBody(request, config.maxBodyBytes);
  if (!bodyResult.ok) {
    return jsonResponse(bodyResult.status, { error: bodyResult.error });
  }

  const signingPayload = buildSignaturePayload(
    sensorId,
    timestampHeader,
    requestId,
    bodyResult.text,
  );
  const expectedHex = await computeHmacSha256Hex(sensorSecret, signingPayload);
  if (!constantTimeEqual(providedHex, expectedHex)) {
    return jsonResponse(401, { error: "Signature verification failed" });
  }

  let parsedJson: unknown;
  try {
    parsedJson = JSON.parse(bodyResult.text);
  } catch {
    return jsonResponse(400, { error: "Malformed JSON body" });
  }

  const validation = validateBatchPayload(parsedJson, sensorId, {
    maxBatchEvents: config.maxBatchEvents,
    nowMs,
  });
  if (!validation.ok) {
    return jsonResponse(400, { error: validation.error });
  }

  // Per-sensor sliding-window rate limit
  const windowStartIso = new Date(nowMs - 60_000).toISOString();
  const recentCount = await repo.countRecentReceipts(sensorId, windowStartIso);
  if (recentCount >= config.rateLimitPerMinute) {
    return jsonResponse(
      429,
      { error: "Per-sensor ingest rate limit exceeded" },
      { "retry-after": "60" },
    );
  }

  // Anti-replay receipt check (persisted nonce)
  const receivedAtIso = new Date(nowMs).toISOString();
  const expiresAtIso = new Date(
    nowMs + Math.max(config.maxSkewSeconds * 2, 600) * 1000,
  ).toISOString();
  const receipt = await repo.recordReceipt(
    sensorId,
    requestId,
    receivedAtIso,
    expiresAtIso,
  );
  if (!receipt.inserted) {
    return jsonResponse(409, { error: "Replayed request detected" });
  }

  // Optionally derive salted keyed IP hashes for privacy-preserving dedupe/counting
  const events = validation.value;
  if (config.ipHashSalt) {
    for (const ev of events) {
      if (ev.src_ip) {
        ev.src_ip_hash = await hashIpWithSalt(ev.src_ip, config.ipHashSalt);
      }
    }
  }

  const { inserted } = await repo.upsertEvents(events);
  await repo.touchSensorHeartbeat(sensorId, receivedAtIso);

  return jsonResponse(200, {
    request_id: requestId,
    accepted: events.length,
    inserted,
    duplicates: events.length - inserted,
  });
}
