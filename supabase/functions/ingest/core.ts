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
// Non-secret placeholder used to execute the same HMAC computation path for
// unknown sensor IDs, reducing timing and error-message enumeration signals.
const UNKNOWN_SENSOR_FALLBACK_KEY = "invalid-sensor-placeholder-hmac-key-do-not-use";

export interface IngestConfig {
  sensorSecrets: Record<string, string>;
  maxSkewSeconds: number;
  maxBodyBytes: number;
  maxBatchEvents: number;
  rateLimitPerMinute: number;
  ipHashSalt?: string;
}

export type CommitBatchResult =
  | { status: "ok"; inserted: number }
  | { status: "replayed" }
  | { status: "rate_limited" }
  | { status: "unknown_sensor" };

export interface IngestRepository {
  commitBatch(params: {
    sensorId: string;
    requestId: string;
    receivedAtIso: string;
    expiresAtIso: string;
    rateLimitPerMinute: number;
    events: NormalizedAttackEvent[];
  }): Promise<CommitBatchResult>;
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

/**
 * Streams the request body up to maxBytes and cancels immediately on overflow,
 * preventing memory exhaustion from chunked or spoofed-Content-Length payloads.
 */
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

  if (!request.body) {
    return { ok: false, status: 400, error: "Request body is empty" };
  }

  const reader = request.body.getReader();
  const chunks: Uint8Array[] = [];
  let totalBytes = 0;

  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      if (!value || value.byteLength === 0) continue;

      totalBytes += value.byteLength;
      if (totalBytes > maxBytes) {
        await reader.cancel("Payload exceeds maximum allowed size").catch(() => undefined);
        return { ok: false, status: 413, error: "Payload exceeds maximum allowed size" };
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }

  if (totalBytes === 0) {
    return { ok: false, status: 400, error: "Request body is empty" };
  }

  const merged = new Uint8Array(totalBytes);
  let offset = 0;
  for (const chunk of chunks) {
    merged.set(chunk, offset);
    offset += chunk.byteLength;
  }

  return { ok: true, text: new TextDecoder("utf-8", { fatal: false }).decode(merged) };
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
    return jsonResponse(401, { error: "Authentication failed" });
  }
  if (!REQUEST_ID_REGEX.test(requestId)) {
    return jsonResponse(400, { error: "Invalid or missing X-Request-Id" });
  }
  if (!/^\d{9,12}$/.test(timestampHeader)) {
    return jsonResponse(401, { error: "Authentication failed" });
  }

  const timestampSec = Number(timestampHeader);
  const nowSec = Math.floor(nowMs / 1000);
  if (Math.abs(nowSec - timestampSec) > config.maxSkewSeconds) {
    return jsonResponse(401, { error: "Authentication failed" });
  }

  if (!signatureHeader.startsWith(SIGNATURE_PREFIX)) {
    return jsonResponse(401, { error: "Authentication failed" });
  }
  const providedHex = signatureHeader.slice(SIGNATURE_PREFIX.length).toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(providedHex)) {
    return jsonResponse(401, { error: "Authentication failed" });
  }

  const bodyResult = await readBoundedBody(request, config.maxBodyBytes);
  if (!bodyResult.ok) {
    return jsonResponse(bodyResult.status, { error: bodyResult.error });
  }

  const hasSensorSecret = Object.prototype.hasOwnProperty.call(
    config.sensorSecrets,
    sensorId,
  );
  const sensorSecret = hasSensorSecret
    ? config.sensorSecrets[sensorId]
    : UNKNOWN_SENSOR_FALLBACK_KEY;

  const signingPayload = buildSignaturePayload(
    sensorId,
    timestampHeader,
    requestId,
    bodyResult.text,
  );
  const expectedHex = await computeHmacSha256Hex(sensorSecret, signingPayload);
  const signatureValid = constantTimeEqual(providedHex, expectedHex);

  // Use one uniform error response for unknown sensor IDs and invalid signatures
  // to prevent sensor ID enumeration.
  if (!hasSensorSecret || !signatureValid) {
    return jsonResponse(401, { error: "Authentication failed" });
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

  // Data minimization: derive a keyed HMAC, then drop the plaintext address.
  // There is no option to persist src_ip. raw_object_key is not an accepted field.
  const events = validation.value;
  for (const ev of events) {
    const rawIp = ev.src_ip;
    if (rawIp && config.ipHashSalt) {
      ev.src_ip_hash = await hashIpWithSalt(rawIp, config.ipHashSalt);
    }
    delete ev.src_ip;
  }

  const receivedAtIso = new Date(nowMs).toISOString();
  const expiresAtIso = new Date(
    nowMs + Math.max(config.maxSkewSeconds * 2, 600) * 1000,
  ).toISOString();

  const commitResult = await repo.commitBatch({
    sensorId,
    requestId,
    receivedAtIso,
    expiresAtIso,
    rateLimitPerMinute: config.rateLimitPerMinute,
    events,
  });

  if (commitResult.status === "unknown_sensor") {
    return jsonResponse(401, { error: "Authentication failed" });
  }
  if (commitResult.status === "replayed") {
    return jsonResponse(409, { error: "Replayed request detected" });
  }
  if (commitResult.status === "rate_limited") {
    return jsonResponse(
      429,
      { error: "Per-sensor ingest rate limit exceeded" },
      { "retry-after": "60" },
    );
  }

  return jsonResponse(200, {
    request_id: requestId,
    accepted: events.length,
    inserted: commitResult.inserted,
    duplicates: events.length - commitResult.inserted,
  });
}
