import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  buildSignaturePayload,
  computeHmacSha256Hex,
  handleIngestRequest,
  type IngestConfig,
  type IngestRepository,
} from "./core.ts";
import type { NormalizedAttackEvent } from "./schema.ts";
import { generateSyntheticBatch } from "./synthetic.ts";

class InMemoryIngestRepo implements IngestRepository {
  receipts = new Map<string, { sensorId: string; receivedAtMs: number; expiresAtMs: number }>();
  events = new Map<string, NormalizedAttackEvent>();
  heartbeats = new Map<string, string>();

  async countRecentReceipts(sensorId: string, sinceIso: string): Promise<number> {
    const sinceMs = Date.parse(sinceIso);
    let count = 0;
    for (const r of this.receipts.values()) {
      if (r.sensorId === sensorId && r.receivedAtMs >= sinceMs) {
        count += 1;
      }
    }
    return count;
  }

  async recordReceipt(
    sensorId: string,
    requestId: string,
    receivedAtIso: string,
    expiresAtIso: string,
  ): Promise<{ inserted: boolean }> {
    const key = `${sensorId}::${requestId}`;
    if (this.receipts.has(key)) {
      return { inserted: false };
    }
    this.receipts.set(key, {
      sensorId,
      receivedAtMs: Date.parse(receivedAtIso),
      expiresAtMs: Date.parse(expiresAtIso),
    });
    return { inserted: true };
  }

  async upsertEvents(events: NormalizedAttackEvent[]): Promise<{ inserted: number }> {
    let inserted = 0;
    for (const ev of events) {
      if (!this.events.has(ev.id)) {
        this.events.set(ev.id, ev);
        inserted += 1;
      }
    }
    return { inserted };
  }

  async touchSensorHeartbeat(sensorId: string, timestampIso: string): Promise<void> {
    this.heartbeats.set(sensorId, timestampIso);
  }
}

const TEST_SECRET = "test-sensor-hmac-secret-at-least-32-chars";
const BASE_NOW_MS = Date.parse("2026-11-21T10:00:00.000Z");

function makeConfig(overrides: Partial<IngestConfig> = {}): IngestConfig {
  return {
    sensorSecrets: { "sensor-dev-01": TEST_SECRET },
    maxSkewSeconds: 300,
    maxBodyBytes: 64 * 1024,
    maxBatchEvents: 50,
    rateLimitPerMinute: 5,
    ipHashSalt: "test-ip-salt-value",
    ...overrides,
  };
}

async function makeSignedRequest(options: {
  body: string;
  sensorId?: string;
  requestId?: string;
  timestampSec?: number;
  secret?: string;
  method?: string;
  contentType?: string;
  signatureOverride?: string;
}): Promise<Request> {
  const sensorId = options.sensorId ?? "sensor-dev-01";
  const requestId = options.requestId ?? "req-00000001";
  const timestamp = String(options.timestampSec ?? Math.floor(BASE_NOW_MS / 1000));
  const payload = buildSignaturePayload(sensorId, timestamp, requestId, options.body);
  const sigHex = await computeHmacSha256Hex(options.secret ?? TEST_SECRET, payload);

  const headers = new Headers({
    "content-type": options.contentType ?? "application/json",
    "x-sensor-id": sensorId,
    "x-timestamp": timestamp,
    "x-request-id": requestId,
    "x-signature": options.signatureOverride ?? `sha256=${sigHex}`,
  });

  return new Request("https://ingest.local/functions/v1/ingest", {
    method: options.method ?? "POST",
    headers,
    body: options.method === "GET" ? undefined : options.body,
  });
}

describe("ingest Edge Function core security & idempotency", () => {
  it("accepts a valid signed batch, redacts secrets, hashes src_ip, and updates heartbeat", async () => {
    const repo = new InMemoryIngestRepo();
    const events = generateSyntheticBatch(BASE_NOW_MS, 6);
    const req = await makeSignedRequest({
      body: JSON.stringify({ events }),
      requestId: "req-valid-001",
    });

    const res = await handleIngestRequest(req, makeConfig(), repo, BASE_NOW_MS);
    assert.equal(res.status, 200);
    const body = (await res.json()) as Record<string, unknown>;
    assert.equal(body.accepted, 6);
    assert.equal(body.inserted, 6);
    assert.equal(body.duplicates, 0);
    assert.equal(repo.events.size, 6);
    assert.equal(repo.heartbeats.get("sensor-dev-01"), new Date(BASE_NOW_MS).toISOString());

    // Verify HTTP path redaction & metadata secret stripping
    const httpEv = repo.events.get("00000000-0000-4000-8000-000000000002");
    assert.ok(httpEv);
    assert.equal(
      httpEv.http_path_redacted,
      "/wp-login.php?user=admin&password=[REDACTED]&redirect=/",
    );
    assert.equal(httpEv.metadata.authorization, "[REDACTED]");
    assert.equal(httpEv.metadata.cookie, "[REDACTED]");
    assert.ok(httpEv.src_ip_hash && httpEv.src_ip_hash.length === 64);

    // Verify SSH password in metadata is redacted
    const sshEv = repo.events.get("00000000-0000-4000-8000-000000000001");
    assert.ok(sshEv);
    assert.equal(sshEv.metadata.password, "[REDACTED]");
  });

  it("deduplicates retried events with a new request_id without creating duplicate rows", async () => {
    const repo = new InMemoryIngestRepo();
    const events = generateSyntheticBatch(BASE_NOW_MS, 3);
    const bodyStr = JSON.stringify({ events });

    const first = await makeSignedRequest({ body: bodyStr, requestId: "req-retry-001" });
    const res1 = await handleIngestRequest(first, makeConfig(), repo, BASE_NOW_MS);
    assert.equal(res1.status, 200);

    const retry = await makeSignedRequest({ body: bodyStr, requestId: "req-retry-002" });
    const res2 = await handleIngestRequest(retry, makeConfig(), repo, BASE_NOW_MS + 1000);
    assert.equal(res2.status, 200);
    const json2 = (await res2.json()) as Record<string, unknown>;
    assert.equal(json2.accepted, 3);
    assert.equal(json2.inserted, 0);
    assert.equal(json2.duplicates, 3);
    assert.equal(repo.events.size, 3);
  });

  it("rejects replayed request_id with 409 Conflict", async () => {
    const repo = new InMemoryIngestRepo();
    const bodyStr = JSON.stringify({ events: generateSyntheticBatch(BASE_NOW_MS, 1) });

    const req1 = await makeSignedRequest({ body: bodyStr, requestId: "req-replay-001" });
    const res1 = await handleIngestRequest(req1, makeConfig(), repo, BASE_NOW_MS);
    assert.equal(res1.status, 200);

    const req2 = await makeSignedRequest({ body: bodyStr, requestId: "req-replay-001" });
    const res2 = await handleIngestRequest(req2, makeConfig(), repo, BASE_NOW_MS + 2000);
    assert.equal(res2.status, 409);
  });

  it("rejects invalid HMAC signatures and unknown sensors with 401", async () => {
    const repo = new InMemoryIngestRepo();
    const bodyStr = JSON.stringify({ events: generateSyntheticBatch(BASE_NOW_MS, 1) });

    const wrongSecretReq = await makeSignedRequest({
      body: bodyStr,
      requestId: "req-bad-sig-1",
      secret: "wrong-secret-00000000000000000000",
    });
    assert.equal((await handleIngestRequest(wrongSecretReq, makeConfig(), repo, BASE_NOW_MS)).status, 401);

    const unknownSensorReq = await makeSignedRequest({
      body: bodyStr,
      sensorId: "sensor-unknown-99",
      requestId: "req-bad-sig-2",
    });
    assert.equal((await handleIngestRequest(unknownSensorReq, makeConfig(), repo, BASE_NOW_MS)).status, 401);
  });

  it("rejects stale or far-future timestamps with 401", async () => {
    const repo = new InMemoryIngestRepo();
    const bodyStr = JSON.stringify({ events: generateSyntheticBatch(BASE_NOW_MS, 1) });
    const nowSec = Math.floor(BASE_NOW_MS / 1000);

    const staleReq = await makeSignedRequest({
      body: bodyStr,
      requestId: "req-stale-001",
      timestampSec: nowSec - 600,
    });
    assert.equal((await handleIngestRequest(staleReq, makeConfig(), repo, BASE_NOW_MS)).status, 401);

    const futureReq = await makeSignedRequest({
      body: bodyStr,
      requestId: "req-future-001",
      timestampSec: nowSec + 600,
    });
    assert.equal((await handleIngestRequest(futureReq, makeConfig(), repo, BASE_NOW_MS)).status, 401);
  });

  it("rejects oversized payloads with 413", async () => {
    const repo = new InMemoryIngestRepo();
    const hugeBody = JSON.stringify({
      events: generateSyntheticBatch(BASE_NOW_MS, 1),
      padding: "x".repeat(4096),
    });
    const req = await makeSignedRequest({ body: hugeBody, requestId: "req-oversize-1" });
    const res = await handleIngestRequest(
      req,
      makeConfig({ maxBodyBytes: 1024 }),
      repo,
      BASE_NOW_MS,
    );
    assert.equal(res.status, 413);
  });

  it("rejects unexpected fields, malformed JSON, and oversize batch counts with 400", async () => {
    const repo = new InMemoryIngestRepo();

    const extraTopFieldReq = await makeSignedRequest({
      body: JSON.stringify({ events: generateSyntheticBatch(BASE_NOW_MS, 1), rogue: true }),
      requestId: "req-bad-schema-1",
    });
    assert.equal((await handleIngestRequest(extraTopFieldReq, makeConfig(), repo, BASE_NOW_MS)).status, 400);

    const extraEventField = {
      ...generateSyntheticBatch(BASE_NOW_MS, 1)[0],
      unexpected_col: "nope",
    };
    const extraEventFieldReq = await makeSignedRequest({
      body: JSON.stringify({ events: [extraEventField] }),
      requestId: "req-bad-schema-2",
    });
    assert.equal((await handleIngestRequest(extraEventFieldReq, makeConfig(), repo, BASE_NOW_MS)).status, 400);

    const malformedReq = await makeSignedRequest({
      body: "{not-json",
      requestId: "req-bad-schema-3",
    });
    assert.equal((await handleIngestRequest(malformedReq, makeConfig(), repo, BASE_NOW_MS)).status, 400);

    const tooManyReq = await makeSignedRequest({
      body: JSON.stringify({ events: generateSyntheticBatch(BASE_NOW_MS, 5) }),
      requestId: "req-bad-schema-4",
    });
    assert.equal(
      (await handleIngestRequest(tooManyReq, makeConfig({ maxBatchEvents: 3 }), repo, BASE_NOW_MS)).status,
      400,
    );
  });

  it("enforces per-sensor rate limits with 429 and Retry-After", async () => {
    const repo = new InMemoryIngestRepo();
    const config = makeConfig({ rateLimitPerMinute: 2 });
    const bodyStr = JSON.stringify({ events: generateSyntheticBatch(BASE_NOW_MS, 1) });

    for (let i = 1; i <= 2; i += 1) {
      const req = await makeSignedRequest({ body: bodyStr, requestId: `req-rate-00${i}` });
      const res = await handleIngestRequest(req, config, repo, BASE_NOW_MS + i * 100);
      assert.equal(res.status, 200);
    }

    const req3 = await makeSignedRequest({ body: bodyStr, requestId: "req-rate-003" });
    const res3 = await handleIngestRequest(req3, config, repo, BASE_NOW_MS + 300);
    assert.equal(res3.status, 429);
    assert.equal(res3.headers.get("retry-after"), "60");
  });

  it("rejects non-POST methods (405) and non-JSON content types (415)", async () => {
    const repo = new InMemoryIngestRepo();
    const getReq = await makeSignedRequest({ body: "", method: "GET", requestId: "req-method-1" });
    assert.equal((await handleIngestRequest(getReq, makeConfig(), repo, BASE_NOW_MS)).status, 405);

    const textReq = await makeSignedRequest({
      body: "plain text",
      contentType: "text/plain",
      requestId: "req-ct-001",
    });
    assert.equal((await handleIngestRequest(textReq, makeConfig(), repo, BASE_NOW_MS)).status, 415);
  });
});
