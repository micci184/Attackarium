import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  buildSignaturePayload,
  type CommitBatchResult,
  computeHmacSha256Hex,
  handleIngestRequest,
  type IngestConfig,
  type IngestRepository,
} from "./core.ts";
import type { NormalizedAttackEvent } from "./schema.ts";
import { generateSyntheticBatch } from "./synthetic.ts";

class InMemoryIngestRepo implements IngestRepository {
  registeredSensors = new Set<string>(["sensor-dev-01"]);
  receipts = new Map<string, { sensorId: string; receivedAtMs: number; expiresAtMs: number }>();
  events = new Map<string, NormalizedAttackEvent>();
  heartbeats = new Map<string, string>();
  failNextCommit = false;

  async commitBatch(params: {
    sensorId: string;
    requestId: string;
    receivedAtIso: string;
    expiresAtIso: string;
    rateLimitPerMinute: number;
    events: NormalizedAttackEvent[];
  }): Promise<CommitBatchResult> {
    if (!this.registeredSensors.has(params.sensorId)) {
      return { status: "unknown_sensor" };
    }

    const receiptKey = `${params.sensorId}::${params.requestId}`;
    if (this.receipts.has(receiptKey)) {
      return { status: "replayed" };
    }

    const receivedAtMs = Date.parse(params.receivedAtIso);
    const windowStartMs = receivedAtMs - 60_000;
    let recentCount = 0;
    for (const r of this.receipts.values()) {
      if (r.sensorId === params.sensorId && r.receivedAtMs >= windowStartMs) {
        recentCount += 1;
      }
    }
    if (recentCount >= params.rateLimitPerMinute) {
      return { status: "rate_limited" };
    }

    // Simulate transactional rollback if event persistence throws
    if (this.failNextCommit) {
      this.failNextCommit = false;
      throw new Error("Simulated transient DB write failure");
    }

    this.receipts.set(receiptKey, {
      sensorId: params.sensorId,
      receivedAtMs,
      expiresAtMs: Date.parse(params.expiresAtIso),
    });

    let inserted = 0;
    for (const ev of params.events) {
      if (!this.events.has(ev.id)) {
        this.events.set(ev.id, ev);
        inserted += 1;
      }
    }

    this.heartbeats.set(params.sensorId, params.receivedAtIso);
    return { status: "ok", inserted };
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
    ipHashSalt: "test-ip-salt-value-at-least-16",
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
  it("accepts a valid signed batch, redacts secrets, hashes src_ip, and drops the plaintext address", async () => {
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

    // Verify HTTP path redaction, metadata secret stripping, and raw IP minimization
    const httpEv = repo.events.get("00000000-0000-4000-8000-000000000002");
    assert.ok(httpEv);
    assert.equal(
      httpEv.http_path_redacted,
      "/wp-login.php?user=admin&password=[REDACTED]&redirect=/",
    );
    assert.equal(httpEv.metadata.authorization, "[REDACTED]");
    assert.equal(httpEv.metadata.cookie, "[REDACTED]");
    assert.equal("src_ip" in httpEv, false);
    assert.equal("raw_object_key" in httpEv, false);
    assert.ok(httpEv.src_ip_hash && httpEv.src_ip_hash.length === 64);

    // Verify SSH password in metadata is redacted
    const sshEv = repo.events.get("00000000-0000-4000-8000-000000000001");
    assert.ok(sshEv);
    assert.equal(sshEv.metadata.password, "[REDACTED]");
    assert.equal("src_ip" in sshEv, false);
    assert.equal(sshEv.attack_category, "auth_attempt");
    assert.equal(httpEv.attack_category, "http_path_probe");
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

  it("does not burn request_id nonce when atomic commit fails", async () => {
    const repo = new InMemoryIngestRepo();
    repo.failNextCommit = true;
    const bodyStr = JSON.stringify({ events: generateSyntheticBatch(BASE_NOW_MS, 1) });

    const req1 = await makeSignedRequest({ body: bodyStr, requestId: "req-atomic-001" });
    await assert.rejects(
      () => handleIngestRequest(req1, makeConfig(), repo, BASE_NOW_MS),
      /Simulated transient DB write failure/,
    );
    assert.equal(repo.receipts.size, 0);

    const req2 = await makeSignedRequest({ body: bodyStr, requestId: "req-atomic-001" });
    const res2 = await handleIngestRequest(req2, makeConfig(), repo, BASE_NOW_MS + 1000);
    assert.equal(res2.status, 200);
  });

  it("returns identical 401 error for invalid HMAC and unknown sensor IDs (anti-enumeration)", async () => {
    const repo = new InMemoryIngestRepo();
    const bodyStr = JSON.stringify({ events: generateSyntheticBatch(BASE_NOW_MS, 1) });

    const wrongSecretReq = await makeSignedRequest({
      body: bodyStr,
      requestId: "req-bad-sig-1",
      secret: "wrong-secret-00000000000000000000",
    });
    const wrongSecretRes = await handleIngestRequest(
      wrongSecretReq,
      makeConfig(),
      repo,
      BASE_NOW_MS,
    );
    assert.equal(wrongSecretRes.status, 401);
    const wrongSecretBody = (await wrongSecretRes.json()) as Record<string, unknown>;

    const unknownSensorReq = await makeSignedRequest({
      body: bodyStr,
      sensorId: "sensor-unknown-99",
      requestId: "req-bad-sig-2",
    });
    const unknownSensorRes = await handleIngestRequest(
      unknownSensorReq,
      makeConfig(),
      repo,
      BASE_NOW_MS,
    );
    assert.equal(unknownSensorRes.status, 401);
    const unknownSensorBody = (await unknownSensorRes.json()) as Record<string, unknown>;

    assert.deepEqual(wrongSecretBody, unknownSensorBody);
    assert.equal(wrongSecretBody.error, "Authentication failed");
  });

  it("rejects stale or far-future timestamps with uniform 401", async () => {
    const repo = new InMemoryIngestRepo();
    const bodyStr = JSON.stringify({ events: generateSyntheticBatch(BASE_NOW_MS, 1) });
    const nowSec = Math.floor(BASE_NOW_MS / 1000);

    const staleReq = await makeSignedRequest({
      body: bodyStr,
      requestId: "req-stale-001",
      timestampSec: nowSec - 600,
    });
    const staleRes = await handleIngestRequest(staleReq, makeConfig(), repo, BASE_NOW_MS);
    assert.equal(staleRes.status, 401);
    assert.deepEqual(await staleRes.json(), { error: "Authentication failed" });

    const futureReq = await makeSignedRequest({
      body: bodyStr,
      requestId: "req-future-001",
      timestampSec: nowSec + 600,
    });
    const futureRes = await handleIngestRequest(futureReq, makeConfig(), repo, BASE_NOW_MS);
    assert.equal(futureRes.status, 401);
    assert.deepEqual(await futureRes.json(), { error: "Authentication failed" });
  });

  it("rejects oversized payloads with 413 and aborts unbounded streams early", async () => {
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

    // Streaming body without Content-Length must cancel as soon as maxBodyBytes is crossed
    let chunksProduced = 0;
    let streamCancelled = false;
    const stream = new ReadableStream<Uint8Array>({
      pull(controller) {
        chunksProduced += 1;
        controller.enqueue(new Uint8Array(600).fill(65));
        if (chunksProduced >= 100) {
          controller.close();
        }
      },
      cancel() {
        streamCancelled = true;
      },
    });
    const nowSec = Math.floor(BASE_NOW_MS / 1000);
    const streamReq = new Request("https://ingest.local/functions/v1/ingest", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-sensor-id": "sensor-dev-01",
        "x-timestamp": String(nowSec),
        "x-request-id": "req-stream-oversize-1",
        "x-signature": "sha256=" + "0".repeat(64),
      },
      body: stream,
      duplex: "half",
    } as RequestInit);

    const streamRes = await handleIngestRequest(
      streamReq,
      makeConfig({ maxBodyBytes: 1024 }),
      repo,
      BASE_NOW_MS,
    );
    assert.equal(streamRes.status, 413);
    assert.equal(streamCancelled, true);
    assert.ok(chunksProduced <= 4, `Expected early stream abort, got ${chunksProduced} chunks`);
  });

  it("rejects unexpected fields, malformed JSON, invalid IPs/keys, and oversize batch counts with 400", async () => {
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

    const badIpv6Event = {
      ...generateSyntheticBatch(BASE_NOW_MS, 1)[0],
      src_ip: "::::::",
    };
    const badIpv6Req = await makeSignedRequest({
      body: JSON.stringify({ events: [badIpv6Event] }),
      requestId: "req-bad-schema-5",
    });
    assert.equal((await handleIngestRequest(badIpv6Req, makeConfig(), repo, BASE_NOW_MS)).status, 400);

    const badCategoryEvent = {
      ...generateSyntheticBatch(BASE_NOW_MS, 1)[0],
      attack_category: "confirmed_exploit",
    };
    const badCategoryReq = await makeSignedRequest({
      body: JSON.stringify({ events: [badCategoryEvent] }),
      requestId: "req-bad-schema-7",
    });
    assert.equal((await handleIngestRequest(badCategoryReq, makeConfig(), repo, BASE_NOW_MS)).status, 400);

    const badKeyEvent = {
      ...generateSyntheticBatch(BASE_NOW_MS, 1)[0],
      raw_object_key: "/etc/passwd",
    };
    const badKeyReq = await makeSignedRequest({
      body: JSON.stringify({ events: [badKeyEvent] }),
      requestId: "req-bad-schema-6",
    });
    assert.equal((await handleIngestRequest(badKeyReq, makeConfig(), repo, BASE_NOW_MS)).status, 400);

    // Valid IPv6 and IPv4-mapped IPv6 are accepted
    const validIpv6Events = [
      { ...generateSyntheticBatch(BASE_NOW_MS, 1)[0], src_ip: "2001:db8::1" },
      {
        ...generateSyntheticBatch(BASE_NOW_MS, 2)[1],
        src_ip: "::ffff:198.51.100.42",
      },
    ];
    const validIpv6Req = await makeSignedRequest({
      body: JSON.stringify({ events: validIpv6Events }),
      requestId: "req-good-ipv6-1",
    });
    assert.equal((await handleIngestRequest(validIpv6Req, makeConfig(), repo, BASE_NOW_MS)).status, 200);
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
