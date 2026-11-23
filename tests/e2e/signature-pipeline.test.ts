// Local, deterministic E2E test for the signature -> candidate CVE pipeline:
//
//   real HTTP collector -> real shipper (spool + HMAC + HTTP delivery)
//   -> real ingest handler -> real SupabaseCveMatchRepository query
//   -> real candidate CVE matching
//
// Guards against the production symptom tracked in #83 (P0-A): HTTP events
// arrive but `signature_detections`, `detections`, and `event_cve_matches`
// stay empty. Everything runs on 127.0.0.1. PostgREST and NVD are replaced by
// an in-memory fetch stub; no external request is made and no payload runs.

import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { createServer, type IncomingMessage, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { after, before, describe, it } from "node:test";
import { fileURLToPath } from "node:url";
import {
  handleIngestRequest,
  type CommitBatchResult,
  type IngestConfig,
  type IngestRepository,
} from "../../supabase/functions/ingest/core.ts";
import type { NormalizedAttackEvent } from "../../supabase/functions/ingest/schema.ts";
import { syncCandidateCves } from "../../jobs/cve-matching/core.ts";
import { SupabaseCveMatchRepository } from "../../jobs/cve-matching/supabase-repo.ts";

const HERE = dirname(fileURLToPath(import.meta.url));
const SENSOR_ID = "sensor-e2e-01";
// Synthetic test-only value; never a real sensor secret.
const HMAC_SECRET = "e2e-synthetic-hmac-secret-not-for-production";
const SUPABASE_URL = "https://e2e.supabase.invalid";
const SERVICE_ROLE_KEY = "e2e-synthetic-service-role-placeholder";

// Expected outcome per probe label in tests/e2e/sensor_pipeline.py.
const EXPECTED: Record<string, { rules: string[]; cves: string[] }> = {
  log4shell_user_agent: { rules: ["http-log4shell-jndi-lookup"], cves: ["CVE-2021-44228"] },
  // Also matches the generic traversal technique rule (/etc/passwd), by design.
  apache_traversal: {
    rules: ["http-apache-path-traversal-cve-2021-41773", "http-path-traversal-attempt"],
    cves: ["CVE-2021-41773", "CVE-2021-42013"],
  },
  spring4shell_body: { rules: ["http-spring4shell-cve-2022-22965"], cves: ["CVE-2022-22965"] },
  php_cgi_soft_hyphen: { rules: ["http-php-cgi-arg-injection-cve-2024-4577"], cves: ["CVE-2024-4577"] },
  sqli_technique_only: { rules: ["http-sqli-attempt"], cves: [] },
  benign: { rules: [], cves: [] },
};

class InMemoryIngestRepo implements IngestRepository {
  events = new Map<string, NormalizedAttackEvent>();
  receipts = new Set<string>();

  async commitBatch(params: {
    sensorId: string;
    requestId: string;
    events: NormalizedAttackEvent[];
  }): Promise<CommitBatchResult> {
    if (params.sensorId !== SENSOR_ID) return { status: "unknown_sensor" };
    const key = `${params.sensorId}::${params.requestId}`;
    if (this.receipts.has(key)) return { status: "replayed" };
    this.receipts.add(key);
    let inserted = 0;
    for (const event of params.events) {
      if (!this.events.has(event.id)) {
        this.events.set(event.id, event);
        inserted += 1;
      }
    }
    return { status: "ok", inserted };
  }
}

const ingestConfig: IngestConfig = {
  sensorSecrets: { [SENSOR_ID]: HMAC_SECRET },
  maxSkewSeconds: 300,
  maxBodyBytes: 256 * 1024,
  maxBatchEvents: 50,
  rateLimitPerMinute: 60,
  ipHashSalt: "e2e-synthetic-ip-hash-salt",
};

async function toRequest(req: IncomingMessage, url: string): Promise<Request> {
  const chunks: Buffer[] = [];
  for await (const chunk of req) chunks.push(chunk as Buffer);
  const headers = new Headers();
  for (const [name, value] of Object.entries(req.headers)) {
    if (typeof value === "string") headers.set(name, value);
  }
  return new Request(url, {
    method: req.method,
    headers,
    body: req.method === "GET" || req.method === "HEAD" ? undefined : Buffer.concat(chunks),
  });
}

/**
 * Minimal PostgREST + NVD stand-in. Applies exactly the filters that
 * SupabaseCveMatchRepository sends and fails on any filter it does not know,
 * so a changed production query cannot silently pass this test.
 */
function createSupabaseStub(events: () => NormalizedAttackEvent[]) {
  const detections = new Map<string, Record<string, unknown> & { id: string }>();
  const matches = new Map<string, Record<string, unknown>>();
  const vulnerabilities = new Set<string>();
  const eventQueries: URLSearchParams[] = [];
  let nvdCalls = 0;
  let sequence = 0;

  const json = (status: number, body: unknown) =>
    new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });

  const fetchImpl: typeof fetch = async (input, init) => {
    const url = new URL(typeof input === "string" ? input : input instanceof URL ? input.href : input.url);
    if (url.hostname.endsWith("nvd.nist.gov")) {
      nvdCalls += 1;
      return json(404, {}); // Leave candidate matches in place; no network.
    }
    assert.equal(url.origin, SUPABASE_URL, `unexpected outbound request to ${url.origin}`);
    const table = url.pathname.replace(/^\/rest\/v1\//, "");
    const method = init?.method ?? "GET";
    const headers = new Headers(init?.headers);
    assert.equal(headers.get("apikey"), SERVICE_ROLE_KEY);
    const expectUpsert = (onConflict: string, resolution: string) => {
      assert.equal(url.searchParams.get("on_conflict"), onConflict, `${table} on_conflict changed`);
      assert.match(headers.get("prefer") ?? "", new RegExp(`resolution=${resolution}`), `${table} Prefer changed`);
    };
    const body = init?.body ? (JSON.parse(String(init.body)) as Record<string, unknown>[]) : [];

    if (table === "attack_events" && method === "GET") {
      const params = url.searchParams;
      eventQueries.push(params);
      const known = new Set(["select", "attack_category", "metadata->signature_detections", "observed_at", "order", "limit", "offset"]);
      for (const key of params.keys()) assert.ok(known.has(key), `unhandled PostgREST filter: ${key}`);
      assert.equal(params.get("select"), "id,metadata");
      const categoryFilter = /^in\.\((.*)\)$/.exec(params.get("attack_category") ?? "");
      assert.ok(categoryFilter, "attack_category filter must be in.(...)");
      const categories = new Set(categoryFilter[1].split(","));
      assert.equal(params.get("metadata->signature_detections"), "not.is.null");
      const since = Date.parse((params.get("observed_at") ?? "").replace(/^gte\./, ""));
      const limit = Number(params.get("limit"));
      const offset = Number(params.get("offset"));
      const rows = events()
        .filter((event) => event.attack_category !== null && categories.has(event.attack_category))
        .filter((event) => event.metadata.signature_detections != null)
        .filter((event) => Date.parse(event.observed_at) >= since)
        .sort((a, b) => Date.parse(b.observed_at) - Date.parse(a.observed_at))
        .slice(offset, offset + limit)
        .map((event) => ({ id: event.id, metadata: event.metadata }));
      return json(200, rows);
    }
    if (table === "detections" && method === "POST") {
      expectUpsert("event_id,rule_id,rule_version", "merge-duplicates");
      const row = body[0];
      const key = `${row.event_id}|${row.rule_id}|${row.rule_version}`;
      const existing = detections.get(key);
      sequence += existing ? 0 : 1;
      const id = existing?.id ?? `00000000-0000-4000-8000-${String(sequence).padStart(12, "0")}`;
      detections.set(key, { ...row, id });
      return json(201, [{ id }]);
    }
    if (table === "vulnerabilities" && method === "POST") {
      expectUpsert("cve_id", "ignore-duplicates");
      vulnerabilities.add(String(body[0].cve_id));
      return new Response(null, { status: 201 });
    }
    if (table === "vulnerabilities" && method === "GET") return json(200, []);
    if (table === "event_cve_matches" && method === "POST") {
      expectUpsert("event_id,cve_id,detection_id", "merge-duplicates");
      const row = body[0];
      matches.set(`${row.event_id}|${row.cve_id}|${row.detection_id}`, row);
      return new Response(null, { status: 201 });
    }
    throw new Error(`unhandled stub request: ${method} ${table}`);
  };

  return {
    fetchImpl,
    detections,
    matches,
    vulnerabilities,
    eventQueries,
    nvdCalls: () => nvdCalls,
  };
}

describe("E2E: collector -> shipper -> ingest -> candidate CVE matching", () => {
  const ingestRepo = new InMemoryIngestRepo();
  let server: Server;
  let workdir: string;
  let sensorSummary: {
    collector_records: number;
    spooled: number;
    remaining: number;
    last_error: string | null;
    probe_labels: string[];
    probe_event_ids: Record<string, string>;
  };
  const ingestResponses: number[] = [];

  before(async () => {
    workdir = mkdtempSync(join(tmpdir(), "attackarium-e2e-"));
    server = createServer((req, res) => {
      const port = (server.address() as AddressInfo).port;
      toRequest(req, `http://127.0.0.1:${port}${req.url ?? "/"}`)
        .then((request) => handleIngestRequest(request, ingestConfig, ingestRepo, Date.now()))
        .then(async (response) => {
          ingestResponses.push(response.status);
          res.writeHead(response.status, Object.fromEntries(response.headers));
          res.end(Buffer.from(await response.arrayBuffer()));
        })
        .catch(() => {
          res.writeHead(500);
          res.end();
        });
    });
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const port = (server.address() as AddressInfo).port;

    // Run the Python sensor half asynchronously so this process keeps serving ingest.
    const child = spawn(
      "python3",
      [
        join(HERE, "sensor_pipeline.py"),
        "--ingest-url",
        `http://127.0.0.1:${port}/ingest`,
        "--sensor-id",
        SENSOR_ID,
        "--workdir",
        workdir,
      ],
      { env: { ...process.env, ATTACKARIUM_E2E_HMAC_SECRET: HMAC_SECRET }, stdio: ["ignore", "pipe", "pipe"] },
    );
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (chunk) => (stdout += chunk));
    child.stderr.on("data", (chunk) => (stderr += chunk));
    const code = await new Promise<number | null>((resolve) => child.on("close", resolve));
    assert.equal(code, 0, `sensor pipeline failed: ${stderr}`);
    sensorSummary = JSON.parse(stdout.trim().split("\n").at(-1) ?? "{}");
  });

  after(() => {
    server?.close();
    if (workdir) rmSync(workdir, { recursive: true, force: true });
  });

  it("delivers every collector record through HMAC-authenticated ingest", () => {
    const probeCount = Object.keys(EXPECTED).length;
    assert.deepEqual(sensorSummary.probe_labels.sort(), Object.keys(EXPECTED).sort());
    assert.equal(sensorSummary.collector_records, probeCount);
    assert.equal(sensorSummary.spooled, probeCount);
    assert.equal(sensorSummary.remaining, 0, `spool not drained: ${sensorSummary.last_error}`);
    assert.ok(ingestResponses.length > 0 && ingestResponses.every((status) => status === 200));
    assert.equal(ingestRepo.events.size, probeCount);
  });

  it("preserves signature_detections and attack_category through ingest", () => {
    const events = [...ingestRepo.events.values()];
    const detected = events.filter((event) => Array.isArray(event.metadata.signature_detections));
    const expectedRules = Object.values(EXPECTED).flatMap((entry) => entry.rules).sort();
    const storedRules = detected
      .flatMap((event) => (event.metadata.signature_detections as Array<{ signature_id: string }>).map((d) => d.signature_id))
      .sort();
    assert.deepEqual(storedRules, expectedRules);
    for (const event of detected) {
      assert.ok(
        event.attack_category === "suspected_cve_probe" || event.attack_category === "web_attack_attempt",
        `unexpected attack_category ${event.attack_category}`,
      );
    }
  });

  it("attributes each detection to the probe that triggered it", () => {
    for (const [label, expected] of Object.entries(EXPECTED)) {
      const event = ingestRepo.events.get(sensorSummary.probe_event_ids[label] ?? "");
      assert.ok(event, `no stored event for probe ${label}`);
      const detections = event.metadata.signature_detections;
      const rules = Array.isArray(detections)
        ? (detections as Array<{ signature_id: string }>).map((d) => d.signature_id).sort()
        : [];
      assert.deepEqual(rules, [...expected.rules].sort(), `detections for probe ${label}`);
    }
  });

  it("never stores raw IPs, callback hosts, or raw payloads", () => {
    // The Host header (the sensor's own address for IP-direct scans) must be
    // reduced to host_kind, so the loopback address appears nowhere.
    const serialized = JSON.stringify([...ingestRepo.events.values()]);
    for (const event of ingestRepo.events.values()) {
      assert.match(String(event.src_ip_hash), /^[0-9a-f]{64}$/, "source IP must be stored only as a hash");
      const headers = (event.metadata.headers as Record<string, unknown> | undefined) ?? {};
      assert.ok(!("host" in headers), "Host header value must never be stored");
      assert.equal(event.metadata.host_kind, "ip_literal");
    }
    for (const forbidden of ["127.0.0.1", "callback-e2e.invalid", "jndi:ldap", "<?php", "classLoader.resources", "password FROM users"]) {
      assert.ok(!serialized.includes(forbidden), `stored events leak ${forbidden}`);
    }
    for (const event of ingestRepo.events.values()) {
      assert.ok(!("src_ip" in event), "plaintext src_ip must never be stored");
    }
  });

  it("produces versioned detections and candidate CVE matches without claiming exploitation", async () => {
    const stub = createSupabaseStub(() => [...ingestRepo.events.values()]);
    const repository = new SupabaseCveMatchRepository(SUPABASE_URL, SERVICE_ROLE_KEY, stub.fetchImpl);
    const runOnce = () =>
      syncCandidateCves({
        repository,
        fetchImpl: stub.fetchImpl,
        now: new Date(),
        since: new Date(Date.now() - 48 * 3600 * 1000).toISOString(),
        limit: 500,
        sleep: async () => {},
      });

    const first = await runOnce();
    const expectedRules = Object.values(EXPECTED).flatMap((entry) => entry.rules);
    const expectedCves = [...new Set(Object.values(EXPECTED).flatMap((entry) => entry.cves))].sort();

    const detectedEvents = Object.values(EXPECTED).filter((entry) => entry.rules.length > 0).length;
    assert.equal(first.eventsRead, detectedEvents);
    assert.equal(first.skipped, 0, "collector output must match the versioned rule catalog");
    assert.equal(first.detections, expectedRules.length);
    assert.equal(first.matches, expectedCves.length);
    assert.equal(stub.detections.size, expectedRules.length);
    assert.deepEqual([...stub.vulnerabilities].sort(), expectedCves);
    assert.deepEqual(
      [...new Set([...stub.matches.values()].map((row) => String(row.cve_id)))].sort(),
      expectedCves,
    );
    for (const row of stub.matches.values()) {
      assert.equal(row.match_type, "candidate_cve");
      assert.match(String(row.reason), /Exploitation was not confirmed\./);
      assert.doesNotMatch(String(row.reason), /\b(exploited|compromised|successful)\b/i);
    }
    for (const row of stub.detections.values()) {
      const evidence = JSON.stringify(row.evidence_redacted);
      assert.ok(!evidence.includes("callback-e2e.invalid"));
    }
    for (const [label, expected] of Object.entries(EXPECTED)) {
      const eventId = sensorSummary.probe_event_ids[label];
      const cves = [...stub.matches.values()]
        .filter((row) => row.event_id === eventId)
        .map((row) => String(row.cve_id))
        .sort();
      assert.deepEqual(cves, [...expected.cves].sort(), `candidate CVEs for probe ${label}`);
      const rules = [...stub.detections.values()]
        .filter((row) => row.event_id === eventId)
        .map((row) => String(row.rule_id))
        .sort();
      assert.deepEqual(rules, [...expected.rules].sort(), `detection rows for probe ${label}`);
    }
    // NVD lookups failed (404 stub) but matches stayed in place.
    assert.equal(first.nvdFailed, expectedCves.length);
    assert.equal(stub.nvdCalls(), expectedCves.length);

    // Re-running is idempotent: same detection and match rows.
    const second = await runOnce();
    assert.equal(second.detections, first.detections);
    assert.equal(stub.detections.size, expectedRules.length);
    assert.equal(
      stub.matches.size,
      Object.values(EXPECTED).reduce((sum, entry) => sum + entry.cves.length, 0),
    );
  });
});

