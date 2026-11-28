import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  createResilientFeedClient,
  EPSS_API_URL,
  type EpssUpsert,
  FeedSyncError,
  KEV_FEED_URL,
  type KevClear,
  type KevUpsert,
  syncThreatIntel,
  type ThreatIntelRepository,
  type TrackedCve,
} from "./core.ts";
import { parseEpssPage, parseKevCatalog, parseUnitScore, parseUtcTimestamp } from "./schema.ts";
import { runThreatIntelSync } from "./run.ts";
import { SupabaseThreatIntelRepository } from "./supabase-repo.ts";

const NOW = new Date("2026-11-22T08:15:00.000Z");

function kevPayload(cves: Array<{ id: string; added?: string }>) {
  return {
    catalogVersion: "2026.11.20",
    dateReleased: "2026-11-20T17:48:39.1516Z",
    vulnerabilities: cves.map((cve) => ({
      cveID: cve.id,
      vendorProject: "Example",
      product: "Widget",
      shortDescription: `Synthetic description for ${cve.id}`,
      dateAdded: cve.added ?? "2026-11-20",
    })),
  };
}

function epssPayload(cves: string[], date = "2026-11-21") {
  return {
    status: "OK",
    data: cves.map((cve) => ({
      cve,
      epss: "0.999990000",
      percentile: "1.000000000",
      date,
    })),
  };
}

class MemoryRepo implements ThreatIntelRepository {
  rows = new Map<string, KevUpsert & { kevPresent: boolean; epssScore: number | null; epssDate: string | null }>();
  scores = new Map<string, EpssUpsert>();
  writes = 0;

  constructor(seed: TrackedCve[] = []) {
    for (const row of seed) {
      this.rows.set(row.cveId, {
        cveId: row.cveId,
        description: "existing",
        vendor: "Existing",
        product: "Existing",
        kevPresent: row.kevPresent,
        kevAddedAt: "2026-01-01T00:00:00.000Z",
        kevUpdatedAt: "2026-01-02T00:00:00.000Z",
        sourceUpdatedAt: "2026-01-02T00:00:00.000Z",
        epssScore: 0.2,
        epssDate: "2026-11-01",
      });
    }
  }

  async listTrackedCves(): Promise<TrackedCve[]> {
    return [...this.rows.values()].map((row) => ({ cveId: row.cveId, kevPresent: row.kevPresent }));
  }

  async upsertKev(rows: KevUpsert[]): Promise<void> {
    this.writes += 1;
    for (const row of rows) {
      const current = this.rows.get(row.cveId);
      this.rows.set(row.cveId, {
        ...row,
        epssScore: current?.epssScore ?? null,
        epssDate: current?.epssDate ?? null,
      });
    }
  }

  async clearKevPresence(clear: KevClear): Promise<void> {
    this.writes += 1;
    for (const cveId of clear.cveIds) {
      const current = this.rows.get(cveId);
      if (!current) continue;
      this.rows.set(cveId, {
        ...current,
        kevPresent: false,
        kevUpdatedAt: clear.kevUpdatedAt,
        sourceUpdatedAt: clear.sourceUpdatedAt,
      });
    }
  }

  async upsertEpss(rows: EpssUpsert[]): Promise<void> {
    this.writes += 1;
    for (const row of rows) {
      const current = this.rows.get(row.cveId);
      if (current) {
        this.rows.set(row.cveId, { ...current, epssScore: row.epssScore, epssDate: row.epssDate });
      }
      this.scores.set(`${row.cveId}|${row.epssDate}`, row);
    }
  }
}

function feedClient(catalogCves: string[]) {
  return {
    async getJson(url: string): Promise<unknown> {
      if (url === KEV_FEED_URL) return kevPayload(catalogCves.map((id) => ({ id })));
      if (url.startsWith(EPSS_API_URL)) {
        const cves = new URL(url).searchParams.get("cve")?.split(",").filter(Boolean) ?? [];
        return epssPayload(cves);
      }
      throw new Error(`Unexpected URL ${url}`);
    },
  };
}

describe("KEV and EPSS parsing", () => {
  it("keeps the catalog release timestamp and rounds EPSS to the stored precision", () => {
    assert.equal(parseUtcTimestamp("2026-11-20T17:48:39.1516Z"), "2026-11-20T17:48:39.151Z");
    assert.equal(parseUnitScore("0.999990000"), 0.99999);
    assert.equal(parseUnitScore("1.000000000"), 1);
    assert.equal(parseUnitScore("1.1"), null);

    const catalog = parseKevCatalog({
      ...kevPayload([{ id: "CVE-2026-129448" }]),
      vulnerabilities: [
        ...kevPayload([{ id: "CVE-2026-129448" }]).vulnerabilities,
        { cveID: "not-a-cve", vendorProject: "X", product: "Y", shortDescription: "bad", dateAdded: "2026-11-20" },
        {
          cveID: "CVE-2024-0001",
          vendorProject: "  Example   Vendor  ",
          product: "Widget",
          shortDescription: ` ${"A".repeat(2_050)} `,
          dateAdded: "2026-11-20",
        },
      ],
    });
    assert.equal(catalog.catalogVersion, "2026.11.20");
    assert.equal(catalog.skipped, 1);
    assert.equal(catalog.rows.find((row) => row.cveId === "CVE-2024-0001")?.description.length, 2_000);
    assert.equal(catalog.rows.find((row) => row.cveId === "CVE-2024-0001")?.vendor, "Example Vendor");
  });

  it("rejects a catalog envelope that has no usable rows", () => {
    assert.throws(() => parseKevCatalog({ catalogVersion: "2026.11.20" }), /vulnerability list/);
    assert.throws(
      () => parseKevCatalog({ catalogVersion: "2026.11.20", dateReleased: "2026-11-20T00:00:00.000Z", vulnerabilities: [] }),
      /any valid CVE/,
    );
    assert.throws(() => parseEpssPage({ status: "ERROR", data: [] }), /OK data list/);
  });
});

describe("syncThreatIntel", () => {
  it("upserts KEV and EPSS once, including a second run for the same score date", async () => {
    const repo = new MemoryRepo();
    const first = await syncThreatIntel({
      client: feedClient(["CVE-2024-0001", "CVE-2024-0002"]),
      repository: repo,
      now: NOW,
      epssBatchSize: 1,
    });
    const second = await syncThreatIntel({
      client: feedClient(["CVE-2024-0001", "CVE-2024-0002"]),
      repository: repo,
      now: NOW,
      epssBatchSize: 1,
    });

    assert.equal(first.catalogVersion, "2026.11.20");
    assert.equal(first.kevUpserts, 2);
    assert.equal(first.epssUpserts, 2);
    assert.equal(second.epssUpserts, 2);
    assert.equal(repo.rows.size, 2);
    assert.equal(repo.scores.size, 2);
    const stored = repo.rows.get("CVE-2024-0001");
    assert.equal(stored?.kevPresent, true);
    assert.equal(stored?.kevAddedAt, "2026-11-20T00:00:00.000Z");
    assert.equal(stored?.kevUpdatedAt, "2026-11-20T17:48:39.151Z");
    assert.equal(stored?.epssScore, 0.99999);
    assert.equal(stored?.epssDate, "2026-11-21");
  });

  it("clears KEV presence without deleting the CVE or its previous EPSS date", async () => {
    const repo = new MemoryRepo([{ cveId: "CVE-2024-9999", kevPresent: true }]);
    const result = await syncThreatIntel({
      client: feedClient(["CVE-2024-0001"]),
      repository: repo,
      now: NOW,
    });

    assert.equal(result.kevCleared, 1);
    const removed = repo.rows.get("CVE-2024-9999");
    assert.equal(removed?.kevPresent, false);
    assert.equal(removed?.description, "existing");
    assert.equal(removed?.epssDate, "2026-11-21");
    assert.equal(repo.scores.has("CVE-2024-9999|2026-11-21"), true);
  });

  it("leaves stored rows unchanged when either feed fails", async () => {
    const repo = new MemoryRepo([{ cveId: "CVE-2024-0001", kevPresent: true }]);
    await assert.rejects(
      syncThreatIntel({
        client: {
          async getJson(url: string) {
            if (url === KEV_FEED_URL) throw new Error("catalog unavailable");
            throw new Error("should not request EPSS");
          },
        },
        repository: repo,
        now: NOW,
      }),
      (error: unknown) => error instanceof FeedSyncError && /No rows were changed/.test(error.message),
    );
    assert.equal(repo.writes, 0);
    assert.equal(repo.rows.get("CVE-2024-0001")?.epssScore, 0.2);

    await assert.rejects(
      syncThreatIntel({
        client: {
          async getJson(url: string) {
            if (url === KEV_FEED_URL) return kevPayload([{ id: "CVE-2024-0001" }]);
            throw new Error("epss unavailable");
          },
        },
        repository: repo,
        now: NOW,
      }),
      /FIRST EPSS fetch failed after 0 of 1 batches\. KEV rows and the completed EPSS batches were saved/,
    );
    // KEV is written before EPSS, so its flags stay current during an EPSS outage.
    assert.equal(repo.writes, 1);
    assert.equal(repo.rows.get("CVE-2024-0001")?.kevUpdatedAt, "2026-11-20T17:48:39.151Z");
    assert.equal(repo.rows.get("CVE-2024-0001")?.epssScore, 0.2, "EPSS left unchanged");
  });

  it("retries a rate-limited feed response and then accepts it", async () => {
    let calls = 0;
    const client = createResilientFeedClient(
      async () => {
        calls += 1;
        if (calls === 1) {
          return new Response("busy", { status: 429, headers: { "retry-after": "0" } });
        }
        return Response.json(epssPayload(["CVE-2024-0001"]));
      },
      { maxRetries: 2, sleep: async () => {} },
    );

    const payload = await client.getJson(EPSS_API_URL);
    assert.equal(calls, 2);
    assert.equal(parseEpssPage(payload).rows[0]?.epssScore, 0.99999);
  });

  it("does not retry a client error", async () => {
    let calls = 0;
    const client = createResilientFeedClient(
      async () => {
        calls += 1;
        return new Response("missing", { status: 404 });
      },
      { maxRetries: 3, sleep: async () => {} },
    );
    await assert.rejects(client.getJson(KEV_FEED_URL), /HTTP 404/);
    assert.equal(calls, 1);
  });

  it("deduplicates repeated EPSS CVE rows before upserting", async () => {
    const repo = new MemoryRepo();
    const result = await syncThreatIntel({
      client: {
        async getJson(url: string): Promise<unknown> {
          if (url === KEV_FEED_URL) return kevPayload([{ id: "CVE-2024-0001" }]);
          return {
            status: "OK",
            data: [
              { cve: "CVE-2024-0001", epss: "0.100000000", percentile: "0.200000000", date: "2026-11-21" },
              { cve: "CVE-2024-0001", epss: "0.500000000", percentile: "0.900000000", date: "2026-11-21" },
            ],
          };
        },
      },
      repository: repo,
      now: NOW,
    });

    assert.equal(result.epssUpserts, 1);
    assert.equal(repo.rows.get("CVE-2024-0001")?.epssScore, 0.5);
  });

  it("rejects oversized feed responses without retrying", async () => {
    let calls = 0;
    const client = createResilientFeedClient(
      async () => {
        calls += 1;
        return new Response(JSON.stringify({ padding: "x".repeat(2_000) }), { status: 200 });
      },
      { maxRetries: 3, maxBytes: 512, sleep: async () => {} },
    );
    await assert.rejects(client.getJson(KEV_FEED_URL), /exceeds the 512 byte cap/);
    assert.equal(calls, 1);
  });

  it("reports invalid JSON clearly", async () => {
    const client = createResilientFeedClient(
      async () => new Response("<html>gateway error</html>", { status: 200 }),
      { maxRetries: 0, sleep: async () => {} },
    );
    await assert.rejects(client.getJson(KEV_FEED_URL), /not valid JSON/);
  });
});

describe("SupabaseThreatIntelRepository", () => {
  it("pages reads and upserts KEV, EPSS, and daily scores without echoing the service key", async () => {
    const calls: Array<{ url: string; method: string; body: unknown; authorization: string }> = [];
    const fetchImpl: typeof fetch = async (input, init) => {
      const url = String(input);
      calls.push({
        url,
        method: init?.method ?? "GET",
        body: init?.body ? JSON.parse(String(init.body)) : null,
        authorization: new Headers(init?.headers).get("authorization") ?? "",
      });
      if (url.includes("offset=0")) {
        return Response.json([{ cve_id: "CVE-2024-0001", kev_present: true }]);
      }
      if (url.includes("offset=1000")) return Response.json([]);
      if (url.includes("epss_daily_scores")) return new Response(null, { status: 500 });
      return new Response(null, { status: 201 });
    };

    const repo = new SupabaseThreatIntelRepository("https://example.supabase.co/", "service-role-secret", fetchImpl);
    const tracked = await repo.listTrackedCves();
    assert.deepEqual(tracked, [{ cveId: "CVE-2024-0001", kevPresent: true }]);

    await repo.upsertKev([
      {
        cveId: "CVE-2024-0001",
        description: "Synthetic",
        vendor: "Example",
        product: "Widget",
        kevPresent: true,
        kevAddedAt: "2026-11-20T00:00:00.000Z",
        kevUpdatedAt: "2026-11-20T17:48:39.151Z",
        sourceUpdatedAt: NOW.toISOString(),
      },
    ]);
    await repo.clearKevPresence({
      cveIds: ["CVE-2024-9999"],
      kevUpdatedAt: "2026-11-20T17:48:39.151Z",
      sourceUpdatedAt: NOW.toISOString(),
    });
    await assert.rejects(
      repo.upsertEpss([
        {
          cveId: "CVE-2024-0001",
          epssScore: 0.99999,
          epssPercentile: 1,
          epssDate: "2026-11-21",
          sourceUpdatedAt: NOW.toISOString(),
        },
      ]),
      (error: unknown) =>
        error instanceof Error &&
        /epss_daily_scores failed with HTTP 500/.test(error.message) &&
        !error.message.includes("service-role-secret"),
    );

    assert.equal(calls[0]?.url.includes("/rest/v1/vulnerabilities?"), true);
    assert.equal(calls.every((call) => call.authorization === "Bearer service-role-secret"), true);
    const kevWrite = calls.find((call) => call.method === "POST" && call.url.includes("on_conflict=cve_id") && !call.url.includes("epss"));
    assert.equal(kevWrite?.body[0].kev_present, true);
    assert.equal(kevWrite?.body[0].description, "Synthetic");
    const clear = calls.find((call) => call.method === "PATCH");
    assert.equal(clear?.url.includes("cve_id=in.(CVE-2024-9999)"), true);
    assert.equal(clear?.body.kev_present, false);
    assert.equal(calls.some((call) => call.url.includes("epss_daily_scores")), true);
  });
});

describe("runThreatIntelSync", () => {
  it("refuses to start without the service-role configuration", async () => {
    await assert.rejects(runThreatIntelSync({}), /No rows were changed/);
  });
});

describe("scheduled-run hardening (observation-jobs)", () => {
  it("saves completed EPSS batches and rotates the start batch by day", async () => {
    const ids = Array.from({ length: 5 }, (_, i) => `CVE-2024-000${i + 1}`);
    const seenFirst: string[] = [];
    const run = async (day: Date, failOnCall?: number) => {
      const repo = new MemoryRepo();
      let calls = 0;
      const client = {
        async getJson(url: string): Promise<unknown> {
          if (url === KEV_FEED_URL) return kevPayload(ids.map((id) => ({ id })));
          calls += 1;
          const cves = new URL(url).searchParams.get("cve")?.split(",") ?? [];
          if (calls === 1) seenFirst.push(cves[0] ?? "");
          if (calls === failOnCall) throw new Error("budget exhausted");
          return epssPayload(cves);
        },
      };
      const result = await syncThreatIntel({ client, repository: repo, now: day, epssBatchSize: 2 }).catch(
        (error: unknown) => error,
      );
      return { repo, result };
    };
    const partial = await run(NOW, 2);
    assert.ok(partial.result instanceof FeedSyncError);
    assert.match((partial.result as Error).message, /after 1 of 3 batches/);
    assert.equal(partial.repo.scores.size, 2, "the first batch was saved before the failure");
    assert.equal([...partial.repo.rows.values()].filter((r) => r.kevPresent).length, 5, "KEV saved");
    const full = await run(new Date(NOW.getTime() + 86_400_000));
    assert.equal((full.result as { epssUpserts: number }).epssUpserts, 5);
    assert.equal((full.result as { epssBatches: number }).epssBatches, 3);
    assert.notEqual(seenFirst[0], seenFirst[1], "the next day starts from a different batch");
  });

  it("keeps kev_present for a CVE still listed with invalid metadata", async () => {
    const repo = new MemoryRepo([{ cveId: "CVE-2024-7777", kevPresent: true }]);
    const payload = kevPayload([{ id: "CVE-2024-0001" }, { id: "CVE-2024-7777" }]);
    (payload.vulnerabilities[1] as Record<string, unknown>).vendorProject = ""; // invalid row
    const client = {
      async getJson(url: string): Promise<unknown> {
        if (url === KEV_FEED_URL) return payload;
        const cves = new URL(url).searchParams.get("cve")?.split(",").filter(Boolean) ?? [];
        return epssPayload(cves);
      },
    };
    const result = await syncThreatIntel({ client, repository: repo, now: NOW });
    assert.equal(result.kevCleared, 0, "a listed CVE must not be cleared");
    assert.equal(repo.rows.get("CVE-2024-7777")?.kevPresent, true);
    assert.equal(result.skippedKevRows, 1);
    assert.ok(parseKevCatalog(payload).listedIds.has("CVE-2024-7777"));
  });

  it("never waits or retries past the deadline", async () => {
    let now = 0;
    const waits: number[] = [];
    let calls = 0;
    const client = createResilientFeedClient(
      async () => {
        calls += 1;
        return new Response("busy", { status: 429, headers: { "retry-after": "60" } });
      },
      {
        sleep: async (ms) => {
          waits.push(ms);
          now += ms;
        },
        deadlineMs: 90_000,
        clock: () => now,
      },
    );
    await assert.rejects(client.getJson(KEV_FEED_URL), /HTTP 429/);
    assert.equal(calls, 2, "one 60 s wait fits; the next would pass the deadline");
    assert.deepEqual(waits, [60_000]);
    assert.ok(now <= 90_000);
  });

  it("does not start a request once the budget is exhausted", async () => {
    let calls = 0;
    const client = createResilientFeedClient(
      async () => {
        calls += 1;
        return Response.json({});
      },
      { deadlineMs: 1_000, clock: () => 2_000 },
    );
    await assert.rejects(client.getJson(KEV_FEED_URL), /time budget/);
    assert.equal(calls, 0);
  });
});
