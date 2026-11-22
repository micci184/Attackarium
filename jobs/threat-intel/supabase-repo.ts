// Service-role writer for the daily KEV / EPSS job.
// Uses PostgREST upserts so reruns update the same CVE and score-date rows.

import type { EpssUpsert, KevClear, KevUpsert, ThreatIntelRepository, TrackedCve } from "./core.ts";

const PAGE_SIZE = 1_000;
const WRITE_CHUNK = 500;

interface RestRow {
  cve_id?: unknown;
  kev_present?: unknown;
}

function restUrl(supabaseUrl: string, pathAndQuery: string): string {
  return `${supabaseUrl.replace(/\/$/, "")}/rest/v1/${pathAndQuery}`;
}

function chunk<T>(rows: T[], size: number): T[][] {
  const chunks: T[][] = [];
  for (let index = 0; index < rows.length; index += size) {
    chunks.push(rows.slice(index, index + size));
  }
  return chunks;
}

export class SupabaseThreatIntelRepository implements ThreatIntelRepository {
  private readonly supabaseUrl: string;
  private readonly serviceRoleKey: string;
  private readonly fetchImpl: typeof fetch;

  constructor(supabaseUrl: string, serviceRoleKey: string, fetchImpl: typeof fetch) {
    this.supabaseUrl = supabaseUrl;
    this.serviceRoleKey = serviceRoleKey;
    this.fetchImpl = fetchImpl;
  }

  async listTrackedCves(): Promise<TrackedCve[]> {
    const tracked: TrackedCve[] = [];
    for (let offset = 0; offset < 100_000; offset += PAGE_SIZE) {
      const response = await this.request(
        `vulnerabilities?select=cve_id,kev_present&order=cve_id.asc&limit=${PAGE_SIZE}&offset=${offset}`,
        { method: "GET" },
      );
      const page = (await response.json()) as RestRow[];
      if (!Array.isArray(page)) {
        throw new Error("Supabase vulnerabilities read did not return a list.");
      }
      for (const row of page) {
        if (typeof row.cve_id !== "string" || typeof row.kev_present !== "boolean") {
          throw new Error("Supabase vulnerabilities read returned an unexpected row.");
        }
        tracked.push({ cveId: row.cve_id, kevPresent: row.kev_present });
      }
      if (page.length < PAGE_SIZE) break;
    }
    return tracked;
  }

  async upsertKev(rows: KevUpsert[]): Promise<void> {
    for (const part of chunk(rows, WRITE_CHUNK)) {
      await this.request("vulnerabilities?on_conflict=cve_id", {
        method: "POST",
        prefer: "resolution=merge-duplicates,return=minimal",
        body: part.map((row) => ({
          cve_id: row.cveId,
          description: row.description,
          vendor: row.vendor,
          product: row.product,
          kev_present: true,
          kev_added_at: row.kevAddedAt,
          kev_updated_at: row.kevUpdatedAt,
          source_updated_at: row.sourceUpdatedAt,
        })),
      });
    }
  }

  async clearKevPresence(clear: KevClear): Promise<void> {
    for (const part of chunk(clear.cveIds, 100)) {
      const list = part.map((id) => encodeURIComponent(id)).join(",");
      await this.request(`vulnerabilities?cve_id=in.(${list})&kev_present=eq.true`, {
        method: "PATCH",
        prefer: "return=minimal",
        body: {
          kev_present: false,
          kev_updated_at: clear.kevUpdatedAt,
          source_updated_at: clear.sourceUpdatedAt,
        },
      });
    }
  }

  async upsertEpss(rows: EpssUpsert[]): Promise<void> {
    for (const part of chunk(rows, WRITE_CHUNK)) {
      const scores = part.map((row) => ({
        cve_id: row.cveId,
        score_date: row.epssDate,
        epss_score: row.epssScore,
        epss_percentile: row.epssPercentile,
      }));
      const current = part.map((row) => ({
        cve_id: row.cveId,
        epss_score: row.epssScore,
        epss_percentile: row.epssPercentile,
        epss_date: row.epssDate,
        source_updated_at: row.sourceUpdatedAt,
      }));
      // History first. A failed snapshot update is retried by the next run,
      // and the previous current score stays in place.
      await this.request("epss_daily_scores?on_conflict=cve_id,score_date", {
        method: "POST",
        prefer: "resolution=merge-duplicates,return=minimal",
        body: scores,
      });
      await this.request("vulnerabilities?on_conflict=cve_id", {
        method: "POST",
        prefer: "resolution=merge-duplicates,return=minimal",
        body: current,
      });
    }
  }

  private async request(
    pathAndQuery: string,
    init: { method: string; prefer?: string; body?: unknown },
  ): Promise<Response> {
    const headers: Record<string, string> = {
      apikey: this.serviceRoleKey,
      authorization: `Bearer ${this.serviceRoleKey}`,
      accept: "application/json",
    };
    if (init.body !== undefined) headers["content-type"] = "application/json";
    if (init.prefer) headers.prefer = init.prefer;

    const response = await this.fetchImpl(restUrl(this.supabaseUrl, pathAndQuery), {
      method: init.method,
      headers,
      body: init.body === undefined ? undefined : JSON.stringify(init.body),
    });
    if (!response.ok) {
      const table = pathAndQuery.split("?")[0];
      throw new Error(`Supabase ${init.method} ${table} failed with HTTP ${response.status}.`);
    }
    return response;
  }
}
