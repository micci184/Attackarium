// Daily CISA KEV and FIRST EPSS sync.
// Both feeds are fetched and validated before any database write.
// A feed outage leaves the last stored KEV flags and EPSS scores unchanged.
// EPSS is requested only for KEV CVEs plus CVEs already stored. The full
// EPSS universe is never downloaded.

import {
  type EpssRecord,
  type KevRecord,
  parseEpssPage,
  parseKevCatalog,
} from "./schema.ts";

export const KEV_FEED_URL =
  "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";
export const EPSS_API_URL = "https://api.first.org/data/v1/epss";
export const MAX_TRACKED_CVES = 20_000;
export const DEFAULT_EPSS_BATCH_SIZE = 100;
export const MAX_FEED_BYTES = 20 * 1024 * 1024;

export interface TrackedCve {
  cveId: string;
  kevPresent: boolean;
}

export interface KevUpsert {
  cveId: string;
  description: string;
  vendor: string;
  product: string;
  kevPresent: true;
  kevAddedAt: string;
  kevUpdatedAt: string;
  sourceUpdatedAt: string;
}

export interface KevClear {
  cveIds: string[];
  kevUpdatedAt: string;
  sourceUpdatedAt: string;
}

export interface EpssUpsert {
  cveId: string;
  epssScore: number;
  epssPercentile: number;
  epssDate: string;
  sourceUpdatedAt: string;
}

export interface ThreatIntelRepository {
  listTrackedCves(): Promise<TrackedCve[]>;
  upsertKev(rows: KevUpsert[]): Promise<void>;
  clearKevPresence(clear: KevClear): Promise<void>;
  upsertEpss(rows: EpssUpsert[]): Promise<void>;
}

export interface FeedClient {
  getJson(url: string): Promise<unknown>;
}

export interface SyncResult {
  catalogVersion: string;
  catalogReleasedAt: string;
  kevUpserts: number;
  kevCleared: number;
  epssUpserts: number;
  skippedKevRows: number;
  skippedEpssRows: number;
}

export class FeedSyncError extends Error {
  constructor(message: string, options?: { cause?: unknown }) {
    super(message, options);
    this.name = "FeedSyncError";
  }
}

function kevUpsert(row: KevRecord, releasedAt: string, sourceUpdatedAt: string): KevUpsert {
  return {
    cveId: row.cveId,
    description: row.description,
    vendor: row.vendor,
    product: row.product,
    kevPresent: true,
    kevAddedAt: `${row.kevAddedAt}T00:00:00.000Z`,
    kevUpdatedAt: releasedAt,
    sourceUpdatedAt,
  };
}

export function epssRequestUrl(cveIds: string[]): string {
  const url = new URL(EPSS_API_URL);
  url.searchParams.set("cve", cveIds.join(","));
  return url.toString();
}

export async function fetchEpssScores(
  client: FeedClient,
  cveIds: string[],
  batchSize = DEFAULT_EPSS_BATCH_SIZE,
): Promise<{ rows: EpssRecord[]; skipped: number }> {
  const rows: EpssRecord[] = [];
  let skipped = 0;
  for (let index = 0; index < cveIds.length; index += batchSize) {
    const batch = cveIds.slice(index, index + batchSize);
    const payload = await client.getJson(epssRequestUrl(batch));
    const page = parseEpssPage(payload);
    rows.push(...page.rows);
    skipped += page.skipped;
  }
  return { rows, skipped };
}

export async function syncThreatIntel(input: {
  client: FeedClient;
  repository: ThreatIntelRepository;
  now?: Date;
  epssBatchSize?: number;
}): Promise<SyncResult> {
  const sourceUpdatedAt = (input.now ?? new Date()).toISOString();
  let tracked: TrackedCve[];
  try {
    tracked = await input.repository.listTrackedCves();
  } catch (error) {
    throw new FeedSyncError("Could not read stored CVEs. No rows were changed.", { cause: error });
  }

  let catalog;
  try {
    catalog = parseKevCatalog(await input.client.getJson(KEV_FEED_URL));
  } catch (error) {
    throw new FeedSyncError("CISA KEV fetch failed. No rows were changed.", { cause: error });
  }

  const kevIds = new Set(catalog.rows.map((row) => row.cveId));
  const targets = [...new Set([...kevIds, ...tracked.map((row) => row.cveId)])];
  if (targets.length > MAX_TRACKED_CVES) {
    throw new FeedSyncError(
      "Tracked CVE set exceeds the 20000 row cap. No rows were changed.",
    );
  }

  let epss;
  try {
    epss = await fetchEpssScores(input.client, targets, input.epssBatchSize);
  } catch (error) {
    throw new FeedSyncError("FIRST EPSS fetch failed. No rows were changed.", { cause: error });
  }

  const allowed = new Set(targets);
  const kevRows = catalog.rows.map((row) => kevUpsert(row, catalog.releasedAt, sourceUpdatedAt));
  const clearedIds = tracked
    .filter((row) => row.kevPresent && !kevIds.has(row.cveId))
    .map((row) => row.cveId);
  const epssByCve = new Map<string, EpssRecord>();
  let droppedEpss = 0;
  for (const row of epss.rows) {
    if (!allowed.has(row.cveId)) {
      droppedEpss += 1;
      continue;
    }
    epssByCve.set(row.cveId, row);
  }
  const epssRows: EpssUpsert[] = [...epssByCve.values()].map((row) => ({
    ...row,
    sourceUpdatedAt,
  }));

  await input.repository.upsertKev(kevRows);
  if (clearedIds.length > 0) {
    await input.repository.clearKevPresence({
      cveIds: clearedIds,
      kevUpdatedAt: catalog.releasedAt,
      sourceUpdatedAt,
    });
  }
  await input.repository.upsertEpss(epssRows);

  return {
    catalogVersion: catalog.catalogVersion,
    catalogReleasedAt: catalog.releasedAt,
    kevUpserts: kevRows.length,
    kevCleared: clearedIds.length,
    epssUpserts: epssRows.length,
    skippedKevRows: catalog.skipped,
    skippedEpssRows: epss.skipped + droppedEpss,
  };
}

function retryDelayMs(attempt: number, retryAfter: string | null): number {
  const seconds = retryAfter ? Number(retryAfter) : Number.NaN;
  if (Number.isFinite(seconds) && seconds >= 0 && seconds <= 60) {
    return seconds * 1_000;
  }
  return 500 * 2 ** attempt;
}

async function readBoundedJson(response: Response, maxBytes: number): Promise<unknown> {
  const declared = Number(response.headers.get("content-length"));
  if (Number.isFinite(declared) && declared > maxBytes) {
    await response.body?.cancel().catch(() => {});
    throw new FeedSyncError(`Feed response exceeds the ${maxBytes} byte cap.`);
  }

  const reader = response.body?.getReader();
  if (!reader) {
    const text = await response.text();
    if (new TextEncoder().encode(text).byteLength > maxBytes) {
      throw new FeedSyncError(`Feed response exceeds the ${maxBytes} byte cap.`);
    }
    return JSON.parse(text);
  }

  const chunks: Uint8Array[] = [];
  let totalBytes = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      totalBytes += value.byteLength;
      if (totalBytes > maxBytes) {
        await reader.cancel().catch(() => {});
        throw new FeedSyncError(`Feed response exceeds the ${maxBytes} byte cap.`);
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }

  // Web-standard concatenation (no Node Buffer), so this runs under Deno too.
  const merged = new Uint8Array(totalBytes);
  let offset = 0;
  for (const chunk of chunks) {
    merged.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return JSON.parse(new TextDecoder().decode(merged));
}

export function createResilientFeedClient(
  fetchImpl: typeof fetch,
  options: {
    timeoutMs?: number;
    maxRetries?: number;
    maxBytes?: number;
    sleep?: (ms: number) => Promise<void>;
  } = {},
): FeedClient {
  const timeoutMs = options.timeoutMs ?? 20_000;
  const maxRetries = options.maxRetries ?? 3;
  const maxBytes = options.maxBytes ?? MAX_FEED_BYTES;
  const sleep = options.sleep ?? ((ms) => new Promise((resolve) => setTimeout(resolve, ms)));

  return {
    async getJson(url: string): Promise<unknown> {
      let lastError: Error | null = null;
      for (let attempt = 0; attempt <= maxRetries; attempt += 1) {
        try {
          const response = await fetchImpl(url, { signal: AbortSignal.timeout(timeoutMs) });
          if (response.status === 429 || response.status >= 500) {
            await response.body?.cancel().catch(() => {});
            lastError = new Error(`Feed request failed with HTTP ${response.status}.`);
            if (attempt === maxRetries) break;
            await sleep(retryDelayMs(attempt, response.headers.get("retry-after")));
            continue;
          }
          if (!response.ok) {
            await response.body?.cancel().catch(() => {});
            throw new FeedSyncError(`Feed request failed with HTTP ${response.status}.`);
          }
          return await readBoundedJson(response, maxBytes);
        } catch (error) {
          if (error instanceof FeedSyncError) throw error;
          lastError =
            error instanceof SyntaxError
              ? new Error("Feed response was not valid JSON.")
              : new Error("Feed request failed before a complete response arrived.");
          if (attempt === maxRetries) break;
          await sleep(retryDelayMs(attempt, null));
        }
      }
      throw lastError ?? new Error("Feed request failed.");
    },
  };
}
