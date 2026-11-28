// CISA KEV and FIRST EPSS payload validation.
// Invalid catalog envelopes throw. A single bad CVE row is skipped.

const CVE_ID = /^CVE-[0-9]{4}-[0-9]{4,}$/;
const ISO_DATE = /^(\d{4})-(\d{2})-(\d{2})$/;
const SCORE = /^(?:0(?:\.\d+)?|1(?:\.0+)?)$/;

export const MAX_DESCRIPTION_LENGTH = 2_000;
export const MAX_LABEL_LENGTH = 200;

export interface KevRecord {
  cveId: string;
  description: string;
  vendor: string;
  product: string;
  kevAddedAt: string;
}

export interface ParsedKevCatalog {
  catalogVersion: string;
  releasedAt: string;
  rows: KevRecord[];
  skipped: number;
}

export interface EpssRecord {
  cveId: string;
  epssScore: number;
  epssPercentile: number;
  epssDate: string;
}

export interface ParsedEpssPage {
  rows: EpssRecord[];
  skipped: number;
}

export class FeedParseError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "FeedParseError";
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function cleanText(value: unknown, maxLength: number): string | null {
  if (typeof value !== "string") return null;
  const trimmed = value.trim().replace(/\s+/g, " ");
  if (trimmed.length === 0) return null;
  return trimmed.length <= maxLength ? trimmed : trimmed.slice(0, maxLength);
}

export function parseUtcTimestamp(value: unknown): string | null {
  if (typeof value !== "string") return null;
  const normalized = value.trim().replace(/(\.\d{3})\d+(Z|[+-]\d{2}:\d{2})$/, "$1$2");
  const ms = Date.parse(normalized);
  if (Number.isNaN(ms)) return null;
  return new Date(ms).toISOString();
}

export function parseUtcDate(value: unknown): string | null {
  if (typeof value !== "string" || !ISO_DATE.test(value)) return null;
  const ms = Date.parse(`${value}T00:00:00.000Z`);
  if (Number.isNaN(ms)) return null;
  const roundTrip = new Date(ms).toISOString().slice(0, 10);
  return roundTrip === value ? value : null;
}

export function parseUnitScore(value: unknown): number | null {
  if (typeof value !== "string" || !SCORE.test(value)) return null;
  const rounded = Math.round(Number(value) * 100_000) / 100_000;
  if (rounded < 0 || rounded > 1) return null;
  return rounded;
}

export function parseKevCatalog(payload: unknown): ParsedKevCatalog {
  if (!isRecord(payload) || !Array.isArray(payload.vulnerabilities)) {
    throw new FeedParseError("CISA KEV catalog is missing its vulnerability list.");
  }
  const catalogVersion = cleanText(payload.catalogVersion, 32);
  const releasedAt = parseUtcTimestamp(payload.dateReleased);
  if (!catalogVersion || !releasedAt) {
    throw new FeedParseError("CISA KEV catalog is missing catalogVersion or dateReleased.");
  }
  if (payload.vulnerabilities.length > 20_000) {
    throw new FeedParseError("CISA KEV catalog exceeds the 20000 CVE storage cap.");
  }

  const byId = new Map<string, KevRecord>();
  let skipped = 0;
  for (const item of payload.vulnerabilities) {
    if (!isRecord(item) || typeof item.cveID !== "string" || !CVE_ID.test(item.cveID)) {
      skipped += 1;
      continue;
    }
    const description = cleanText(item.shortDescription, MAX_DESCRIPTION_LENGTH);
    const vendor = cleanText(item.vendorProject, MAX_LABEL_LENGTH);
    const product = cleanText(item.product, MAX_LABEL_LENGTH);
    const kevAddedAt = parseUtcDate(item.dateAdded);
    if (!description || !vendor || !product || !kevAddedAt) {
      skipped += 1;
      continue;
    }
    byId.set(item.cveID, {
      cveId: item.cveID,
      description,
      vendor,
      product,
      kevAddedAt,
    });
  }

  if (byId.size === 0) {
    throw new FeedParseError("CISA KEV catalog did not contain any valid CVE rows.");
  }

  return {
    catalogVersion,
    releasedAt,
    rows: [...byId.values()],
    skipped,
  };
}

export function parseEpssPage(payload: unknown): ParsedEpssPage {
  if (!isRecord(payload) || payload.status !== "OK" || !Array.isArray(payload.data)) {
    throw new FeedParseError("FIRST EPSS response is missing an OK data list.");
  }
  if (payload.data.length > 20_000) {
    throw new FeedParseError("FIRST EPSS page exceeds the 20000 CVE storage cap.");
  }

  const rows: EpssRecord[] = [];
  let skipped = 0;
  for (const item of payload.data) {
    if (!isRecord(item) || typeof item.cve !== "string" || !CVE_ID.test(item.cve)) {
      skipped += 1;
      continue;
    }
    const epssScore = parseUnitScore(item.epss);
    const epssPercentile = parseUnitScore(item.percentile);
    const epssDate = parseUtcDate(item.date);
    if (epssScore === null || epssPercentile === null || !epssDate) {
      skipped += 1;
      continue;
    }
    rows.push({ cveId: item.cve, epssScore, epssPercentile, epssDate });
  }
  return { rows, skipped };
}
