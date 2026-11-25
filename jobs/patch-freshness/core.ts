// Weekly safety net for automatic sensor OS updates (ADR-027, #94).
// Pure logic: classify active sensors and summarize WITHOUT identifiers,
// timestamps, or ages, because GitHub Actions logs of this public repository
// are world-readable and patch state is host-hardening information.

import { classifyPatchFreshness } from "../../apps/web/src/lib/patch-freshness.ts";

export interface SensorPatchRow {
  id: string;
  is_active: boolean;
  last_patch_success_at: string | null;
}

export interface FreshnessReport {
  ok: boolean;
  activeSensors: number;
  needsAttention: number;
  message: string;
}

export function evaluatePatchFreshness(
  rows: readonly SensorPatchRow[],
  nowMs: number,
): FreshnessReport {
  const active = rows.filter((row) => row.is_active);
  const needsAttention = active.filter(
    (row) => classifyPatchFreshness(row.last_patch_success_at, nowMs).state !== "current",
  ).length;
  if (active.length === 0) {
    return {
      ok: false,
      activeSensors: 0,
      needsAttention: 0,
      message: "No active sensors found; cannot confirm patch freshness. Check /admin.",
    };
  }
  if (needsAttention > 0) {
    return {
      ok: false,
      activeSensors: active.length,
      needsAttention,
      message: `${needsAttention} of ${active.length} active sensor(s) are not current on OS updates. Check /admin and docs/RUNBOOK.md.`,
    };
  }
  return {
    ok: true,
    activeSensors: active.length,
    needsAttention: 0,
    message: `All ${active.length} active sensor(s) are current on OS updates.`,
  };
}

/**
 * Active sensors only, with an exact count. PostgREST caps responses at
 * max_rows (1,000 in supabase/config.toml); a truncated response must fail the
 * check rather than silently skip a stale sensor. Supported fleet size: up to
 * 1,000 active sensors (Attackarium runs one).
 */
export async function fetchSensorPatchRows(
  supabaseUrl: string,
  serviceRoleKey: string,
  fetchFn: typeof fetch = fetch,
): Promise<SensorPatchRow[]> {
  const url = new URL("/rest/v1/sensors", supabaseUrl);
  url.searchParams.set("select", "id,is_active,last_patch_success_at");
  url.searchParams.set("is_active", "eq.true");
  const response = await fetchFn(url, {
    headers: {
      apikey: serviceRoleKey,
      authorization: `Bearer ${serviceRoleKey}`,
      accept: "application/json",
      prefer: "count=exact",
    },
    signal: AbortSignal.timeout(20_000),
  });
  if (!response.ok) {
    throw new Error(`sensors query failed with HTTP ${response.status}`);
  }
  const body: unknown = await response.json();
  if (!Array.isArray(body)) {
    throw new Error("sensors query returned an unexpected shape");
  }
  // Content-Range: "0-0/1" (or "*/0" when empty). The total must be known and
  // must equal what was returned.
  const total = Number((response.headers.get("content-range") ?? "").split("/")[1]);
  if (!Number.isInteger(total) || total !== body.length) {
    throw new Error("sensors query response may be truncated; refusing to report success");
  }
  return body.map((row) => {
    const r = row as Record<string, unknown>;
    return {
      id: String(r.id ?? ""),
      is_active: r.is_active === true,
      last_patch_success_at:
        typeof r.last_patch_success_at === "string" ? r.last_patch_success_at : null,
    };
  });
}
