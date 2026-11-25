// Operator-only OS patch freshness for sensors (#94). Pure logic so it can be
// unit-tested without the admin console's auth and database dependencies.

export const PATCH_DUE_AFTER_DAYS = 30;
export const PATCH_OVERDUE_AFTER_DAYS = 35;

const DAY_MS = 24 * 60 * 60 * 1000;

export type PatchFreshnessState = "current" | "due" | "overdue" | "unknown";

export interface PatchFreshness {
  state: PatchFreshnessState;
  /** Whole days since the last successful patch window, or null when unknown. */
  ageDays: number | null;
  label: string;
}

/**
 * Classify a sensor's last successful patch window.
 * - current: within the monthly cadence (<= 30 days)
 * - due:     the monthly window is due (30–35 days)
 * - overdue: past the 35-day alert threshold in docs/SECURITY.md
 * - unknown: never reported, unparsable, or in the future (clock skew)
 */
export function classifyPatchFreshness(
  lastPatchSuccessAt: string | null | undefined,
  nowMs: number,
): PatchFreshness {
  if (!lastPatchSuccessAt) {
    return { state: "unknown", ageDays: null, label: "Never reported" };
  }
  const patchedMs = Date.parse(lastPatchSuccessAt);
  if (Number.isNaN(patchedMs) || patchedMs > nowMs + 5 * 60 * 1000) {
    return { state: "unknown", ageDays: null, label: "Invalid report" };
  }
  const ageMs = Math.max(0, nowMs - patchedMs);
  const ageDays = Math.floor(ageMs / DAY_MS);
  if (ageMs > PATCH_OVERDUE_AFTER_DAYS * DAY_MS) {
    return { state: "overdue", ageDays, label: `Overdue (${ageDays} days)` };
  }
  if (ageMs > PATCH_DUE_AFTER_DAYS * DAY_MS) {
    return { state: "due", ageDays, label: `Due (${ageDays} days)` };
  }
  return { state: "current", ageDays, label: `Current (${ageDays} days)` };
}

/** Attach freshness to sensor rows. `nowMs` defaults to the request time. */
export function withPatchFreshness<T extends { last_patch_success_at: string | null }>(
  rows: readonly T[],
  nowMs: number = Date.now(),
): (T & { freshness: PatchFreshness })[] {
  return rows.map((row) => ({
    ...row,
    freshness: classifyPatchFreshness(row.last_patch_success_at, nowMs),
  }));
}
