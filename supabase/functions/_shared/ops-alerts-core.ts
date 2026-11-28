// Scheduled operator alerts (#32): evaluate sensor and database health and
// notify Slack when an alert starts, resolves, or is still active a day later.
//
// Shared by the Supabase Edge Function `ops-alerts` (run every 15 minutes by
// pg_cron) and the GitHub Actions job (manual test sends and a delayed
// backup). Runtime-neutral: Web APIs only, no Deno or Node imports.
//
// Pure logic first (evaluateAlerts, planNotifications, buildSlackMessage), then
// thin I/O helpers and runOpsAlerts. Logs must print counts only; the Slack
// message (a private channel) may carry ages and percentages but never IPs,
// payloads, or secrets.

const DAY_MS = 24 * 60 * 60 * 1000;

/**
 * Same "current" rule as classifyPatchFreshness in
 * apps/web/src/lib/patch-freshness.ts (the operator console): a valid report
 * no more than 3 days old and not in the future beyond 5 minutes of skew.
 * Duplicated so the Edge Function bundle stays inside supabase/functions; a
 * test in jobs/ops-alerts compares both across boundaries.
 */
export function isPatchCurrent(lastPatchSuccessAt: string | null | undefined, nowMs: number): boolean {
  if (!lastPatchSuccessAt) return false;
  const patchedMs = Date.parse(lastPatchSuccessAt);
  if (Number.isNaN(patchedMs) || patchedMs > nowMs + 5 * 60 * 1000) return false;
  return Math.max(0, nowMs - patchedMs) <= 3 * DAY_MS;
}

export interface SensorHealthRow {
  id: string;
  is_active: boolean;
  last_heartbeat_at: string | null;
  last_patch_success_at: string | null;
}

export interface AlertState {
  alert_key: string;
  active: boolean;
  since: string;
  last_notified_at: string | null;
}

export type AlertKey =
  | "no_active_sensors"
  | "heartbeat_stale"
  | "db_storage"
  | "patch_freshness"
  | "edge_runner_stale";

/**
 * Written by the primary (Edge Function) runner after every successful run.
 * The GitHub watchdog reads it; it is never an alert itself.
 */
export const EDGE_RUNNER_HEARTBEAT_KEY = "runner_heartbeat:edge";
export const EDGE_RUNNER_STALE_MINUTES = 60;

export interface AlertCheck {
  key: AlertKey;
  active: boolean;
  title: string;
  detail: string;
}

export interface AlertOptions {
  nowMs: number;
  /** Shipper heartbeats every 5 minutes; allow for scheduling delays. */
  heartbeatStaleMinutes: number;
  dbQuotaBytes: number;
  dbWarnRatio: number;
}

export const DEFAULT_OPTIONS: Omit<AlertOptions, "nowMs"> = {
  heartbeatStaleMinutes: 20,
  dbQuotaBytes: 500 * 1024 * 1024, // Supabase Free plan database size
  dbWarnRatio: 0.7, // docs/RUNBOOK.md operational alerts: 350 MB of 500 MB
};

/** Unrounded age in milliseconds; round only for display. */
function ageMs(iso: string | null, nowMs: number): number | null {
  if (!iso) return null;
  const t = Date.parse(iso);
  return Number.isFinite(t) ? nowMs - t : null;
}

export function evaluateAlerts(
  sensors: readonly SensorHealthRow[],
  dbBytes: number,
  options: AlertOptions,
): AlertCheck[] {
  const active = sensors.filter((s) => s.is_active);
  const checks: AlertCheck[] = [];

  checks.push({
    key: "no_active_sensors",
    active: active.length === 0,
    title: "No active sensors",
    detail: "No sensor is marked active, so collection is not running anywhere.",
  });

  const stale = active
    .map((s) => ageMs(s.last_heartbeat_at, options.nowMs))
    .filter((age) => age === null || age > options.heartbeatStaleMinutes * 60_000);
  const oldest = stale.reduce<number | null>(
    (max, age) => (age === null ? max : max === null ? age : Math.max(max, age)),
    null,
  );
  checks.push({
    key: "heartbeat_stale",
    active: stale.length > 0,
    title: "Sensor heartbeat missing",
    detail:
      stale.length > 0
        ? `${stale.length} of ${active.length} active sensor(s) sent no heartbeat for more than ${options.heartbeatStaleMinutes} min` +
          (oldest !== null ? ` (longest: ${Math.floor(oldest / 60_000)} min).` : " (never reported).") +
          " Collection or delivery may be down; check /sensors and the shipper on the host."
        : `All ${active.length} active sensor(s) reported within ${options.heartbeatStaleMinutes} min.`,
  });

  const ratio = options.dbQuotaBytes > 0 ? dbBytes / options.dbQuotaBytes : 0;
  const pct = Math.round(ratio * 1000) / 10;
  const mb = Math.round(dbBytes / (1024 * 1024));
  const quotaMb = Math.round(options.dbQuotaBytes / (1024 * 1024));
  checks.push({
    key: "db_storage",
    active: ratio >= options.dbWarnRatio,
    title: "Database storage high",
    detail: `Database size ${mb} MB of ${quotaMb} MB (${pct}%). Alert threshold ${Math.round(options.dbWarnRatio * 100)}%. See the retention section of docs/RUNBOOK.md.`,
  });

  const notCurrent = active.filter((s) => !isPatchCurrent(s.last_patch_success_at, options.nowMs)).length;
  checks.push({
    key: "patch_freshness",
    active: notCurrent > 0,
    title: "Sensor OS updates not current",
    detail:
      notCurrent > 0
        ? `${notCurrent} of ${active.length} active sensor(s) have no successful automatic update in the last 3 days. Check /admin and docs/RUNBOOK.md.`
        : `All ${active.length} active sensor(s) are current on OS updates.`,
  });

  return checks;
}

export type NotificationKind = "firing" | "resolved" | "reminder";

export interface Notification {
  kind: NotificationKind;
  check: AlertCheck;
}

export interface NotificationPlan {
  notifications: Notification[];
  /** Rows to upsert after the notifications were delivered. */
  nextStates: AlertState[];
}

/**
 * Notify on transitions only: inactive -> active ("firing"), active ->
 * inactive ("resolved"), and once a day while an alert stays active
 * ("reminder"). Alerts that were never active create no rows.
 */
export function planNotifications(
  checks: readonly AlertCheck[],
  previous: readonly AlertState[],
  nowMs: number,
  reminderHours = 24,
): NotificationPlan {
  const nowIso = new Date(nowMs).toISOString();
  const byKey = new Map(previous.map((row) => [row.alert_key, row]));
  const notifications: Notification[] = [];
  const nextStates: AlertState[] = [];

  for (const check of checks) {
    const prev = byKey.get(check.key);
    if (check.active) {
      if (!prev || !prev.active) {
        notifications.push({ kind: "firing", check });
        nextStates.push({ alert_key: check.key, active: true, since: nowIso, last_notified_at: nowIso });
        continue;
      }
      const last = prev.last_notified_at ? Date.parse(prev.last_notified_at) : Number.NaN;
      if (!Number.isFinite(last) || nowMs - last >= reminderHours * 3_600_000) {
        notifications.push({ kind: "reminder", check });
        nextStates.push({ ...prev, last_notified_at: nowIso });
      }
    } else if (prev?.active) {
      notifications.push({ kind: "resolved", check });
      nextStates.push({ alert_key: check.key, active: false, since: nowIso, last_notified_at: nowIso });
    }
  }
  return { notifications, nextStates };
}

function escapeSlack(text: string): string {
  return text.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

const LABEL: Record<NotificationKind, string> = {
  firing: ":rotating_light: ALERT",
  reminder: ":warning: STILL ACTIVE",
  resolved: ":white_check_mark: RESOLVED",
};

/** Sent only on an explicit manual "send test" run, to prove delivery end to end. */
export function buildSlackTestMessage(nowMs: number): { text: string } {
  return {
    text: `*Attackarium operator alerts*\n\n:white_check_mark: Test message (manual run, ${new Date(nowMs).toISOString()}). Slack delivery works; no alert is implied.`,
  };
}

export function buildSlackMessage(notifications: readonly Notification[]): { text: string } {
  const lines = notifications.map(
    (n) => `${LABEL[n.kind]} *${escapeSlack(n.check.title)}*\n${escapeSlack(n.check.detail)}`,
  );
  return { text: `*Attackarium operator alerts*\n\n${lines.join("\n\n")}` };
}

/** Only Slack incoming-webhook URLs are accepted, so the secret cannot point elsewhere. */
export function isSlackWebhookUrl(value: string): boolean {
  try {
    const url = new URL(value);
    return url.protocol === "https:" && url.hostname === "hooks.slack.com" && url.pathname.startsWith("/services/");
  } catch {
    return false;
  }
}

// ---------------------------------------------------------------------------
// I/O helpers (service_role over PostgREST; Slack incoming webhook)
// ---------------------------------------------------------------------------

function restHeaders(serviceRoleKey: string, extra: Record<string, string> = {}): Record<string, string> {
  return {
    apikey: serviceRoleKey,
    authorization: `Bearer ${serviceRoleKey}`,
    accept: "application/json",
    ...extra,
  };
}

/** All sensors with an exact count; a truncated response must fail, not hide a sensor. */
export async function fetchSensors(
  supabaseUrl: string,
  serviceRoleKey: string,
  fetchFn: typeof fetch = fetch,
): Promise<SensorHealthRow[]> {
  const url = new URL("/rest/v1/sensors", supabaseUrl);
  url.searchParams.set("select", "id,is_active,last_heartbeat_at,last_patch_success_at");
  const response = await fetchFn(url, {
    headers: restHeaders(serviceRoleKey, { prefer: "count=exact" }),
    signal: AbortSignal.timeout(20_000),
  });
  if (!response.ok) throw new Error(`sensors query failed with HTTP ${response.status}`);
  const body: unknown = await response.json();
  if (!Array.isArray(body)) throw new Error("sensors query returned an unexpected shape");
  const total = Number((response.headers.get("content-range") ?? "").split("/")[1]);
  if (!Number.isInteger(total) || total !== body.length) {
    throw new Error("sensors query response may be truncated");
  }
  return body.map((row) => {
    const r = row as Record<string, unknown>;
    return {
      id: String(r.id ?? ""),
      is_active: r.is_active === true,
      last_heartbeat_at: typeof r.last_heartbeat_at === "string" ? r.last_heartbeat_at : null,
      last_patch_success_at: typeof r.last_patch_success_at === "string" ? r.last_patch_success_at : null,
    };
  });
}

export async function fetchDatabaseSizeBytes(
  supabaseUrl: string,
  serviceRoleKey: string,
  fetchFn: typeof fetch = fetch,
): Promise<number> {
  const response = await fetchFn(new URL("/rest/v1/rpc/ops_database_size_bytes", supabaseUrl), {
    method: "POST",
    headers: restHeaders(serviceRoleKey, { "content-type": "application/json" }),
    body: "{}",
    signal: AbortSignal.timeout(20_000),
  });
  if (!response.ok) throw new Error(`database size probe failed with HTTP ${response.status}`);
  const value = Number(await response.json());
  if (!Number.isFinite(value) || value <= 0) throw new Error("database size probe returned an invalid value");
  return value;
}

export async function fetchAlertStates(
  supabaseUrl: string,
  serviceRoleKey: string,
  fetchFn: typeof fetch = fetch,
): Promise<AlertState[]> {
  const url = new URL("/rest/v1/ops_alert_state", supabaseUrl);
  url.searchParams.set("select", "alert_key,active,since,last_notified_at");
  const response = await fetchFn(url, {
    headers: restHeaders(serviceRoleKey),
    signal: AbortSignal.timeout(20_000),
  });
  if (!response.ok) throw new Error(`alert state query failed with HTTP ${response.status}`);
  const body: unknown = await response.json();
  if (!Array.isArray(body)) throw new Error("alert state query returned an unexpected shape");
  return body.map((row) => {
    const r = row as Record<string, unknown>;
    return {
      alert_key: String(r.alert_key ?? ""),
      active: r.active === true,
      since: String(r.since ?? ""),
      last_notified_at: typeof r.last_notified_at === "string" ? r.last_notified_at : null,
    };
  });
}

export async function saveAlertStates(
  supabaseUrl: string,
  serviceRoleKey: string,
  rows: readonly AlertState[],
  fetchFn: typeof fetch = fetch,
): Promise<void> {
  if (rows.length === 0) return;
  const url = new URL("/rest/v1/ops_alert_state", supabaseUrl);
  url.searchParams.set("on_conflict", "alert_key");
  const response = await fetchFn(url, {
    method: "POST",
    headers: restHeaders(serviceRoleKey, {
      "content-type": "application/json",
      prefer: "resolution=merge-duplicates,return=minimal",
    }),
    body: JSON.stringify(rows.map((row) => ({ ...row, updated_at: new Date().toISOString() }))),
    signal: AbortSignal.timeout(20_000),
  });
  if (!response.ok) throw new Error(`alert state upsert failed with HTTP ${response.status}`);
}

export async function postSlack(
  webhookUrl: string,
  message: { text: string },
  fetchFn: typeof fetch = fetch,
): Promise<void> {
  if (!isSlackWebhookUrl(webhookUrl)) throw new Error("SLACK_WEBHOOK_URL is not a Slack incoming webhook URL");
  const response = await fetchFn(webhookUrl, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(message),
    redirect: "error",
    signal: AbortSignal.timeout(20_000),
  });
  if (!response.ok) throw new Error(`Slack webhook failed with HTTP ${response.status}`);
}

// ---------------------------------------------------------------------------
// One run (shared by the Edge Function and the GitHub Actions job)
// ---------------------------------------------------------------------------

export interface RunConfig {
  supabaseUrl: string;
  serviceRoleKey: string;
  webhookUrl: string;
  /** Optional database quota override in MB. */
  dbQuotaMb?: number;
  /** Also post an explicit test message (manual verification only). */
  sendTest?: boolean;
  /** Primary runner only: record a heartbeat for the watchdog. */
  recordRunnerHeartbeat?: boolean;
  /**
   * Take the single-runner lease first and skip when another run holds it,
   * so overlapping runs never post the same transition.
   */
  useLease?: boolean;
}

export interface RunResult {
  checks: number;
  active: number;
  notified: number;
  testSent: boolean;
  /** True when another run held the lease and this one did nothing. */
  skipped?: boolean;
}

async function rpc(
  supabaseUrl: string,
  serviceRoleKey: string,
  name: string,
  args: Record<string, unknown>,
  fetchFn: typeof fetch,
): Promise<unknown> {
  const response = await fetchFn(new URL(`/rest/v1/rpc/${name}`, supabaseUrl), {
    method: "POST",
    headers: restHeaders(serviceRoleKey, { "content-type": "application/json" }),
    body: JSON.stringify(args),
    signal: AbortSignal.timeout(20_000),
  });
  if (!response.ok) throw new Error(`${name} failed with HTTP ${response.status}`);
  const text = await response.text();
  return text ? JSON.parse(text) : null;
}

export async function runOpsAlerts(
  config: RunConfig,
  nowMs: number = Date.now(),
  fetchFn: typeof fetch = fetch,
): Promise<RunResult> {
  if (!config.supabaseUrl || !config.serviceRoleKey || !config.webhookUrl) {
    throw new Error("SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, or SLACK_WEBHOOK_URL is not configured");
  }
  if (!config.useLease) {
    return runChecks(config, nowMs, fetchFn);
  }
  const holder = crypto.randomUUID();
  const acquired = await rpc(
    config.supabaseUrl,
    config.serviceRoleKey,
    "ops_alerts_acquire_lease",
    { p_holder: holder, p_ttl_seconds: 120 },
    fetchFn,
  );
  if (acquired !== true) {
    return { checks: 0, active: 0, notified: 0, testSent: false, skipped: true };
  }
  try {
    return await runChecks(config, nowMs, fetchFn);
  } finally {
    // Best effort: the lease also expires on its own.
    await rpc(config.supabaseUrl, config.serviceRoleKey, "ops_alerts_release_lease", { p_holder: holder }, fetchFn).catch(
      () => undefined,
    );
  }
}

async function runChecks(config: RunConfig, nowMs: number, fetchFn: typeof fetch): Promise<RunResult> {
  const [sensors, dbBytes, previous] = await Promise.all([
    fetchSensors(config.supabaseUrl, config.serviceRoleKey, fetchFn),
    fetchDatabaseSizeBytes(config.supabaseUrl, config.serviceRoleKey, fetchFn),
    fetchAlertStates(config.supabaseUrl, config.serviceRoleKey, fetchFn),
  ]);
  const quotaMb = config.dbQuotaMb;
  const checks = evaluateAlerts(sensors, dbBytes, {
    ...DEFAULT_OPTIONS,
    ...(quotaMb !== undefined && Number.isFinite(quotaMb) && quotaMb > 0
      ? { dbQuotaBytes: quotaMb * 1024 * 1024 }
      : {}),
    nowMs,
  });
  const plan = planNotifications(checks, previous, nowMs);
  if (config.sendTest) {
    // A run with nothing to report never calls Slack, so it cannot prove the
    // webhook works. This explicit test does.
    await postSlack(config.webhookUrl, buildSlackTestMessage(nowMs), fetchFn);
  }
  if (plan.notifications.length > 0) {
    await postSlack(config.webhookUrl, buildSlackMessage(plan.notifications), fetchFn);
  }
  // Saved only after Slack accepted the message, so a failed post is retried
  // on the next run while the condition lasts.
  const nowIso = new Date(nowMs).toISOString();
  const rows = config.recordRunnerHeartbeat
    ? [
        ...plan.nextStates,
        { alert_key: EDGE_RUNNER_HEARTBEAT_KEY, active: false, since: nowIso, last_notified_at: null },
      ]
    : plan.nextStates;
  await saveAlertStates(config.supabaseUrl, config.serviceRoleKey, rows, fetchFn);
  return {
    checks: checks.length,
    active: checks.filter((c) => c.active).length,
    notified: plan.notifications.length,
    testSent: config.sendTest === true,
  };
}

/**
 * Watchdog check (GitHub backup). The Edge Function owns the four health
 * alerts; the watchdog only alerts when that runner has not completed a run
 * recently, so the two runners never post the same transition.
 */
export function evaluateEdgeRunner(previous: readonly AlertState[], nowMs: number): AlertCheck {
  const row = previous.find((r) => r.alert_key === EDGE_RUNNER_HEARTBEAT_KEY);
  const lastMs = row ? Date.parse(row.since) : Number.NaN;
  const ageMs = Number.isFinite(lastMs) ? nowMs - lastMs : null;
  const stale = ageMs === null || ageMs > EDGE_RUNNER_STALE_MINUTES * 60_000;
  return {
    key: "edge_runner_stale",
    active: stale,
    title: "Alert runner not running",
    detail: stale
      ? (ageMs === null
          ? "The ops-alerts Edge Function has never completed a run."
          : `The ops-alerts Edge Function last completed a run ${Math.floor(ageMs / 60_000)} min ago.`) +
        " Sensor alerts are not being checked; see the Slack alerts section of docs/RUNBOOK.md (pg_cron job, net._http_response, function logs)."
      : `The ops-alerts Edge Function completed a run within ${EDGE_RUNNER_STALE_MINUTES} min.`,
  };
}

export async function runWatchdog(
  config: Pick<RunConfig, "supabaseUrl" | "serviceRoleKey" | "webhookUrl" | "sendTest">,
  nowMs: number = Date.now(),
  fetchFn: typeof fetch = fetch,
): Promise<RunResult> {
  if (!config.supabaseUrl || !config.serviceRoleKey || !config.webhookUrl) {
    throw new Error("SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, or SLACK_WEBHOOK_URL is not configured");
  }
  if (config.sendTest) {
    await postSlack(config.webhookUrl, buildSlackTestMessage(nowMs), fetchFn);
  }
  const previous = await fetchAlertStates(config.supabaseUrl, config.serviceRoleKey, fetchFn);
  const check = evaluateEdgeRunner(previous, nowMs);
  const plan = planNotifications([check], previous, nowMs);
  if (plan.notifications.length > 0) {
    await postSlack(config.webhookUrl, buildSlackMessage(plan.notifications), fetchFn);
  }
  await saveAlertStates(config.supabaseUrl, config.serviceRoleKey, plan.nextStates, fetchFn);
  return {
    checks: 1,
    active: check.active ? 1 : 0,
    notified: plan.notifications.length,
    testSent: config.sendTest === true,
  };
}
