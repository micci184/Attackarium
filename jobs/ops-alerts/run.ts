import {
  DEFAULT_OPTIONS,
  buildSlackMessage,
  buildSlackTestMessage,
  evaluateAlerts,
  fetchAlertStates,
  fetchDatabaseSizeBytes,
  fetchSensors,
  planNotifications,
  postSlack,
  saveAlertStates,
} from "./core.ts";

// Logs are public (GitHub Actions on a public repository): print counts only.
const supabaseUrl = process.env.SUPABASE_URL ?? "";
const serviceRoleKey = process.env.SUPABASE_SERVICE_ROLE_KEY ?? "";
const webhookUrl = process.env.SLACK_WEBHOOK_URL ?? "";
const quotaMb = Number(process.env.OPS_DB_QUOTA_MB ?? "");
const sendTest = process.env.OPS_ALERTS_SEND_TEST === "true";

if (!supabaseUrl || !serviceRoleKey || !webhookUrl) {
  // An alert job that silently skips is worse than none: fail so GitHub emails.
  console.error("::error::SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, or SLACK_WEBHOOK_URL is not configured.");
  process.exit(1);
}

try {
  const nowMs = Date.now();
  const [sensors, dbBytes, previous] = await Promise.all([
    fetchSensors(supabaseUrl, serviceRoleKey),
    fetchDatabaseSizeBytes(supabaseUrl, serviceRoleKey),
    fetchAlertStates(supabaseUrl, serviceRoleKey),
  ]);
  const checks = evaluateAlerts(sensors, dbBytes, {
    ...DEFAULT_OPTIONS,
    ...(Number.isFinite(quotaMb) && quotaMb > 0 ? { dbQuotaBytes: quotaMb * 1024 * 1024 } : {}),
    nowMs,
  });
  const plan = planNotifications(checks, previous, nowMs);
  if (sendTest) {
    // A normal run with nothing to report never calls Slack, so it cannot prove
    // the webhook works. This explicit test does.
    await postSlack(webhookUrl, buildSlackTestMessage(nowMs));
  }
  if (plan.notifications.length > 0) {
    await postSlack(webhookUrl, buildSlackMessage(plan.notifications));
  }
  // Saved only after Slack accepted the message, so a failed post is retried.
  await saveAlertStates(supabaseUrl, serviceRoleKey, plan.nextStates);
  console.log(
    `checks=${checks.length} active=${checks.filter((c) => c.active).length} notified=${plan.notifications.length} test_sent=${sendTest}`,
  );
} catch (err) {
  console.error(`::error::Ops alert job failed: ${err instanceof Error ? err.message : "unknown error"}`);
  process.exit(1);
}
