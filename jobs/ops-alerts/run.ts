import { runOpsAlerts } from "./core.ts";

// GitHub Actions runner: manual test sends (send_test) and a delayed backup to
// the pg_cron-scheduled Edge Function. Logs are public: counts only.
const quotaMb = Number(process.env.OPS_DB_QUOTA_MB ?? "");

try {
  const result = await runOpsAlerts({
    supabaseUrl: process.env.SUPABASE_URL ?? "",
    serviceRoleKey: process.env.SUPABASE_SERVICE_ROLE_KEY ?? "",
    webhookUrl: process.env.SLACK_WEBHOOK_URL ?? "",
    dbQuotaMb: Number.isFinite(quotaMb) && quotaMb > 0 ? quotaMb : undefined,
    sendTest: process.env.OPS_ALERTS_SEND_TEST === "true",
  });
  console.log(
    `checks=${result.checks} active=${result.active} notified=${result.notified} test_sent=${result.testSent}`,
  );
} catch (err) {
  // Fail so GitHub emails: an alert job that silently skips is worse than none.
  console.error(`::error::Ops alert job failed: ${err instanceof Error ? err.message : "unknown error"}`);
  process.exit(1);
}
