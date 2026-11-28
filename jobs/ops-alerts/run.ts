import { runWatchdog } from "./core.ts";

// GitHub Actions runner: WATCHDOG ONLY (scheduled and manual). It alerts when
// the primary runner (the pg_cron-scheduled ops-alerts Edge Function) has not
// completed a run for 60 minutes. It never evaluates or posts the health
// alerts, so it can never duplicate a transition posted by the Edge runner.
// A manual run with send_test also posts a Slack test message (verifies the
// repository secret). Run the health check on demand with
// `select public.ops_alerts_dispatch();` instead. Logs are public: counts only.
try {
  const result = await runWatchdog({
    supabaseUrl: process.env.SUPABASE_URL ?? "",
    serviceRoleKey: process.env.SUPABASE_SERVICE_ROLE_KEY ?? "",
    webhookUrl: process.env.SLACK_WEBHOOK_URL ?? "",
    sendTest: process.env.OPS_ALERTS_SEND_TEST === "true",
  });
  console.log(
    `mode=watchdog checks=${result.checks} active=${result.active} notified=${result.notified} test_sent=${result.testSent}`,
  );
} catch (err) {
  // Fail so GitHub emails: an alert job that silently skips is worse than none.
  console.error(`::error::Ops alert watchdog failed: ${err instanceof Error ? err.message : "unknown error"}`);
  process.exit(1);
}
