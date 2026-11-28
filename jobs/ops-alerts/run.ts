import { runOpsAlerts, runWatchdog } from "./core.ts";

// GitHub Actions runner. Logs are public: counts only.
// - OPS_ALERTS_MODE=watchdog (scheduled): only checks that the primary
//   runner (the pg_cron-scheduled Edge Function) is still running, so the two
//   runners never post the same health alert.
// - otherwise (manual): the full check, optionally with send_test.
const quotaMb = Number(process.env.OPS_DB_QUOTA_MB ?? "");
const config = {
  supabaseUrl: process.env.SUPABASE_URL ?? "",
  serviceRoleKey: process.env.SUPABASE_SERVICE_ROLE_KEY ?? "",
  webhookUrl: process.env.SLACK_WEBHOOK_URL ?? "",
};

try {
  const result =
    process.env.OPS_ALERTS_MODE === "watchdog"
      ? await runWatchdog(config)
      : await runOpsAlerts({
          ...config,
          dbQuotaMb: Number.isFinite(quotaMb) && quotaMb > 0 ? quotaMb : undefined,
          sendTest: process.env.OPS_ALERTS_SEND_TEST === "true",
        });
  console.log(
    `mode=${process.env.OPS_ALERTS_MODE === "watchdog" ? "watchdog" : "full"} checks=${result.checks} active=${result.active} notified=${result.notified} test_sent=${result.testSent}`,
  );
} catch (err) {
  // Fail so GitHub emails: an alert job that silently skips is worse than none.
  console.error(`::error::Ops alert job failed: ${err instanceof Error ? err.message : "unknown error"}`);
  process.exit(1);
}
