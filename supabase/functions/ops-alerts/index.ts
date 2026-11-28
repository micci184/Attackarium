import { handleOpsAlerts } from "./handler.ts";

Deno.serve((request: Request) => {
  const quotaMb = Number(Deno.env.get("OPS_DB_QUOTA_MB") ?? "");
  return handleOpsAlerts(request, {
    supabaseUrl: Deno.env.get("SUPABASE_URL") ?? "",
    serviceRoleKey: Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") ?? "",
    webhookUrl: Deno.env.get("SLACK_WEBHOOK_URL") ?? "",
    dbQuotaMb: Number.isFinite(quotaMb) && quotaMb > 0 ? quotaMb : undefined,
    cronSecret: Deno.env.get("OPS_ALERTS_CRON_SECRET") ?? "",
  });
});
