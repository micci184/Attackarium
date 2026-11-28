import { handleObservationJobs } from "./handler.ts";

Deno.serve((request: Request) =>
  handleObservationJobs(request, {
    supabaseUrl: Deno.env.get("SUPABASE_URL") ?? "",
    serviceRoleKey: Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") ?? "",
    cronSecret: Deno.env.get("OPS_ALERTS_CRON_SECRET") ?? "",
    nvdApiKey: Deno.env.get("NVD_API_KEY") ?? undefined,
    lookbackHours: Deno.env.get("CVE_MATCH_LOOKBACK_HOURS") ?? undefined,
    eventLimit: Deno.env.get("CVE_MATCH_EVENT_LIMIT") ?? undefined,
  }),
);
