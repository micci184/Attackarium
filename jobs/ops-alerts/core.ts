// The logic lives in supabase/functions/_shared so the ops-alerts Edge Function
// (the primary, pg_cron-scheduled runner) and this GitHub Actions job share it.
export * from "../../supabase/functions/_shared/ops-alerts-core.ts";
