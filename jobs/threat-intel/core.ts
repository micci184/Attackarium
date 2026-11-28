// Moved to supabase/functions/_shared/threat-intel so the observation-jobs
// Edge Function (pg_cron) and this Node job share one implementation.
export * from "../../supabase/functions/_shared/threat-intel/core.ts";
