import { evaluatePatchFreshness, fetchSensorPatchRows } from "./core.ts";

const supabaseUrl = process.env.SUPABASE_URL ?? "";
const serviceRoleKey = process.env.SUPABASE_SERVICE_ROLE_KEY ?? "";

if (!supabaseUrl || !serviceRoleKey) {
  // A safety net that silently skips is worse than none.
  console.error("::error::SUPABASE_URL or SUPABASE_SERVICE_ROLE_KEY is not configured.");
  process.exit(1);
}

try {
  const rows = await fetchSensorPatchRows(supabaseUrl, serviceRoleKey);
  const report = evaluatePatchFreshness(rows, Date.now());
  if (report.ok) {
    console.log(report.message);
  } else {
    console.error(`::error::${report.message}`);
    process.exit(1);
  }
} catch (err) {
  console.error(
    `::error::Patch freshness check could not run: ${err instanceof Error ? err.message : "unknown error"}`,
  );
  process.exit(1);
}
