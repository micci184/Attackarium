// Run the daily KEV / EPSS sync.
// Requires SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY. Never log those values.
//
// Schedule: .github/workflows/threat-intel-daily.yml at 08:15 UTC.
// The workflow skips when those secrets are not configured.

import { pathToFileURL } from "node:url";
import { createResilientFeedClient, syncThreatIntel } from "./core.ts";
import { SupabaseThreatIntelRepository } from "./supabase-repo.ts";

export async function runThreatIntelSync(env: NodeJS.ProcessEnv = process.env): Promise<void> {
  const supabaseUrl = env.SUPABASE_URL;
  const serviceRoleKey = env.SUPABASE_SERVICE_ROLE_KEY;
  if (!supabaseUrl || !serviceRoleKey) {
    throw new Error("SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY are required. No rows were changed.");
  }

  const result = await syncThreatIntel({
    client: createResilientFeedClient(fetch),
    repository: new SupabaseThreatIntelRepository(supabaseUrl, serviceRoleKey, fetch),
  });
  console.log(
    `KEV/EPSS sync applied catalog ${result.catalogVersion} ` +
      `(${result.catalogReleasedAt}): ${result.kevUpserts} KEV rows, ` +
      `${result.kevCleared} cleared, ${result.epssUpserts} EPSS rows.`,
  );
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  runThreatIntelSync().catch((error: unknown) => {
    const message = error instanceof Error ? error.message : "KEV/EPSS sync failed.";
    console.error(message);
    process.exitCode = 1;
  });
}
