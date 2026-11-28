// HTTP handler for the ops-alerts Edge Function (#32). Runtime-neutral so it
// is unit-tested under Node; index.ts wires Deno.env and Deno.serve.
//
// Invoked every 15 minutes by pg_cron through pg_net (see migration
// 20261128000003_ops_alerts_cron.sql). verify_jwt is off: the caller must send
// the shared OPS_ALERTS_CRON_SECRET as a Bearer token. Responses and logs carry
// counts only.

import { checkCronRequest, jsonResponse, readSmallJsonBody } from "../_shared/cron-auth.ts";
import { runOpsAlerts, type RunConfig, type RunResult } from "../_shared/ops-alerts-core.ts";

export interface HandlerEnv extends Omit<RunConfig, "sendTest"> {
  cronSecret: string;
}

// Re-exported for existing tests and callers.
export { secretsEqual } from "../_shared/cron-auth.ts";

export async function handleOpsAlerts(
  request: Request,
  env: HandlerEnv,
  run: (config: RunConfig) => Promise<RunResult> = (config) => runOpsAlerts(config),
): Promise<Response> {
  const refused = checkCronRequest(request, env.cronSecret);
  if (refused) return refused;
  // Optional JSON body {"send_test": true} (operator verification through the
  // dispatcher). Anything else, including no body, means a normal run.
  const body = await readSmallJsonBody(request);
  const sendTest = body.send_test === true;
  try {
    const result = await run({
      supabaseUrl: env.supabaseUrl,
      serviceRoleKey: env.serviceRoleKey,
      webhookUrl: env.webhookUrl,
      dbQuotaMb: env.dbQuotaMb,
      recordRunnerHeartbeat: true,
      useLease: true,
      sendTest,
    });
    return jsonResponse(200, result);
  } catch (err) {
    // Message only (no stack, no secrets); visible in the function logs.
    console.error(`ops-alerts run failed: ${err instanceof Error ? err.message : "unknown error"}`);
    return jsonResponse(500, { error: "run_failed" });
  }
}
