// HTTP handler for the ops-alerts Edge Function (#32). Runtime-neutral so it
// is unit-tested under Node; index.ts wires Deno.env and Deno.serve.
//
// Invoked every 15 minutes by pg_cron through pg_net (see migration
// 20261128000003_ops_alerts_cron.sql). verify_jwt is off: the caller must send
// the shared OPS_ALERTS_CRON_SECRET as a Bearer token. Responses and logs carry
// counts only.

import { runOpsAlerts, type RunConfig, type RunResult } from "../_shared/ops-alerts-core.ts";

export interface HandlerEnv extends Omit<RunConfig, "sendTest"> {
  cronSecret: string;
}

/** Constant-time comparison of two strings (length leak only). */
export function secretsEqual(a: string, b: string): boolean {
  const enc = new TextEncoder();
  const x = enc.encode(a);
  const y = enc.encode(b);
  let diff = x.length ^ y.length;
  for (let i = 0; i < Math.max(x.length, y.length); i++) {
    diff |= (x[i] ?? 0) ^ (y[i] ?? 0);
  }
  return diff === 0;
}

function json(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json", "cache-control": "no-store" },
  });
}

export async function handleOpsAlerts(
  request: Request,
  env: HandlerEnv,
  run: (config: RunConfig) => Promise<RunResult> = (config) => runOpsAlerts(config),
): Promise<Response> {
  if (request.method !== "POST") {
    return json(405, { error: "method_not_allowed" });
  }
  // A missing secret must never mean "open": refuse every call.
  if (env.cronSecret.length < 32) {
    return json(503, { error: "not_configured" });
  }
  const header = request.headers.get("authorization") ?? "";
  const token = header.startsWith("Bearer ") ? header.slice("Bearer ".length) : "";
  if (!secretsEqual(token, env.cronSecret)) {
    return json(401, { error: "unauthorized" });
  }
  // Optional JSON body {"send_test": true} (operator verification through the
  // dispatcher). Anything else, including no body, means a normal run.
  let sendTest = false;
  try {
    const text = await request.text();
    if (text.length > 0 && text.length <= 1024) {
      const body: unknown = JSON.parse(text);
      sendTest = typeof body === "object" && body !== null && (body as { send_test?: unknown }).send_test === true;
    }
  } catch {
    sendTest = false;
  }
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
    return json(200, result);
  } catch (err) {
    // Message only (no stack, no secrets); visible in the function logs.
    console.error(`ops-alerts run failed: ${err instanceof Error ? err.message : "unknown error"}`);
    return json(500, { error: "run_failed" });
  }
}
