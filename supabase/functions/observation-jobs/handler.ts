// HTTP handler for the observation-jobs Edge Function. pg_cron calls it through
// pg_net (migration 20261128000004_observation_jobs_cron.sql) because GitHub
// Actions schedules run hours late on this repository:
//   {"job": "cve-matching"}  hourly: persist detections, candidate CVE matches,
//                            and NVD records
//   {"job": "threat-intel"}  daily: KEV / EPSS sync
// Same shared Bearer secret as ops-alerts. Runtime-neutral (unit-tested under
// Node); index.ts wires Deno.env and Deno.serve. Responses carry counts only.

import { checkCronRequest, jsonResponse, readSmallJsonBody } from "../_shared/cron-auth.ts";
import {
  DEFAULT_EVENT_LIMIT,
  DEFAULT_LOOKBACK_HOURS,
  MAX_EVENT_LIMIT,
  MAX_LOOKBACK_HOURS,
  syncCandidateCves,
} from "../_shared/cve-matching/core.ts";
import { SupabaseCveMatchRepository } from "../_shared/cve-matching/supabase-repo.ts";
import { createResilientFeedClient, syncThreatIntel } from "../_shared/threat-intel/core.ts";
import { SupabaseThreatIntelRepository } from "../_shared/threat-intel/supabase-repo.ts";

export const JOBS = ["cve-matching", "threat-intel"] as const;
export type JobName = (typeof JOBS)[number];

export interface JobsEnv {
  supabaseUrl: string;
  serviceRoleKey: string;
  cronSecret: string;
  nvdApiKey?: string;
  lookbackHours?: string;
  eventLimit?: string;
}

export type JobRunner = (job: JobName, env: JobsEnv) => Promise<Record<string, number | string>>;

function boundedInteger(value: string | undefined, fallback: number, max: number): number {
  const parsed = Number(value);
  if (!Number.isInteger(parsed) || parsed < 1) return fallback;
  return Math.min(parsed, max);
}

export const runJob: JobRunner = async (job, env) => {
  if (!env.supabaseUrl || !env.serviceRoleKey) {
    throw new Error("SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY are required");
  }
  if (job === "cve-matching") {
    const now = new Date();
    const lookbackHours = boundedInteger(env.lookbackHours, DEFAULT_LOOKBACK_HOURS, MAX_LOOKBACK_HOURS);
    const result = await syncCandidateCves({
      repository: new SupabaseCveMatchRepository(env.supabaseUrl, env.serviceRoleKey, fetch),
      fetchImpl: fetch,
      now,
      since: new Date(now.getTime() - lookbackHours * 3_600_000).toISOString(),
      limit: boundedInteger(env.eventLimit, DEFAULT_EVENT_LIMIT, MAX_EVENT_LIMIT),
      apiKey: env.nvdApiKey || undefined,
    });
    return {
      eventsRead: result.eventsRead,
      detections: result.detections,
      matches: result.matches,
      skipped: result.skipped,
      nvdCached: result.nvdCached,
      nvdFailed: result.nvdFailed,
    };
  }
  const result = await syncThreatIntel({
    client: createResilientFeedClient(fetch),
    repository: new SupabaseThreatIntelRepository(env.supabaseUrl, env.serviceRoleKey, fetch),
  });
  return {
    catalogVersion: result.catalogVersion,
    kevUpserts: result.kevUpserts,
    kevCleared: result.kevCleared,
    epssUpserts: result.epssUpserts,
  };
};

export async function handleObservationJobs(
  request: Request,
  env: JobsEnv,
  run: JobRunner = runJob,
): Promise<Response> {
  const refused = checkCronRequest(request, env.cronSecret);
  if (refused) return refused;
  const body = await readSmallJsonBody(request);
  const job = body.job;
  if (typeof job !== "string" || !(JOBS as readonly string[]).includes(job)) {
    return jsonResponse(400, { error: "unknown_job" });
  }
  try {
    const result = await run(job as JobName, env);
    return jsonResponse(200, { job, ...result });
  } catch (err) {
    // Message only (no stack, no secrets); visible in the function logs.
    console.error(`${job} failed: ${err instanceof Error ? err.message : "unknown error"}`);
    return jsonResponse(500, { job, error: "run_failed" });
  }
}
