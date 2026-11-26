// Supabase Edge Function entrypoint: authenticated, replay-resistant sensor ingest.
// Deploy only with server-managed secrets (SUPABASE_SERVICE_ROLE_KEY,
// INGEST_SENSOR_SECRETS_JSON, IP_HASH_SALT). Never expose these secrets to
// sensors or browsers.

import { createClient } from "jsr:@supabase/supabase-js@2";
import {
  type CommitBatchResult,
  handleIngestRequest,
  type IngestConfig,
  type IngestRepository,
} from "./core.ts";

function parsePositiveInt(raw: string | undefined, fallback: number): number {
  if (!raw) return fallback;
  const parsed = Number.parseInt(raw, 10);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback;
}

function loadConfig(): IngestConfig {
  const rawSecrets = Deno.env.get("INGEST_SENSOR_SECRETS_JSON") ?? "{}";
  let sensorSecrets: Record<string, string> = {};
  try {
    const parsed = JSON.parse(rawSecrets);
    if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
      sensorSecrets = Object.fromEntries(
        Object.entries(parsed).filter(
          (entry): entry is [string, string] =>
            typeof entry[0] === "string" &&
            typeof entry[1] === "string" &&
            entry[1].length >= 16,
        ),
      );
    }
  } catch {
    sensorSecrets = {};
  }

  const ipHashSalt = (Deno.env.get("IP_HASH_SALT") ?? "").trim();

  // Fail closed when IP_HASH_SALT is missing or weak so deployments cannot
  // silently fall back to unhashed IP handling.
  if (ipHashSalt.length < 16) {
    throw new Error("IP_HASH_SALT must be configured with at least 16 characters");
  }

  return {
    sensorSecrets,
    maxSkewSeconds: parsePositiveInt(Deno.env.get("INGEST_MAX_SKEW_SECONDS"), 300),
    maxBodyBytes: parsePositiveInt(Deno.env.get("INGEST_MAX_BODY_BYTES"), 262_144),
    maxBatchEvents: parsePositiveInt(Deno.env.get("INGEST_MAX_BATCH_EVENTS"), 100),
    rateLimitPerMinute: parsePositiveInt(Deno.env.get("INGEST_RATE_LIMIT_PER_MINUTE"), 60),
    ipHashSalt,
  };
}

function createSupabaseRepository(): IngestRepository {
  const url = Deno.env.get("SUPABASE_URL");
  const serviceRoleKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");
  if (!url || !serviceRoleKey) {
    throw new Error("Missing SUPABASE_URL or SUPABASE_SERVICE_ROLE_KEY");
  }

  const supabase = createClient(url, serviceRoleKey, {
    auth: { persistSession: false, autoRefreshToken: false },
  });

  return {
    async commitBatch(params): Promise<CommitBatchResult> {
      const { data, error } = await supabase.rpc("commit_ingest_batch", {
        p_sensor_id: params.sensorId,
        p_request_id: params.requestId,
        p_received_at: params.receivedAtIso,
        p_expires_at: params.expiresAtIso,
        p_rate_limit: params.rateLimitPerMinute,
        p_events: params.events,
      });

      if (error) {
        throw new Error(`commit_ingest_batch failed: ${error.code ?? "db_error"}`);
      }

      const row = Array.isArray(data) ? data[0] : data;
      const status = row?.status;
      if (status === "replayed") return { status: "replayed" };
      if (status === "rate_limited") return { status: "rate_limited" };
      if (status === "unknown_sensor") return { status: "unknown_sensor" };
      if (status === "ok") {
        return {
          status: "ok",
          inserted: typeof row?.inserted_count === "number" ? row.inserted_count : 0,
        };
      }
      throw new Error("Unexpected response from commit_ingest_batch");
    },
    async recordSensorOverload(params): Promise<void> {
      const { error } = await supabase.rpc("record_sensor_overload", {
        p_sensor_id: params.sensorId,
        p_rejected: params.rejected,
        p_deadline_cut: params.deadlineCut,
        p_window_start: params.windowStartIso,
        p_window_end: params.windowEndIso,
      });
      if (error) {
        throw new Error(`record_sensor_overload failed: ${error.code ?? "db_error"}`);
      }
    },
    async recordSensorStatus(params): Promise<void> {
      const { error } = await supabase.rpc("record_sensor_patch_status", {
        p_sensor_id: params.sensorId,
        p_patch_last_success_at: params.patchLastSuccessAtIso,
        p_received_at: params.receivedAtIso,
      });
      if (error) {
        throw new Error(`record_sensor_patch_status failed: ${error.code ?? "db_error"}`);
      }
    },
  };
}

Deno.serve(async (request: Request) => {
  try {
    const config = loadConfig();
    const repo = createSupabaseRepository();
    return await handleIngestRequest(request, config, repo);
  } catch (err) {
    console.error("Ingest handler failed:", err instanceof Error ? err.message : "unknown");
    return new Response(JSON.stringify({ error: "Internal ingest error" }), {
      status: 500,
      headers: {
        "content-type": "application/json; charset=utf-8",
        "cache-control": "no-store",
      },
    });
  }
});
