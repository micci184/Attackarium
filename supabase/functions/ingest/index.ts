// Supabase Edge Function entrypoint: authenticated, replay-resistant sensor ingest.
// Deploy only with server-managed secrets (SUPABASE_SERVICE_ROLE_KEY,
// INGEST_SENSOR_SECRETS_JSON). Never expose these secrets to sensors or browsers.

import { createClient } from "jsr:@supabase/supabase-js@2";
import {
  handleIngestRequest,
  type IngestConfig,
  type IngestRepository,
} from "./core.ts";
import type { NormalizedAttackEvent } from "./schema.ts";

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
            typeof entry[0] === "string" && typeof entry[1] === "string" && entry[1].length >= 16,
        ),
      );
    }
  } catch {
    sensorSecrets = {};
  }

  return {
    sensorSecrets,
    maxSkewSeconds: parsePositiveInt(Deno.env.get("INGEST_MAX_SKEW_SECONDS"), 300),
    maxBodyBytes: parsePositiveInt(Deno.env.get("INGEST_MAX_BODY_BYTES"), 262_144),
    maxBatchEvents: parsePositiveInt(Deno.env.get("INGEST_MAX_BATCH_EVENTS"), 100),
    rateLimitPerMinute: parsePositiveInt(Deno.env.get("INGEST_RATE_LIMIT_PER_MINUTE"), 60),
    ipHashSalt: Deno.env.get("IP_HASH_SALT") || undefined,
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
    async countRecentReceipts(sensorId: string, sinceIso: string): Promise<number> {
      const { count, error } = await supabase
        .from("ingest_receipts")
        .select("request_id", { count: "exact", head: true })
        .eq("sensor_id", sensorId)
        .gte("received_at", sinceIso);
      if (error) throw new Error(`Failed counting receipts: ${error.code ?? error.message}`);
      return count ?? 0;
    },

    async recordReceipt(
      sensorId: string,
      requestId: string,
      receivedAtIso: string,
      expiresAtIso: string,
    ): Promise<{ inserted: boolean }> {
      const { error } = await supabase.from("ingest_receipts").insert({
        sensor_id: sensorId,
        request_id: requestId,
        received_at: receivedAtIso,
        expires_at: expiresAtIso,
      });
      if (!error) return { inserted: true };
      if (error.code === "23505") return { inserted: false };
      throw new Error(`Failed recording receipt: ${error.code ?? error.message}`);
    },

    async upsertEvents(events: NormalizedAttackEvent[]): Promise<{ inserted: number }> {
      const { data, error } = await supabase
        .from("attack_events")
        .upsert(events, { onConflict: "id", ignoreDuplicates: true })
        .select("id");
      if (error) throw new Error(`Failed upserting events: ${error.code ?? error.message}`);
      return { inserted: data?.length ?? 0 };
    },

    async touchSensorHeartbeat(sensorId: string, timestampIso: string): Promise<void> {
      const { error } = await supabase
        .from("sensors")
        .update({ last_heartbeat_at: timestampIso })
        .eq("id", sensorId);
      if (error) throw new Error(`Failed updating sensor heartbeat: ${error.code ?? error.message}`);
    },
  };
}

Deno.serve(async (request: Request): Promise<Response> => {
  try {
    const config = loadConfig();
    const repo = createSupabaseRepository();
    return await handleIngestRequest(request, config, repo);
  } catch (err) {
    // Log sanitized operational error server-side; never leak secrets/stack to caller.
    console.error("ingest_internal_error", err instanceof Error ? err.message : "unknown");
    return new Response(JSON.stringify({ error: "Internal ingest error" }), {
      status: 500,
      headers: { "content-type": "application/json; charset=utf-8" },
    });
  }
});
