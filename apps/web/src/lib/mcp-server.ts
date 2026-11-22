import { createClient, type SupabaseClient } from "@supabase/supabase-js";
import { createMcpHandler, getPublicOrigin } from "mcp-handler";
import {
  MCP_READ_SCOPE,
  MCP_TERMS_VERSION,
  evaluateMcpAccess,
  type McpEntitlementState,
} from "./mcp-access.ts";
import {
  buildWwwAuthenticateHeader,
  createSupabaseJwtVerifier,
  extractBearerToken,
  type VerifyMcpTokenFn,
} from "./mcp-auth.ts";
import {
  defaultObservatorySource,
  isMcpToolName,
  registerAttackariumTools,
  type McpObservatorySource,
  type McpToolName,
} from "./mcp-tools.ts";

export type McpRequestKind = "initialize" | "tool_call";

export interface McpRateLimitResult {
  allowed: boolean;
  currentCount: number;
  retryAfterSeconds: number;
}

/**
 * Strictly aggregate-only usage telemetry.
 * Never includes user prompts, tool arguments, auth tokens, or user IDs.
 */
export interface McpUsageRecord {
  observedAt: string;
  requestKind: McpRequestKind;
  toolName: "" | McpToolName;
  callDelta: 0 | 1;
  successDelta: 0 | 1;
  errorDelta: 0 | 1;
  authFailureDelta: 0 | 1;
  rateLimitedDelta: 0 | 1;
  latencyMs: number;
}

export interface McpServerDependencies {
  verifyToken: VerifyMcpTokenFn;
  fetchEntitlement: (userId: string) => Promise<McpEntitlementState | null>;
  consumeRateLimit: (userId: string) => Promise<McpRateLimitResult>;
  recordUsage?: (record: McpUsageRecord) => Promise<void>;
  observatory?: McpObservatorySource;
  requiredTermsVersion?: string;
  siteOrigin?: string;
  now?: () => number;
}

interface ParsedRpcTarget {
  requestKind: McpRequestKind;
  toolName: "" | McpToolName;
  trackCall: boolean;
}

const MAX_MCP_BODY_BYTES = 64 * 1024;

function resolveResourceOrigin(request: Request, configuredOrigin?: string): string {
  const candidate = configuredOrigin?.trim();
  if (candidate) {
    try {
      return new URL(candidate).origin;
    } catch {
      // Fall back to request origin when env URL is malformed.
    }
  }
  return getPublicOrigin(request);
}

async function inspectRpcTarget(request: Request): Promise<ParsedRpcTarget> {
  if (request.method !== "POST") {
    return { requestKind: "initialize", toolName: "", trackCall: false };
  }
  try {
    const body = (await request.clone().json()) as {
      method?: unknown;
      params?: { name?: unknown } | null;
    } | null;

    if (body?.method === "initialize") {
      return { requestKind: "initialize", toolName: "", trackCall: true };
    }
    if (
      body?.method === "tools/call" &&
      typeof body.params?.name === "string" &&
      isMcpToolName(body.params.name)
    ) {
      return {
        requestKind: "tool_call",
        toolName: body.params.name,
        trackCall: true,
      };
    }
  } catch {
    // Malformed JSON will be handled by the MCP handler itself.
  }
  return { requestKind: "initialize", toolName: "", trackCall: false };
}

function jsonError(
  status: number,
  body: Record<string, unknown>,
  extraHeaders: Record<string, string> = {},
): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      "Content-Type": "application/json",
      "Cache-Control": "no-store",
      ...extraHeaders,
    },
  });
}

function withNoStore(response: Response): Response {
  const headers = new Headers(response.headers);
  headers.set("Cache-Control", "no-store");
  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers,
  });
}

async function safeRecordUsage(
  recordUsage: McpServerDependencies["recordUsage"],
  record: McpUsageRecord,
): Promise<void> {
  if (!recordUsage) return;
  try {
    await recordUsage(record);
  } catch {
    // Telemetry failures must not break read-only MCP responses or leak secrets.
  }
}

export function createAttackariumMcpHandler(
  deps: McpServerDependencies,
): (request: Request) => Promise<Response> {
  const observatory = deps.observatory ?? defaultObservatorySource;
  const requiredTermsVersion = deps.requiredTermsVersion ?? MCP_TERMS_VERSION;
  const nowFn = deps.now ?? Date.now;

  const mcpHandler = createMcpHandler(
    (server) => {
      registerAttackariumTools(server, observatory);
    },
    {
      serverInfo: {
        name: "attackarium-mcp",
        version: "0.1.0",
      },
    },
  );

  return async (request: Request): Promise<Response> => {
    const startedAt = nowFn();
    const observedAt = new Date(startedAt).toISOString();
    const origin = resolveResourceOrigin(request, deps.siteOrigin);
    const resourceMetadataUrl = `${origin}/.well-known/oauth-protected-resource`;

    // Gate 1a: Require a valid Bearer JWT before reading any untrusted body.
    const bearerToken = extractBearerToken(request);
    if (!bearerToken) {
      await safeRecordUsage(deps.recordUsage, {
        observedAt,
        requestKind: "initialize",
        toolName: "",
        callDelta: 0,
        successDelta: 0,
        errorDelta: 0,
        authFailureDelta: 1,
        rateLimitedDelta: 0,
        latencyMs: Math.max(0, nowFn() - startedAt),
      });
      return jsonError(
        401,
        { error: "unauthorized" },
        {
          "WWW-Authenticate": buildWwwAuthenticateHeader(
            resourceMetadataUrl,
            MCP_READ_SCOPE,
          ),
        },
      );
    }

    const identity = await deps.verifyToken(bearerToken);
    if (!identity) {
      await safeRecordUsage(deps.recordUsage, {
        observedAt,
        requestKind: "initialize",
        toolName: "",
        callDelta: 0,
        successDelta: 0,
        errorDelta: 0,
        authFailureDelta: 1,
        rateLimitedDelta: 0,
        latencyMs: Math.max(0, nowFn() - startedAt),
      });
      return jsonError(
        401,
        { error: "unauthorized" },
        {
          "WWW-Authenticate": buildWwwAuthenticateHeader(
            resourceMetadataUrl,
            MCP_READ_SCOPE,
          ),
        },
      );
    }

    // Gates 1b-5: Live DB lookup on every request so suspension and revocation
    // take effect immediately even before JWT expiry.
    let entitlement: McpEntitlementState | null;
    try {
      entitlement = await deps.fetchEntitlement(identity.userId);
    } catch {
      return jsonError(503, { error: "authorization_unavailable" });
    }

    const decision = evaluateMcpAccess(
      identity,
      entitlement,
      requiredTermsVersion,
    );
    if (!decision.ok) {
      await safeRecordUsage(deps.recordUsage, {
        observedAt,
        requestKind: "initialize",
        toolName: "",
        callDelta: 0,
        successDelta: 0,
        errorDelta: 0,
        authFailureDelta: 1,
        rateLimitedDelta: 0,
        latencyMs: Math.max(0, nowFn() - startedAt),
      });

      const extraHeaders: Record<string, string> =
        decision.gate === "consent"
          ? {
              "WWW-Authenticate": `${buildWwwAuthenticateHeader(
                resourceMetadataUrl,
                MCP_READ_SCOPE,
              )}, error="insufficient_scope"`,
            }
          : {};

      return jsonError(
        403,
        { error: "forbidden", gate: decision.gate },
        extraHeaders,
      );
    }

    // Per-user rate limit check (fail closed if the rate-limit store errors).
    let rateLimit: McpRateLimitResult;
    try {
      rateLimit = await deps.consumeRateLimit(identity.userId);
    } catch {
      return jsonError(503, { error: "rate_limit_unavailable" });
    }

    if (!rateLimit.allowed) {
      await safeRecordUsage(deps.recordUsage, {
        observedAt,
        requestKind: "initialize",
        toolName: "",
        callDelta: 0,
        successDelta: 0,
        errorDelta: 0,
        authFailureDelta: 0,
        rateLimitedDelta: 1,
        latencyMs: Math.max(0, nowFn() - startedAt),
      });
      return jsonError(
        429,
        {
          error: "rate_limited",
          retryAfterSeconds: rateLimit.retryAfterSeconds,
        },
        {
          "Retry-After": String(rateLimit.retryAfterSeconds),
        },
      );
    }

    // Bound POST payload size before parsing JSON or invoking the MCP handler.
    if (request.method === "POST") {
      const contentLength = Number.parseInt(
        request.headers.get("content-length") ?? "",
        10,
      );
      if (Number.isFinite(contentLength) && contentLength > MAX_MCP_BODY_BYTES) {
        return jsonError(413, { error: "payload_too_large" });
      }
      const rawBytes = (await request.clone().arrayBuffer()).byteLength;
      if (rawBytes > MAX_MCP_BODY_BYTES) {
        return jsonError(413, { error: "payload_too_large" });
      }
    }

    const target = await inspectRpcTarget(request);

    try {
      const response = await mcpHandler(request);
      const isSuccess = response.status >= 200 && response.status < 400;
      if (target.trackCall) {
        await safeRecordUsage(deps.recordUsage, {
          observedAt,
          requestKind: target.requestKind,
          toolName: target.toolName,
          callDelta: 1,
          successDelta: isSuccess ? 1 : 0,
          errorDelta: isSuccess ? 0 : 1,
          authFailureDelta: 0,
          rateLimitedDelta: 0,
          latencyMs: Math.max(0, nowFn() - startedAt),
        });
      }
      return withNoStore(response);
    } catch {
      if (target.trackCall) {
        await safeRecordUsage(deps.recordUsage, {
          observedAt,
          requestKind: target.requestKind,
          toolName: target.toolName,
          callDelta: 1,
          successDelta: 0,
          errorDelta: 1,
          authFailureDelta: 0,
          rateLimitedDelta: 0,
          latencyMs: Math.max(0, nowFn() - startedAt),
        });
      }
      return jsonError(500, { error: "internal_error" });
    }
  };
}

let cachedLiveHandler: ((request: Request) => Promise<Response>) | null = null;
let cachedSupabaseClient: SupabaseClient | null = null;

function parseRateLimitPerMinute(raw: string | undefined): number {
  if (!raw) return 30;
  const parsed = Number.parseInt(raw, 10);
  if (!Number.isFinite(parsed) || parsed < 1) return 30;
  return Math.min(parsed, 1000);
}

function getServiceRoleClient(
  supabaseUrl: string,
  serviceRoleKey: string,
): SupabaseClient {
  if (cachedSupabaseClient) return cachedSupabaseClient;
  cachedSupabaseClient = createClient(supabaseUrl, serviceRoleKey, {
    auth: {
      persistSession: false,
      autoRefreshToken: false,
    },
  });
  return cachedSupabaseClient;
}

export function getLiveAttackariumMcpHandler(): (
  request: Request,
) => Promise<Response> {
  if (cachedLiveHandler) return cachedLiveHandler;

  const supabaseUrl =
    process.env.SUPABASE_URL ?? process.env.NEXT_PUBLIC_SUPABASE_URL;
  const serviceRoleKey = process.env.SUPABASE_SERVICE_ROLE_KEY;
  const authIssuer =
    process.env.SUPABASE_AUTH_ISSUER ??
    (supabaseUrl ? `${supabaseUrl.replace(/\/+$/, "")}/auth/v1` : undefined);

  if (!supabaseUrl || !serviceRoleKey || !authIssuer) {
    return async () => jsonError(503, { error: "mcp_not_configured" });
  }

  const client = getServiceRoleClient(supabaseUrl, serviceRoleKey);
  const rateLimitPerMinute = parseRateLimitPerMinute(
    process.env.MCP_RATE_LIMIT_PER_MINUTE,
  );
  const requiredTermsVersion =
    process.env.MCP_REQUIRED_TERMS_VERSION?.trim() || MCP_TERMS_VERSION;
  const audience = process.env.MCP_JWT_AUDIENCE?.trim() || "authenticated";

  const verifyToken = createSupabaseJwtVerifier({
    issuer: authIssuer,
    audience,
  });

  cachedLiveHandler = createAttackariumMcpHandler({
    verifyToken,
    requiredTermsVersion,
    siteOrigin: process.env.NEXT_PUBLIC_SITE_URL,
    fetchEntitlement: async (userId) => {
      const { data, error } = await client
        .from("user_mcp_entitlements")
        .select("terms_accepted_at, terms_version, mcp_enabled, is_suspended")
        .eq("user_id", userId)
        .maybeSingle();

      if (error) {
        throw new Error("entitlement_query_failed");
      }
      if (!data) return null;
      return {
        termsAcceptedAt: data.terms_accepted_at,
        termsVersion: data.terms_version,
        mcpEnabled: Boolean(data.mcp_enabled),
        isSuspended: Boolean(data.is_suspended),
      };
    },
    consumeRateLimit: async (userId) => {
      const { data, error } = await client.rpc("consume_mcp_rate_limit", {
        p_user_id: userId,
        p_limit: rateLimitPerMinute,
        p_window_seconds: 60,
      });

      if (error || !Array.isArray(data) || data.length === 0) {
        throw new Error("rate_limit_rpc_failed");
      }
      const row = data[0] as {
        allowed?: boolean;
        current_count?: number;
        retry_after_seconds?: number;
      };
      return {
        allowed: Boolean(row.allowed),
        currentCount: Number(row.current_count ?? 0),
        retryAfterSeconds: Math.max(1, Number(row.retry_after_seconds ?? 60)),
      };
    },
    recordUsage: async (record) => {
      await client.rpc("record_mcp_usage_bucket", {
        p_observed_at: record.observedAt,
        p_request_kind: record.requestKind,
        p_tool_name: record.toolName,
        p_call_delta: record.callDelta,
        p_success_delta: record.successDelta,
        p_error_delta: record.errorDelta,
        p_auth_failure_delta: record.authFailureDelta,
        p_rate_limited_delta: record.rateLimitedDelta,
        p_latency_ms: record.latencyMs,
      });
    },
  });

  return cachedLiveHandler;
}
