/**
 * Pure server-side operator admin authorization and MCP usage aggregation logic.
 * Default-deny: requires explicit server-side ADMIN_ALLOWED_USER_IDS allowlist
 * AND mandatory MFA (aal2). Never trusts a database is_admin flag alone.
 */

const UUID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

export interface OperatorSessionInfo {
  userId: string;
  aal: string | null;
}

export type AdminAuthDecision =
  | { ok: true; userId: string }
  | {
      ok: false;
      status: 401 | 403;
      reason: "unauthenticated" | "not_allowlisted" | "mfa_required";
    };

export function isValidUuid(value: string): boolean {
  return UUID_PATTERN.test(value.trim());
}

export function parseAdminAllowedUserIds(
  raw: string | undefined,
): Set<string> {
  const allowed = new Set<string>();
  if (!raw) return allowed;
  for (const part of raw.split(",")) {
    const trimmed = part.trim().toLowerCase();
    if (UUID_PATTERN.test(trimmed)) {
      allowed.add(trimmed);
    }
  }
  return allowed;
}

export function evaluateOperatorAdmin(
  session: OperatorSessionInfo | null,
  allowedUserIds: ReadonlySet<string>,
): AdminAuthDecision {
  if (!session || !isValidUuid(session.userId)) {
    return { ok: false, status: 401, reason: "unauthenticated" };
  }

  const normalizedId = session.userId.trim().toLowerCase();
  if (allowedUserIds.size === 0 || !allowedUserIds.has(normalizedId)) {
    return { ok: false, status: 403, reason: "not_allowlisted" };
  }

  if (session.aal !== "aal2") {
    return { ok: false, status: 403, reason: "mfa_required" };
  }

  return { ok: true, userId: normalizedId };
}

export interface McpUsageBucketRow {
  bucket_start: string;
  granularity: "hour" | "day";
  request_kind: "initialize" | "tool_call";
  tool_name: string;
  call_count: number;
  success_count: number;
  error_count: number;
  auth_failure_count: number;
  rate_limited_count: number;
  total_latency_ms: number;
  active_user_count: number;
}

export interface McpUsageSummary {
  initializeCalls: number;
  toolCalls: number;
  successCount: number;
  errorCount: number;
  successRatePct: number | null;
  errorRatePct: number | null;
  avgLatencyMs: number | null;
  authFailureCount: number;
  rateLimitedCount: number;
  peakActiveUsers: number;
  topTools: Array<{
    toolName: string;
    callCount: number;
    successCount: number;
    errorCount: number;
    avgLatencyMs: number | null;
  }>;
  buckets: McpUsageBucketRow[];
}

export function summarizeMcpUsageBuckets(
  rows: readonly McpUsageBucketRow[],
): McpUsageSummary {
  let initializeCalls = 0;
  let toolCalls = 0;
  let successCount = 0;
  let errorCount = 0;
  let totalLatencyMs = 0;
  let authFailureCount = 0;
  let rateLimitedCount = 0;
  let peakActiveUsers = 0;

  const toolTotals = new Map<
    string,
    { callCount: number; successCount: number; errorCount: number; latencyMs: number }
  >();

  for (const row of rows) {
    const calls = Number(row.call_count) || 0;
    const succ = Number(row.success_count) || 0;
    const err = Number(row.error_count) || 0;
    const authFail = Number(row.auth_failure_count) || 0;
    const rateLim = Number(row.rate_limited_count) || 0;
    const latency = Number(row.total_latency_ms) || 0;
    const active = Number(row.active_user_count) || 0;

    if (row.request_kind === "initialize") {
      initializeCalls += calls;
    } else if (row.request_kind === "tool_call") {
      toolCalls += calls;
      const key = row.tool_name || "unknown";
      const existing = toolTotals.get(key) ?? {
        callCount: 0,
        successCount: 0,
        errorCount: 0,
        latencyMs: 0,
      };
      existing.callCount += calls;
      existing.successCount += succ;
      existing.errorCount += err;
      existing.latencyMs += latency;
      toolTotals.set(key, existing);
    }

    successCount += succ;
    errorCount += err;
    totalLatencyMs += latency;
    authFailureCount += authFail;
    rateLimitedCount += rateLim;
    if (active > peakActiveUsers) {
      peakActiveUsers = active;
    }
  }

  const totalCalls = initializeCalls + toolCalls;
  const successRatePct =
    totalCalls > 0 ? Math.round((successCount / totalCalls) * 1000) / 10 : null;
  const errorRatePct =
    totalCalls > 0 ? Math.round((errorCount / totalCalls) * 1000) / 10 : null;
  const avgLatencyMs =
    totalCalls > 0 ? Math.round(totalLatencyMs / totalCalls) : null;

  const topTools = [...toolTotals.entries()]
    .map(([toolName, stats]) => ({
      toolName,
      callCount: stats.callCount,
      successCount: stats.successCount,
      errorCount: stats.errorCount,
      avgLatencyMs:
        stats.callCount > 0
          ? Math.round(stats.latencyMs / stats.callCount)
          : null,
    }))
    .toSorted((a, b) => b.callCount - a.callCount);

  return {
    initializeCalls,
    toolCalls,
    successCount,
    errorCount,
    successRatePct,
    errorRatePct,
    avgLatencyMs,
    authFailureCount,
    rateLimitedCount,
    peakActiveUsers,
    topTools,
    buckets: [...rows],
  };
}
