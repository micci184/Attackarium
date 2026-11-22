import Link from "next/link";
import {
  getAdminServiceClient,
  requireOperatorAdmin,
} from "@/lib/admin-auth";
import {
  summarizeMcpUsageBuckets,
  type McpUsageBucketRow,
} from "@/lib/admin-auth-core";

export const dynamic = "force-dynamic";

export default async function AdminMcpUsagePage({
  searchParams,
}: {
  searchParams: Promise<{ granularity?: string }>;
}) {
  const auth = await requireOperatorAdmin();
  if (!auth.ok) {
    return (
      <section className="mx-auto max-w-xl rounded-xl border border-slate-200 bg-white p-6 shadow-xs">
        <p className="text-xs font-medium uppercase tracking-wide text-red-700">
          403 Forbidden
        </p>
        <h1 className="mt-1 text-lg font-semibold text-slate-900">
          Operator access required
        </h1>
        <p className="mt-2 text-sm text-slate-600">
          MCP Usage analytics are strictly operator-only and require MFA (aal2).
        </p>
        <Link
          href="/"
          className="mt-4 inline-flex items-center rounded-md border border-slate-300 px-3 py-1.5 text-sm font-medium text-slate-700 hover:bg-slate-50"
        >
          Return to Activity
        </Link>
      </section>
    );
  }

  const client = getAdminServiceClient();
  if (!client) {
    return (
      <section className="rounded-xl border border-slate-200 bg-white p-6 shadow-xs">
        <h1 className="text-lg font-semibold text-slate-900">
          MCP Usage — Database not configured
        </h1>
      </section>
    );
  }

  const { granularity: rawGranularity } = await searchParams;
  const granularity: "hour" | "day" =
    rawGranularity === "hour" ? "hour" : "day";

  const { data } = await client
    .from("mcp_usage_buckets")
    .select(
      "bucket_start, granularity, request_kind, tool_name, call_count, success_count, error_count, auth_failure_count, rate_limited_count, total_latency_ms, active_user_count",
    )
    .eq("granularity", granularity)
    .order("bucket_start", { ascending: false })
    .limit(granularity === "hour" ? 168 : 90);

  const summary = summarizeMcpUsageBuckets(
    (data ?? []) as McpUsageBucketRow[],
  );

  return (
    <div className="space-y-6">
      <header className="flex flex-wrap items-center justify-between gap-3 border-b border-slate-200 pb-4">
        <div>
          <p className="text-xs font-medium uppercase tracking-wide text-[#632ca6]">
            Operator Only — Aggregate Telemetry
          </p>
          <h1 className="mt-0.5 text-2xl font-semibold tracking-tight text-slate-900">
            MCP Usage
          </h1>
          <p className="mt-1 text-xs text-slate-500">
            Separates <code className="font-mono">initialize</code> from{" "}
            <code className="font-mono">tool_call</code>. Zero prompts,
            arguments, or auth tokens are stored.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <Link
            href="/admin/mcp-usage?granularity=day"
            className={`rounded-md px-3 py-1.5 text-xs font-medium ${
              granularity === "day"
                ? "bg-slate-900 text-white"
                : "border border-slate-300 bg-white text-slate-700"
            }`}
          >
            Daily
          </Link>
          <Link
            href="/admin/mcp-usage?granularity=hour"
            className={`rounded-md px-3 py-1.5 text-xs font-medium ${
              granularity === "hour"
                ? "bg-slate-900 text-white"
                : "border border-slate-300 bg-white text-slate-700"
            }`}
          >
            Hourly
          </Link>
          <Link
            href="/admin"
            className="rounded-md border border-slate-300 bg-white px-3 py-1.5 text-xs font-medium text-slate-700 hover:bg-slate-50"
          >
            Back to Admin
          </Link>
        </div>
      </header>

      {/* KPI cards */}
      <dl className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <div className="rounded-xl border border-slate-200 bg-white p-4 shadow-xs">
          <dt className="text-xs font-medium text-slate-500">Tool calls</dt>
          <dd className="mt-1 text-2xl font-semibold tabular-nums text-slate-900">
            {summary.toolCalls}
          </dd>
          <p className="mt-1 text-xs text-slate-500">
            Initialize handshakes: {summary.initializeCalls}
          </p>
        </div>
        <div className="rounded-xl border border-slate-200 bg-white p-4 shadow-xs">
          <dt className="text-xs font-medium text-slate-500">
            Success / Error rate
          </dt>
          <dd className="mt-1 text-2xl font-semibold tabular-nums text-slate-900">
            {summary.successRatePct !== null ? `${summary.successRatePct}%` : "—"}
          </dd>
          <p className="mt-1 text-xs text-slate-500">
            Errors: {summary.errorCount} (
            {summary.errorRatePct !== null ? `${summary.errorRatePct}%` : "—"})
          </p>
        </div>
        <div className="rounded-xl border border-slate-200 bg-white p-4 shadow-xs">
          <dt className="text-xs font-medium text-slate-500">Avg latency</dt>
          <dd className="mt-1 text-2xl font-semibold tabular-nums text-slate-900">
            {summary.avgLatencyMs !== null ? `${summary.avgLatencyMs} ms` : "—"}
          </dd>
          <p className="mt-1 text-xs text-slate-500">
            Peak active users: {summary.peakActiveUsers}
          </p>
        </div>
        <div className="rounded-xl border border-slate-200 bg-white p-4 shadow-xs">
          <dt className="text-xs font-medium text-slate-500">
            Auth failures / Rate limits
          </dt>
          <dd className="mt-1 text-2xl font-semibold tabular-nums text-slate-900">
            {summary.authFailureCount} / {summary.rateLimitedCount}
          </dd>
          <p className="mt-1 text-xs text-slate-500">
            Denied or throttled requests
          </p>
        </div>
      </dl>

      {/* Top tools */}
      <section className="rounded-xl border border-slate-200 bg-white p-5 shadow-xs">
        <h2 className="text-base font-semibold text-slate-900">
          Top tools (tool_call only)
        </h2>
        <div className="mt-3 overflow-x-auto">
          <table className="min-w-full divide-y divide-slate-200 text-left text-xs">
            <thead className="bg-slate-50 text-slate-600">
              <tr>
                <th className="px-3 py-2 font-medium">Tool</th>
                <th className="px-3 py-2 font-medium">Calls</th>
                <th className="px-3 py-2 font-medium">Success</th>
                <th className="px-3 py-2 font-medium">Errors</th>
                <th className="px-3 py-2 font-medium">Avg latency</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-200">
              {summary.topTools.length === 0 ? (
                <tr>
                  <td colSpan={5} className="px-3 py-4 text-slate-500">
                    No tool calls recorded in this window.
                  </td>
                </tr>
              ) : (
                summary.topTools.map((tool) => (
                  <tr key={tool.toolName}>
                    <td className="px-3 py-2 font-mono font-medium text-slate-900">
                      {tool.toolName}
                    </td>
                    <td className="px-3 py-2 tabular-nums">{tool.callCount}</td>
                    <td className="px-3 py-2 tabular-nums">
                      {tool.successCount}
                    </td>
                    <td className="px-3 py-2 tabular-nums">{tool.errorCount}</td>
                    <td className="px-3 py-2 tabular-nums">
                      {tool.avgLatencyMs !== null
                        ? `${tool.avgLatencyMs} ms`
                        : "—"}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </section>

      {/* Raw buckets separating initialize vs tool_call */}
      <section className="rounded-xl border border-slate-200 bg-white p-5 shadow-xs">
        <h2 className="text-base font-semibold text-slate-900">
          Recent {granularity} buckets
        </h2>
        <div className="mt-3 overflow-x-auto">
          <table className="min-w-full divide-y divide-slate-200 text-left text-xs">
            <thead className="bg-slate-50 text-slate-600">
              <tr>
                <th className="px-3 py-2 font-medium">Bucket (UTC)</th>
                <th className="px-3 py-2 font-medium">Kind</th>
                <th className="px-3 py-2 font-medium">Tool</th>
                <th className="px-3 py-2 font-medium">Calls</th>
                <th className="px-3 py-2 font-medium">Auth fail</th>
                <th className="px-3 py-2 font-medium">429</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-200">
              {summary.buckets.length === 0 ? (
                <tr>
                  <td colSpan={6} className="px-3 py-4 text-slate-500">
                    No usage buckets recorded yet.
                  </td>
                </tr>
              ) : (
                summary.buckets.map((bucket) => (
                  <tr
                    key={`${bucket.bucket_start}-${bucket.request_kind}-${bucket.tool_name}`}
                  >
                    <td className="px-3 py-2 font-mono text-slate-600">
                      {bucket.bucket_start}
                    </td>
                    <td className="px-3 py-2 font-mono text-slate-800">
                      {bucket.request_kind}
                    </td>
                    <td className="px-3 py-2 font-mono text-slate-700">
                      {bucket.tool_name || "—"}
                    </td>
                    <td className="px-3 py-2 tabular-nums">
                      {bucket.call_count}
                    </td>
                    <td className="px-3 py-2 tabular-nums">
                      {bucket.auth_failure_count}
                    </td>
                    <td className="px-3 py-2 tabular-nums">
                      {bucket.rate_limited_count}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
}
