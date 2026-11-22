import { NextResponse } from "next/server";
import {
  adminErrorResponse,
  getAdminServiceClient,
  requireOperatorAdmin,
} from "@/lib/admin-auth";
import {
  summarizeMcpUsageBuckets,
  type McpUsageBucketRow,
} from "@/lib/admin-auth-core";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function GET(request: Request): Promise<Response> {
  const auth = await requireOperatorAdmin();
  if (!auth.ok) return adminErrorResponse(auth);

  const client = getAdminServiceClient();
  if (!client) {
    return NextResponse.json(
      { error: "admin_db_not_configured" },
      { status: 503, headers: { "Cache-Control": "no-store" } },
    );
  }

  const url = new URL(request.url);
  const rawGranularity = url.searchParams.get("granularity");
  const granularity: "hour" | "day" =
    rawGranularity === "hour" ? "hour" : "day";

  const { data, error } = await client
    .from("mcp_usage_buckets")
    .select(
      "bucket_start, granularity, request_kind, tool_name, call_count, success_count, error_count, auth_failure_count, rate_limited_count, total_latency_ms, active_user_count",
    )
    .eq("granularity", granularity)
    .order("bucket_start", { ascending: false })
    .limit(granularity === "hour" ? 168 : 90);

  if (error) {
    return NextResponse.json(
      { error: "mcp_usage_query_failed" },
      { status: 500, headers: { "Cache-Control": "no-store" } },
    );
  }

  const summary = summarizeMcpUsageBuckets(
    (data ?? []) as McpUsageBucketRow[],
  );

  return NextResponse.json(
    { granularity, ...summary },
    { status: 200, headers: { "Cache-Control": "no-store" } },
  );
}
