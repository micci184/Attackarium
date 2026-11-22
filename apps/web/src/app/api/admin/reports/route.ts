import { NextResponse } from "next/server";
import { z } from "zod";
import {
  adminErrorResponse,
  appendAdminAuditLog,
  getAdminServiceClient,
  isJsonContentType,
  requireOperatorAdmin,
} from "@/lib/admin-auth";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

const ReviewReportSchema = z.object({
  reportId: z.uuid(),
  status: z.enum(["reviewed", "rejected", "published"]),
});

export async function GET(): Promise<Response> {
  const auth = await requireOperatorAdmin();
  if (!auth.ok) return adminErrorResponse(auth);

  const client = getAdminServiceClient();
  if (!client) {
    return NextResponse.json(
      { error: "admin_db_not_configured" },
      { status: 503, headers: { "Cache-Control": "no-store" } },
    );
  }

  const { data, error } = await client
    .from("daily_reports")
    .select(
      "id, date_utc, status, summary_md, x_post_draft, model_id, prompt_version, source_window_start, source_window_end, reviewed_at, created_at",
    )
    .order("date_utc", { ascending: false })
    .limit(30);

  if (error) {
    return NextResponse.json(
      { error: "reports_query_failed" },
      { status: 500, headers: { "Cache-Control": "no-store" } },
    );
  }

  return NextResponse.json(
    { items: data ?? [] },
    { status: 200, headers: { "Cache-Control": "no-store" } },
  );
}

export async function POST(request: Request): Promise<Response> {
  const auth = await requireOperatorAdmin();
  if (!auth.ok) return adminErrorResponse(auth);

  if (!isJsonContentType(request)) {
    return NextResponse.json(
      { error: "unsupported_media_type" },
      { status: 415, headers: { "Cache-Control": "no-store" } },
    );
  }

  const client = getAdminServiceClient();
  if (!client) {
    return NextResponse.json(
      { error: "admin_db_not_configured" },
      { status: 503, headers: { "Cache-Control": "no-store" } },
    );
  }

  let body: unknown;
  try {
    body = await request.json();
  } catch {
    return NextResponse.json(
      { error: "invalid_json" },
      { status: 400, headers: { "Cache-Control": "no-store" } },
    );
  }

  const parsed = ReviewReportSchema.safeParse(body);
  if (!parsed.success) {
    return NextResponse.json(
      { error: "invalid_payload" },
      { status: 400, headers: { "Cache-Control": "no-store" } },
    );
  }

  const { reportId, status } = parsed.data;
  const nowIso = new Date().toISOString();

  const { data: updated, error: updateError } = await client
    .from("daily_reports")
    .update({ status, reviewed_at: nowIso })
    .eq("id", reportId)
    .select("id, date_utc, status, reviewed_at")
    .maybeSingle();

  if (updateError) {
    return NextResponse.json(
      { error: "report_update_failed" },
      { status: 500, headers: { "Cache-Control": "no-store" } },
    );
  }

  if (!updated) {
    return NextResponse.json(
      { error: "report_not_found" },
      { status: 404, headers: { "Cache-Control": "no-store" } },
    );
  }

  await appendAdminAuditLog(client, {
    actorUserId: auth.userId,
    action: "daily_report.review",
    targetType: "daily_reports",
    targetId: reportId,
    metadata: { status, date_utc: updated.date_utc },
  });

  return NextResponse.json(
    { item: updated },
    { status: 200, headers: { "Cache-Control": "no-store" } },
  );
}
