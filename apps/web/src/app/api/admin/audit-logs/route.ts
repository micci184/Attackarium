import { NextResponse } from "next/server";
import {
  adminErrorResponse,
  getAdminServiceClient,
  requireOperatorAdmin,
} from "@/lib/admin-auth";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

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
    .from("admin_audit_logs")
    .select(
      "id, actor_user_id, action, target_type, target_id, metadata, created_at",
    )
    .order("created_at", { ascending: false })
    .limit(100);

  if (error) {
    return NextResponse.json(
      { error: "audit_logs_query_failed" },
      { status: 500, headers: { "Cache-Control": "no-store" } },
    );
  }

  return NextResponse.json(
    { items: data ?? [] },
    { status: 200, headers: { "Cache-Control": "no-store" } },
  );
}
