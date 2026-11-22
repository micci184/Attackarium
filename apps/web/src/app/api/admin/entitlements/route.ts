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

const UpdateEntitlementSchema = z
  .object({
    userId: z.uuid(),
    mcpEnabled: z.boolean().optional(),
    isSuspended: z.boolean().optional(),
  })
  .refine(
    (data) => data.mcpEnabled !== undefined || data.isSuspended !== undefined,
    { message: "At least one of mcpEnabled or isSuspended is required" },
  );

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
    .from("user_mcp_entitlements")
    .select(
      "user_id, terms_accepted_at, terms_version, mcp_enabled, is_suspended, updated_at",
    )
    .order("updated_at", { ascending: false })
    .limit(200);

  if (error) {
    return NextResponse.json(
      { error: "entitlements_query_failed" },
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

  const parsed = UpdateEntitlementSchema.safeParse(body);
  if (!parsed.success) {
    return NextResponse.json(
      { error: "invalid_payload" },
      { status: 400, headers: { "Cache-Control": "no-store" } },
    );
  }

  const { userId, mcpEnabled, isSuspended } = parsed.data;
  const nowIso = new Date().toISOString();

  const { data: existing, error: fetchError } = await client
    .from("user_mcp_entitlements")
    .select("mcp_enabled, is_suspended")
    .eq("user_id", userId)
    .maybeSingle();

  if (fetchError) {
    return NextResponse.json(
      { error: "entitlement_lookup_failed" },
      { status: 500, headers: { "Cache-Control": "no-store" } },
    );
  }

  const nextMcpEnabled = mcpEnabled ?? existing?.mcp_enabled ?? false;
  const nextIsSuspended = isSuspended ?? existing?.is_suspended ?? false;

  const { data: updated, error: upsertError } = await client
    .from("user_mcp_entitlements")
    .upsert(
      {
        user_id: userId,
        mcp_enabled: nextMcpEnabled,
        is_suspended: nextIsSuspended,
        updated_at: nowIso,
      },
      { onConflict: "user_id" },
    )
    .select(
      "user_id, terms_accepted_at, terms_version, mcp_enabled, is_suspended, updated_at",
    )
    .single();

  if (upsertError || !updated) {
    return NextResponse.json(
      { error: "entitlement_update_failed" },
      { status: 500, headers: { "Cache-Control": "no-store" } },
    );
  }

  await appendAdminAuditLog(client, {
    actorUserId: auth.userId,
    action: "entitlement.update",
    targetType: "user_mcp_entitlements",
    targetId: userId,
    metadata: {
      mcp_enabled: nextMcpEnabled,
      is_suspended: nextIsSuspended,
    },
  });

  return NextResponse.json(
    { item: updated },
    { status: 200, headers: { "Cache-Control": "no-store" } },
  );
}
