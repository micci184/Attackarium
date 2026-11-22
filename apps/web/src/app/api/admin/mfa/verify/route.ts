import { NextResponse } from "next/server";
import {
  appendAdminAuditLog,
  getAdminServiceClient,
  isJsonContentType,
  requireAllowlistedOperatorSession,
} from "@/lib/admin-auth";
import { createSupabaseAuthServerClient } from "@/lib/supabase-auth";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

const NO_STORE_HEADERS = { "Cache-Control": "no-store" } as const;
const TOTP_CODE_PATTERN = /^\d{6}$/;

export async function POST(request: Request): Promise<Response> {
  if (!isJsonContentType(request)) {
    return NextResponse.json(
      { error: "unsupported_media_type" },
      { status: 415, headers: NO_STORE_HEADERS },
    );
  }

  const session = await requireAllowlistedOperatorSession();
  if (!session.ok) {
    return NextResponse.json(
      { error: session.reason },
      { status: session.status, headers: NO_STORE_HEADERS },
    );
  }

  let body: unknown;
  try {
    body = await request.json();
  } catch {
    return NextResponse.json(
      { error: "invalid_json" },
      { status: 400, headers: NO_STORE_HEADERS },
    );
  }

  if (!body || typeof body !== "object") {
    return NextResponse.json(
      { error: "invalid_body" },
      { status: 400, headers: NO_STORE_HEADERS },
    );
  }

  const record = body as Record<string, unknown>;
  const factorId =
    typeof record.factorId === "string" ? record.factorId.trim() : "";
  const code = typeof record.code === "string" ? record.code.trim() : "";

  if (!factorId || !TOTP_CODE_PATTERN.test(code)) {
    return NextResponse.json(
      { error: "invalid_totp_code" },
      { status: 400, headers: NO_STORE_HEADERS },
    );
  }

  const supabase = await createSupabaseAuthServerClient();
  if (!supabase) {
    return NextResponse.json(
      { error: "auth_not_configured" },
      { status: 503, headers: NO_STORE_HEADERS },
    );
  }

  const { error } = await supabase.auth.mfa.challengeAndVerify({
    factorId,
    code,
  });

  if (error) {
    return NextResponse.json(
      { error: "mfa_verification_failed" },
      { status: 400, headers: NO_STORE_HEADERS },
    );
  }

  const serviceClient = getAdminServiceClient();
  if (serviceClient) {
    await appendAdminAuditLog(serviceClient, {
      actorUserId: session.userId,
      action: "admin.mfa.verified",
      targetType: "mfa_factor",
      targetId: factorId,
    }).catch(() => null);
  }

  return NextResponse.json(
    { ok: true, redirectTo: "/admin" },
    { status: 200, headers: NO_STORE_HEADERS },
  );
}
