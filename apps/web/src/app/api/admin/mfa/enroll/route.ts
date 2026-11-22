import { NextResponse } from "next/server";
import {
  isJsonContentType,
  requireAllowlistedOperatorSession,
} from "@/lib/admin-auth";
import { createSupabaseAuthServerClient } from "@/lib/supabase-auth";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

const NO_STORE_HEADERS = { "Cache-Control": "no-store" } as const;

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

  const supabase = await createSupabaseAuthServerClient();
  if (!supabase) {
    return NextResponse.json(
      { error: "auth_not_configured" },
      { status: 503, headers: NO_STORE_HEADERS },
    );
  }

  // Clean up any stale unverified TOTP factors so re-enrollment succeeds cleanly.
  const { data: factorsData } = await supabase.auth.mfa.listFactors();
  const existingVerified = factorsData?.totp.find(
    (factor) => factor.status === "verified",
  );
  if (existingVerified) {
    return NextResponse.json(
      {
        alreadyEnrolled: true,
        factorId: existingVerified.id,
      },
      { status: 200, headers: NO_STORE_HEADERS },
    );
  }

  const staleUnverified = (factorsData?.all ?? []).filter(
    (factor) => factor.factor_type === "totp" && factor.status === "unverified",
  );
  for (const factor of staleUnverified) {
    await supabase.auth.mfa.unenroll({ factorId: factor.id }).catch(() => null);
  }

  const { data, error } = await supabase.auth.mfa.enroll({
    factorType: "totp",
    friendlyName: "Attackarium Operator",
    issuer: "Attackarium",
  });

  if (error || !data?.id || !data.totp?.qr_code || !data.totp?.secret) {
    return NextResponse.json(
      { error: "mfa_enroll_failed" },
      { status: 400, headers: NO_STORE_HEADERS },
    );
  }

  return NextResponse.json(
    {
      alreadyEnrolled: false,
      factorId: data.id,
      qrCode: data.totp.qr_code,
      secret: data.totp.secret,
    },
    { status: 200, headers: NO_STORE_HEADERS },
  );
}
