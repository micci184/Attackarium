import { getPublicOrigin } from "mcp-handler";
import { NextResponse } from "next/server";
import {
  createSupabaseAuthServerClient,
  getSiteOrigin,
  sanitizeRedirectPath,
} from "@/lib/supabase-auth";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function GET(request: Request): Promise<Response> {
  const url = new URL(request.url);
  const code = url.searchParams.get("code");
  const nextPath = sanitizeRedirectPath(url.searchParams.get("next"), "/mcp");
  const origin = getSiteOrigin(getPublicOrigin(request));

  if (!code) {
    return NextResponse.redirect(
      new URL("/mcp?auth_error=missing_code", origin),
      303,
    );
  }

  const supabase = await createSupabaseAuthServerClient();
  if (!supabase) {
    return NextResponse.redirect(
      new URL("/mcp?auth_error=not_configured", origin),
      303,
    );
  }

  const { error } = await supabase.auth.exchangeCodeForSession(code);
  if (error) {
    return NextResponse.redirect(
      new URL("/mcp?auth_error=exchange_failed", origin),
      303,
    );
  }

  return NextResponse.redirect(new URL(nextPath, origin), 303);
}
