import { getPublicOrigin } from "mcp-handler";
import { NextResponse } from "next/server";
import {
  createSupabaseAuthServerClient,
  getSiteOrigin,
  sanitizeRedirectPath,
} from "@/lib/supabase-auth";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

const ALLOWED_PROVIDERS = new Set(["google", "github"] as const);

export async function POST(request: Request): Promise<Response> {
  const formData = await request.formData();
  const rawProvider = String(formData.get("provider") ?? "").trim().toLowerCase();
  const nextPath = sanitizeRedirectPath(
    typeof formData.get("next") === "string"
      ? String(formData.get("next"))
      : "/mcp",
    "/mcp",
  );

  if (rawProvider !== "google" && rawProvider !== "github") {
    return NextResponse.json({ error: "unsupported_provider" }, { status: 400 });
  }
  if (!ALLOWED_PROVIDERS.has(rawProvider)) {
    return NextResponse.json({ error: "unsupported_provider" }, { status: 400 });
  }

  const supabase = await createSupabaseAuthServerClient();
  if (!supabase) {
    return NextResponse.redirect(
      new URL("/mcp?auth_error=not_configured", getSiteOrigin(getPublicOrigin(request))),
      303,
    );
  }

  const origin = getSiteOrigin(getPublicOrigin(request));
  const callbackUrl = new URL("/auth/callback", origin);
  callbackUrl.searchParams.set("next", nextPath);

  const { data, error } = await supabase.auth.signInWithOAuth({
    provider: rawProvider,
    options: {
      redirectTo: callbackUrl.toString(),
    },
  });

  if (error || !data?.url) {
    return NextResponse.redirect(
      new URL("/mcp?auth_error=signin_failed", origin),
      303,
    );
  }

  return NextResponse.redirect(data.url, 303);
}
