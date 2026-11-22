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
const NO_STORE_HEADERS = { "Cache-Control": "no-store" } as const;

async function parseLoginRequest(
  request: Request,
): Promise<{ provider: string; next: string } | null> {
  const contentType = request.headers.get("content-type")?.toLowerCase() ?? "";
  if (contentType.includes("application/json")) {
    let body: unknown;
    try {
      body = await request.json();
    } catch {
      return null;
    }
    if (!body || typeof body !== "object") return null;
    const record = body as Record<string, unknown>;
    return {
      provider: typeof record.provider === "string" ? record.provider.trim().toLowerCase() : "",
      next: typeof record.next === "string" ? record.next : "/mcp",
    };
  }

  const formData = await request.formData();
  return {
    provider: String(formData.get("provider") ?? "").trim().toLowerCase(),
    next: typeof formData.get("next") === "string" ? String(formData.get("next")) : "/mcp",
  };
}

export async function POST(request: Request): Promise<Response> {
  const wantsJson =
    request.headers.get("accept")?.toLowerCase().includes("application/json") ??
    false;

  const parsed = await parseLoginRequest(request);
  if (!parsed) {
    return NextResponse.json(
      { error: "invalid_request" },
      { status: 400, headers: NO_STORE_HEADERS },
    );
  }

  const rawProvider = parsed.provider;
  const nextPath = sanitizeRedirectPath(parsed.next, "/mcp");

  if (rawProvider !== "google" && rawProvider !== "github") {
    return NextResponse.json(
      { error: "unsupported_provider" },
      { status: 400, headers: NO_STORE_HEADERS },
    );
  }
  if (!ALLOWED_PROVIDERS.has(rawProvider)) {
    return NextResponse.json(
      { error: "unsupported_provider" },
      { status: 400, headers: NO_STORE_HEADERS },
    );
  }

  const supabase = await createSupabaseAuthServerClient();
  if (!supabase) {
    if (wantsJson) {
      return NextResponse.json(
        { error: "not_configured" },
        { status: 503, headers: NO_STORE_HEADERS },
      );
    }
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
    if (wantsJson) {
      return NextResponse.json(
        { error: "signin_failed" },
        { status: 502, headers: NO_STORE_HEADERS },
      );
    }
    return NextResponse.redirect(
      new URL("/mcp?auth_error=signin_failed", origin),
      303,
    );
  }

  if (wantsJson) {
    return NextResponse.json(
      { url: data.url },
      { status: 200, headers: NO_STORE_HEADERS },
    );
  }

  return NextResponse.redirect(data.url, 303);
}
