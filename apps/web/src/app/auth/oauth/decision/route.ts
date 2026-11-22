import { NextResponse } from "next/server";
import { createSupabaseAuthServerClient } from "@/lib/supabase-auth";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

const NO_STORE_HEADERS = { "Cache-Control": "no-store" } as const;

async function parseDecisionRequest(
  request: Request,
): Promise<{ authorizationId: string; decision: string } | null> {
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
      authorizationId:
        typeof record.authorization_id === "string"
          ? record.authorization_id.trim()
          : "",
      decision: typeof record.decision === "string" ? record.decision.trim() : "",
    };
  }

  const formData = await request.formData();
  return {
    authorizationId: String(formData.get("authorization_id") ?? "").trim(),
    decision: String(formData.get("decision") ?? "").trim(),
  };
}

export async function POST(request: Request): Promise<Response> {
  const wantsJson =
    request.headers.get("accept")?.toLowerCase().includes("application/json") ??
    false;

  const parsed = await parseDecisionRequest(request);
  if (
    !parsed ||
    !parsed.authorizationId ||
    (parsed.decision !== "approve" && parsed.decision !== "deny")
  ) {
    return NextResponse.json(
      { error: "invalid_consent_request" },
      { status: 400, headers: NO_STORE_HEADERS },
    );
  }

  const { authorizationId, decision } = parsed;

  const supabase = await createSupabaseAuthServerClient();
  if (!supabase) {
    return NextResponse.json(
      { error: "oauth_not_configured" },
      { status: 503, headers: NO_STORE_HEADERS },
    );
  }

  const {
    data: { user },
  } = await supabase.auth.getUser();
  if (!user) {
    return NextResponse.json(
      { error: "unauthorized" },
      { status: 401, headers: NO_STORE_HEADERS },
    );
  }

  const result =
    decision === "approve"
      ? await supabase.auth.oauth.approveAuthorization(authorizationId, {
          skipBrowserRedirect: true,
        })
      : await supabase.auth.oauth.denyAuthorization(authorizationId, {
          skipBrowserRedirect: true,
        });

  if (result.error || !result.data?.redirect_url) {
    return NextResponse.json(
      { error: "oauth_decision_failed" },
      { status: 400, headers: NO_STORE_HEADERS },
    );
  }

  const redirectUrl = result.data.redirect_url;
  const lowerUrl = redirectUrl.trim().toLowerCase();
  if (lowerUrl.startsWith("javascript:") || lowerUrl.startsWith("data:")) {
    return NextResponse.json(
      { error: "invalid_redirect_url" },
      { status: 400, headers: NO_STORE_HEADERS },
    );
  }

  if (wantsJson) {
    return NextResponse.json(
      { redirect_url: redirectUrl },
      { status: 200, headers: NO_STORE_HEADERS },
    );
  }

  return NextResponse.redirect(redirectUrl, 303);
}
