import { NextResponse } from "next/server";
import { createSupabaseAuthServerClient } from "@/lib/supabase-auth";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function POST(request: Request): Promise<Response> {
  const formData = await request.formData();
  const authorizationId = String(formData.get("authorization_id") ?? "").trim();
  const decision = String(formData.get("decision") ?? "").trim();

  if (!authorizationId || (decision !== "approve" && decision !== "deny")) {
    return NextResponse.json(
      { error: "invalid_consent_request" },
      { status: 400 },
    );
  }

  const supabase = await createSupabaseAuthServerClient();
  if (!supabase) {
    return NextResponse.json({ error: "oauth_not_configured" }, { status: 503 });
  }

  const {
    data: { user },
  } = await supabase.auth.getUser();
  if (!user) {
    return NextResponse.json({ error: "unauthorized" }, { status: 401 });
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
      { status: 400 },
    );
  }

  return NextResponse.redirect(result.data.redirect_url, 303);
}
