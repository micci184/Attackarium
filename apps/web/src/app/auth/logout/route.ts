import { getPublicOrigin } from "mcp-handler";
import { NextResponse } from "next/server";
import {
  createSupabaseAuthServerClient,
  getSiteOrigin,
} from "@/lib/supabase-auth";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function POST(request: Request): Promise<Response> {
  const origin = getSiteOrigin(getPublicOrigin(request));
  const supabase = await createSupabaseAuthServerClient();
  if (supabase) {
    await supabase.auth.signOut();
  }
  return NextResponse.redirect(new URL("/mcp", origin), 303);
}
