"use server";

import { revalidatePath } from "next/cache";
import {
  createSupabaseAuthServerClient,
  getRequiredTermsVersion,
} from "@/lib/supabase-auth";

export async function acceptCurrentTermsAction(): Promise<void> {
  const supabase = await createSupabaseAuthServerClient();
  if (!supabase) return;

  const {
    data: { user },
  } = await supabase.auth.getUser();
  if (!user) return;

  const termsVersion = getRequiredTermsVersion();
  await supabase.rpc("accept_mcp_terms", {
    p_terms_version: termsVersion,
  });

  revalidatePath("/mcp");
}

export async function revokeOAuthGrantAction(formData: FormData): Promise<void> {
  const clientId = String(formData.get("client_id") ?? "").trim();
  if (!clientId) return;

  const supabase = await createSupabaseAuthServerClient();
  if (!supabase) return;

  const {
    data: { user },
  } = await supabase.auth.getUser();
  if (!user) return;

  await supabase.auth.oauth.revokeGrant({ clientId });
  revalidatePath("/mcp");
}
