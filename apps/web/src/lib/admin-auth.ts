import { createClient, type SupabaseClient } from "@supabase/supabase-js";
import { NextResponse } from "next/server";
import {
  evaluateOperatorAdmin,
  parseAdminAllowedUserIds,
  type AdminAuthDecision,
} from "./admin-auth-core.ts";
import { createSupabaseAuthServerClient } from "./supabase-auth.ts";

let cachedAdminClient: SupabaseClient | null = null;

export function getAdminServiceClient(): SupabaseClient | null {
  if (cachedAdminClient) return cachedAdminClient;
  const supabaseUrl =
    process.env.SUPABASE_URL?.trim() ??
    process.env.NEXT_PUBLIC_SUPABASE_URL?.trim();
  const serviceRoleKey = process.env.SUPABASE_SERVICE_ROLE_KEY?.trim();
  if (!supabaseUrl || !serviceRoleKey) return null;

  cachedAdminClient = createClient(supabaseUrl, serviceRoleKey, {
    auth: {
      persistSession: false,
      autoRefreshToken: false,
    },
  });
  return cachedAdminClient;
}

/**
 * Enforces server-side operator admin authorization on every admin page,
 * Server Action, and API route:
 *   1. Authenticated Supabase Auth user (verified via getUser)
 *   2. User ID present in server-side ADMIN_ALLOWED_USER_IDS
 *   3. Mandatory MFA (aal === "aal2")
 */
export async function requireOperatorAdmin(): Promise<AdminAuthDecision> {
  const allowedUserIds = parseAdminAllowedUserIds(
    process.env.ADMIN_ALLOWED_USER_IDS,
  );
  const supabase = await createSupabaseAuthServerClient();
  if (!supabase) {
    return { ok: false, status: 401, reason: "unauthenticated" };
  }

  const {
    data: { user },
  } = await supabase.auth.getUser();

  if (!user) {
    return { ok: false, status: 401, reason: "unauthenticated" };
  }

  const { data: aalData } =
    await supabase.auth.mfa.getAuthenticatorAssuranceLevel();

  return evaluateOperatorAdmin(
    {
      userId: user.id,
      aal: aalData?.currentLevel ?? null,
    },
    allowedUserIds,
  );
}

/**
 * Verifies that the caller is an authenticated allowlisted operator (aal1 or aal2).
 * Used strictly by the operator MFA enrollment/challenge flow so allowlisted
 * operators can elevate from aal1 to aal2 without exposing MFA UI to general users.
 */
export async function requireAllowlistedOperatorSession(): Promise<
  | { ok: true; userId: string; currentLevel: string | null }
  | { ok: false; status: 401 | 403; reason: "unauthenticated" | "not_allowlisted" }
> {
  const allowedUserIds = parseAdminAllowedUserIds(
    process.env.ADMIN_ALLOWED_USER_IDS,
  );
  const supabase = await createSupabaseAuthServerClient();
  if (!supabase) {
    return { ok: false, status: 401, reason: "unauthenticated" };
  }

  const {
    data: { user },
  } = await supabase.auth.getUser();
  if (!user) {
    return { ok: false, status: 401, reason: "unauthenticated" };
  }

  if (allowedUserIds.size === 0 || !allowedUserIds.has(user.id.toLowerCase())) {
    return { ok: false, status: 403, reason: "not_allowlisted" };
  }

  const { data: aalData } =
    await supabase.auth.mfa.getAuthenticatorAssuranceLevel();

  return {
    ok: true,
    userId: user.id,
    currentLevel: aalData?.currentLevel ?? null,
  };
}

export function adminErrorResponse(
  decision: Extract<AdminAuthDecision, { ok: false }>,
): Response {
  return NextResponse.json(
    { error: decision.reason },
    {
      status: decision.status,
      headers: { "Cache-Control": "no-store" },
    },
  );
}

export function isJsonContentType(request: Request): boolean {
  const contentType = request.headers.get("content-type") ?? "";
  return contentType.toLowerCase().split(";")[0]?.trim() === "application/json";
}

export async function appendAdminAuditLog(
  client: SupabaseClient,
  entry: {
    actorUserId: string;
    action: string;
    targetType?: string | null;
    targetId?: string | null;
    metadata?: Record<string, unknown>;
  },
): Promise<void> {
  const { error } = await client.from("admin_audit_logs").insert({
    actor_user_id: entry.actorUserId,
    action: entry.action,
    target_type: entry.targetType ?? null,
    target_id: entry.targetId ?? null,
    metadata: entry.metadata ?? {},
  });

  if (error) {
    throw new Error("audit_log_insert_failed");
  }
}
