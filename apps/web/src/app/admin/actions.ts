"use server";

import { revalidatePath } from "next/cache";
import {
  appendAdminAuditLog,
  getAdminServiceClient,
  requireOperatorAdmin,
} from "@/lib/admin-auth";
import { isValidUuid } from "@/lib/admin-auth-core";

export async function updateEntitlementAction(formData: FormData): Promise<void> {
  const auth = await requireOperatorAdmin();
  if (!auth.ok) return;

  const client = getAdminServiceClient();
  if (!client) return;

  const userId = String(formData.get("user_id") ?? "").trim().toLowerCase();
  if (!isValidUuid(userId)) return;

  const rawEnabled = formData.get("mcp_enabled");
  const rawSuspended = formData.get("is_suspended");

  const { data: existing } = await client
    .from("user_mcp_entitlements")
    .select("mcp_enabled, is_suspended")
    .eq("user_id", userId)
    .maybeSingle();

  const nextMcpEnabled =
    rawEnabled === "true"
      ? true
      : rawEnabled === "false"
        ? false
        : (existing?.mcp_enabled ?? false);

  const nextIsSuspended =
    rawSuspended === "true"
      ? true
      : rawSuspended === "false"
        ? false
        : (existing?.is_suspended ?? false);

  const { error } = await client.from("user_mcp_entitlements").upsert(
    {
      user_id: userId,
      mcp_enabled: nextMcpEnabled,
      is_suspended: nextIsSuspended,
      updated_at: new Date().toISOString(),
    },
    { onConflict: "user_id" },
  );

  if (error) return;

  await appendAdminAuditLog(client, {
    actorUserId: auth.userId,
    action: "entitlement.update",
    targetType: "user_mcp_entitlements",
    targetId: userId,
    metadata: {
      mcp_enabled: nextMcpEnabled,
      is_suspended: nextIsSuspended,
    },
  });

  revalidatePath("/admin");
}

export async function reviewDailyReportAction(formData: FormData): Promise<void> {
  const auth = await requireOperatorAdmin();
  if (!auth.ok) return;

  const client = getAdminServiceClient();
  if (!client) return;

  const reportId = String(formData.get("report_id") ?? "").trim();
  const status = String(formData.get("status") ?? "").trim();

  if (
    !isValidUuid(reportId) ||
    (status !== "reviewed" && status !== "rejected" && status !== "published")
  ) {
    return;
  }

  const { data: updated, error } = await client
    .from("daily_reports")
    .update({ status, reviewed_at: new Date().toISOString() })
    .eq("id", reportId)
    .select("id, date_utc")
    .maybeSingle();

  if (error || !updated) return;

  await appendAdminAuditLog(client, {
    actorUserId: auth.userId,
    action: "daily_report.review",
    targetType: "daily_reports",
    targetId: reportId,
    metadata: { status, date_utc: updated.date_utc },
  });

  revalidatePath("/admin");
}
