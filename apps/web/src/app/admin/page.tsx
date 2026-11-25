import Link from "next/link";
import { redirect } from "next/navigation";
import {
  getAdminServiceClient,
  requireOperatorAdmin,
} from "@/lib/admin-auth";
import { FormattedTime, TimezoneLabel } from "@/components/timezone-provider";
import {
  PATCH_OVERDUE_AFTER_DAYS,
  type PatchFreshnessState,
  withPatchFreshness,
} from "@/lib/patch-freshness";
import { reviewDailyReportAction, updateEntitlementAction } from "./actions";

const SENSOR_PATCH_ROW_LIMIT = 500;

const PATCH_STATE_CLASS: Record<PatchFreshnessState, string> = {
  current: "text-emerald-700",
  due: "font-medium text-amber-700",
  overdue: "font-semibold text-red-700",
  unknown: "font-medium text-amber-700",
};

export const dynamic = "force-dynamic";

function AdminDeniedView() {
  return (
    <section className="mx-auto max-w-xl rounded-xl border border-slate-200 bg-white p-6 shadow-xs">
      <p className="text-xs font-medium uppercase tracking-wide text-red-700">
        403 Forbidden
      </p>
      <h1 className="mt-1 text-lg font-semibold text-slate-900">
        Operator access required
      </h1>
      <p className="mt-2 text-sm text-slate-600">
        This console is restricted to allowlisted operators authenticated with
        multi-factor authentication (MFA / aal2).
      </p>
      <Link
        href="/"
        className="mt-4 inline-flex items-center rounded-md border border-slate-300 px-3 py-1.5 text-sm font-medium text-slate-700 hover:bg-slate-50"
      >
        Return to Activity
      </Link>
    </section>
  );
}

export default async function AdminConsolePage() {
  const auth = await requireOperatorAdmin();
  if (!auth.ok) {
    if (auth.reason === "mfa_required") {
      redirect("/admin/mfa");
    }
    return <AdminDeniedView />;
  }

  const client = getAdminServiceClient();
  if (!client) {
    return (
      <section className="rounded-xl border border-slate-200 bg-white p-6 shadow-xs">
        <h1 className="text-lg font-semibold text-slate-900">
          Admin Console — Database not configured
        </h1>
        <p className="mt-2 text-sm text-slate-600">
          Configure <code className="font-mono text-xs">SUPABASE_URL</code> and{" "}
          <code className="font-mono text-xs">SUPABASE_SERVICE_ROLE_KEY</code>{" "}
          on the server.
        </p>
      </section>
    );
  }

  const [
    entitlementsRes,
    reportsRes,
    auditRes,
    authUsersRes,
    termsAcceptedCountRes,
    mcpEnabledCountRes,
    suspendedCountRes,
    sensorsRes,
  ] = await Promise.all([
    client
      .from("user_mcp_entitlements")
      .select(
        "user_id, terms_accepted_at, terms_version, mcp_enabled, is_suspended, updated_at",
      )
      .order("updated_at", { ascending: false })
      .limit(100),
    client
      .from("daily_reports")
      .select("id, date_utc, status, summary_md, x_post_draft, reviewed_at")
      .order("date_utc", { ascending: false })
      .limit(20),
    client
      .from("admin_audit_logs")
      .select(
        "id, actor_user_id, action, target_type, target_id, metadata, created_at",
      )
      .order("created_at", { ascending: false })
      .limit(50),
    client.auth.admin
      .listUsers({ page: 1, perPage: 1 })
      .catch(() => ({ data: null, error: new Error("list_users_failed") })),
    client
      .from("user_mcp_entitlements")
      .select("user_id", { count: "exact", head: true })
      .not("terms_accepted_at", "is", null),
    client
      .from("user_mcp_entitlements")
      .select("user_id", { count: "exact", head: true })
      .eq("mcp_enabled", true)
      .eq("is_suspended", false),
    client
      .from("user_mcp_entitlements")
      .select("user_id", { count: "exact", head: true })
      .eq("is_suspended", true),
    // Operator-only host status (#94); never exposed through public views.
    client
      .from("sensors")
      .select("id, is_active, last_heartbeat_at, last_patch_success_at", {
        count: "exact",
      })
      // Active sensors first, so an inactive backlog never hides a live one.
      .order("is_active", { ascending: false })
      .order("id", { ascending: true })
      .limit(SENSOR_PATCH_ROW_LIMIT),
  ]);

  const entitlements = entitlementsRes.data ?? [];
  const reports = reportsRes.data ?? [];
  const auditLogs = auditRes.data ?? [];
  const registeredUsersCount =
    !authUsersRes.error &&
    authUsersRes.data &&
    "total" in authUsersRes.data &&
    typeof authUsersRes.data.total === "number"
      ? authUsersRes.data.total
      : null;
  const termsAcceptedCount = termsAcceptedCountRes.count ?? 0;
  const mcpEnabledCount = mcpEnabledCountRes.count ?? 0;
  const suspendedCount = suspendedCountRes.count ?? 0;
  const sensorPatchRows = withPatchFreshness(sensorsRes.data ?? []);
  const sensorTotal = sensorsRes.count ?? sensorPatchRows.length;

  return (
    <div className="space-y-6">
      <header className="flex flex-wrap items-center justify-between gap-3 border-b border-slate-200 pb-4">
        <div>
          <p className="text-xs font-medium uppercase tracking-wide text-[#632ca6]">
            Operator Only (MFA aal2)
          </p>
          <h1 className="mt-0.5 text-2xl font-semibold tracking-tight text-slate-900">
            Admin Console
          </h1>
        </div>
        <Link
          href="/admin/mcp-usage"
          className="rounded-md bg-[#632ca6] px-3.5 py-2 text-sm font-medium text-white hover:bg-[#53238d]"
        >
          View MCP Usage
        </Link>
      </header>

      {/* Summary KPIs (aggregate counts only, no PII) */}
      <dl className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <div className="rounded-xl border border-slate-200 bg-white p-4 shadow-xs">
          <dt className="text-xs font-medium text-slate-500">
            Registered users
          </dt>
          <dd className="mt-1 text-2xl font-semibold tabular-nums text-slate-900">
            {registeredUsersCount !== null
              ? registeredUsersCount.toLocaleString()
              : "—"}
          </dd>
          <p className="mt-1 text-xs text-slate-500">
            Total Supabase Auth accounts
          </p>
        </div>
        <div className="rounded-xl border border-slate-200 bg-white p-4 shadow-xs">
          <dt className="text-xs font-medium text-slate-500">
            Terms accepted
          </dt>
          <dd className="mt-1 text-2xl font-semibold tabular-nums text-slate-900">
            {termsAcceptedCount.toLocaleString()}
          </dd>
          <p className="mt-1 text-xs text-slate-500">
            Recorded in entitlements
          </p>
        </div>
        <div className="rounded-xl border border-slate-200 bg-white p-4 shadow-xs">
          <dt className="text-xs font-medium text-slate-500">
            MCP enabled (active)
          </dt>
          <dd className="mt-1 text-2xl font-semibold tabular-nums text-emerald-700">
            {mcpEnabledCount.toLocaleString()}
          </dd>
          <p className="mt-1 text-xs text-slate-500">
            Approved and not suspended
          </p>
        </div>
        <div className="rounded-xl border border-slate-200 bg-white p-4 shadow-xs">
          <dt className="text-xs font-medium text-slate-500">Suspended</dt>
          <dd className="mt-1 text-2xl font-semibold tabular-nums text-red-700">
            {suspendedCount.toLocaleString()}
          </dd>
          <p className="mt-1 text-xs text-slate-500">
            Blocked from Remote MCP
          </p>
        </div>
      </dl>

      {/* Sensor OS patch freshness (#94) */}
      <section
        aria-labelledby="sensor-patch-heading"
        className="rounded-xl border border-slate-200 bg-white p-5 shadow-xs"
      >
        <h2
          id="sensor-patch-heading"
          className="text-base font-semibold text-slate-900"
        >
          Sensor OS patch freshness
        </h2>
        <p className="mt-1 text-xs text-slate-500">
          Last successful patch window as reported by each sensor over signed
          ingest. Patch monthly; alert after {PATCH_OVERDUE_AFTER_DAYS} days.
          Procedure: <code className="font-mono">docs/RUNBOOK.md</code> (OS
          security patch window).
        </p>
        <div className="mt-4 overflow-x-auto">
          <table className="min-w-full divide-y divide-slate-200 text-left text-xs">
            <thead className="bg-slate-50 text-slate-600">
              <tr>
                <th scope="col" className="px-3 py-2 font-medium">Sensor</th>
                <th scope="col" className="px-3 py-2 font-medium">Status</th>
                <th scope="col" className="px-3 py-2 font-medium">
                  Last patch (<TimezoneLabel />)
                </th>
                <th scope="col" className="px-3 py-2 font-medium">
                  Last heartbeat (<TimezoneLabel />)
                </th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-200">
              {sensorsRes.error ? (
                <tr>
                  <td colSpan={4} className="px-3 py-4 text-red-700">
                    Could not load sensor status.
                  </td>
                </tr>
              ) : sensorPatchRows.length === 0 ? (
                <tr>
                  <td colSpan={4} className="px-3 py-4 text-slate-500">
                    No sensors registered.
                  </td>
                </tr>
              ) : (
                sensorPatchRows.map((row) => (
                  <tr key={row.id}>
                    <td className="px-3 py-2 font-mono text-slate-800">
                      {row.id}
                      {row.is_active ? "" : " (inactive)"}
                    </td>
                    <td className={`px-3 py-2 ${PATCH_STATE_CLASS[row.freshness.state]}`}>
                      {row.freshness.label}
                    </td>
                    <td className="px-3 py-2 tabular-nums text-slate-600">
                      <FormattedTime iso={row.last_patch_success_at} />
                    </td>
                    <td className="px-3 py-2 tabular-nums text-slate-600">
                      <FormattedTime iso={row.last_heartbeat_at} />
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
        {sensorTotal > sensorPatchRows.length ? (
          <p role="status" className="mt-2 text-xs font-medium text-amber-700">
            Showing {sensorPatchRows.length} of {sensorTotal} sensors (active
            first). Check the remaining sensors in the database.
          </p>
        ) : null}
      </section>

      {/* 1. MCP Entitlements */}
      <section className="rounded-xl border border-slate-200 bg-white p-5 shadow-xs">
        <h2 className="text-base font-semibold text-slate-900">
          MCP entitlements &amp; account status
        </h2>
        <p className="mt-1 text-xs text-slate-500">
          Minimal UUID identifiers only. Every change is appended to{" "}
          <code className="font-mono">admin_audit_logs</code>.
        </p>

        <form
          action={updateEntitlementAction}
          className="mt-4 flex flex-wrap items-end gap-3 rounded-lg border border-slate-200 bg-slate-50 p-3"
        >
          <label className="flex flex-col text-xs font-medium text-slate-700">
            User UUID
            <input
              name="user_id"
              required
              pattern="[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-8][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}"
              placeholder="xxxxxxxx-xxxx-4xxx-8xxx-xxxxxxxxxxxx"
              className="mt-1 w-72 rounded-md border border-slate-300 bg-white px-2.5 py-1.5 font-mono text-xs text-slate-900"
            />
          </label>
          <input type="hidden" name="mcp_enabled" value="true" />
          <input type="hidden" name="is_suspended" value="false" />
          <button
            type="submit"
            className="rounded-md bg-slate-900 px-3 py-1.5 text-xs font-medium text-white hover:bg-slate-800"
          >
            Grant MCP access
          </button>
        </form>

        <div className="mt-4 overflow-x-auto">
          <table className="min-w-full divide-y divide-slate-200 text-left text-xs">
            <thead className="bg-slate-50 text-slate-600">
              <tr>
                <th className="px-3 py-2 font-medium">User ID</th>
                <th className="px-3 py-2 font-medium">Terms</th>
                <th className="px-3 py-2 font-medium">MCP</th>
                <th className="px-3 py-2 font-medium">Status</th>
                <th className="px-3 py-2 font-medium">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-200">
              {entitlements.length === 0 ? (
                <tr>
                  <td colSpan={5} className="px-3 py-4 text-slate-500">
                    No entitlement records yet.
                  </td>
                </tr>
              ) : (
                entitlements.map((row) => (
                  <tr key={row.user_id}>
                    <td className="px-3 py-2 font-mono text-slate-800">
                      {row.user_id}
                    </td>
                    <td className="px-3 py-2 text-slate-600">
                      {row.terms_version ?? "unaccepted"}
                    </td>
                    <td className="px-3 py-2">
                      <span
                        className={
                          row.mcp_enabled
                            ? "font-medium text-emerald-700"
                            : "text-slate-500"
                        }
                      >
                        {row.mcp_enabled ? "enabled" : "disabled"}
                      </span>
                    </td>
                    <td className="px-3 py-2">
                      <span
                        className={
                          row.is_suspended
                            ? "font-medium text-red-700"
                            : "text-slate-600"
                        }
                      >
                        {row.is_suspended ? "suspended" : "active"}
                      </span>
                    </td>
                    <td className="px-3 py-2">
                      <div className="flex flex-wrap gap-2">
                        <form action={updateEntitlementAction}>
                          <input type="hidden" name="user_id" value={row.user_id} />
                          <input
                            type="hidden"
                            name="mcp_enabled"
                            value={row.mcp_enabled ? "false" : "true"}
                          />
                          <button
                            type="submit"
                            className="rounded border border-slate-300 px-2 py-1 text-xs text-slate-700 hover:bg-slate-50"
                          >
                            {row.mcp_enabled ? "Revoke MCP" : "Enable MCP"}
                          </button>
                        </form>
                        <form action={updateEntitlementAction}>
                          <input type="hidden" name="user_id" value={row.user_id} />
                          <input
                            type="hidden"
                            name="is_suspended"
                            value={row.is_suspended ? "false" : "true"}
                          />
                          <button
                            type="submit"
                            className="rounded border border-red-200 px-2 py-1 text-xs text-red-700 hover:bg-red-50"
                          >
                            {row.is_suspended ? "Unsuspend" : "Suspend"}
                          </button>
                        </form>
                      </div>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </section>

      {/* 2. Daily AI Report review queue */}
      <section className="rounded-xl border border-slate-200 bg-white p-5 shadow-xs">
        <h2 className="text-base font-semibold text-slate-900">
          Daily AI report review queue
        </h2>
        <p className="mt-1 text-xs text-slate-500">
          Drafts remain private until explicitly reviewed and published. X post
          drafts are never auto-posted.
        </p>

        {reports.length === 0 ? (
          <p className="mt-3 text-sm text-slate-500">No daily reports yet.</p>
        ) : (
          <div className="mt-4 divide-y divide-slate-200 rounded-lg border border-slate-200">
            {reports.map((report) => (
              <div key={report.id} className="p-4">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <span className="font-mono text-sm font-semibold text-slate-900">
                    {report.date_utc}
                  </span>
                  <span className="rounded bg-slate-100 px-2 py-0.5 text-xs font-medium text-slate-700">
                    {report.status}
                  </span>
                </div>
                <p className="mt-2 line-clamp-3 whitespace-pre-wrap text-xs text-slate-600">
                  {report.summary_md}
                </p>
                {report.x_post_draft ? (
                  <p className="mt-2 rounded bg-slate-50 p-2 font-mono text-xs text-slate-700">
                    X draft: {report.x_post_draft}
                  </p>
                ) : null}
                <div className="mt-3 flex flex-wrap gap-2">
                  {(["reviewed", "published", "rejected"] as const).map(
                    (nextStatus) => (
                      <form key={nextStatus} action={reviewDailyReportAction}>
                        <input
                          type="hidden"
                          name="report_id"
                          value={report.id}
                        />
                        <input
                          type="hidden"
                          name="status"
                          value={nextStatus}
                        />
                        <button
                          type="submit"
                          className="rounded border border-slate-300 px-2.5 py-1 text-xs font-medium text-slate-700 hover:bg-slate-50"
                        >
                          Mark {nextStatus}
                        </button>
                      </form>
                    ),
                  )}
                </div>
              </div>
            ))}
          </div>
        )}
      </section>

      {/* 3. Append-only Audit Log Viewer */}
      <section className="rounded-xl border border-slate-200 bg-white p-5 shadow-xs">
        <h2 className="text-base font-semibold text-slate-900">
          Audit logs (append-only)
        </h2>
        <div className="mt-3 overflow-x-auto">
          <table className="min-w-full divide-y divide-slate-200 text-left text-xs">
            <thead className="bg-slate-50 text-slate-600">
              <tr>
                <th scope="col" className="px-3 py-2 font-medium">
                  Time (<TimezoneLabel />)
                </th>
                <th className="px-3 py-2 font-medium">Actor</th>
                <th className="px-3 py-2 font-medium">Action</th>
                <th className="px-3 py-2 font-medium">Target</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-200">
              {auditLogs.length === 0 ? (
                <tr>
                  <td colSpan={4} className="px-3 py-4 text-slate-500">
                    No audit entries recorded yet.
                  </td>
                </tr>
              ) : (
                auditLogs.map((log) => (
                  <tr key={log.id}>
                    <td className="px-3 py-2 font-mono text-slate-600">
                      <FormattedTime iso={log.created_at} />
                    </td>
                    <td className="px-3 py-2 font-mono text-slate-700">
                      {log.actor_user_id}
                    </td>
                    <td className="px-3 py-2 font-mono font-medium text-slate-900">
                      {log.action}
                    </td>
                    <td className="px-3 py-2 font-mono text-slate-600">
                      {log.target_type
                        ? `${log.target_type}:${log.target_id ?? "-"}`
                        : "-"}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
}
