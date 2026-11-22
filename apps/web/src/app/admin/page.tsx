import Link from "next/link";
import {
  getAdminServiceClient,
  requireOperatorAdmin,
} from "@/lib/admin-auth";
import { reviewDailyReportAction, updateEntitlementAction } from "./actions";

export const dynamic = "force-dynamic";

function AdminDeniedView({ reason }: { reason: string }) {
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
      <p className="mt-2 font-mono text-xs text-slate-500">
        Reason: {reason}
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
    return <AdminDeniedView reason={auth.reason} />;
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

  const [entitlementsRes, reportsRes, auditRes] = await Promise.all([
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
  ]);

  const entitlements = entitlementsRes.data ?? [];
  const reports = reportsRes.data ?? [];
  const auditLogs = auditRes.data ?? [];

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
                <th className="px-3 py-2 font-medium">Time (UTC)</th>
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
                      {log.created_at}
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
