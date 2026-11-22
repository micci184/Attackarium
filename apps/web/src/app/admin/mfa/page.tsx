import Link from "next/link";
import { redirect } from "next/navigation";
import { AdminMfaChallenge } from "@/components/admin-mfa-challenge";
import { requireAllowlistedOperatorSession } from "@/lib/admin-auth";
import { createSupabaseAuthServerClient } from "@/lib/supabase-auth";

export const dynamic = "force-dynamic";

export default async function AdminMfaPage() {
  const session = await requireAllowlistedOperatorSession();
  if (!session.ok) {
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

  if (session.currentLevel === "aal2") {
    redirect("/admin");
  }

  const supabase = await createSupabaseAuthServerClient();
  const factorsRes = supabase
    ? await supabase.auth.mfa.listFactors()
    : { data: null };
  const verifiedTotp =
    factorsRes.data?.totp.find((factor) => factor.status === "verified") ??
    null;

  return (
    <section className="mx-auto max-w-xl rounded-xl border border-slate-200 bg-white p-6 shadow-xs">
      <p className="text-xs font-medium uppercase tracking-wide text-[#632ca6]">
        Operator MFA (aal2)
      </p>
      <h1 className="mt-1 text-xl font-semibold text-slate-900">
        Verify multi-factor authentication
      </h1>
      <p className="mt-2 text-sm text-slate-600">
        Your account is on the operator allowlist, but this session is currently{" "}
        <code className="font-mono text-xs">aal1</code>. Complete TOTP
        verification to access <code className="font-mono text-xs">/admin</code>{" "}
        and <code className="font-mono text-xs">/admin/mcp-usage</code>.
      </p>

      <AdminMfaChallenge initialFactorId={verifiedTotp?.id ?? null} />
    </section>
  );
}
