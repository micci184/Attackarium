import Link from "next/link";
import { redirect } from "next/navigation";
import { OAuthConsentActions } from "@/components/oauth-consent-actions";
import { OAuthLoginButtons } from "@/components/oauth-login-buttons";
import { createSupabaseAuthServerClient } from "@/lib/supabase-auth";

export const dynamic = "force-dynamic";

export default async function OAuthConsentPage({
  searchParams,
}: {
  searchParams: Promise<{ authorization_id?: string }>;
}) {
  const { authorization_id: rawAuthId } = await searchParams;
  const authorizationId = rawAuthId?.trim() ?? "";

  if (!authorizationId) {
    return (
      <section className="mx-auto max-w-xl rounded-xl border border-slate-200 bg-white p-6 shadow-xs">
        <h1 className="text-lg font-semibold text-slate-900">
          Invalid OAuth request
        </h1>
        <p className="mt-2 text-sm text-slate-600">
          Missing <code className="font-mono text-xs">authorization_id</code>{" "}
          parameter. Start the connection from your MCP client.
        </p>
        <Link
          href="/mcp"
          className="mt-4 inline-flex items-center rounded-md border border-slate-300 px-3 py-1.5 text-sm font-medium text-slate-700 hover:bg-slate-50"
        >
          Back to Remote MCP
        </Link>
      </section>
    );
  }

  const supabase = await createSupabaseAuthServerClient();
  if (!supabase) {
    return (
      <section className="mx-auto max-w-xl rounded-xl border border-slate-200 bg-white p-6 shadow-xs">
        <h1 className="text-lg font-semibold text-slate-900">
          Authentication unavailable
        </h1>
        <p className="mt-2 text-sm text-slate-600">
          Supabase Auth OAuth 2.1 is not configured in this environment.
        </p>
      </section>
    );
  }

  const {
    data: { user },
  } = await supabase.auth.getUser();

  if (!user) {
    const returnTo = `/oauth/consent?authorization_id=${encodeURIComponent(authorizationId)}`;
    return (
      <section className="mx-auto max-w-xl rounded-xl border border-slate-200 bg-white p-6 shadow-xs">
        <h1 className="text-lg font-semibold text-slate-900">
          Sign in to authorize Remote MCP
        </h1>
        <p className="mt-2 text-sm text-slate-600">
          Sign in with Google or GitHub to review and approve this read-only
          Remote MCP connection request.
        </p>
        <p className="mt-2 text-xs text-slate-500">
          Signing in with Google or GitHub stores account metadata (such as your
          email address) in Supabase Auth. Attackarium does not collect
          additional profile PII.
        </p>

        <div className="mt-5">
          <OAuthLoginButtons
            nextPath={returnTo}
            githubLabel="Continue with GitHub"
            googleLabel="Continue with Google"
          />
        </div>
      </section>
    );
  }

  const { data: authDetails, error } =
    await supabase.auth.oauth.getAuthorizationDetails(authorizationId);

  if (error || !authDetails) {
    return (
      <section className="mx-auto max-w-xl rounded-xl border border-slate-200 bg-white p-6 shadow-xs">
        <h1 className="text-lg font-semibold text-slate-900">
          Authorization request expired or invalid
        </h1>
        <p className="mt-2 text-sm text-slate-600">
          Restart the OAuth connection flow from your MCP client.
        </p>
        <Link
          href="/mcp"
          className="mt-4 inline-flex items-center rounded-md border border-slate-300 px-3 py-1.5 text-sm font-medium text-slate-700 hover:bg-slate-50"
        >
          Back to Remote MCP
        </Link>
      </section>
    );
  }

  if (!("authorization_id" in authDetails)) {
    redirect(authDetails.redirect_url);
  }

  const requestedScopes = authDetails.scope
    ? authDetails.scope.split(/\s+/).filter(Boolean)
    : [];

  return (
    <section className="mx-auto max-w-xl rounded-xl border border-slate-200 bg-white p-6 shadow-xs">
      <p className="text-xs font-medium uppercase tracking-wide text-[#632ca6]">
        OAuth 2.1 Client Consent
      </p>
      <h1 className="mt-1 text-xl font-semibold text-slate-900">
        Authorize {authDetails.client.name}
      </h1>
      <p className="mt-2 text-sm text-slate-600">
        This MCP client is requesting read-only access to sanitized Attackarium
        observatory aggregates.
      </p>

      <dl className="mt-5 space-y-3 rounded-lg border border-slate-200 bg-slate-50 p-4 text-sm">
        <div>
          <dt className="text-xs font-medium text-slate-500">Client</dt>
          <dd className="mt-0.5 font-medium text-slate-900">
            {authDetails.client.name}
          </dd>
        </div>
        <div>
          <dt className="text-xs font-medium text-slate-500">Redirect URI</dt>
          <dd className="mt-0.5 break-all font-mono text-xs text-slate-700">
            {authDetails.redirect_uri}
          </dd>
        </div>
        <div>
          <dt className="text-xs font-medium text-slate-500">
            Requested scopes
          </dt>
          <dd className="mt-1 flex flex-wrap gap-1.5">
            {requestedScopes.length > 0 ? (
              requestedScopes.map((scope) => (
                <span
                  key={scope}
                  className="rounded bg-white px-2 py-0.5 font-mono text-xs text-slate-800 ring-1 ring-slate-200"
                >
                  {scope}
                </span>
              ))
            ) : (
              <span className="text-xs text-slate-500">None specified</span>
            )}
          </dd>
        </div>
      </dl>

      <p className="mt-4 text-xs text-slate-500">
        Approving client consent alone does not bypass Terms acceptance or MCP
        entitlement checks. You can revoke client access at any time on{" "}
        <Link href="/mcp" className="text-[#632ca6] underline">
          /mcp
        </Link>
        .
      </p>

      <OAuthConsentActions authorizationId={authorizationId} />
    </section>
  );
}
