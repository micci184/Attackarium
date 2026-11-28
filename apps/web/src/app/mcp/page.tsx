import { headers } from "next/headers";
import { OAuthLoginButtons } from "@/components/oauth-login-buttons";
import {
  createSupabaseAuthServerClient,
  getRequiredTermsVersion,
  getSiteOrigin,
} from "@/lib/supabase-auth";
import { acceptCurrentTermsAction, revokeOAuthGrantAction } from "./actions";

export const dynamic = "force-dynamic";

const TOOL_CATALOG = [
  {
    name: "get_attack_trends",
    description:
      "Time-series observation volume, protocol/port breakdowns, and coverage gaps for 24h, 7d, or 30d.",
    parameters: "period?: '24h' | '7d' | '30d', protocol?: Protocol",
  },
  {
    name: "get_attack_patterns",
    description:
      "Observed attack categories, representative sanitized HTTP paths, and evidence-backed candidate CVE/KEV/EPSS context.",
    parameters: "period?: '24h' | '7d' | '30d', protocol?: Protocol, limit?: 1..50",
  },
  {
    name: "get_observation_summary",
    description:
      "24h/window KPIs, baseline-building status, noteworthy shifts, sensor health, and coverage caveats.",
    parameters: "period?: '24h' | '7d' | '30d', protocol?: Protocol",
  },
] as const;

async function resolveDisplayOrigin(): Promise<string> {
  const configured = process.env.NEXT_PUBLIC_SITE_URL?.trim();
  if (configured) {
    return getSiteOrigin();
  }
  const hdrs = await headers();
  const host = hdrs.get("x-forwarded-host") ?? hdrs.get("host");
  const proto = hdrs.get("x-forwarded-proto") ?? "https";
  if (host) {
    return `${proto}://${host}`;
  }
  return getSiteOrigin();
}

export default async function McpPage({
  searchParams,
}: {
  searchParams: Promise<{ auth_error?: string }>;
}) {
  const [{ auth_error: authError }, origin, supabase] = await Promise.all([
    searchParams,
    resolveDisplayOrigin(),
    createSupabaseAuthServerClient(),
  ]);

  const mcpEndpointUrl = `${origin}/api/mcp`;
  const requiredTermsVersion = getRequiredTermsVersion();

  const cursorConfigSnippet = JSON.stringify(
    {
      mcpServers: {
        attackarium: {
          url: mcpEndpointUrl,
        },
      },
    },
    null,
    2,
  );

  let user: { id: string; provider: string | null } | null = null;
  let entitlement: {
    terms_accepted_at: string | null;
    terms_version: string | null;
    mcp_enabled: boolean;
    is_suspended: boolean;
  } | null = null;
  let grants: Array<{
    clientId: string;
    clientName: string;
    scopes: string[];
    grantedAt: string | null;
  }> = [];

  if (supabase) {
    const {
      data: { user: authUser },
    } = await supabase.auth.getUser();

    if (authUser) {
      const appProvider =
        typeof authUser.app_metadata?.provider === "string"
          ? authUser.app_metadata.provider
          : null;
      user = { id: authUser.id, provider: appProvider };

      const [entitlementRes, grantsRes] = await Promise.all([
        supabase
          .from("user_mcp_entitlements")
          .select("terms_accepted_at, terms_version, mcp_enabled, is_suspended")
          .eq("user_id", authUser.id)
          .maybeSingle(),
        supabase.auth.oauth.listGrants().catch(() => ({ data: null, error: null })),
      ]);

      if (!entitlementRes.error && entitlementRes.data) {
        entitlement = entitlementRes.data;
      }

      if (grantsRes && "data" in grantsRes && Array.isArray(grantsRes.data)) {
        grants = grantsRes.data.map((grant) => ({
          clientId: grant.client.id,
          clientName: grant.client.name,
          scopes: grant.scopes ?? [],
          grantedAt: grant.granted_at ?? null,
        }));
      }
    }
  }

  const termsAcceptedCurrent =
    entitlement?.terms_accepted_at != null &&
    entitlement.terms_version === requiredTermsVersion;

  return (
    <div className="space-y-6">
      <header className="border-b border-slate-200 pb-4">
        <h1 className="text-2xl font-semibold tracking-tight text-slate-900">
          Remote MCP
        </h1>
        <p className="mt-1 text-sm text-slate-600">
          Authenticated, read-only Streamable HTTP MCP access to sanitized
          Attackarium aggregates.
        </p>
      </header>

      {authError ? (
        <div
          role="alert"
          className="rounded-lg border border-amber-200 bg-amber-50 px-4 py-3 text-sm text-amber-900"
        >
          Sign-in did not complete. Verify that Google or GitHub OAuth is
          enabled in Supabase Auth and try again.
        </div>
      ) : null}

      {/* 1. Remote MCP setup guide */}
      <section className="rounded-xl border border-slate-200 bg-white p-5 shadow-xs">
        <h2 className="text-base font-semibold text-slate-900">
          1. Connection setup
        </h2>
        <p className="mt-1 text-sm text-slate-600">
          Add the Streamable HTTP endpoint below to your MCP client (for
          example, Cursor <code className="font-mono text-xs">.cursor/mcp.json</code>
          ). The client discovers OAuth 2.1 + PKCE metadata automatically via{" "}
          <code className="font-mono text-xs">
            /.well-known/oauth-protected-resource
          </code>
          .
        </p>

        <pre className="mt-4 overflow-x-auto rounded-lg bg-slate-900 p-4 font-mono text-xs text-slate-100">
          <code>{cursorConfigSnippet}</code>
        </pre>

        <p className="mt-3 text-xs text-slate-500">
          Minimal OAuth scope: <code className="font-mono">openid</code>{" "}
          (read-only access is enforced server-side). Requests require sign-in,
          current Terms acceptance, an active account, operator-approved MCP
          entitlement, and OAuth client consent.
        </p>
      </section>

      {/* 2. Read-only MCP tool catalog */}
      <section className="rounded-xl border border-slate-200 bg-white p-5 shadow-xs">
        <h2 className="text-base font-semibold text-slate-900">
          2. Read-only tool catalog
        </h2>
        <p className="mt-1 text-sm text-slate-600">
          Remote MCP exposes strictly three read-only tools over sanitized
          aggregates. Raw logs, source IPs, credentials, database writes, and
          admin actions are never exposed.
        </p>

        <div className="mt-4 divide-y divide-slate-200 rounded-lg border border-slate-200">
          {TOOL_CATALOG.map((tool) => (
            <div key={tool.name} className="p-4">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <code className="font-mono text-sm font-semibold text-slate-900">
                  {tool.name}
                </code>
                <span className="rounded bg-slate-100 px-2 py-0.5 text-xs font-medium text-slate-700">
                  read-only
                </span>
              </div>
              <p className="mt-1.5 text-sm text-slate-600">
                {tool.description}
              </p>
              <p className="mt-1 font-mono text-xs text-slate-500">
                Parameters: {tool.parameters}
              </p>
            </div>
          ))}
        </div>
      </section>

      {/* 3. Terms acceptance, entitlement status & OAuth consent controls */}
      <section className="rounded-xl border border-slate-200 bg-white p-5 shadow-xs">
        <h2 className="text-base font-semibold text-slate-900">
          3. Terms, entitlement &amp; OAuth consent
        </h2>

        {!supabase ? (
          <p className="mt-2 text-sm text-slate-600">
            Supabase Auth is not configured in this environment. Public
            observatory pages remain available without sign-in.
          </p>
        ) : !user ? (
          <div className="mt-3 space-y-4">
            <p className="text-sm text-slate-600">
              Sign in with Google or GitHub to accept the current Terms, check
              your MCP entitlement status, or revoke OAuth client access.
            </p>
            <p className="rounded-lg border border-slate-200 bg-slate-50 p-3 text-xs text-slate-600">
              Data notice: Signing in with Google or GitHub stores account
              metadata (such as your email address) inside Supabase Auth.
              Attackarium does not collect additional profile fields (name,
              address, or phone number) and does not log MCP prompts or auth
              tokens.
            </p>
            <OAuthLoginButtons nextPath="/mcp" />
          </div>
        ) : (
          <div className="mt-4 space-y-5">
            <div className="flex flex-wrap items-center justify-between gap-3 rounded-lg border border-slate-200 bg-slate-50 px-4 py-3">
              <div className="text-sm">
                <span className="text-slate-500">Signed in via </span>
                <span className="font-medium capitalize text-slate-900">
                  {user.provider ?? "unknown provider"}
                </span>
              </div>
              <div className="flex flex-wrap items-center gap-2">
                <form action="/auth/logout" method="POST">
                  <button
                    type="submit"
                    className="rounded-md border border-slate-300 bg-white px-3 py-1.5 text-xs font-medium text-slate-700 hover:bg-slate-100"
                  >
                    Sign out
                  </button>
                </form>
              </div>
            </div>

            <dl className="grid gap-4 sm:grid-cols-2">
              <div className="rounded-lg border border-slate-200 p-4">
                <dt className="text-xs font-medium text-slate-500">
                  Terms acceptance (version {requiredTermsVersion})
                </dt>
                <dd className="mt-1 text-sm font-medium text-slate-900">
                  {termsAcceptedCurrent ? "Accepted" : "Not yet accepted"}
                </dd>
                {!termsAcceptedCurrent && !entitlement?.is_suspended ? (
                  <form action={acceptCurrentTermsAction} className="mt-3">
                    <button
                      type="submit"
                      className="rounded-md bg-[#632ca6] px-3 py-1.5 text-xs font-medium text-white hover:bg-[#53238d]"
                    >
                      Accept Terms ({requiredTermsVersion})
                    </button>
                  </form>
                ) : null}
              </div>

              <div className="rounded-lg border border-slate-200 p-4">
                <dt className="text-xs font-medium text-slate-500">
                  MCP entitlement
                </dt>
                <dd className="mt-1 text-sm font-medium text-slate-900">
                  {entitlement?.is_suspended
                    ? "Suspended"
                    : entitlement?.mcp_enabled
                      ? "Enabled"
                      : "Pending operator approval"}
                </dd>
                <p className="mt-1.5 text-xs text-slate-500">
                  Signing in does not automatically enable Remote MCP access.
                </p>
              </div>
            </dl>

            <div className="rounded-lg border border-slate-200 p-4">
              <h3 className="text-sm font-medium text-slate-900">
                Authorized OAuth clients
              </h3>
              {grants.length === 0 ? (
                <p className="mt-1.5 text-xs text-slate-500">
                  No OAuth clients currently have consent to access Remote MCP
                  on your behalf.
                </p>
              ) : (
                <ul className="mt-3 divide-y divide-slate-200">
                  {grants.map((grant) => (
                    <li
                      key={grant.clientId}
                      className="flex flex-wrap items-center justify-between gap-3 py-2.5 first:pt-0 last:pb-0"
                    >
                      <div>
                        <p className="text-sm font-medium text-slate-900">
                          {grant.clientName}
                        </p>
                        <p className="font-mono text-xs text-slate-500">
                          Scopes:{" "}
                          {grant.scopes.length > 0
                            ? grant.scopes.join(", ")
                            : "none"}
                        </p>
                      </div>
                      <form action={revokeOAuthGrantAction}>
                        <input
                          type="hidden"
                          name="client_id"
                          value={grant.clientId}
                        />
                        <button
                          type="submit"
                          className="rounded-md border border-red-200 bg-white px-3 py-1.5 text-xs font-medium text-red-700 hover:bg-red-50"
                        >
                          Revoke
                        </button>
                      </form>
                    </li>
                  ))}
                </ul>
              )}
            </div>
          </div>
        )}
      </section>
    </div>
  );
}
