/**
 * Server-side decision for the five Remote MCP gates.
 * Authentication is a verified identity. Entitlement is a separate database row.
 * This function does not read tokens, prompts, or user profile fields.
 */

export const MCP_READ_SCOPE = "mcp:read";
export const MCP_TERMS_VERSION = "2026-11-22";

const ALLOWED_LOGIN_PROVIDERS = new Set(["google", "github"]);
const USER_ID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

export type McpGate = "login" | "terms" | "suspended" | "entitlement" | "consent";

export interface McpAccessIdentity {
  userId: string;
  provider: string | null;
  clientId: string | null;
  scopes: readonly string[];
}

export interface McpEntitlementState {
  termsVersion: string | null;
  termsAcceptedAt: string | null;
  mcpEnabled: boolean;
  isSuspended: boolean;
}

export type McpAccessDecision =
  | { ok: true }
  | { ok: false; gate: McpGate };

export function evaluateMcpAccess(
  identity: McpAccessIdentity | null,
  entitlement: McpEntitlementState | null,
  termsVersion: string = MCP_TERMS_VERSION,
): McpAccessDecision {
  if (
    identity === null
    || !USER_ID_PATTERN.test(identity.userId)
    || identity.provider === null
    || !ALLOWED_LOGIN_PROVIDERS.has(identity.provider)
  ) {
    return { ok: false, gate: "login" };
  }

  const termsAccepted = termsVersion.trim() !== ""
    && entitlement?.termsAcceptedAt != null
    && entitlement.termsAcceptedAt.trim() !== ""
    && !Number.isNaN(Date.parse(entitlement.termsAcceptedAt))
    && entitlement.termsVersion === termsVersion;
  if (!termsAccepted) {
    return { ok: false, gate: "terms" };
  }

  if (entitlement.isSuspended) {
    return { ok: false, gate: "suspended" };
  }

  if (!entitlement.mcpEnabled) {
    return { ok: false, gate: "entitlement" };
  }

  const scopes = new Set(identity.scopes);
  if (identity.clientId === null || identity.clientId.trim() === "" || !scopes.has(MCP_READ_SCOPE)) {
    return { ok: false, gate: "consent" };
  }

  return { ok: true };
}
