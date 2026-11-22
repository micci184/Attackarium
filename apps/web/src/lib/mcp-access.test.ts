import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  MCP_READ_SCOPE,
  MCP_TERMS_VERSION,
  evaluateMcpAccess,
  type McpAccessIdentity,
  type McpEntitlementState,
} from "./mcp-access.ts";

const userId = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";

function identity(overrides: Partial<McpAccessIdentity> = {}): McpAccessIdentity {
  return {
    userId,
    provider: "google",
    clientId: "oauth-client",
    scopes: [MCP_READ_SCOPE],
    ...overrides,
  };
}

function entitlement(overrides: Partial<McpEntitlementState> = {}): McpEntitlementState {
  return {
    termsVersion: MCP_TERMS_VERSION,
    termsAcceptedAt: "2026-11-22T00:00:00.000Z",
    mcpEnabled: true,
    isSuspended: false,
    ...overrides,
  };
}

describe("evaluateMcpAccess", () => {
  it("allows an entitled OAuth user who accepted the current terms", () => {
    assert.deepEqual(evaluateMcpAccess(identity(), entitlement()), { ok: true });
    assert.deepEqual(
      evaluateMcpAccess(identity({ provider: "github" }), entitlement()),
      { ok: true },
    );
  });

  it("denies a missing login, an unknown provider, and a session without a user id", () => {
    assert.deepEqual(evaluateMcpAccess(null, entitlement()), { ok: false, gate: "login" });
    assert.deepEqual(
      evaluateMcpAccess(identity({ provider: "email" }), entitlement()),
      { ok: false, gate: "login" },
    );
    assert.deepEqual(
      evaluateMcpAccess(identity({ provider: null }), entitlement()),
      { ok: false, gate: "login" },
    );
    assert.deepEqual(
      evaluateMcpAccess(identity({ userId: "not-a-uuid" }), entitlement()),
      { ok: false, gate: "login" },
    );
  });

  it("requires the current terms version before suspension or entitlement", () => {
    assert.deepEqual(
      evaluateMcpAccess(identity(), null),
      { ok: false, gate: "terms" },
    );
    assert.deepEqual(
      evaluateMcpAccess(identity(), entitlement({ termsVersion: "2026-01-01" })),
      { ok: false, gate: "terms" },
    );
    assert.deepEqual(
      evaluateMcpAccess(identity(), entitlement({ termsAcceptedAt: "" })),
      { ok: false, gate: "terms" },
    );
    assert.deepEqual(
      evaluateMcpAccess(identity(), entitlement({ termsAcceptedAt: "not-a-timestamp" })),
      { ok: false, gate: "terms" },
    );
    assert.deepEqual(
      evaluateMcpAccess(identity(), entitlement({ termsVersion: "" }), ""),
      { ok: false, gate: "terms" },
    );
    assert.deepEqual(
      evaluateMcpAccess(identity(), entitlement({
        termsAcceptedAt: null,
        isSuspended: true,
        mcpEnabled: false,
      })),
      { ok: false, gate: "terms" },
    );
  });

  it("denies a suspended account even when MCP is enabled", () => {
    assert.deepEqual(
      evaluateMcpAccess(identity(), entitlement({ isSuspended: true })),
      { ok: false, gate: "suspended" },
    );
  });

  it("keeps authentication separate from entitlement", () => {
    assert.deepEqual(
      evaluateMcpAccess(identity(), entitlement({ mcpEnabled: false })),
      { ok: false, gate: "entitlement" },
    );
  });

  it("requires an OAuth client and rejects disallowed scopes while accepting Supabase OAuth tokens without a scope claim", () => {
    assert.deepEqual(
      evaluateMcpAccess(identity({ clientId: null }), entitlement()),
      { ok: false, gate: "consent" },
    );
    assert.deepEqual(
      evaluateMcpAccess(identity({ clientId: "  " }), entitlement()),
      { ok: false, gate: "consent" },
    );
    // Supabase OAuth 2.1 access tokens include client_id without a scope claim
    assert.deepEqual(
      evaluateMcpAccess(identity({ scopes: [] }), entitlement()),
      { ok: true },
    );
    assert.deepEqual(
      evaluateMcpAccess(identity({ scopes: ["admin:write"] }), entitlement()),
      { ok: false, gate: "consent" },
    );
  });
});
