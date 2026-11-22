import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { SignJWT, generateKeyPair, jwtVerify } from "jose";
import {
  MCP_READ_SCOPE,
  MCP_TERMS_VERSION,
  type McpEntitlementState,
} from "./mcp-access.ts";
import {
  extractMcpIdentityFromClaims,
  type VerifyMcpTokenFn,
} from "./mcp-auth.ts";
import {
  createAttackariumMcpHandler,
  type McpUsageRecord,
} from "./mcp-server.ts";
import { MCP_TOOL_NAMES } from "./mcp-tools.ts";
import {
  getOverviewData,
  getSensorsData,
  getTrendsData,
} from "./observatory.ts";

const TEST_USER_ID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const TEST_ISSUER = "https://example.supabase.co/auth/v1";
const TEST_AUDIENCE = "authenticated";
const MCP_URL = "https://attackarium.example/api/mcp";

const MCP_HEADERS = {
  "Content-Type": "application/json",
  Accept: "application/json, text/event-stream",
};

async function createTestCryptoVerifier() {
  const { publicKey, privateKey } = await generateKeyPair("ES256");

  const signToken = async (
    claims: Record<string, unknown>,
    options: { issuer?: string; audience?: string; expiresIn?: string } = {},
  ): Promise<string> => {
    return new SignJWT(claims)
      .setProtectedHeader({ alg: "ES256" })
      .setIssuedAt()
      .setIssuer(options.issuer ?? TEST_ISSUER)
      .setAudience(options.audience ?? TEST_AUDIENCE)
      .setExpirationTime(options.expiresIn ?? "5m")
      .sign(privateKey);
  };

  const verifyToken: VerifyMcpTokenFn = async (bearerToken) => {
    try {
      const { payload } = await jwtVerify(bearerToken, publicKey, {
        issuer: TEST_ISSUER,
        audience: TEST_AUDIENCE,
        algorithms: ["ES256"],
      });
      return extractMcpIdentityFromClaims(payload);
    } catch {
      return null;
    }
  };

  return { signToken, verifyToken };
}

function validClaims(overrides: Record<string, unknown> = {}) {
  return {
    sub: TEST_USER_ID,
    app_metadata: { provider: "github" },
    client_id: "cursor-mcp-client",
    scope: MCP_READ_SCOPE,
    ...overrides,
  };
}

function validEntitlement(
  overrides: Partial<McpEntitlementState> = {},
): McpEntitlementState {
  return {
    termsAcceptedAt: "2026-11-22T00:00:00.000Z",
    termsVersion: MCP_TERMS_VERSION,
    mcpEnabled: true,
    isSuspended: false,
    ...overrides,
  };
}

function mcpRequest(
  body: Record<string, unknown>,
  token?: string,
): Request {
  const headers: Record<string, string> = { ...MCP_HEADERS };
  if (token) {
    headers.Authorization = `Bearer ${token}`;
  }
  return new Request(MCP_URL, {
    method: "POST",
    headers,
    body: JSON.stringify(body),
  });
}

async function parseJsonRpcResponse(response: Response): Promise<Record<string, unknown>> {
  const text = await response.text();
  const contentType = response.headers.get("content-type") ?? "";
  if (contentType.includes("text/event-stream")) {
    const dataLines = text
      .split("\n")
      .filter((line) => line.startsWith("data:"))
      .map((line) => line.slice(5).trim())
      .filter(Boolean);
    assert.ok(dataLines.length > 0, `Expected SSE data line, got: ${text}`);
    return JSON.parse(dataLines[dataLines.length - 1]) as Record<string, unknown>;
  }
  return JSON.parse(text) as Record<string, unknown>;
}

const mockObservatory = {
  getOverviewData: async () => {
    const prev = process.env.USE_MOCK;
    process.env.USE_MOCK = "true";
    try {
      return await getOverviewData();
    } finally {
      process.env.USE_MOCK = prev;
    }
  },
  getTrendsData: async (period?: "24h" | "7d" | "30d") => {
    const prev = process.env.USE_MOCK;
    process.env.USE_MOCK = "true";
    try {
      return await getTrendsData(period);
    } finally {
      process.env.USE_MOCK = prev;
    }
  },
  getSensorsData: async () => {
    const prev = process.env.USE_MOCK;
    process.env.USE_MOCK = "true";
    try {
      return await getSensorsData();
    } finally {
      process.env.USE_MOCK = prev;
    }
  },
};

describe("Remote MCP server security boundaries", () => {
  it("returns 401 with WWW-Authenticate on missing, invalid, expired, or wrong-issuer JWT", async () => {
    const { signToken, verifyToken } = await createTestCryptoVerifier();
    const usage: McpUsageRecord[] = [];
    const handler = createAttackariumMcpHandler({
      verifyToken,
      fetchEntitlement: async () => validEntitlement(),
      consumeRateLimit: async () => ({ allowed: true, currentCount: 1, retryAfterSeconds: 60 }),
      recordUsage: async (record) => {
        usage.push(record);
      },
      observatory: mockObservatory,
    });

    const initBody = {
      jsonrpc: "2.0",
      id: 1,
      method: "initialize",
      params: {
        protocolVersion: "2025-03-26",
        capabilities: {},
        clientInfo: { name: "test-client", version: "1.0.0" },
      },
    };

    // 1. Missing token
    const resMissing = await handler(mcpRequest(initBody));
    assert.equal(resMissing.status, 401);
    assert.equal(resMissing.headers.get("cache-control"), "no-store");
    const wwwAuth = resMissing.headers.get("www-authenticate") ?? "";
    assert.ok(
      wwwAuth.includes('resource_metadata="https://attackarium.example/.well-known/oauth-protected-resource"'),
    );
    assert.ok(wwwAuth.includes('scope="mcp:read"'));

    // 2. Malformed token
    const resBad = await handler(mcpRequest(initBody, "not-a-jwt-secret-token"));
    assert.equal(resBad.status, 401);

    // 3. Expired JWT
    const expiredToken = await signToken(validClaims(), { expiresIn: "-10s" });
    const resExpired = await handler(mcpRequest(initBody, expiredToken));
    assert.equal(resExpired.status, 401);

    // 4. Wrong issuer JWT
    const wrongIssuerToken = await signToken(validClaims(), {
      issuer: "https://evil.example/auth/v1",
    });
    const resWrongIss = await handler(mcpRequest(initBody, wrongIssuerToken));
    assert.equal(resWrongIss.status, 401);

    // 5. Wrong audience JWT
    const wrongAudToken = await signToken(validClaims(), { audience: "other" });
    const resWrongAud = await handler(mcpRequest(initBody, wrongAudToken));
    assert.equal(resWrongAud.status, 401);

    assert.equal(usage.length, 5);
    assert.ok(usage.every((u) => u.authFailureDelta === 1 && u.callDelta === 0));
    assert.ok(!JSON.stringify(usage).includes("not-a-jwt-secret-token"));
  });

  it("enforces all 5 gates server-side and reflects immediate revocation/suspension", async () => {
    const { signToken, verifyToken } = await createTestCryptoVerifier();
    let currentEntitlement: McpEntitlementState | null = validEntitlement();

    const handler = createAttackariumMcpHandler({
      verifyToken,
      fetchEntitlement: async () => currentEntitlement,
      consumeRateLimit: async () => ({ allowed: true, currentCount: 1, retryAfterSeconds: 60 }),
      observatory: mockObservatory,
    });

    const listReq = { jsonrpc: "2.0", id: 1, method: "tools/list" };

    // Never trust user_metadata.provider when app_metadata.provider is absent
    const spoofedProviderToken = await signToken({
      sub: TEST_USER_ID,
      user_metadata: { provider: "google" },
      client_id: "cursor-mcp-client",
      scope: MCP_READ_SCOPE,
    });
    const resSpoofed = await handler(mcpRequest(listReq, spoofedProviderToken));
    assert.equal(resSpoofed.status, 403);
    assert.deepEqual(await resSpoofed.json(), { error: "forbidden", gate: "login" });

    // Missing scope -> 403 + insufficient_scope challenge
    const noScopeToken = await signToken(validClaims({ scope: "" }));
    const resNoScope = await handler(mcpRequest(listReq, noScopeToken));
    assert.equal(resNoScope.status, 403);
    assert.deepEqual(await resNoScope.json(), { error: "forbidden", gate: "consent" });
    assert.ok(
      (resNoScope.headers.get("www-authenticate") ?? "").includes('error="insufficient_scope"'),
    );

    const token = await signToken(validClaims());

    // Unaccepted Terms
    currentEntitlement = validEntitlement({ termsVersion: "2026-01-01" });
    const resTerms = await handler(mcpRequest(listReq, token));
    assert.equal(resTerms.status, 403);
    assert.deepEqual(await resTerms.json(), { error: "forbidden", gate: "terms" });

    // Unentitled user (authenticated != entitled)
    currentEntitlement = validEntitlement({ mcpEnabled: false });
    const resUnentitled = await handler(mcpRequest(listReq, token));
    assert.equal(resUnentitled.status, 403);
    assert.deepEqual(await resUnentitled.json(), { error: "forbidden", gate: "entitlement" });

    // Entitled -> succeeds
    currentEntitlement = validEntitlement();
    const resAllowed = await handler(mcpRequest(listReq, token));
    assert.equal(resAllowed.status, 200);

    // Immediate suspension with the exact same still-valid JWT -> denied on next call
    currentEntitlement = validEntitlement({ isSuspended: true });
    const resSuspended = await handler(mcpRequest(listReq, token));
    assert.equal(resSuspended.status, 403);
    assert.deepEqual(await resSuspended.json(), { error: "forbidden", gate: "suspended" });

    // Immediate revocation with the exact same still-valid JWT -> denied on next call
    currentEntitlement = validEntitlement({ mcpEnabled: false });
    const resRevoked = await handler(mcpRequest(listReq, token));
    assert.equal(resRevoked.status, 403);
    assert.deepEqual(await resRevoked.json(), { error: "forbidden", gate: "entitlement" });
  });

  it("enforces per-user rate limits with 429 and Retry-After", async () => {
    const { signToken, verifyToken } = await createTestCryptoVerifier();
    const token = await signToken(validClaims());
    let calls = 0;
    const usage: McpUsageRecord[] = [];

    const handler = createAttackariumMcpHandler({
      verifyToken,
      fetchEntitlement: async () => validEntitlement(),
      consumeRateLimit: async () => {
        calls += 1;
        return {
          allowed: calls <= 1,
          currentCount: calls,
          retryAfterSeconds: 42,
        };
      },
      recordUsage: async (record) => {
        usage.push(record);
      },
      observatory: mockObservatory,
    });

    const toolReq = {
      jsonrpc: "2.0",
      id: 1,
      method: "tools/call",
      params: { name: "get_observation_summary", arguments: { period: "24h" } },
    };

    const first = await handler(mcpRequest(toolReq, token));
    assert.equal(first.status, 200);

    const second = await handler(mcpRequest(toolReq, token));
    assert.equal(second.status, 429);
    assert.equal(second.headers.get("retry-after"), "42");
    assert.deepEqual(await second.json(), {
      error: "rate_limited",
      retryAfterSeconds: 42,
    });

    assert.equal(usage.length, 2);
    assert.equal(usage[0].requestKind, "tool_call");
    assert.equal(usage[0].toolName, "get_observation_summary");
    assert.equal(usage[0].successDelta, 1);
    assert.equal(usage[1].rateLimitedDelta, 1);
    assert.equal(usage[1].callDelta, 0);
  });

  it("exposes strictly the 3 read-only tools, executes them safely, and logs no prompts or tokens", async () => {
    const { signToken, verifyToken } = await createTestCryptoVerifier();
    const token = await signToken(validClaims());
    const usage: McpUsageRecord[] = [];

    const handler = createAttackariumMcpHandler({
      verifyToken,
      fetchEntitlement: async () => validEntitlement(),
      consumeRateLimit: async () => ({ allowed: true, currentCount: 1, retryAfterSeconds: 60 }),
      recordUsage: async (record) => {
        usage.push(record);
      },
      observatory: mockObservatory,
    });

    // initialize
    const initRes = await handler(
      mcpRequest(
        {
          jsonrpc: "2.0",
          id: 1,
          method: "initialize",
          params: {
            protocolVersion: "2025-03-26",
            capabilities: {},
            clientInfo: { name: "cursor-test", version: "1.0.0" },
          },
        },
        token,
      ),
    );
    assert.equal(initRes.status, 200);
    assert.equal(initRes.headers.get("cache-control"), "no-store");

    // tools/list -> strictly 3 read-only tools
    const listRes = await handler(
      mcpRequest({ jsonrpc: "2.0", id: 2, method: "tools/list" }, token),
    );
    assert.equal(listRes.status, 200);
    const listJson = await parseJsonRpcResponse(listRes);
    const tools = (listJson.result as { tools: Array<{ name: string; annotations?: { readOnlyHint?: boolean; destructiveHint?: boolean } }> }).tools;
    assert.deepEqual(
      tools.map((tool) => tool.name),
      [...MCP_TOOL_NAMES],
    );
    for (const tool of tools) {
      assert.equal(tool.annotations?.readOnlyHint, true);
      assert.equal(tool.annotations?.destructiveHint, false);
    }

    // Call each of the 3 tools
    for (const [idx, call] of [
      { name: "get_attack_trends", arguments: { period: "7d", protocol: "http" } },
      { name: "get_attack_patterns", arguments: { period: "7d", protocol: "http", limit: 5 } },
      { name: "get_observation_summary", arguments: { period: "24h" } },
    ].entries()) {
      const res = await handler(
        mcpRequest(
          {
            jsonrpc: "2.0",
            id: 10 + idx,
            method: "tools/call",
            params: call,
          },
          token,
        ),
      );
      assert.equal(res.status, 200);
      const rpc = await parseJsonRpcResponse(res);
      const content = (rpc.result as { content: Array<{ text: string }> }).content;
      const text = content[0]?.text ?? "";
      const parsed = JSON.parse(text) as { caveats?: string[] };
      assert.ok(Array.isArray(parsed.caveats) && parsed.caveats.length > 0);
      assert.ok(!text.includes("src_ip_hash"));
      assert.ok(!text.includes("raw_object_key"));
      assert.ok(!text.includes("last_error_summary"));
    }

    // Verify usage telemetry separates initialize vs tool_call and never stores tokens or arguments
    assert.equal(usage.length, 4);
    assert.equal(usage[0].requestKind, "initialize");
    assert.equal(usage[0].toolName, "");
    assert.deepEqual(
      usage.slice(1).map((u) => [u.requestKind, u.toolName, u.successDelta]),
      [
        ["tool_call", "get_attack_trends", 1],
        ["tool_call", "get_attack_patterns", 1],
        ["tool_call", "get_observation_summary", 1],
      ],
    );

    const serializedUsage = JSON.stringify(usage);
    assert.ok(!serializedUsage.includes(token));
    assert.ok(!serializedUsage.includes(TEST_USER_ID));
    assert.ok(!serializedUsage.includes("cursor-test"));
  });

  it("rejects oversized POST payloads with 413", async () => {
    const { signToken, verifyToken } = await createTestCryptoVerifier();
    const token = await signToken(validClaims());
    const handler = createAttackariumMcpHandler({
      verifyToken,
      fetchEntitlement: async () => validEntitlement(),
      consumeRateLimit: async () => ({ allowed: true, currentCount: 1, retryAfterSeconds: 60 }),
      observatory: mockObservatory,
    });

    const hugeReq = new Request(MCP_URL, {
      method: "POST",
      headers: {
        ...MCP_HEADERS,
        Authorization: `Bearer ${token}`,
      },
      body: JSON.stringify({
        jsonrpc: "2.0",
        id: 1,
        method: "tools/list",
        padding: "x".repeat(70 * 1024),
      }),
    });

    const res = await handler(hugeReq);
    assert.equal(res.status, 413);
    assert.deepEqual(await res.json(), { error: "payload_too_large" });
  });
});
