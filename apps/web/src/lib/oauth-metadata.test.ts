import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  buildProtectedResourceMetadata,
  sanitizeRedirectPath,
} from "./oauth-metadata.ts";

describe("OAuth 2.1 metadata and redirect sanitization", () => {
  it("builds RFC 9728 protected resource metadata pointing to /api/mcp", () => {
    const metadata = buildProtectedResourceMetadata({
      origin: "https://attackarium.vercel.app/",
      authIssuer: "https://example.supabase.co/auth/v1/",
    });

    assert.deepEqual(metadata, {
      resource: "https://attackarium.vercel.app/api/mcp",
      authorization_servers: ["https://example.supabase.co/auth/v1"],
      scopes_supported: ["mcp:read"],
      bearer_methods_supported: ["header"],
      resource_documentation: "https://attackarium.vercel.app/mcp",
    });
  });

  it("blocks open redirects and allows safe same-origin paths", () => {
    assert.equal(sanitizeRedirectPath("/mcp"), "/mcp");
    assert.equal(
      sanitizeRedirectPath("/oauth/consent?authorization_id=abc-123"),
      "/oauth/consent?authorization_id=abc-123",
    );
    assert.equal(sanitizeRedirectPath("https://evil.example/phish"), "/mcp");
    assert.equal(sanitizeRedirectPath("//evil.example/phish"), "/mcp");
    assert.equal(sanitizeRedirectPath("/\\evil.example/phish"), "/mcp");
    assert.equal(sanitizeRedirectPath("/mcp\r\nSet-Cookie: a=b"), "/mcp");
    assert.equal(sanitizeRedirectPath(""), "/mcp");
    assert.equal(sanitizeRedirectPath(null), "/mcp");
  });
});
