import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { sanitizeAnalyticsUrl } from "./analytics-privacy.ts";

const ORIGIN = "https://attackarium.vercel.app";

describe("sanitizeAnalyticsUrl", () => {
  it("keeps public pages by path only", () => {
    for (const path of ["/", "/trends", "/events", "/sensors", "/mcp"]) {
      assert.equal(sanitizeAnalyticsUrl(`${ORIGIN}${path}`), `${ORIGIN}${path}`);
    }
    assert.equal(sanitizeAnalyticsUrl(`${ORIGIN}/trends/`), `${ORIGIN}/trends`);
  });

  it("always drops query strings and fragments", () => {
    assert.equal(
      sanitizeAnalyticsUrl(`${ORIGIN}/events?cve=CVE-2025-31324&page=2#top`),
      `${ORIGIN}/events`,
    );
    assert.equal(sanitizeAnalyticsUrl(`${ORIGIN}/?tz=utc`), `${ORIGIN}/`);
  });

  it("collapses event detail pages to one route", () => {
    assert.equal(
      sanitizeAnalyticsUrl(`${ORIGIN}/events/bfa3894b-7222-4aed-ab6e-5e80f121f6ba`),
      `${ORIGIN}/events/[id]`,
    );
  });

  it("never reports operator, auth, OAuth, or API routes", () => {
    for (const path of [
      "/admin",
      "/admin/usage",
      "/auth/callback?code=secret-code&state=xyz",
      "/auth/login",
      "/auth/oauth/authorize?client_id=a&code_challenge=b",
      "/oauth/consent?authorization_id=abc",
      "/api/mcp",
      "/.well-known/oauth-protected-resource",
      "/events/a/b",
      "/unknown",
    ]) {
      assert.equal(sanitizeAnalyticsUrl(`${ORIGIN}${path}`), null, path);
    }
  });

  it("drops malformed and non-web URLs", () => {
    assert.equal(sanitizeAnalyticsUrl("not a url"), null);
    assert.equal(sanitizeAnalyticsUrl("javascript:alert(1)"), null);
  });
});
