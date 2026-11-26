/**
 * Privacy filter for the cookieless, aggregate-only Vercel Web Analytics.
 *
 * Allowlist, not denylist: only public dashboard pages are counted, and only
 * by path. Query strings and fragments are always dropped (they can carry
 * filters today and OAuth `code` / `state` values on auth routes). Operator,
 * auth, OAuth consent, and API routes are never sent. Event detail pages are
 * collapsed to one route so individual events are not tracked.
 */

const PUBLIC_PATHS = new Set(["/", "/trends", "/events", "/sensors", "/mcp"]);
const EVENT_DETAIL = /^\/events\/[^/]+$/;

/** Returns the URL to report (origin + allowlisted path), or null to drop it. */
export function sanitizeAnalyticsUrl(rawUrl: string): string | null {
  let url: URL;
  try {
    url = new URL(rawUrl);
  } catch {
    return null;
  }
  if (url.protocol !== "https:" && url.protocol !== "http:") return null;

  const path = url.pathname.length > 1 ? url.pathname.replace(/\/+$/, "") : url.pathname;
  let reported: string;
  if (PUBLIC_PATHS.has(path)) {
    reported = path;
  } else if (EVENT_DETAIL.test(path)) {
    reported = "/events/[id]";
  } else {
    return null;
  }
  return `${url.origin}${reported}`;
}
