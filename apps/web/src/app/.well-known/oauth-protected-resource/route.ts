import { getPublicOrigin } from "mcp-handler";
import {
  buildProtectedResourceMetadata,
  getAuthIssuerUrl,
  getSiteOrigin,
} from "@/lib/oauth-metadata";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

const CORS_HEADERS: Record<string, string> = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization",
};

export function OPTIONS(): Response {
  return new Response(null, {
    status: 204,
    headers: CORS_HEADERS,
  });
}

export function GET(request: Request): Response {
  const authIssuer = getAuthIssuerUrl();
  if (!authIssuer) {
    return new Response(
      JSON.stringify({ error: "oauth_not_configured" }),
      {
        status: 503,
        headers: {
          "Content-Type": "application/json",
          "Cache-Control": "no-store",
          ...CORS_HEADERS,
        },
      },
    );
  }

  const origin = getSiteOrigin(getPublicOrigin(request));
  const metadata = buildProtectedResourceMetadata({ origin, authIssuer });

  return new Response(JSON.stringify(metadata), {
    status: 200,
    headers: {
      "Content-Type": "application/json",
      "Cache-Control": "public, max-age=300",
      ...CORS_HEADERS,
    },
  });
}
