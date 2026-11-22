import { MCP_READ_SCOPE, MCP_TERMS_VERSION } from "./mcp-access.ts";

export interface SupabasePublicConfig {
  url: string;
  anonKey: string;
}

export interface ProtectedResourceMetadata {
  resource: string;
  authorization_servers: string[];
  scopes_supported: string[];
  bearer_methods_supported: string[];
  resource_documentation: string;
}

export function getSupabasePublicConfig(): SupabasePublicConfig | null {
  const url = process.env.NEXT_PUBLIC_SUPABASE_URL?.trim();
  const anonKey = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY?.trim();
  if (!url || !anonKey) return null;
  return { url: url.replace(/\/+$/, ""), anonKey };
}

export function getRequiredTermsVersion(): string {
  return process.env.MCP_REQUIRED_TERMS_VERSION?.trim() || MCP_TERMS_VERSION;
}

export function getAuthIssuerUrl(): string | null {
  const explicit = process.env.SUPABASE_AUTH_ISSUER?.trim();
  if (explicit) return explicit.replace(/\/+$/, "");
  const supabaseUrl =
    process.env.SUPABASE_URL?.trim() ??
    process.env.NEXT_PUBLIC_SUPABASE_URL?.trim();
  if (!supabaseUrl) return null;
  return `${supabaseUrl.replace(/\/+$/, "")}/auth/v1`;
}

export function getSiteOrigin(fallbackOrigin = "http://localhost:3000"): string {
  const configured = process.env.NEXT_PUBLIC_SITE_URL?.trim();
  if (configured) {
    try {
      return new URL(configured).origin;
    } catch {
      // Fall through to fallbackOrigin when env URL is invalid.
    }
  }
  return fallbackOrigin.replace(/\/+$/, "");
}

/**
 * Prevents open redirects by allowing only same-origin relative paths.
 */
export function sanitizeRedirectPath(
  raw: string | null | undefined,
  fallback = "/mcp",
): string {
  if (!raw) return fallback;
  const trimmed = raw.trim();
  if (
    !trimmed.startsWith("/") ||
    trimmed.startsWith("//") ||
    trimmed.startsWith("/\\") ||
    /[\r\n\u0000-\u001f]/.test(trimmed)
  ) {
    return fallback;
  }
  return trimmed;
}

export function buildProtectedResourceMetadata(options: {
  origin: string;
  authIssuer: string;
}): ProtectedResourceMetadata {
  const cleanOrigin = options.origin.replace(/\/+$/, "");
  const cleanIssuer = options.authIssuer.replace(/\/+$/, "");
  return {
    resource: `${cleanOrigin}/api/mcp`,
    authorization_servers: [cleanIssuer],
    scopes_supported: [MCP_READ_SCOPE],
    bearer_methods_supported: ["header"],
    resource_documentation: `${cleanOrigin}/mcp`,
  };
}
