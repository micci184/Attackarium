import {
  createRemoteJWKSet,
  decodeProtectedHeader,
  jwtVerify,
  type JWTPayload,
} from "jose";
import { MCP_READ_SCOPE, type McpAccessIdentity } from "./mcp-access.ts";

const ALLOWED_JWT_ALGORITHMS = ["RS256", "ES256"];

export interface JwtVerifierConfig {
  issuer: string;
  audience: string | string[];
  jwksUrl?: string;
}

export type VerifyMcpTokenFn = (
  bearerToken: string,
) => Promise<McpAccessIdentity | null>;

const MAX_BEARER_TOKEN_LENGTH = 8192;

export function extractBearerToken(request: Request): string | null {
  const header = request.headers.get("authorization");
  if (!header) return null;
  const match = /^Bearer\s+(\S+)$/i.exec(header.trim());
  const token = match?.[1] ?? null;
  if (!token || token.length > MAX_BEARER_TOKEN_LENGTH) return null;
  return token;
}

const JWT_SEGMENT_PATTERN = /^[A-Za-z0-9_-]+$/;

/**
 * Cheap, side-effect-free pre-auth guard that runs before signature
 * verification. Rejects bearer strings that cannot be a compact JWS signed
 * with an allowed algorithm, so garbage tokens never reach JWKS lookups or
 * any database call. Passing this check proves nothing about authenticity.
 */
export function isPlausibleJwt(token: string): boolean {
  const segments = token.split(".");
  if (segments.length !== 3) return false;
  if (!segments.every((segment) => JWT_SEGMENT_PATTERN.test(segment))) {
    return false;
  }
  try {
    const header = decodeProtectedHeader(token);
    return (
      typeof header.alg === "string" &&
      ALLOWED_JWT_ALGORITHMS.includes(header.alg)
    );
  } catch {
    return false;
  }
}

export function buildWwwAuthenticateHeader(
  resourceMetadataUrl: string,
  scope: string = MCP_READ_SCOPE,
): string {
  const safeUrl = resourceMetadataUrl.replaceAll('"', "");
  const safeScope = scope.replaceAll('"', "");
  return `Bearer resource_metadata="${safeUrl}", scope="${safeScope}"`;
}

/**
 * Extracts verified identity claims for MCP authorization.
 * Reads provider strictly from app_metadata (never user_metadata).
 */
export function extractMcpIdentityFromClaims(
  claims: JWTPayload,
): McpAccessIdentity | null {
  if (typeof claims.sub !== "string" || claims.sub.trim() === "") {
    return null;
  }

  const appMetadata =
    typeof claims.app_metadata === "object" && claims.app_metadata !== null
      ? (claims.app_metadata as Record<string, unknown>)
      : null;

  const provider =
    typeof appMetadata?.provider === "string" ? appMetadata.provider : null;

  const clientId =
    typeof claims.client_id === "string"
      ? claims.client_id
      : typeof claims.azp === "string"
        ? claims.azp
        : null;

  const scopes: string[] = [];
  if (typeof claims.scope === "string") {
    for (const part of claims.scope.split(/\s+/)) {
      if (part) scopes.push(part);
    }
  } else if (Array.isArray(claims.scp)) {
    for (const part of claims.scp) {
      if (typeof part === "string" && part.trim() !== "") {
        scopes.push(part.trim());
      }
    }
  }

  return {
    userId: claims.sub,
    provider,
    clientId,
    scopes,
  };
}

export function createSupabaseJwtVerifier(
  config: JwtVerifierConfig,
): VerifyMcpTokenFn {
  const normalizedIssuer = config.issuer.replace(/\/+$/, "");
  const jwksEndpoint =
    config.jwksUrl ?? `${normalizedIssuer}/.well-known/jwks.json`;
  const jwks = createRemoteJWKSet(new URL(jwksEndpoint));

  return async (bearerToken: string): Promise<McpAccessIdentity | null> => {
    try {
      const { payload } = await jwtVerify(bearerToken, jwks, {
        issuer: normalizedIssuer,
        audience: config.audience,
        algorithms: ALLOWED_JWT_ALGORITHMS,
      });
      return extractMcpIdentityFromClaims(payload);
    } catch {
      return null;
    }
  };
}
