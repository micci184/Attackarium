// Shared Bearer check for Edge Functions that pg_cron calls through pg_net.
// The secret is OPS_ALERTS_CRON_SECRET (function secret; the same value is in
// Vault as ops_alerts_cron_secret). A missing or short secret refuses every
// call, so a function is never open by misconfiguration.

/** Constant-time comparison of two strings (length leak only). */
export function secretsEqual(a: string, b: string): boolean {
  const enc = new TextEncoder();
  const x = enc.encode(a);
  const y = enc.encode(b);
  let diff = x.length ^ y.length;
  for (let i = 0; i < Math.max(x.length, y.length); i++) {
    diff |= (x[i] ?? 0) ^ (y[i] ?? 0);
  }
  return diff === 0;
}

export function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json", "cache-control": "no-store" },
  });
}

/** Returns an error response, or null when the request may proceed. */
export function checkCronRequest(request: Request, cronSecret: string): Response | null {
  if (request.method !== "POST") return jsonResponse(405, { error: "method_not_allowed" });
  if (cronSecret.length < 32) return jsonResponse(503, { error: "not_configured" });
  const header = request.headers.get("authorization") ?? "";
  const token = header.startsWith("Bearer ") ? header.slice("Bearer ".length) : "";
  if (!secretsEqual(token, cronSecret)) return jsonResponse(401, { error: "unauthorized" });
  return null;
}

/**
 * Reads a small JSON object body; anything else (too large, not JSON, not an
 * object) yields {}. The size cap applies while reading: the stream is
 * cancelled as soon as it exceeds `maxBytes`, so a large body is never
 * buffered.
 */
export async function readSmallJsonBody(request: Request, maxBytes = 1024): Promise<Record<string, unknown>> {
  const reader = request.body?.getReader();
  if (!reader) return {};
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > maxBytes) {
        await reader.cancel().catch(() => {});
        return {};
      }
      chunks.push(value);
    }
  } catch {
    return {};
  }
  if (total === 0) return {};
  const bytes = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  try {
    const body: unknown = JSON.parse(new TextDecoder().decode(bytes));
    return typeof body === "object" && body !== null && !Array.isArray(body) ? (body as Record<string, unknown>) : {};
  } catch {
    return {};
  }
}
