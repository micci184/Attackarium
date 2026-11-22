import { createServerClient } from "@supabase/ssr";
import { cookies } from "next/headers";
import { getSupabasePublicConfig } from "./oauth-metadata.ts";

export {
  buildProtectedResourceMetadata,
  getAuthIssuerUrl,
  getRequiredTermsVersion,
  getSiteOrigin,
  getSupabasePublicConfig,
  sanitizeRedirectPath,
  type ProtectedResourceMetadata,
  type SupabasePublicConfig,
} from "./oauth-metadata.ts";

export async function createSupabaseAuthServerClient() {
  const config = getSupabasePublicConfig();
  if (!config) return null;

  const cookieStore = await cookies();

  return createServerClient(config.url, config.anonKey, {
    cookies: {
      getAll() {
        return cookieStore.getAll();
      },
      setAll(cookiesToSet) {
        try {
          for (const { name, value, options } of cookiesToSet) {
            cookieStore.set(name, value, options);
          }
        } catch {
          // Server Components cannot mutate cookies; Route Handlers and Server Actions can.
        }
      },
    },
  });
}
