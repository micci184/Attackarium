"use client";

import { Analytics, type BeforeSendEvent } from "@vercel/analytics/next";
import { sanitizeAnalyticsUrl } from "@/lib/analytics-privacy";

function beforeSend(event: BeforeSendEvent): BeforeSendEvent | null {
  const url = sanitizeAnalyticsUrl(event.url);
  return url === null ? null : { ...event, url };
}

/** Cookieless, aggregate-only page counts for public pages (see analytics-privacy.ts). */
export function PrivacyAnalytics() {
  return <Analytics beforeSend={beforeSend} />;
}
