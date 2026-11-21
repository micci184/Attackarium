const JST_DATETIME_FORMATTER = new Intl.DateTimeFormat("ja-JP", {
  timeZone: "Asia/Tokyo",
  year: "numeric",
  month: "2-digit",
  day: "2-digit",
  hour: "2-digit",
  minute: "2-digit",
  second: "2-digit",
  hour12: false,
});

const JST_SHORT_FORMATTER = new Intl.DateTimeFormat("ja-JP", {
  timeZone: "Asia/Tokyo",
  month: "2-digit",
  day: "2-digit",
  hour: "2-digit",
  minute: "2-digit",
  hour12: false,
});

const NUMBER_FORMATTER = new Intl.NumberFormat("en-US");

export function formatCount(value: number): string {
  return NUMBER_FORMATTER.format(value);
}

export function formatJstDateTime(isoString: string | null | undefined): string {
  if (!isoString) return "—";
  const date = new Date(isoString);
  if (Number.isNaN(date.getTime())) return "—";
  return `${JST_DATETIME_FORMATTER.format(date)} JST`;
}

export function formatJstShort(isoString: string | null | undefined): string {
  if (!isoString) return "—";
  const date = new Date(isoString);
  if (Number.isNaN(date.getTime())) return "—";
  return `${JST_SHORT_FORMATTER.format(date)} JST`;
}

export function formatConfidence(confidence: number): string {
  return `${Math.round(confidence * 100)}%`;
}

export function formatEpss(score: number | null | undefined): string {
  if (score === null || score === undefined || Number.isNaN(score)) return "N/A";
  return `${(score * 100).toFixed(2)}%`;
}

/**
 * Strips non-printable control chars before rendering untrusted strings as text.
 * React already escapes HTML entities; this additionally guards against
 * bidirectional overrides and control characters in logs.
 */
export function safeDisplayText(value: string | null | undefined, fallback = "—"): string {
  if (!value) return fallback;
  const cleaned = value.replace(/[\u0000-\u001f\u007f\u202a-\u202e\u2066-\u2069]/g, "");
  return cleaned.length > 0 ? cleaned : fallback;
}
