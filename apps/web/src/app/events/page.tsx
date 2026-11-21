import Link from "next/link";
import { MethodologyBanner } from "@/components/methodology-banner";
import { ProtocolBadge } from "@/components/protocol-badge";
import { formatCount, formatJstDateTime, safeDisplayText } from "@/lib/format";
import { getPaginatedEvents } from "@/lib/observatory";
import type { Protocol } from "@/lib/types";

export const dynamic = "force-dynamic";

const PROTOCOL_FILTERS: Array<Protocol | "all"> = [
  "all",
  "ssh",
  "http",
  "https",
  "telnet",
  "ftp",
  "mysql",
  "redis",
  "other",
];

interface EventsPageProps {
  searchParams: Promise<{ page?: string; protocol?: string }>;
}

export default async function EventsPage({ searchParams }: EventsPageProps) {
  const params = await searchParams;
  const parsedPage = Number.parseInt(params.page ?? "1", 10);
  const page = Number.isFinite(parsedPage) && parsedPage > 0 ? parsedPage : 1;

  const result = await getPaginatedEvents({
    page,
    pageSize: 12,
    protocol: params.protocol,
  });

  const buildUrl = (nextPage: number, nextProtocol: string) => {
    const q = new URLSearchParams();
    if (nextPage > 1) q.set("page", String(nextPage));
    if (nextProtocol !== "all") q.set("protocol", nextProtocol);
    const qs = q.toString();
    return qs ? `/events?${qs}` : "/events";
  };

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="text-lg font-semibold tracking-tight text-gray-900">
            Event Explorer
          </h1>
          <p className="mt-0.5 text-xs text-gray-500">
            Sanitized observation log explorer (raw IPs, credentials, and payloads excluded)
          </p>
        </div>
        <span className="font-mono text-xs tabular-nums text-gray-500">
          Total: {formatCount(result.totalCount)} events
        </span>
      </div>

      <MethodologyBanner sourceMode={result.sourceMode} />

      {/* Datadog-style filter toolbar + log table */}
      <section className="rounded border border-gray-200 bg-white">
        <div className="flex flex-wrap items-center justify-between gap-3 border-b border-gray-200 bg-gray-50/70 px-4 py-2.5">
          <nav aria-label="Protocol filter" className="flex flex-wrap items-center gap-1">
            <span className="mr-1.5 text-[11px] font-semibold uppercase tracking-wider text-gray-500">
              Protocol:
            </span>
            {PROTOCOL_FILTERS.map((proto) => {
              const active = result.protocolFilter === proto;
              return (
                <Link
                  key={proto}
                  href={buildUrl(1, proto)}
                  translate="no"
                  aria-current={active ? "true" : undefined}
                  className={`rounded border px-2 py-1 font-mono text-[11px] uppercase leading-none transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#632ca6] ${
                    active
                      ? "border-[#632ca6] bg-[#632ca6] text-white"
                      : "border-gray-200 bg-white text-gray-600 hover:bg-gray-100 hover:text-gray-900"
                  }`}
                >
                  {proto}
                </Link>
              );
            })}
          </nav>

          <span className="font-mono text-[11px] tabular-nums text-gray-500">
            Page {result.page} / {result.totalPages}
          </span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead>
              <tr className="border-b border-gray-200 bg-gray-50 text-[11px] font-semibold uppercase tracking-wider text-gray-500">
                <th className="px-4 py-2">Observed (JST)</th>
                <th className="px-3 py-2">Protocol</th>
                <th className="px-3 py-2">Port</th>
                <th className="px-3 py-2">Event Type</th>
                <th className="px-3 py-2">Region / ASN</th>
                <th className="px-4 py-2">Sanitized Path / Fingerprint</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-100">
              {result.items.length === 0 ? (
                <tr>
                  <td colSpan={6} className="px-4 py-10 text-center text-gray-500">
                    No matching events found.
                  </td>
                </tr>
              ) : (
                result.items.map((ev) => (
                  <tr key={ev.id} className="transition-colors hover:bg-gray-50">
                    <td className="whitespace-nowrap px-4 py-2 font-mono tabular-nums text-gray-600">
                      {formatJstDateTime(ev.observed_at)}
                    </td>
                    <td className="px-3 py-2">
                      <ProtocolBadge protocol={ev.protocol} />
                    </td>
                    <td className="px-3 py-2 font-mono tabular-nums text-gray-700">
                      {ev.dst_port}
                    </td>
                    <td translate="no" className="px-3 py-2 font-mono text-gray-800">
                      {safeDisplayText(ev.event_type)}
                    </td>
                    <td
                      translate="no"
                      className="whitespace-nowrap px-3 py-2 font-mono text-gray-500"
                    >
                      {safeDisplayText(ev.src_country)} / {safeDisplayText(ev.src_asn)}
                    </td>
                    <td className="max-w-md truncate px-4 py-2 font-mono">
                      <Link
                        href={`/events/${ev.id}`}
                        translate="no"
                        className="rounded text-[#632ca6] transition-colors hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#632ca6]"
                      >
                        {ev.http_method ? `${ev.http_method} ` : ""}
                        {safeDisplayText(ev.http_path_redacted, ev.fingerprint ?? ev.id)}
                      </Link>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>

        <div className="flex flex-wrap items-center justify-between gap-3 border-t border-gray-200 bg-gray-50/50 px-4 py-2.5 text-xs text-gray-600">
          <span className="tabular-nums">
            Showing page {result.page} of {result.totalPages} ({formatCount(result.totalCount)}{" "}
            total events)
          </span>
          <div className="inline-flex items-center rounded border border-gray-200 bg-white">
            {result.page > 1 ? (
              <Link
                href={buildUrl(result.page - 1, result.protocolFilter)}
                className="border-r border-gray-200 px-3 py-1.5 font-medium text-gray-700 transition-colors hover:bg-gray-50 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-[#632ca6]"
              >
                ← Prev
              </Link>
            ) : (
              <span
                aria-disabled="true"
                className="border-r border-gray-200 px-3 py-1.5 text-gray-300"
              >
                ← Prev
              </span>
            )}
            {result.page < result.totalPages ? (
              <Link
                href={buildUrl(result.page + 1, result.protocolFilter)}
                className="px-3 py-1.5 font-medium text-gray-700 transition-colors hover:bg-gray-50 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-[#632ca6]"
              >
                Next →
              </Link>
            ) : (
              <span aria-disabled="true" className="px-3 py-1.5 text-gray-300">
                Next →
              </span>
            )}
          </div>
        </div>
      </section>
    </div>
  );
}
