import type { ReactNode } from "react";
import Link from "next/link";
import { MethodologyBanner } from "@/components/methodology-banner";
import { ProtocolBadge } from "@/components/protocol-badge";
import { PageHeader, Panel } from "@/components/ui";
import { attackCategoryLabel } from "@/lib/dashboard-metrics";
import {
  formatCount,
  formatJstDateTime,
  safeDisplayHttpPath,
  safeDisplayText,
} from "@/lib/format";
import { getPaginatedEvents } from "@/lib/observatory";
import type { EventCategoryFilter, EventPeriodFilter, Protocol } from "@/lib/types";

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

const PERIOD_FILTERS: Array<{ value: EventPeriodFilter; label: string }> = [
  { value: "all", label: "All" },
  { value: "24h", label: "24h" },
  { value: "7d", label: "7d" },
  { value: "30d", label: "30d" },
];

const CATEGORY_FILTERS: Array<{ value: EventCategoryFilter; label: string }> = [
  { value: "all", label: "All" },
  { value: "port_scan", label: attackCategoryLabel("port_scan") },
  { value: "auth_attempt", label: attackCategoryLabel("auth_attempt") },
  { value: "http_path_probe", label: attackCategoryLabel("http_path_probe") },
  { value: "web_attack_attempt", label: attackCategoryLabel("web_attack_attempt") },
  { value: "suspected_cve_probe", label: attackCategoryLabel("suspected_cve_probe") },
  { value: "unclassified", label: attackCategoryLabel(null) },
];

interface EventsPageProps {
  searchParams: Promise<{ page?: string; protocol?: string; period?: string; category?: string }>;
}

export default async function EventsPage({ searchParams }: EventsPageProps) {
  const params = await searchParams;
  const parsedPage = Number.parseInt(params.page ?? "1", 10);
  const page = Number.isFinite(parsedPage) && parsedPage > 0 ? parsedPage : 1;

  const result = await getPaginatedEvents({
    page,
    pageSize: 12,
    protocol: params.protocol,
    period: params.period,
    category: params.category,
  });

  const activeFilterCount =
    (result.protocolFilter !== "all" ? 1 : 0) +
    (result.periodFilter !== "all" ? 1 : 0) +
    (result.categoryFilter !== "all" ? 1 : 0);

  const buildUrl = (
    nextPage: number,
    nextProtocol: Protocol | "all" = result.protocolFilter,
    nextPeriod: EventPeriodFilter = result.periodFilter,
    nextCategory: EventCategoryFilter = result.categoryFilter,
  ) => {
    const q = new URLSearchParams();
    if (nextPage > 1) q.set("page", String(nextPage));
    if (nextProtocol !== "all") q.set("protocol", nextProtocol);
    if (nextPeriod !== "all") q.set("period", nextPeriod);
    if (nextCategory !== "all") q.set("category", nextCategory);
    const qs = q.toString();
    return qs ? `/events?${qs}` : "/events";
  };

  return (
    <div className="space-y-5">
      <PageHeader
        title="Event Explorer"
        description="Sanitized observation log explorer (raw IPs, query values, credentials, and payloads excluded)"
        actions={
          <span className="rounded-lg border border-slate-200 bg-white px-3 py-1.5 font-mono text-xs font-medium tabular-nums text-slate-700 shadow-[0_1px_2px_rgba(15,23,42,0.03)]">
            Total: {formatCount(result.totalCount)} events
          </span>
        }
      />

      <MethodologyBanner sourceMode={result.sourceMode} />

      <Panel>
        <div className="space-y-2.5 border-b border-slate-200 bg-slate-50/70 px-4 py-3">
          <FilterRow label="Protocol">
            {PROTOCOL_FILTERS.map((proto) => (
              <FilterLink
                key={proto}
                href={buildUrl(1, proto)}
                active={result.protocolFilter === proto}
                mono
              >
                {proto}
              </FilterLink>
            ))}
          </FilterRow>
          <FilterRow label="Window">
            {PERIOD_FILTERS.map((item) => (
              <FilterLink
                key={item.value}
                href={buildUrl(1, result.protocolFilter, item.value)}
                active={result.periodFilter === item.value}
                mono
              >
                {item.label}
              </FilterLink>
            ))}
          </FilterRow>
          <FilterRow label="Category">
            {CATEGORY_FILTERS.map((item) => (
              <FilterLink
                key={item.value}
                href={buildUrl(1, result.protocolFilter, result.periodFilter, item.value)}
                active={result.categoryFilter === item.value}
              >
                {item.label}
              </FilterLink>
            ))}
          </FilterRow>
          <div className="flex flex-wrap items-center justify-between gap-2 pt-1 text-[11px] text-slate-500">
            <p className="font-mono tabular-nums">
              Page {result.page} / {result.totalPages}
              {activeFilterCount > 0 ? ` · ${activeFilterCount} active filter(s)` : ""}
            </p>
            {activeFilterCount > 0 ? (
              <Link
                href="/events"
                className="rounded font-medium text-[#632ca6] transition-colors hover:text-[#4e2185] hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#632ca6]"
              >
                Reset filters
              </Link>
            ) : null}
          </div>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead>
              <tr className="border-b border-slate-200 bg-slate-50/80 text-[11px] font-semibold uppercase tracking-wider text-slate-500">
                <th className="px-4 py-2.5">Observed (JST)</th>
                <th className="px-3 py-2.5">Protocol</th>
                <th className="px-3 py-2.5">Category</th>
                <th className="px-3 py-2.5">Port</th>
                <th className="px-3 py-2.5">Event Type</th>
                <th className="px-3 py-2.5">Region / ASN</th>
                <th className="px-4 py-2.5">Sanitized Path / Fingerprint</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {result.items.length === 0 ? (
                <tr>
                  <td colSpan={7} className="px-4 py-10 text-center text-slate-500">
                    No sanitized events match these filters.
                  </td>
                </tr>
              ) : (
                result.items.map((ev) => (
                  <tr key={ev.id} className="transition-colors hover:bg-slate-50/80">
                    <td className="whitespace-nowrap px-4 py-2.5 font-mono tabular-nums text-slate-600">
                      {formatJstDateTime(ev.observed_at)}
                    </td>
                    <td className="px-3 py-2.5">
                      <ProtocolBadge protocol={ev.protocol} />
                    </td>
                    <td className="px-3 py-2.5 text-slate-700">
                      {attackCategoryLabel(ev.attack_category)}
                    </td>
                    <td className="px-3 py-2.5 font-mono tabular-nums text-slate-700">
                      {ev.dst_port}
                    </td>
                    <td translate="no" className="px-3 py-2.5 font-mono text-slate-800">
                      {safeDisplayText(ev.event_type)}
                    </td>
                    <td
                      translate="no"
                      className="whitespace-nowrap px-3 py-2.5 font-mono text-slate-500"
                    >
                      {safeDisplayText(ev.src_country)} / {safeDisplayText(ev.src_asn)}
                    </td>
                    <td className="max-w-md truncate px-4 py-2.5 font-mono">
                      <Link
                        href={`/events/${ev.id}`}
                        translate="no"
                        className="rounded text-[#632ca6] transition-colors hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#632ca6]"
                      >
                        {ev.http_method ? `${safeDisplayText(ev.http_method)} ` : ""}
                        {safeDisplayHttpPath(ev.http_path_redacted, ev.fingerprint ?? ev.id)}
                      </Link>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>

        <div className="flex flex-wrap items-center justify-between gap-3 border-t border-slate-200 bg-slate-50/60 px-4 py-2.5 text-xs text-slate-600">
          <span className="tabular-nums">
            Showing page {result.page} of {result.totalPages} ({formatCount(result.totalCount)}{" "}
            total events)
          </span>
          <div className="inline-flex items-center overflow-hidden rounded-md border border-slate-200 bg-white">
            {result.page > 1 ? (
              <Link
                href={buildUrl(result.page - 1)}
                className="border-r border-slate-200 px-3 py-1.5 font-medium text-slate-700 transition-colors hover:bg-slate-50 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-[#632ca6]"
              >
                ← Prev
              </Link>
            ) : (
              <span
                aria-disabled="true"
                className="border-r border-slate-200 px-3 py-1.5 text-slate-300"
              >
                ← Prev
              </span>
            )}
            {result.page < result.totalPages ? (
              <Link
                href={buildUrl(result.page + 1)}
                className="px-3 py-1.5 font-medium text-slate-700 transition-colors hover:bg-slate-50 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-[#632ca6]"
              >
                Next →
              </Link>
            ) : (
              <span aria-disabled="true" className="px-3 py-1.5 text-slate-300">
                Next →
              </span>
            )}
          </div>
        </div>
      </Panel>
    </div>
  );
}

function FilterRow({ label, children }: { label: string; children: ReactNode }) {
  return (
    <nav aria-label={`${label} filter`} className="flex flex-wrap items-center gap-1.5">
      <span className="mr-1 w-16 shrink-0 text-[11px] font-semibold uppercase tracking-wider text-slate-500">
        {label}
      </span>
      {children}
    </nav>
  );
}

function FilterLink({
  href,
  active,
  mono,
  children,
}: {
  href: string;
  active: boolean;
  mono?: boolean;
  children: ReactNode;
}) {
  return (
    <Link
      href={href}
      translate="no"
      aria-current={active ? "true" : undefined}
      className={`rounded-md border px-2.5 py-1 text-[11px] font-medium leading-none transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#632ca6] ${
        mono ? "font-mono uppercase" : ""
      } ${
        active
          ? "border-[#632ca6] bg-[#632ca6] text-white"
          : "border-slate-200 bg-white text-slate-600 hover:bg-slate-100 hover:text-slate-900"
      }`}
    >
      {children}
    </Link>
  );
}
