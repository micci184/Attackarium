import Link from "next/link";
import { ProtocolBadge } from "@/components/protocol-badge";
import { Panel, PanelHeader } from "@/components/ui";
import {
  formatEvidenceBasis,
  formatMatchStrength,
  formatCount,
  formatCvss,
  formatEpss,
  formatEpssPercentile,
  formatUtcDate,
  safeDisplayHttpPath,
  safeDisplayText,
} from "@/lib/format";
import type { HttpPathTotal, PatternCveContext, PatternTotal } from "@/lib/types";

export function PatternLists({
  patterns,
  httpPaths,
  sampledNote,
  cveContext = [],
}: {
  patterns: PatternTotal[];
  httpPaths: HttpPathTotal[];
  sampledNote: string | null;
  cveContext?: PatternCveContext[];
}) {
  return (
    <div className="grid gap-4 lg:grid-cols-2">
      <Panel>
        <PanelHeader
          title="Observed Categories"
          subtitle="Grouped by protocol and classified activity type"
        />
        <div className="p-4">
          {patterns.length === 0 ? (
            <p className="text-xs text-slate-500">No attack patterns stored in this window.</p>
          ) : (
            <ol className="divide-y divide-slate-100">
              {patterns.map((pattern) => (
                <li
                  key={pattern.key}
                  className="flex items-center justify-between gap-3 py-2 text-xs"
                >
                  <div className="flex min-w-0 items-center gap-2">
                    <ProtocolBadge protocol={pattern.protocol} />
                    {pattern.eventsHref ? (
                      <Link
                        href={pattern.eventsHref}
                        className="truncate rounded font-medium text-slate-800 hover:text-[#632ca6] hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#632ca6]"
                      >
                        {safeDisplayText(pattern.label)}
                      </Link>
                    ) : (
                      <span className="truncate text-slate-800">
                        {safeDisplayText(pattern.label)}
                      </span>
                    )}
                  </div>
                  <span className="font-mono font-medium tabular-nums text-slate-900">
                    {formatCount(pattern.count)}
                  </span>
                </li>
              ))}
            </ol>
          )}

          {cveContext.length > 0 ? (
            <div className="mt-4 border-t border-slate-200 pt-3.5">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <h3 className="text-xs font-semibold text-slate-800">
                  Candidate CVE Context (Evidence-Backed)
                </h3>
                <Link
                  href="/events?category=suspected_cve_probe"
                  title="All events with a candidate CVE; select a CVE below to see only its events"
                  className="rounded text-[11px] font-medium text-[#632ca6] transition-colors hover:text-[#4e2185] hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#632ca6]"
                >
                  Inspect Matched Events →
                </Link>
              </div>
              <p className="mt-1 text-[11px] leading-relaxed text-slate-500">
                Shown only when backed by a versioned detection rule in this window. Candidate
                associations are not proof of exploitation; EPSS is a vulnerability-level 30-day
                forecast, not per-request exploit probability.
              </p>
              <ul className="mt-2.5 space-y-2">
                {cveContext.map((item) => (
                  <li
                    key={item.cveId}
                    className="rounded-md border border-slate-200 border-l-2 border-l-amber-500 bg-slate-50/70 p-3 text-xs"
                  >
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <div className="flex flex-wrap items-center gap-2">
                        <Link
                          href={item.eventsHref}
                          translate="no"
                          className="rounded font-mono font-semibold text-slate-900 hover:text-[#632ca6] hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#632ca6]"
                        >
                          {safeDisplayText(item.cveId)}
                        </Link>
                        <span className="font-mono text-[11px] tabular-nums text-slate-500">
                          {formatCount(item.matchedEventCount)}{" "}
                          {item.matchedEventCount === 1 ? "event" : "events"}
                        </span>
                      </div>
                      <div className="flex flex-wrap items-center gap-x-3 gap-y-1 font-mono text-[11px] tabular-nums text-slate-600">
                        <span
                          translate="no"
                          className="text-amber-800"
                          title={`Rule-defined evidence grade, not a probability${
                            formatEvidenceBasis(item.indicator, item.matchedLocation)
                              ? `. Basis: ${formatEvidenceBasis(item.indicator, item.matchedLocation)}`
                              : ""
                          }`}
                        >
                          {formatMatchStrength(item.matchStrength)} match
                        </span>
                        <span
                          translate="no"
                          className={item.kevPresent ? "font-medium text-red-700" : "text-slate-600"}
                        >
                          KEV: {item.kevPresent ? "Listed" : "Not listed"}
                          {item.kevPresent && item.kevAddedAt
                            ? ` (${formatUtcDate(item.kevAddedAt)})`
                            : ""}
                        </span>
                        <span translate="no">
                          EPSS {formatEpss(item.epssScore)}
                          {item.epssPercentile !== null
                            ? ` · ${formatEpssPercentile(item.epssPercentile)}`
                            : ""}
                          {item.epssDate ? ` (${item.epssDate})` : ""}
                        </span>
                        {item.cvssScore !== null ? (
                          <span translate="no">CVSS {formatCvss(item.cvssScore)}</span>
                        ) : null}
                      </div>
                    </div>
                    {item.description ? (
                      <p className="mt-1.5 line-clamp-2 text-[11px] leading-relaxed text-slate-600">
                        {safeDisplayText(item.description)}
                      </p>
                    ) : null}
                    <p className="mt-1.5 font-mono text-[11px] text-slate-500">
                      Rule:{" "}
                      <span translate="no">
                        {safeDisplayText(item.ruleId)}@{safeDisplayText(item.ruleVersion)}
                      </span>
                      {item.vendor || item.product ? (
                        <>
                          {" "}
                          · Target:{" "}
                          <span translate="no">
                            {safeDisplayText(item.vendor)}/{safeDisplayText(item.product)}
                          </span>
                        </>
                      ) : null}
                    </p>
                  </li>
                ))}
              </ul>
            </div>
          ) : null}
        </div>
      </Panel>

      <Panel>
        <PanelHeader
          title="Representative HTTP Paths"
          subtitle="Query values redacted by default before public display"
        />
        <div className="p-4">
          <p className="pb-2.5 text-[11px] leading-relaxed text-slate-500">
            Paths are sanitized before storage and display. A repeated path is a probe pattern,
            not proof that a request succeeded.
          </p>
          {httpPaths.length === 0 ? (
            <p className="text-xs text-slate-500">
              No sanitized HTTP paths stored in this window.
            </p>
          ) : (
            <ol className="divide-y divide-slate-100">
              {httpPaths.map((item) => (
                <li
                  key={`${item.method} ${item.path}`}
                  className="flex items-center justify-between gap-3 py-2 text-xs"
                >
                  <span translate="no" className="min-w-0 truncate font-mono text-slate-800">
                    <span className="mr-1.5 text-slate-500">
                      {safeDisplayText(item.method)}
                    </span>
                    {safeDisplayHttpPath(item.path)}
                  </span>
                  <span className="shrink-0 font-mono font-medium tabular-nums text-slate-900">
                    {formatCount(item.count)}
                  </span>
                </li>
              ))}
            </ol>
          )}
          {sampledNote ? <p className="mt-3 text-[11px] text-slate-500">{sampledNote}</p> : null}
        </div>
      </Panel>
    </div>
  );
}
