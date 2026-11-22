import Link from "next/link";
import { ProtocolBadge } from "@/components/protocol-badge";
import {
  formatConfidence,
  formatCount,
  formatCvss,
  formatEpss,
  formatEpssPercentile,
  formatUtcDate,
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
      <section className="rounded border border-gray-200 bg-white">
        <div className="border-b border-gray-200 px-4 py-3">
          <h2 className="text-xs font-semibold uppercase tracking-wider text-gray-700">
            Observed Patterns
          </h2>
        </div>
        <div className="p-4">
          {patterns.length === 0 ? (
            <p className="text-xs text-gray-500">No attack patterns stored in this window.</p>
          ) : (
            <ol className="divide-y divide-gray-100">
              {patterns.map((pattern) => (
                <li key={pattern.key} className="flex items-center justify-between gap-3 py-2 text-xs">
                  <div className="flex min-w-0 items-center gap-2">
                    <ProtocolBadge protocol={pattern.protocol} />
                    {pattern.eventsHref ? (
                      <Link
                        href={pattern.eventsHref}
                        className="truncate rounded text-gray-800 hover:text-[#632ca6] hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#632ca6]"
                      >
                        {safeDisplayText(pattern.label)}
                      </Link>
                    ) : (
                      <span className="truncate text-gray-800">{safeDisplayText(pattern.label)}</span>
                    )}
                  </div>
                  <span className="font-mono tabular-nums text-gray-900">{formatCount(pattern.count)}</span>
                </li>
              ))}
            </ol>
          )}

          {cveContext.length > 0 ? (
            <div className="mt-4 border-t border-gray-200 pt-3">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <h3 className="text-[11px] font-semibold uppercase tracking-wider text-gray-700">
                  Candidate CVE Context (Evidence-Backed)
                </h3>
                <Link
                  href="/events?category=suspected_cve_probe"
                  className="rounded text-[11px] font-medium text-[#632ca6] transition-colors hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#632ca6]"
                >
                  Inspect Matched Events →
                </Link>
              </div>
              <p className="mt-1 text-[11px] leading-relaxed text-gray-500">
                Shown only when backed by a versioned detection rule in this window. Candidate
                associations are not proof of exploitation; EPSS is a vulnerability-level 30-day
                forecast, not per-request exploit probability.
              </p>
              <ul className="mt-2.5 space-y-2">
                {cveContext.map((item) => (
                  <li
                    key={item.cveId}
                    className="rounded border border-gray-200 border-l-2 border-l-amber-500 bg-gray-50/60 p-2.5 text-xs"
                  >
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <div className="flex flex-wrap items-center gap-2">
                        <Link
                          href={item.eventsHref}
                          translate="no"
                          className="rounded font-mono font-semibold text-gray-900 hover:text-[#632ca6] hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#632ca6]"
                        >
                          {safeDisplayText(item.cveId)}
                        </Link>
                        <span className="font-mono text-[11px] tabular-nums text-gray-500">
                          {formatCount(item.matchedEventCount)}{" "}
                          {item.matchedEventCount === 1 ? "event" : "events"}
                        </span>
                      </div>
                      <div className="flex flex-wrap items-center gap-1.5 text-[11px]">
                        <span
                          translate="no"
                          className="rounded border border-amber-200 bg-amber-50 px-1.5 py-0.5 font-mono tabular-nums text-amber-800"
                        >
                          Conf: {formatConfidence(item.maxConfidence)}
                        </span>
                        <span
                          translate="no"
                          className={`rounded border px-1.5 py-0.5 font-mono ${
                            item.kevPresent
                              ? "border-red-200 bg-red-50 text-red-700"
                              : "border-gray-200 bg-white text-gray-600"
                          }`}
                        >
                          KEV: {item.kevPresent ? "Listed" : "Not Listed"}
                          {item.kevPresent && item.kevAddedAt
                            ? ` (${formatUtcDate(item.kevAddedAt)})`
                            : ""}
                        </span>
                        <span
                          translate="no"
                          className="rounded border border-gray-200 bg-white px-1.5 py-0.5 font-mono tabular-nums text-gray-700"
                        >
                          EPSS: {formatEpss(item.epssScore)}
                          {item.epssPercentile !== null
                            ? ` · ${formatEpssPercentile(item.epssPercentile)}`
                            : ""}
                          {item.epssDate ? ` (${item.epssDate})` : ""}
                        </span>
                        {item.cvssScore !== null ? (
                          <span
                            translate="no"
                            className="rounded border border-gray-200 bg-white px-1.5 py-0.5 font-mono tabular-nums text-gray-700"
                          >
                            CVSS: {formatCvss(item.cvssScore)}
                          </span>
                        ) : null}
                      </div>
                    </div>
                    {item.description ? (
                      <p className="mt-1.5 line-clamp-2 text-[11px] leading-relaxed text-gray-600">
                        {safeDisplayText(item.description)}
                      </p>
                    ) : null}
                    <p className="mt-1.5 font-mono text-[11px] text-gray-500">
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
      </section>

      <section className="rounded border border-gray-200 bg-white">
        <div className="border-b border-gray-200 px-4 py-3">
          <h2 className="text-xs font-semibold uppercase tracking-wider text-gray-700">
            Representative HTTP Paths
          </h2>
        </div>
        <div className="p-4">
          <p className="pb-2 text-[11px] leading-relaxed text-gray-500">
            Paths are sanitized before storage. A repeated path is a probe pattern, not proof that a request succeeded.
          </p>
          {httpPaths.length === 0 ? (
            <p className="text-xs text-gray-500">No sanitized HTTP paths stored in this window.</p>
          ) : (
            <ol className="divide-y divide-gray-100">
              {httpPaths.map((item) => (
                <li
                  key={`${item.method} ${item.path}`}
                  className="flex items-center justify-between gap-3 py-2 text-xs"
                >
                  <span translate="no" className="min-w-0 truncate font-mono text-gray-800">
                    {safeDisplayText(item.method)} {safeDisplayText(item.path)}
                  </span>
                  <span className="font-mono tabular-nums text-gray-900">{formatCount(item.count)}</span>
                </li>
              ))}
            </ol>
          )}
          {sampledNote ? <p className="mt-3 text-[11px] text-gray-500">{sampledNote}</p> : null}
        </div>
      </section>
    </div>
  );
}
