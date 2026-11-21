import { formatCount } from "@/lib/format";
import type { TrendBucket } from "@/lib/types";

export function VolumeChart({
  series,
  heading,
  emptyLabel,
  footnote,
}: {
  series: TrendBucket[];
  heading: string;
  emptyLabel: string;
  footnote: string;
}) {
  const peak = series.reduce((max, bucket) => Math.max(max, bucket.totalEvents), 0);
  const hasEvents = peak > 0;
  const hasAnyGap = series.some((bucket) => bucket.hasCoverageGap);
  const showCounts = series.length > 0 && series.length <= 8;

  return (
    <section className="rounded border border-gray-200 bg-white">
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-gray-200 px-4 py-3">
        <h2 className="text-xs font-semibold uppercase tracking-wider text-gray-700">{heading}</h2>
        <div className="flex flex-wrap items-center gap-3 text-[11px]">
          {hasAnyGap ? (
            <span className="inline-flex items-center gap-1.5 rounded border border-amber-300 bg-amber-50 px-2 py-0.5 font-medium text-amber-900">
              <span aria-hidden="true" className="font-mono font-bold">
                [GAP]
              </span>
              Collection outage / degraded interval
            </span>
          ) : null}
          {hasEvents ? (
            <span className="font-mono tabular-nums text-gray-400">
              Peak: {formatCount(peak)}
            </span>
          ) : null}
        </div>
      </div>
      <div className="p-4">
        {series.length === 0 || (!hasEvents && !hasAnyGap) ? (
          <p className="text-xs text-gray-500">{emptyLabel}</p>
        ) : (
          <div className="overflow-x-auto">
            <ol
              className="flex h-56 min-w-full items-end gap-1"
              style={{ minWidth: `${series.length * 30}px` }}
            >
              {series.map((bucket) => {
                const height =
                  peak > 0
                    ? Math.max(
                        Math.round((bucket.totalEvents / peak) * 100),
                        bucket.totalEvents > 0 ? 4 : 0,
                      )
                    : 0;
                const gapText = bucket.hasCoverageGap
                  ? ` — collection gap (${(bucket.gapStatuses ?? ["offline"]).join(", ")}; not a measured zero)`
                  : "";
                return (
                  <li
                    key={bucket.bucketStart}
                    title={`${bucket.label}: ${formatCount(bucket.totalEvents)} events${gapText}`}
                    className={`flex min-w-6 flex-1 flex-col items-center gap-1 rounded-sm px-0.5 pt-1 ${
                      bucket.hasCoverageGap ? "bg-amber-50/80 ring-1 ring-inset ring-amber-300/80" : ""
                    }`}
                  >
                    <span className="sr-only">
                      {bucket.label}: {formatCount(bucket.totalEvents)} events{gapText}
                    </span>
                    {bucket.hasCoverageGap ? (
                      <span
                        aria-hidden="true"
                        className="rounded border border-amber-400 bg-amber-100 px-1 font-mono text-[9px] font-bold leading-tight text-amber-900"
                      >
                        GAP
                      </span>
                    ) : showCounts ? (
                      <span className="font-mono text-[11px] tabular-nums text-gray-700">
                        {formatCount(bucket.totalEvents)}
                      </span>
                    ) : null}
                    <div className="flex h-40 w-full items-end">
                      {bucket.totalEvents > 0 ? (
                        <div
                          className={`w-full rounded-t-sm ${
                            bucket.hasCoverageGap
                              ? "border border-dashed border-amber-600 bg-[#632ca6]/75"
                              : "bg-[#632ca6]"
                          }`}
                          style={{ height: `${height}%` }}
                        />
                      ) : bucket.hasCoverageGap ? (
                        <div
                          aria-hidden="true"
                          className="h-3 w-full rounded-t-sm border border-dashed border-amber-500 bg-amber-200/80"
                        />
                      ) : null}
                    </div>
                    <span translate="no" className="font-mono text-[10px] tabular-nums text-gray-500">
                      {bucket.label}
                    </span>
                  </li>
                );
              })}
            </ol>
          </div>
        )}
        <p className="mt-3 text-[11px] leading-relaxed text-gray-500">{footnote}</p>
      </div>
    </section>
  );
}
