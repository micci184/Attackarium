import { Panel, PanelHeader } from "@/components/ui";
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
  let peak = 0;
  let total = 0;
  let hasAnyGap = false;
  for (const bucket of series) {
    if (bucket.totalEvents > peak) peak = bucket.totalEvents;
    total += bucket.totalEvents;
    if (bucket.hasCoverageGap) hasAnyGap = true;
  }
  const hasEvents = peak > 0;
  const showCounts = series.length > 0 && series.length <= 8;

  return (
    <Panel>
      <PanelHeader
        title={heading}
        action={
          <div className="flex flex-wrap items-center gap-2.5 text-[11px]">
            {hasAnyGap ? (
              <span className="inline-flex items-center gap-1.5 rounded-md border border-amber-300 bg-amber-50 px-2 py-0.5 font-medium text-amber-900">
                <span aria-hidden="true" className="font-mono font-bold">
                  [GAP]
                </span>
                Collection outage / degraded interval
              </span>
            ) : null}
            {hasEvents ? (
              <div className="flex items-center gap-3 font-mono tabular-nums text-slate-600">
                <span>
                  Total: <strong className="font-semibold text-slate-900">{formatCount(total)}</strong>
                </span>
                <span className="text-slate-300" aria-hidden="true">
                  |
                </span>
                <span>
                  Peak: <strong className="font-semibold text-slate-900">{formatCount(peak)}</strong>
                </span>
              </div>
            ) : null}
          </div>
        }
      />

      <div className="p-4">
        {series.length === 0 || (!hasEvents && !hasAnyGap) ? (
          <p className="py-4 text-xs text-slate-500">{emptyLabel}</p>
        ) : (
          <div className="overflow-x-auto pb-1">
            <div className="relative" style={{ minWidth: `${Math.max(series.length * 32, 320)}px` }}>
              {/* Subtle horizontal reference lines */}
              <div
                aria-hidden="true"
                className="pointer-events-none absolute inset-x-0 top-6 bottom-6 flex flex-col justify-between"
              >
                <div className="border-t border-dashed border-slate-200/80" />
                <div className="border-t border-dashed border-slate-200/80" />
                <div className="border-t border-slate-200" />
              </div>

              <ol className="relative flex h-56 min-w-full items-end gap-1">
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
                      className={`group flex min-w-6 flex-1 flex-col items-center gap-1 rounded-sm px-0.5 pt-1 transition-colors hover:bg-slate-100/70 ${
                        bucket.hasCoverageGap
                          ? "bg-amber-50/80 ring-1 ring-inset ring-amber-300/80"
                          : ""
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
                        <span className="font-mono text-[11px] font-medium tabular-nums text-slate-700">
                          {formatCount(bucket.totalEvents)}
                        </span>
                      ) : (
                        <span className="h-3.5" aria-hidden="true" />
                      )}
                      <div className="flex h-40 w-full items-end">
                        {bucket.totalEvents > 0 ? (
                          <div
                            className={`w-full rounded-t-sm transition-colors ${
                              bucket.hasCoverageGap
                                ? "border border-dashed border-amber-600 bg-[#632ca6]/75 group-hover:bg-[#632ca6]/90"
                                : "bg-[#632ca6] group-hover:bg-[#4e2185]"
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
                      <span
                        translate="no"
                        className="font-mono text-[10px] tabular-nums text-slate-500"
                      >
                        {bucket.label}
                      </span>
                    </li>
                  );
                })}
              </ol>
            </div>
          </div>
        )}
        <p className="mt-3 text-[11px] leading-relaxed text-slate-500">{footnote}</p>
      </div>
    </Panel>
  );
}
