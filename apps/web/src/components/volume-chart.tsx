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
  const showCounts = series.length > 0 && series.length <= 8;

  return (
    <section className="rounded border border-gray-200 bg-white">
      <div className="flex items-center justify-between gap-3 border-b border-gray-200 px-4 py-3">
        <h2 className="text-xs font-semibold uppercase tracking-wider text-gray-700">{heading}</h2>
        {hasEvents ? (
          <span className="font-mono text-[11px] tabular-nums text-gray-400">
            Peak: {formatCount(peak)}
          </span>
        ) : null}
      </div>
      <div className="p-4">
        {series.length === 0 || !hasEvents ? (
          <p className="text-xs text-gray-500">{emptyLabel}</p>
        ) : (
          <div className="overflow-x-auto">
            <ol
              className="flex h-52 min-w-full items-end gap-1"
              style={{ minWidth: `${series.length * 28}px` }}
            >
              {series.map((bucket) => {
                const height = Math.max(Math.round((bucket.totalEvents / peak) * 100), bucket.totalEvents > 0 ? 4 : 0);
                return (
                  <li
                    key={bucket.bucketStart}
                    title={`${bucket.label}: ${formatCount(bucket.totalEvents)} events`}
                    className="flex min-w-6 flex-1 flex-col items-center gap-1"
                  >
                    <span className="sr-only">
                      {bucket.label}: {formatCount(bucket.totalEvents)} events
                    </span>
                    {showCounts ? (
                      <span className="font-mono text-[11px] tabular-nums text-gray-700">
                        {formatCount(bucket.totalEvents)}
                      </span>
                    ) : null}
                    <div className="flex h-40 w-full items-end">
                      <div
                        className="w-full rounded-t-sm bg-[#632ca6]"
                        style={{ height: `${height}%` }}
                      />
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
