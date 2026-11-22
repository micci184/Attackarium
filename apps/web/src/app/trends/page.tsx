import Link from "next/link";
import { MethodologyBanner } from "@/components/methodology-banner";
import { ObservationMeta } from "@/components/observation-meta";
import { PatternLists } from "@/components/pattern-lists";
import { PeriodNav } from "@/components/period-nav";
import { PROTOCOL_COLORS, ProtocolBadge } from "@/components/protocol-badge";
import { VolumeChart } from "@/components/volume-chart";
import { WorldGeoMap } from "@/components/world-geo-map";
import { seriesHasLeadingGap, parseTrendPeriod, trendPeriodLabel } from "@/lib/dashboard-metrics";
import { formatCount, formatJstDateTime } from "@/lib/format";
import { getTrendsData } from "@/lib/observatory";
import { buildWorldMapData } from "@/lib/world-map";

export const dynamic = "force-dynamic";

interface TrendsPageProps {
  searchParams: Promise<{ period?: string }>;
}

export default async function TrendsPage({ searchParams }: TrendsPageProps) {
  const params = await searchParams;
  const period = parseTrendPeriod(params.period);
  const data = await getTrendsData(period);
  const worldMapData = buildWorldMapData(data.regionTotals);
  const maxProto = Math.max(...data.protocolTotals.map((p) => p.count), 1);
  const maxPort = Math.max(...data.portTotals.map((p) => p.count), 1);
  const maxRegion = Math.max(...data.regionTotals.map((r) => r.count), 1);
  const maxAsn = Math.max(...data.asnTotals.map((a) => a.count), 1);

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="text-lg font-semibold tracking-tight text-gray-900">
            Trends
          </h1>
          <p className="mt-0.5 text-xs text-gray-500">
            Event volume for the selected window, plus protocol, pattern, and sanitized HTTP path trends
          </p>
          <div className="mt-2">
            <ObservationMeta
              windowLabel={trendPeriodLabel(period)}
              updatedAt={data.dataUpdatedAt}
              sensorCount={data.registeredSensorCount}
            />
          </div>
        </div>
        <PeriodNav period={period} />
      </div>

      <MethodologyBanner sourceMode={data.sourceMode} />

      {data.coverageGaps.length > 0 ? (
        <section
          aria-label="Collection gap notice"
          className="flex flex-wrap items-center justify-between gap-2 rounded border border-amber-300 bg-amber-50 px-4 py-2.5 text-xs text-amber-950"
        >
          <p className="min-w-0 flex-1 leading-relaxed">
            <span aria-hidden="true" className="mr-1.5 font-mono font-bold">
              [GAP]
            </span>
            <span className="font-semibold">Collection gap detected in this window:</span>{" "}
            {formatCount(data.coverageGaps.length)} outage/degraded interval(s) overlap the
            selected range. Marked buckets may undercount traffic and must not be read as zero
            activity.
          </p>
          <Link
            href="/sensors"
            className="shrink-0 rounded font-medium text-amber-950 underline hover:text-amber-800 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#632ca6]"
          >
            Inspect Sensors →
          </Link>
        </section>
      ) : null}

      <VolumeChart
        series={data.series}
        heading={period === "24h" ? "Hourly Event Volume (UTC)" : "Daily Event Volume (UTC)"}
        emptyLabel="No stored observations in this window."
        footnote={[
          seriesHasLeadingGap(data.series, data.historyStartedAt)
            ? `Early zero buckets precede the first stored observation (${formatJstDateTime(data.historyStartedAt)}). They indicate missing history, not a measured quiet period.`
            : null,
          data.aggregateComplete
            ? data.seriesSource === "event_aggregates"
              ? "Hourly totals are complete UTC-hour rollups. The bucket sum is the period total. The current hour is still open until the next rollup."
              : data.seriesSource === "daily_stats"
                ? "Daily totals come from every rollup row in the UTC window. The bucket sum is the period total. A zero day has no stored rollup."
                : "Totals are counted from stored events. A zero bucket has no stored observation."
            : "The aggregate read stopped early. Bucket totals are partial and are not an exact period count.",
          data.rollupPendingEvents > 0
            ? `${formatCount(data.rollupPendingEvents)} recent or unclassified events in this window are pending the next 15m rollup.`
            : null,
        ]
          .filter((line) => line !== null)
          .join(" ")}
      />

      <PatternLists
        patterns={data.patterns}
        cveContext={data.patternCveContext}
        httpPaths={data.httpPaths}
        sampledNote={
          data.isEventSampled
            ? data.seriesSource === "event_aggregates"
              ? "Ports, regions, and HTTP paths use the newest stored events in this window. Pattern totals use the full UTC-hour rollup."
              : "Path and pattern lists use the newest stored events in this window, not every row."
            : null
        }
      />

      <WorldGeoMap
        data={worldMapData}
        title="Geographic Distribution (GeoIP Estimate)"
        subtitle="Country/region-level heatmap across sampled events (hover or focus to inspect)"
      />

      {/* Datadog-style Top Lists (2x2 flat panels) */}
      <div className="grid gap-4 md:grid-cols-2">
        <section className="rounded border border-gray-200 bg-white">
          <div className="border-b border-gray-200 px-4 py-3">
            <h2 className="text-xs font-semibold uppercase tracking-wider text-gray-700">
              Protocols In This Window
            </h2>
          </div>
          <div className="space-y-1.5 p-4">
            {data.protocolTotals.length === 0 ? (
              <p className="text-xs text-gray-500">No protocol statistics recorded yet.</p>
            ) : (
              data.protocolTotals.map((item) => {
                const widthPct = Math.max(Math.round((item.count / maxProto) * 100), 3);
                return (
                  <div
                    key={item.protocol}
                    className="relative overflow-hidden rounded border border-gray-100 bg-gray-50/70 px-3 py-1.5"
                  >
                    <div
                      aria-hidden="true"
                      className="absolute inset-y-0 left-0 opacity-15"
                      style={{
                        width: `${widthPct}%`,
                        backgroundColor: PROTOCOL_COLORS[item.protocol],
                      }}
                    />
                    <div className="relative flex items-center justify-between text-xs">
                      <ProtocolBadge protocol={item.protocol} />
                      <span className="font-mono font-medium tabular-nums text-gray-900">
                        {formatCount(item.count)}
                      </span>
                    </div>
                  </div>
                );
              })
            )}
          </div>
        </section>

        <section className="rounded border border-gray-200 bg-white">
          <div className="border-b border-gray-200 px-4 py-3">
            <h2 className="text-xs font-semibold uppercase tracking-wider text-gray-700">
              Top Destination Ports
            </h2>
          </div>
          <div className="space-y-1.5 p-4">
            {data.portTotals.length === 0 ? (
              <p className="text-xs text-gray-500">No destination port data available yet.</p>
            ) : (
              data.portTotals.map((item) => {
                const widthPct = Math.max(Math.round((item.count / maxPort) * 100), 3);
                return (
                  <div
                    key={`${item.protocol}:${item.dstPort}`}
                    className="relative overflow-hidden rounded border border-gray-100 bg-gray-50/70 px-3 py-1.5"
                  >
                    <div
                      aria-hidden="true"
                      className="absolute inset-y-0 left-0 bg-[#632ca6]/10"
                      style={{ width: `${widthPct}%` }}
                    />
                    <div className="relative flex items-center justify-between text-xs">
                      <div className="flex items-center gap-2">
                        <ProtocolBadge protocol={item.protocol} />
                        <span
                          translate="no"
                          className="font-mono tabular-nums text-gray-700"
                        >
                          :{item.dstPort}
                        </span>
                      </div>
                      <span className="font-mono font-medium tabular-nums text-gray-900">
                        {formatCount(item.count)}
                      </span>
                    </div>
                  </div>
                );
              })
            )}
          </div>
        </section>

        <section className="rounded border border-gray-200 bg-white">
          <div className="border-b border-gray-200 px-4 py-3">
            <h2 className="text-xs font-semibold uppercase tracking-wider text-gray-700">
              Approx. Source Regions (GeoIP Estimate)
            </h2>
          </div>
          <div className="space-y-1.5 p-4">
            <p className="pb-1 text-[11px] text-gray-500">
              IP-based geolocation may be inaccurate due to proxies, VPNs, or cloud VPS hosts.
            </p>
            {data.regionTotals.length === 0 ? (
              <p className="text-xs text-gray-500">No regional data available yet.</p>
            ) : (
              data.regionTotals.map((item) => {
                const widthPct = Math.max(Math.round((item.count / maxRegion) * 100), 3);
                return (
                  <div
                    key={item.country}
                    className="relative overflow-hidden rounded border border-gray-100 bg-gray-50/70 px-3 py-1.5"
                  >
                    <div
                      aria-hidden="true"
                      className="absolute inset-y-0 left-0 bg-blue-600/10"
                      style={{ width: `${widthPct}%` }}
                    />
                    <div className="relative flex items-center justify-between text-xs">
                      <span translate="no" className="font-mono text-gray-700">
                        {item.country}
                      </span>
                      <span className="font-mono font-medium tabular-nums text-gray-900">
                        {formatCount(item.count)}
                      </span>
                    </div>
                  </div>
                );
              })
            )}
          </div>
        </section>

        <section className="rounded border border-gray-200 bg-white">
          <div className="border-b border-gray-200 px-4 py-3">
            <h2 className="text-xs font-semibold uppercase tracking-wider text-gray-700">
              Observed ASNs (Reference Only)
            </h2>
          </div>
          <div className="space-y-1.5 p-4">
            {data.asnTotals.length === 0 ? (
              <p className="text-xs text-gray-500">No ASN observations recorded yet.</p>
            ) : (
              data.asnTotals.map((item) => {
                const widthPct = Math.max(Math.round((item.count / maxAsn) * 100), 3);
                return (
                  <div
                    key={item.asn}
                    className="relative overflow-hidden rounded border border-gray-100 bg-gray-50/70 px-3 py-1.5"
                  >
                    <div
                      aria-hidden="true"
                      className="absolute inset-y-0 left-0 bg-teal-600/10"
                      style={{ width: `${widthPct}%` }}
                    />
                    <div className="relative flex items-center justify-between text-xs">
                      <span translate="no" className="font-mono text-gray-700">
                        {item.asn}
                      </span>
                      <span className="font-mono font-medium tabular-nums text-gray-900">
                        {formatCount(item.count)}
                      </span>
                    </div>
                  </div>
                );
              })
            )}
          </div>
        </section>
      </div>
    </div>
  );
}
