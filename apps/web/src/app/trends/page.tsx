import Link from "next/link";
import { MethodologyBanner } from "@/components/methodology-banner";
import { ObservationMeta } from "@/components/observation-meta";
import { PatternLists } from "@/components/pattern-lists";
import { PeriodNav } from "@/components/period-nav";
import { PROTOCOL_COLORS, ProtocolBadge } from "@/components/protocol-badge";
import { Callout, PageHeader, Panel, PanelHeader } from "@/components/ui";
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

  const knownRegions = data.regionTotals.filter((r) => r.country !== "UNKNOWN");
  const knownAsns = data.asnTotals.filter((a) => a.asn !== "UNKNOWN");
  const hasGeoData = worldMapData.totalMapped > 0;
  const hasAsnData = knownAsns.length > 0;

  const maxProto = Math.max(...data.protocolTotals.map((p) => p.count), 1);
  const maxPort = Math.max(...data.portTotals.map((p) => p.count), 1);
  const maxRegion = Math.max(...knownRegions.map((r) => r.count), 1);
  const maxAsn = Math.max(...knownAsns.map((a) => a.count), 1);

  return (
    <div className="space-y-5">
      <PageHeader
        title="Trends"
        description="Event volume over time, protocol distribution, and observed probe patterns"
        meta={
          <ObservationMeta
            windowLabel={`${trendPeriodLabel(period)} (UTC buckets, timestamps in JST)`}
            updatedAt={data.dataUpdatedAt}
            sensorCount={data.registeredSensorCount}
          />
        }
        actions={<PeriodNav period={period} />}
      />

      <MethodologyBanner sourceMode={data.sourceMode} sensorCount={data.registeredSensorCount} />

      {data.coverageGaps.length > 0 ? (
        <Callout
          tone="warning"
          ariaLabel="Collection gap notice"
          action={
            <Link
              href="/sensors"
              className="rounded font-medium text-amber-950 underline hover:text-amber-800 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#632ca6]"
            >
              Inspect Coverage →
            </Link>
          }
        >
          <span className="font-semibold">Collection gap detected in this window:</span>{" "}
          {formatCount(data.coverageGaps.length)} outage or degraded interval(s) overlap the selected
          range. Shaded buckets may undercount traffic and must not be read as zero activity.
        </Callout>
      ) : null}

      {/* 1. Event volume over time */}
      <VolumeChart
        series={data.series}
        heading={period === "24h" ? "Hourly Event Volume (UTC)" : "Daily Event Volume (UTC)"}
        emptyLabel="No stored observations in this window."
        footnote={[
          seriesHasLeadingGap(data.series, data.historyStartedAt)
            ? `Dashed buckets before ${formatJstDateTime(data.historyStartedAt)} precede the start of observation and represent missing history, not measured zero-event periods.`
            : null,
          data.aggregateComplete
            ? data.seriesSource === "event_aggregates"
              ? "Hourly totals use complete UTC-hour rollups. The current hour remains open until the next rollup."
              : data.seriesSource === "daily_stats"
                ? "Daily totals use complete UTC-day rollups. Unshaded zero days had no stored events."
                : "Totals are counted from stored events."
            : "The aggregate read stopped early; bucket totals are partial.",
          data.rollupPendingEvents > 0
            ? `${formatCount(data.rollupPendingEvents)} recent or unclassified events are pending the next 15m rollup.`
            : null,
        ]
          .filter((line) => line !== null)
          .join(" ")}
      />

      {/* 2. Protocol distribution & destination ports */}
      <div className="grid gap-4 md:grid-cols-2">
        <Panel>
          <PanelHeader title="Protocol Distribution" />
          <div className="space-y-1.5 p-4">
            {data.protocolTotals.length === 0 ? (
              <p className="text-xs text-slate-500">No protocol statistics recorded yet.</p>
            ) : (
              data.protocolTotals.map((item) => {
                const widthPct = Math.max(Math.round((item.count / maxProto) * 100), 3);
                return (
                  <div
                    key={item.protocol}
                    className="relative overflow-hidden rounded-md border border-slate-200/70 bg-slate-50/70 px-3 py-2"
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
                      <Link
                        href={`/events?protocol=${item.protocol}&period=${period}`}
                        className="rounded hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#632ca6]"
                      >
                        <ProtocolBadge protocol={item.protocol} />
                      </Link>
                      <span className="font-mono font-medium tabular-nums text-slate-900">
                        {formatCount(item.count)}
                      </span>
                    </div>
                  </div>
                );
              })
            )}
          </div>
        </Panel>

        <Panel>
          <PanelHeader title="Top Destination Ports" />
          <div className="space-y-1.5 p-4">
            {data.portTotals.length === 0 ? (
              <p className="text-xs text-slate-500">No destination port data available yet.</p>
            ) : (
              data.portTotals.map((item) => {
                const widthPct = Math.max(Math.round((item.count / maxPort) * 100), 3);
                return (
                  <div
                    key={`${item.protocol}:${item.dstPort}`}
                    className="relative overflow-hidden rounded-md border border-slate-200/70 bg-slate-50/70 px-3 py-2"
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
                          className="font-mono font-medium tabular-nums text-slate-700"
                        >
                          :{item.dstPort}
                        </span>
                      </div>
                      <span className="font-mono font-medium tabular-nums text-slate-900">
                        {formatCount(item.count)}
                      </span>
                    </div>
                  </div>
                );
              })
            )}
          </div>
        </Panel>
      </div>

      {/* 3. Observed categories & HTTP probe paths */}
      <PatternLists
        patterns={data.patterns}
        cveContext={data.patternCveContext}
        httpPaths={data.httpPaths}
        sampledNote={
          data.isEventSampled
            ? data.seriesSource === "event_aggregates"
              ? "Destination ports and HTTP paths use the newest stored events in this window. Category totals use the full UTC-hour rollup."
              : "Path and port lists use the newest stored events in this window, not every row."
            : null
        }
      />

      {/* GeoIP & ASN section — shown in full when enrichment data is present, compact note otherwise */}
      {hasGeoData || hasAsnData ? (
        <>
          {hasGeoData ? (
            <WorldGeoMap
              data={worldMapData}
              title="Geographic Distribution (GeoIP Estimate)"
              subtitle="Country/region-level heatmap across sampled events (hover or focus to inspect)"
            />
          ) : null}

          <div className="grid gap-4 md:grid-cols-2">
            {hasGeoData ? (
              <Panel>
                <PanelHeader
                  title="Approx. Source Regions (GeoIP Estimate)"
                  subtitle="IP geolocation is approximate (proxies, VPNs, or VPS hosts)"
                />
                <div className="space-y-1.5 p-4">
                  {knownRegions.map((item) => {
                    const widthPct = Math.max(Math.round((item.count / maxRegion) * 100), 3);
                    return (
                      <div
                        key={item.country}
                        className="relative overflow-hidden rounded-md border border-slate-200/70 bg-slate-50/70 px-3 py-2"
                      >
                        <div
                          aria-hidden="true"
                          className="absolute inset-y-0 left-0 bg-blue-600/10"
                          style={{ width: `${widthPct}%` }}
                        />
                        <div className="relative flex items-center justify-between text-xs">
                          <span translate="no" className="font-mono font-medium text-slate-700">
                            {item.country}
                          </span>
                          <span className="font-mono font-medium tabular-nums text-slate-900">
                            {formatCount(item.count)}
                          </span>
                        </div>
                      </div>
                    );
                  })}
                </div>
              </Panel>
            ) : null}

            {hasAsnData ? (
              <Panel>
                <PanelHeader title="Observed ASNs (Reference Only)" />
                <div className="space-y-1.5 p-4">
                  {knownAsns.map((item) => {
                    const widthPct = Math.max(Math.round((item.count / maxAsn) * 100), 3);
                    return (
                      <div
                        key={item.asn}
                        className="relative overflow-hidden rounded-md border border-slate-200/70 bg-slate-50/70 px-3 py-2"
                      >
                        <div
                          aria-hidden="true"
                          className="absolute inset-y-0 left-0 bg-teal-600/10"
                          style={{ width: `${widthPct}%` }}
                        />
                        <div className="relative flex items-center justify-between text-xs">
                          <span translate="no" className="font-mono font-medium text-slate-700">
                            {item.asn}
                          </span>
                          <span className="font-mono font-medium tabular-nums text-slate-900">
                            {formatCount(item.count)}
                          </span>
                        </div>
                      </div>
                    );
                  })}
                </div>
              </Panel>
            ) : null}
          </div>
        </>
      ) : (
        <p className="rounded-lg border border-slate-200 bg-white px-4 py-3 text-xs text-slate-500">
          <span className="font-medium text-slate-700">Region &amp; ASN breakdown:</span>{" "}
          GeoIP and ASN enrichment is not enabled for this sensor in Phase 1; source IPs are hashed
          and excluded from public views.
        </p>
      )}
    </div>
  );
}
