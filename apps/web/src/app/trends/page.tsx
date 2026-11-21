import { MethodologyBanner } from "@/components/methodology-banner";
import { PROTOCOL_COLORS, ProtocolBadge } from "@/components/protocol-badge";
import { WorldGeoMap } from "@/components/world-geo-map";
import { formatCount } from "@/lib/format";
import { getTrendsData } from "@/lib/observatory";
import { buildWorldMapData } from "@/lib/world-map";

export const dynamic = "force-dynamic";

export default async function TrendsPage() {
  const data = await getTrendsData();
  const worldMapData = buildWorldMapData(data.regionTotals);
  const series = data.dailySeries.slice(-7);
  const maxDaily = Math.max(...series.map((d) => d.totalEvents), 1);
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
            Daily rollups and top breakdowns by protocol, destination port, region, and ASN
          </p>
        </div>
        <span
          translate="no"
          className="rounded border border-gray-200 bg-white px-2.5 py-1.5 font-mono text-xs text-gray-600"
        >
          Past 7d (UTC)
        </span>
      </div>

      <MethodologyBanner sourceMode={data.sourceMode} />

      {/* Daily Event Volume Chart */}
      <section className="rounded border border-gray-200 bg-white">
        <div className="flex items-center justify-between border-b border-gray-200 px-4 py-3">
          <h2 className="text-xs font-semibold uppercase tracking-wider text-gray-700">
            Daily Event Volume (UTC)
          </h2>
          <span className="font-mono text-[11px] tabular-nums text-gray-400">
            Peak: {formatCount(maxDaily)} events/day
          </span>
        </div>

        <div className="p-4">
          {series.length === 0 ? (
            <p className="text-xs text-gray-500">No daily rollup data available yet.</p>
          ) : (
            <div className="relative">
              {/* Subtle horizontal grid lines */}
              <div
                aria-hidden="true"
                className="pointer-events-none absolute inset-x-0 top-6 bottom-6 flex flex-col justify-between"
              >
                <div className="border-t border-dashed border-gray-200" />
                <div className="border-t border-dashed border-gray-200" />
                <div className="border-t border-dashed border-gray-200" />
                <div className="border-t border-gray-200" />
              </div>

              <div className="relative grid grid-cols-7 items-end gap-3 pt-1 sm:gap-5">
                {series.map((day) => {
                  const pct = Math.max(Math.round((day.totalEvents / maxDaily) * 100), 4);
                  return (
                    <div
                      key={day.dateUtc}
                      className="flex min-w-0 flex-col items-center gap-1.5"
                    >
                      <span className="font-mono text-[11px] font-medium tabular-nums text-gray-700">
                        {formatCount(day.totalEvents)}
                      </span>
                      <div className="flex h-44 w-full max-w-[52px] items-end">
                        <div
                          className="w-full rounded-t-sm bg-[#632ca6] transition-[height]"
                          style={{ height: `${pct}%` }}
                        />
                      </div>
                      <span
                        translate="no"
                        className="font-mono text-[11px] tabular-nums text-gray-500"
                      >
                        {day.dateUtc.slice(5)}
                      </span>
                    </div>
                  );
                })}
              </div>
            </div>
          )}
        </div>
      </section>

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
              Top Protocols (<span translate="no">daily_stats</span>)
            </h2>
          </div>
          <div className="space-y-1.5 p-4">
            {data.protocolTotals.map((item) => {
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
            })}
          </div>
        </section>

        <section className="rounded border border-gray-200 bg-white">
          <div className="border-b border-gray-200 px-4 py-3">
            <h2 className="text-xs font-semibold uppercase tracking-wider text-gray-700">
              Top Destination Ports
            </h2>
          </div>
          <div className="space-y-1.5 p-4">
            {data.portTotals.map((item) => {
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
            })}
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
            {data.regionTotals.map((item) => {
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
            })}
          </div>
        </section>

        <section className="rounded border border-gray-200 bg-white">
          <div className="border-b border-gray-200 px-4 py-3">
            <h2 className="text-xs font-semibold uppercase tracking-wider text-gray-700">
              Observed ASNs (Reference Only)
            </h2>
          </div>
          <div className="space-y-1.5 p-4">
            {data.asnTotals.map((item) => {
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
            })}
          </div>
        </section>
      </div>
    </div>
  );
}
