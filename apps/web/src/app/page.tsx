import Link from "next/link";
import { AutoRefresh } from "@/components/auto-refresh";
import { MethodologyBanner } from "@/components/methodology-banner";
import { ObservationMeta } from "@/components/observation-meta";
import { PatternLists } from "@/components/pattern-lists";
import { PROTOCOL_COLORS, ProtocolBadge } from "@/components/protocol-badge";
import { VolumeChart } from "@/components/volume-chart";
import { WorldGeoMap } from "@/components/world-geo-map";
import { formatCount, formatJstShort, safeDisplayText } from "@/lib/format";
import { getOverviewData } from "@/lib/observatory";
import { buildWorldMapData } from "@/lib/world-map";

function formatPriorWindow(current: number, prior: number): string {
  const delta = current - prior;
  const signed = `${delta > 0 ? "+" : ""}${formatCount(delta)}`;
  if (prior < 10) {
    return `${signed} vs the previous 24 UTC hours`;
  }
  const pct = Math.round((delta / prior) * 1000) / 10;
  return `${signed} (${pct > 0 ? "+" : ""}${pct.toFixed(1)}%) vs the previous 24 UTC hours`;
}

export const dynamic = "force-dynamic";

export default async function OverviewPage() {
  const data = await getOverviewData();
  const worldMapData = buildWorldMapData(data.regionTotals24h);

  const sensorBadge =
    data.activeSensorCount === 0
      ? { label: "Offline", textClass: "text-gray-600", dotClass: "bg-gray-400" }
      : data.healthySensorCount === data.activeSensorCount
        ? { label: "Healthy", textClass: "text-emerald-700", dotClass: "bg-emerald-600" }
        : data.healthySensorCount > 0
          ? { label: "Degraded", textClass: "text-amber-700", dotClass: "bg-amber-500" }
          : { label: "Heartbeat Stale", textClass: "text-red-700", dotClass: "bg-red-600" };

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="min-w-0">
          <h1 className="text-lg font-semibold tracking-tight text-gray-900">
            Overview
          </h1>
          <p className="mt-0.5 text-xs text-gray-500">
            24-hour observation summary, sensor health, and recent sanitized events
          </p>
          <div className="mt-2">
            <ObservationMeta
              windowLabel="24 UTC hours, timestamps in JST"
              updatedAt={data.dataUpdatedAt}
              sensorCount={data.sensors.length}
            />
          </div>
        </div>
        <div className="flex items-center gap-2">
          <span
            translate="no"
            className="rounded border border-gray-200 bg-white px-2.5 py-1.5 font-mono text-xs text-gray-600"
          >
            Past 24h
          </span>
          <AutoRefresh intervalSeconds={30} />
        </div>
      </div>

      <MethodologyBanner sourceMode={data.sourceMode} />

      <section
        aria-label="24 hour activity"
        className="grid gap-px overflow-hidden rounded border border-gray-200 bg-gray-200 sm:grid-cols-2"
      >
        <div className="bg-white p-4">
          <p className="text-[11px] font-semibold uppercase tracking-wider text-gray-500">
            Events (24 UTC hours)
          </p>
          <p className="mt-1.5 font-mono text-2xl font-semibold tabular-nums text-gray-900">
            {formatCount(data.totalEvents24h)}
          </p>
          <p className="mt-1 text-[11px] text-gray-500">{formatPriorWindow(data.totalEvents24h, data.priorEvents24h)}</p>
          {data.sourceMode === "supabase" ? (
            <p className="mt-1 text-[11px] text-gray-400">UTC hour buckets, including the current hour</p>
          ) : null}
          {data.rollupPendingEvents24h > 0 ? (
            <p className="mt-1 text-[11px] text-gray-500">
              +{formatCount(data.rollupPendingEvents24h)} recent or unclassified events pending next 15m rollup
            </p>
          ) : null}
          {data.aggregateComplete ? null : (
            <p className="mt-1 inline-flex items-center gap-1 rounded border border-amber-300 bg-amber-50 px-1.5 py-0.5 text-[10px] font-medium text-amber-900">
              Aggregate read is incomplete. This total is partial, not an exact count.
            </p>
          )}
          {data.coverageGapIn24h || data.coverageGapInPrior24h ? (
            <p className="mt-1 inline-flex items-center gap-1 rounded border border-amber-300 bg-amber-50 px-1.5 py-0.5 text-[10px] font-medium text-amber-900">
              <span aria-hidden="true" className="font-mono font-bold">
                [GAP]
              </span>
              Collection gap in window — comparison may undercount
            </p>
          ) : null}
        </div>

        <div className="bg-white p-4">
          <p className="text-[11px] font-semibold uppercase tracking-wider text-gray-500">
            Observation status
          </p>
          <div className="mt-1.5 flex items-baseline gap-2">
            <p className="font-mono text-2xl font-semibold tabular-nums text-gray-900">
              {formatCount(data.healthySensorCount)}
            </p>
            <span
              className={`inline-flex items-center gap-1 text-xs font-medium ${sensorBadge.textClass}`}
            >
              <span
                aria-hidden="true"
                className={`h-1.5 w-1.5 rounded-full ${sensorBadge.dotClass}`}
              />
              {sensorBadge.label}
            </span>
          </div>
          <p className="mt-1 text-[11px] text-gray-400">
            {formatCount(data.activeSensorCount)} active / {formatCount(data.sensors.length)} registered
            {data.activeOutages.length > 0 ? ` · ${formatCount(data.activeOutages.length)} open coverage gap` : ""}
          </p>
        </div>
      </section>

      <section aria-label="Noteworthy observations" className="rounded border border-gray-200 bg-white">
        <div className="border-b border-gray-200 px-4 py-3">
          <h2 className="text-xs font-semibold uppercase tracking-wider text-gray-700">
            Noteworthy observations
          </h2>
        </div>
        {data.noteworthy.length === 0 ? (
          <p className="px-4 py-6 text-xs text-gray-500">
            No noteworthy changes in this 24 UTC hour comparison.
          </p>
        ) : (
          <ol className="divide-y divide-gray-100">
            {data.noteworthy.map((note) => (
              <li key={note.id} className="px-4 py-3">
                <div className="flex flex-wrap items-baseline justify-between gap-2">
                  <Link
                    href={note.href}
                    className="rounded text-sm font-medium text-gray-900 hover:text-[#632ca6] hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#632ca6]"
                  >
                    {note.title}
                  </Link>
                  <ProtocolBadge protocol={note.protocol} />
                </div>
                <p className="mt-1 text-xs text-gray-600">{note.detail}</p>
                {note.showPercent ? (
                  <p className="mt-1 font-mono text-[11px] tabular-nums text-gray-500">
                    {note.priorCount > 0
                      ? `${(((note.delta / note.priorCount) * 100).toFixed(0))}% vs the previous 24 UTC hours`
                      : null}
                  </p>
                ) : (
                  <p className="mt-1 text-[11px] text-gray-500">
                    Absolute change only. The previous window is too small for a percentage.
                  </p>
                )}
                {note.comparisonReliable ? null : (
                  <p className="mt-1 text-[11px] text-amber-800">
                    A coverage gap, incomplete rollup, or pending events makes this comparison less reliable.
                  </p>
                )}
              </li>
            ))}
          </ol>
        )}
      </section>

      <VolumeChart
        series={data.hourlySeries}
        heading="Activity trend (24 UTC hours)"
        emptyLabel="No stored observations in this window."
        footnote="7-day and 30-day series are on Trends. Counts are UTC hour buckets; timestamps elsewhere are JST."
      />

      <div className="grid gap-4 lg:grid-cols-2">
        {/* Protocol Distribution */}
        <section className="rounded border border-gray-200 bg-white">
          <div className="flex items-center justify-between border-b border-gray-200 px-4 py-3">
            <h2 className="text-xs font-semibold uppercase tracking-wider text-gray-700">
              Protocol Distribution (24h UTC)
            </h2>
            <Link
              href="/trends"
              className="rounded text-xs font-medium text-[#632ca6] transition-colors hover:text-[#4e2185] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#632ca6]"
            >
              View Trends →
            </Link>
          </div>
          <div className="p-4">
            {data.protocolBreakdown.length === 0 ? (
              <p className="text-xs text-gray-500">No observations recorded yet.</p>
            ) : (
              <>
                {/* Stacked horizontal bar */}
                <div
                  aria-label="Protocol share bar"
                  className="flex h-2.5 w-full overflow-hidden rounded-sm bg-gray-100"
                >
                  {data.protocolBreakdown.map((item) => (
                    <div
                      key={item.protocol}
                      title={`${item.protocol.toUpperCase()}: ${item.count} (${item.sharePct}%)`}
                      style={{
                        width: `${Math.max(item.sharePct, 1)}%`,
                        backgroundColor: PROTOCOL_COLORS[item.protocol],
                      }}
                    />
                  ))}
                </div>

                <div className="mt-4 divide-y divide-gray-100">
                  {data.protocolBreakdown.map((item) => (
                    <div
                      key={item.protocol}
                      className="flex items-center justify-between py-2 text-xs"
                    >
                      <ProtocolBadge protocol={item.protocol} />
                      <div className="flex items-center gap-4 font-mono tabular-nums">
                        <span className="text-gray-900">
                          {formatCount(item.count)}
                        </span>
                        <span className="w-12 text-right text-gray-500">
                          {item.sharePct.toFixed(1)}%
                        </span>
                      </div>
                    </div>
                  ))}
                </div>
              </>
            )}
          </div>
        </section>

        {/* Sensor Health */}
        <section className="rounded border border-gray-200 bg-white">
          <div className="flex items-center justify-between border-b border-gray-200 px-4 py-3">
            <h2 className="text-xs font-semibold uppercase tracking-wider text-gray-700">
              Sensor Health
            </h2>
            <Link
              href="/sensors"
              className="rounded text-xs font-medium text-[#632ca6] transition-colors hover:text-[#4e2185] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#632ca6]"
            >
              Open Sensors →
            </Link>
          </div>
          <div className="divide-y divide-gray-100 p-4">
            {data.sensors.length === 0 ? (
              <p className="text-xs text-gray-500">No registered sensors.</p>
            ) : (
              data.sensors.map((sensor) => (
                <div key={sensor.id} className="space-y-2 py-1">
                  <div className="flex items-center justify-between gap-2">
                    <div className="min-w-0">
                      <p className="truncate text-sm font-medium text-gray-900">
                        {safeDisplayText(sensor.name)}
                      </p>
                      <p translate="no" className="font-mono text-[11px] text-gray-500">
                        {safeDisplayText(sensor.id)} · {safeDisplayText(sensor.region)}
                      </p>
                    </div>
                    <span
                      translate="no"
                      className={`inline-flex shrink-0 items-center gap-1.5 rounded border px-2 py-0.5 text-[11px] font-medium ${
                        sensor.healthStatus === "healthy"
                          ? "border-emerald-200 bg-emerald-50 text-emerald-700"
                          : sensor.healthStatus === "stale"
                            ? "border-amber-200 bg-amber-50 text-amber-800"
                            : "border-gray-200 bg-gray-100 text-gray-600"
                      }`}
                    >
                      <span
                        aria-hidden="true"
                        className={`h-1.5 w-1.5 rounded-full ${
                          sensor.healthStatus === "healthy"
                            ? "bg-emerald-600"
                            : sensor.healthStatus === "stale"
                              ? "bg-amber-500"
                              : "bg-gray-400"
                        }`}
                      />
                      {sensor.healthStatus === "healthy"
                        ? "Healthy"
                        : sensor.healthStatus === "stale"
                          ? "Stale Heartbeat"
                          : "Inactive"}
                    </span>
                  </div>

                  <dl className="grid grid-cols-3 gap-2 rounded border border-gray-100 bg-gray-50 px-3 py-2 text-[11px]">
                    <div>
                      <dt className="text-gray-400">Type</dt>
                      <dd translate="no" className="mt-0.5 font-mono text-gray-700">
                        {sensor.type}
                      </dd>
                    </div>
                    <div>
                      <dt className="text-gray-400">Heartbeat</dt>
                      <dd className="mt-0.5 font-mono tabular-nums text-gray-700">
                        {formatJstShort(sensor.last_heartbeat_at)}
                      </dd>
                    </div>
                    <div>
                      <dt className="text-gray-400">Last Event</dt>
                      <dd className="mt-0.5 font-mono tabular-nums text-gray-700">
                        {formatJstShort(sensor.last_event_at)}
                      </dd>
                    </div>
                  </dl>
                </div>
              ))
            )}
          </div>
        </section>
      </div>

      <PatternLists
        patterns={data.patterns24h}
        httpPaths={data.httpPaths24h}
        sampledNote={
          data.is24hBreakdownSampled
            ? `HTTP paths and the region map use the latest ${formatCount(data.sampled24hCount)} events. Protocol and pattern totals use the full UTC-hour rollup.`
            : null
        }
      />

      {/* Recent Sanitized Events */}
      <section className="rounded border border-gray-200 bg-white">
        <div className="flex items-center justify-between border-b border-gray-200 px-4 py-3">
          <h2 className="text-xs font-semibold uppercase tracking-wider text-gray-700">
            Recent Sanitized Events
          </h2>
          <Link
            href="/events"
            className="rounded text-xs font-medium text-[#632ca6] transition-colors hover:text-[#4e2185] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#632ca6]"
          >
            Open Event Explorer →
          </Link>
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
                <th className="px-4 py-2">Sanitized Path / Detail</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-100">
              {data.recentEvents.length === 0 ? (
                <tr>
                  <td colSpan={6} className="px-4 py-8 text-center text-gray-500">
                    No observations recorded yet.
                  </td>
                </tr>
              ) : (
                data.recentEvents.map((ev) => (
                  <tr key={ev.id} className="transition-colors hover:bg-gray-50">
                    <td className="whitespace-nowrap px-4 py-2 font-mono tabular-nums text-gray-600">
                      {formatJstShort(ev.observed_at)}
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
                    <td className="max-w-xs truncate px-4 py-2 font-mono">
                      <Link
                        href={`/events/${ev.id}`}
                        translate="no"
                        className="rounded text-[#632ca6] transition-colors hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#632ca6]"
                      >
                        {ev.http_method ? `${ev.http_method} ` : ""}
                        {safeDisplayText(ev.http_path_redacted, ev.fingerprint ?? "Inspect")}
                      </Link>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </section>

      <WorldGeoMap
        data={worldMapData}
        title="Observed Source Regions (24h · GeoIP Estimate)"
        subtitle={
          data.is24hBreakdownSampled
            ? `Secondary view from the latest ${formatCount(data.sampled24hCount)} sampled events (raw IPs excluded)`
            : "Secondary country/region view. Raw IPs and exact locations are excluded."
        }
      />
    </div>
  );
}
