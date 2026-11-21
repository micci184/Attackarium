import Link from "next/link";
import { AutoRefresh } from "@/components/auto-refresh";
import { MethodologyBanner } from "@/components/methodology-banner";
import { PROTOCOL_COLORS, ProtocolBadge } from "@/components/protocol-badge";
import { WorldGeoMap } from "@/components/world-geo-map";
import { formatCount, formatJstShort, safeDisplayText } from "@/lib/format";
import { getOverviewData } from "@/lib/observatory";
import { buildWorldMapData } from "@/lib/world-map";

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

      {/* Datadog-style flat KPI strip */}
      <section
        aria-label="Key metrics"
        className="grid grid-cols-2 divide-y divide-gray-200 rounded border border-gray-200 bg-white sm:grid-cols-4 sm:divide-x sm:divide-y-0"
      >
        <div className="p-4">
          <p className="text-[11px] font-semibold uppercase tracking-wider text-gray-500">
            Events (24h)
          </p>
          <p className="mt-1.5 font-mono text-2xl font-semibold tabular-nums text-gray-900">
            {formatCount(data.totalEvents24h)}
          </p>
          <p className="mt-1 text-[11px] text-gray-400">Sanitized public records</p>
        </div>

        <div className="p-4">
          <p className="text-[11px] font-semibold uppercase tracking-wider text-gray-500">
            Healthy Sensors
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
          </p>
        </div>

        <div className="p-4">
          <p className="text-[11px] font-semibold uppercase tracking-wider text-gray-500">
            Protocols Seen
          </p>
          <p className="mt-1.5 font-mono text-2xl font-semibold tabular-nums text-gray-900">
            {formatCount(data.protocolBreakdown.length)}
          </p>
          <p className="mt-1 text-[11px] text-gray-400">OpenCanary + HTTP</p>
        </div>

        <div className="p-4">
          <p className="text-[11px] font-semibold uppercase tracking-wider text-gray-500">
            Approx. Regions
          </p>
          <p className="mt-1.5 font-mono text-2xl font-semibold tabular-nums text-gray-900">
            {formatCount(data.uniqueCountries24h)}
          </p>
          <p className="mt-1 text-[11px] text-gray-400">GeoIP estimate only</p>
        </div>
      </section>

      <WorldGeoMap
        data={worldMapData}
        title="Observed Source Regions (24h · GeoIP Estimate)"
        subtitle={
          data.is24hBreakdownSampled
            ? `Country/region heatmap based on the latest ${formatCount(data.sampled24hCount)} of ${formatCount(data.totalEvents24h)} events (raw IPs excluded)`
            : "Country/region-level heatmap for the past 24 hours (raw IPs and exact locations are excluded)"
        }
      />

      <div className="grid gap-4 lg:grid-cols-2">
        {/* Protocol Distribution */}
        <section className="rounded border border-gray-200 bg-white">
          <div className="flex items-center justify-between border-b border-gray-200 px-4 py-3">
            <h2 className="text-xs font-semibold uppercase tracking-wider text-gray-700">
              Protocol Distribution (24h)
              {data.is24hBreakdownSampled ? (
                <span className="ml-1.5 font-normal normal-case text-gray-400">
                  (latest {formatCount(data.sampled24hCount)} sampled)
                </span>
              ) : null}
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
            <span className="text-[11px] text-gray-400">Heartbeat &amp; Last Seen</span>
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
    </div>
  );
}
