import Link from "next/link";
import { AutoRefresh } from "@/components/auto-refresh";
import { MethodologyBanner } from "@/components/methodology-banner";
import { ObservationMeta } from "@/components/observation-meta";
import { PatternLists } from "@/components/pattern-lists";
import { PROTOCOL_COLORS, ProtocolBadge } from "@/components/protocol-badge";
import { PageHeader, Panel, PanelHeader } from "@/components/ui";
import { VolumeChart } from "@/components/volume-chart";
import { WorldGeoMap } from "@/components/world-geo-map";
import {
  formatCount,
  formatJstShort,
  safeDisplayHttpPath,
  safeDisplayText,
} from "@/lib/format";
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
      ? {
          label: "Offline",
          textClass: "text-slate-600",
          dotClass: "bg-slate-400",
        }
      : data.healthySensorCount === data.activeSensorCount
        ? {
            label: "Healthy",
            textClass: "text-emerald-700",
            dotClass: "bg-emerald-600",
          }
        : data.healthySensorCount > 0
          ? {
              label: "Degraded",
              textClass: "text-amber-700",
              dotClass: "bg-amber-500",
            }
          : {
              label: "Heartbeat stale",
              textClass: "text-red-700",
              dotClass: "bg-red-600",
            };

  return (
    <div className="space-y-5">
      <PageHeader
        title="Overview"
        description="24-hour observation summary, sensor health, and recent sanitized events"
        meta={
          <ObservationMeta
            windowLabel="24 UTC hours, timestamps in JST"
            updatedAt={data.dataUpdatedAt}
            sensorCount={data.sensors.length}
          />
        }
        actions={
          <>
            <span
              translate="no"
              className="rounded-lg border border-slate-200 bg-white px-3 py-1.5 font-mono text-xs font-medium text-slate-700 shadow-[0_1px_2px_rgba(15,23,42,0.03)]"
            >
              Past 24h
            </span>
            <AutoRefresh intervalSeconds={30} />
          </>
        }
      />

      <MethodologyBanner sourceMode={data.sourceMode} />

      {/* Top KPI Strip */}
      <section
        aria-label="Observation status and 24 hour activity"
        className="grid gap-4 sm:grid-cols-2"
      >
        <Panel className="p-5">
          <div className="flex items-center justify-between gap-2">
            <p className="text-xs font-medium text-slate-500">
              Observation status
            </p>
            <span
              className={`inline-flex items-center gap-1.5 text-xs font-medium ${sensorBadge.textClass}`}
            >
              <span
                aria-hidden="true"
                className={`h-2 w-2 rounded-full ${sensorBadge.dotClass}`}
              />
              {sensorBadge.label}
            </span>
          </div>
          <div className="mt-2 flex items-baseline gap-2">
            <p className="font-mono text-3xl font-semibold tracking-tight tabular-nums text-slate-900">
              {formatCount(data.healthySensorCount)}
            </p>
            <span className="text-xs text-slate-500">
              healthy of {formatCount(data.activeSensorCount)} active
            </span>
          </div>
          <p className="mt-2 text-xs text-slate-500">
            {formatCount(data.sensors.length)} registered sensor
            {data.sensors.length === 1 ? "" : "s"}
            {data.activeOutages.length > 0
              ? ` · ${formatCount(data.activeOutages.length)} open coverage gap`
              : " · no open coverage gaps"}
          </p>
        </Panel>

        <Panel className="p-5">
          <div className="flex items-center justify-between gap-2">
            <p className="text-xs font-medium text-slate-500">
              Events (24 UTC hours)
            </p>
            {data.sourceMode === "supabase" ? (
              <span className="text-xs text-slate-500">UTC hourly rollups</span>
            ) : null}
          </div>
          <p className="mt-2 font-mono text-3xl font-semibold tracking-tight tabular-nums text-slate-900">
            {formatCount(data.totalEvents24h)}
          </p>
          <p className="mt-2 text-xs text-slate-600">
            {formatPriorWindow(data.totalEvents24h, data.priorEvents24h)}
          </p>
          {data.rollupPendingEvents24h > 0 ? (
            <p className="mt-1.5 text-xs text-slate-500">
              +{formatCount(data.rollupPendingEvents24h)} recent or unclassified events pending next
              15m rollup
            </p>
          ) : null}
          {data.aggregateComplete ? null : (
            <p className="mt-2 text-xs font-medium text-amber-800">
              Aggregate read is incomplete. This total is partial, not an exact count.
            </p>
          )}
          {data.coverageGapIn24h || data.coverageGapInPrior24h ? (
            <p className="mt-2 text-xs font-medium text-amber-800">
              Collection gap in window — comparison may undercount.
            </p>
          ) : null}
        </Panel>
      </section>

      {/* Noteworthy Observations */}
      <Panel ariaLabel="Noteworthy observations">
        <PanelHeader
          title="Noteworthy observations"
          subtitle="Notable shifts vs. the previous 24 UTC hours (filtered for minimum sample size)"
        />
        {data.noteworthy.length === 0 ? (
          <p className="px-4 py-6 text-xs text-slate-500">
            No noteworthy changes in this 24 UTC hour comparison.
          </p>
        ) : (
          <ol className="divide-y divide-slate-100">
            {data.noteworthy.map((note) => (
              <li key={note.id} className="px-4 py-3.5 transition-colors hover:bg-slate-50/70">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <Link
                    href={note.href}
                    className="rounded text-sm font-medium text-slate-900 hover:text-[#632ca6] hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#632ca6]"
                  >
                    {safeDisplayText(note.title)}
                  </Link>
                  <ProtocolBadge protocol={note.protocol} />
                </div>
                <p translate="no" className="mt-1 break-all text-xs text-slate-700">
                  {safeDisplayText(note.detail)}
                </p>
                {note.kind === "first_seen" ? (
                  <p className="mt-1 text-xs text-slate-500">
                    First observed in stored history during this 24 UTC hour window.
                  </p>
                ) : note.showPercent && note.priorCount > 0 ? (
                  <p className="mt-1 font-mono text-xs tabular-nums text-slate-600">
                    {note.delta > 0 ? "+" : ""}
                    {((note.delta / note.priorCount) * 100).toFixed(0)}% vs the previous 24 UTC
                    hours
                  </p>
                ) : (
                  <p className="mt-1 text-xs text-slate-500">
                    Absolute change only. The previous window is too small for a percentage.
                  </p>
                )}
                {note.comparisonReliable ? null : (
                  <p className="mt-1 text-xs font-medium text-amber-800">
                    A coverage gap or incomplete rollup makes this comparison less reliable.
                  </p>
                )}
              </li>
            ))}
          </ol>
        )}
      </Panel>

      <VolumeChart
        series={data.hourlySeries}
        heading="Activity Trend (24 UTC Hours)"
        emptyLabel="No stored observations in this window."
        footnote="7-day and 30-day series are on Trends. Counts are UTC hour buckets; timestamps elsewhere are JST."
      />

      <div className="grid gap-4 lg:grid-cols-2">
        {/* Protocol Distribution */}
        <Panel>
          <PanelHeader
            title="Protocol Distribution (24h UTC)"
            action={
              <Link
                href="/trends"
                className="rounded text-xs font-medium text-[#632ca6] transition-colors hover:text-[#4e2185] hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#632ca6]"
              >
                View Trends →
              </Link>
            }
          />
          <div className="p-4">
            {data.protocolBreakdown.length === 0 ? (
              <p className="text-xs text-slate-500">No observations recorded yet.</p>
            ) : (
              <>
                <div
                  aria-label="Protocol share bar"
                  className="flex h-3 w-full overflow-hidden rounded-full bg-slate-100"
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

                <div className="mt-4 divide-y divide-slate-100">
                  {data.protocolBreakdown.map((item) => (
                    <div
                      key={item.protocol}
                      className="flex items-center justify-between py-2 text-xs"
                    >
                      <ProtocolBadge protocol={item.protocol} />
                      <div className="flex items-center gap-4 font-mono tabular-nums">
                        <span className="font-medium text-slate-900">
                          {formatCount(item.count)}
                        </span>
                        <span className="w-12 text-right text-slate-500">
                          {item.sharePct.toFixed(1)}%
                        </span>
                      </div>
                    </div>
                  ))}
                </div>
              </>
            )}
          </div>
        </Panel>

        {/* Sensor Health */}
        <Panel>
          <PanelHeader
            title="Sensor Health"
            action={
              <Link
                href="/sensors"
                className="rounded text-xs font-medium text-[#632ca6] transition-colors hover:text-[#4e2185] hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#632ca6]"
              >
                Open Sensors →
              </Link>
            }
          />
          <div className="divide-y divide-slate-100 p-4">
            {data.sensors.length === 0 ? (
              <p className="text-xs text-slate-500">No registered sensors.</p>
            ) : (
              data.sensors.map((sensor) => (
                <div key={sensor.id} className="space-y-2.5 py-1.5 first:pt-0 last:pb-0">
                  <div className="flex items-center justify-between gap-2">
                    <div className="min-w-0">
                      <p className="truncate text-sm font-semibold text-slate-900">
                        {safeDisplayText(sensor.name)}
                      </p>
                      <p translate="no" className="font-mono text-[11px] text-slate-500">
                        {safeDisplayText(sensor.id)} · {safeDisplayText(sensor.region)}
                      </p>
                    </div>
                    <span
                      translate="no"
                      className={`inline-flex shrink-0 items-center gap-1.5 text-xs font-medium ${
                        sensor.healthStatus === "healthy"
                          ? "text-emerald-700"
                          : sensor.healthStatus === "stale"
                            ? "text-amber-700"
                            : "text-slate-600"
                      }`}
                    >
                      <span
                        aria-hidden="true"
                        className={`h-2 w-2 rounded-full ${
                          sensor.healthStatus === "healthy"
                            ? "bg-emerald-600"
                            : sensor.healthStatus === "stale"
                              ? "bg-amber-500"
                              : "bg-slate-400"
                        }`}
                      />
                      {sensor.healthStatus === "healthy"
                        ? "Healthy"
                        : sensor.healthStatus === "stale"
                          ? "Stale heartbeat"
                          : "Inactive"}
                    </span>
                  </div>

                  <dl className="grid grid-cols-3 gap-2 rounded-md border border-slate-200/80 bg-slate-50/80 px-3 py-2 text-[11px]">
                    <div>
                      <dt className="text-slate-500">Type</dt>
                      <dd translate="no" className="mt-0.5 font-mono font-medium text-slate-800">
                        {sensor.type}
                      </dd>
                    </div>
                    <div>
                      <dt className="text-slate-500">Heartbeat</dt>
                      <dd className="mt-0.5 font-mono tabular-nums text-slate-800">
                        {formatJstShort(sensor.last_heartbeat_at)}
                      </dd>
                    </div>
                    <div>
                      <dt className="text-slate-500">Last Event</dt>
                      <dd className="mt-0.5 font-mono tabular-nums text-slate-800">
                        {formatJstShort(sensor.last_event_at)}
                      </dd>
                    </div>
                  </dl>
                </div>
              ))
            )}
          </div>
        </Panel>
      </div>

      <PatternLists
        patterns={data.patterns24h}
        cveContext={data.patternCveContext24h}
        httpPaths={data.httpPaths24h}
        sampledNote={
          data.is24hBreakdownSampled
            ? `HTTP paths and the region map use the latest ${formatCount(data.sampled24hCount)} events. Protocol and pattern totals use the full UTC-hour rollup.`
            : null
        }
      />

      {/* Recent Sanitized Events */}
      <Panel>
        <PanelHeader
          title="Recent Sanitized Events"
          subtitle="Latest stored probes (query values redacted by default)"
          action={
            <Link
              href="/events"
              className="rounded text-xs font-medium text-[#632ca6] transition-colors hover:text-[#4e2185] hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#632ca6]"
            >
              Open Event Explorer →
            </Link>
          }
        />

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead>
              <tr className="border-b border-slate-200 bg-slate-50/80 text-xs font-medium text-slate-500">
                <th className="px-4 py-2.5 font-medium">Observed (JST)</th>
                <th className="px-3 py-2.5 font-medium">Protocol</th>
                <th className="px-3 py-2.5 font-medium">Port</th>
                <th className="px-3 py-2.5 font-medium">Event type</th>
                <th className="px-3 py-2.5 font-medium">Region / ASN</th>
                <th className="px-4 py-2.5 font-medium">Sanitized path / detail</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {data.recentEvents.length === 0 ? (
                <tr>
                  <td colSpan={6} className="px-4 py-8 text-center text-slate-500">
                    No observations recorded yet.
                  </td>
                </tr>
              ) : (
                data.recentEvents.map((ev) => (
                  <tr key={ev.id} className="transition-colors hover:bg-slate-50/80">
                    <td className="whitespace-nowrap px-4 py-2.5 font-mono tabular-nums text-slate-600">
                      {formatJstShort(ev.observed_at)}
                    </td>
                    <td className="px-3 py-2.5">
                      <ProtocolBadge protocol={ev.protocol} />
                    </td>
                    <td className="px-3 py-2.5 font-mono tabular-nums text-slate-700">
                      {ev.dst_port}
                    </td>
                    <td translate="no" className="px-3 py-2.5 font-mono text-slate-800">
                      {safeDisplayText(ev.event_type)}
                    </td>
                    <td
                      translate="no"
                      className="whitespace-nowrap px-3 py-2.5 font-mono text-slate-500"
                    >
                      {safeDisplayText(ev.src_country)} / {safeDisplayText(ev.src_asn)}
                    </td>
                    <td className="max-w-xs truncate px-4 py-2.5 font-mono">
                      <Link
                        href={`/events/${ev.id}`}
                        translate="no"
                        className="rounded text-[#632ca6] transition-colors hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#632ca6]"
                      >
                        {ev.http_method ? `${ev.http_method} ` : ""}
                        {safeDisplayHttpPath(ev.http_path_redacted, ev.fingerprint ?? "Inspect")}
                      </Link>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </Panel>

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
