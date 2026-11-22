import Link from "next/link";
import { AutoRefresh } from "@/components/auto-refresh";
import { MethodologyBanner } from "@/components/methodology-banner";
import { ObservationMeta } from "@/components/observation-meta";
import { PatternLists } from "@/components/pattern-lists";
import { PROTOCOL_COLORS, ProtocolBadge } from "@/components/protocol-badge";
import { FormattedTime, TimezoneLabel } from "@/components/timezone-provider";
import { PageHeader, Panel, PanelHeader } from "@/components/ui";
import { VolumeChart } from "@/components/volume-chart";
import { WorldGeoMap } from "@/components/world-geo-map";
import {
  formatCount,
  formatEventTypeLabel,
  formatFingerprintLabel,
  formatUtcDateTime,
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

export default async function ActivityPage() {
  const data = await getOverviewData();
  const worldMapData = buildWorldMapData(data.regionTotals24h);
  const hasRegionOrAsn = data.recentEvents.some(
    (ev) => Boolean(ev.src_country) || Boolean(ev.src_asn),
  );
  const topProtocols = data.protocolBreakdown.slice(0, 2);

  const sensorBadge =
    data.activeSensorCount === 0
      ? {
          label: "Sensor offline",
          textClass: "text-slate-600",
          dotClass: "bg-slate-400",
        }
      : data.healthySensorCount === data.activeSensorCount
        ? {
            label: `${formatCount(data.healthySensorCount)}/${formatCount(data.activeSensorCount)} sensor healthy`,
            textClass: "text-emerald-700",
            dotClass: "bg-emerald-600",
          }
        : data.healthySensorCount > 0
          ? {
              label: `${formatCount(data.healthySensorCount)}/${formatCount(data.activeSensorCount)} sensors healthy`,
              textClass: "text-amber-700",
              dotClass: "bg-amber-500",
            }
          : {
              label: "Sensor heartbeat stale",
              textClass: "text-red-700",
              dotClass: "bg-red-600",
            };

  return (
    <div className="space-y-5">
      <PageHeader
        title="Activity"
        description="Observed unsolicited probes, key patterns, and recent sanitized events"
        meta={
          <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
            <ObservationMeta
              windowLabel="Last 24 UTC hours"
              updatedAt={data.dataUpdatedAt}
              sensorCount={data.sensors.length}
            />
            <span className="text-slate-300" aria-hidden="true">
              ·
            </span>
            <Link
              href="/sensors"
              className={`inline-flex items-center gap-1.5 rounded text-xs font-medium hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#632ca6] ${sensorBadge.textClass}`}
            >
              <span
                aria-hidden="true"
                className={`h-2 w-2 rounded-full ${sensorBadge.dotClass}`}
              />
              {sensorBadge.label}
            </Link>
          </div>
        }
        actions={
          <>
            <span
              translate="no"
              className="rounded-lg border border-slate-200 bg-white px-3 py-1.5 font-mono text-xs font-medium text-slate-700 shadow-[0_1px_2px_rgba(15,23,42,0.03)]"
            >
              Last 24h
            </span>
            <AutoRefresh intervalSeconds={30} />
          </>
        }
      />

      <MethodologyBanner sourceMode={data.sourceMode} sensorCount={data.sensors.length} />

      {/* 2. Key Observation Metrics */}
      <section
        aria-label="Key observation metrics"
        className="grid gap-4 sm:grid-cols-2"
      >
        <Panel className="p-5">
          <div className="flex items-center justify-between gap-2">
            <p className="text-xs font-medium text-slate-500">
              Observed events (24h UTC)
            </p>
            {!data.hasPriorWindowBaseline ? (
              <span className="font-mono text-[11px] font-medium text-[#632ca6]">
                Baseline building
              </span>
            ) : null}
          </div>
          <p className="mt-2 font-mono text-3xl font-semibold tracking-tight tabular-nums text-slate-900">
            {formatCount(data.totalEvents24h)}
          </p>
          {data.hasPriorWindowBaseline ? (
            <p className="mt-2 text-xs text-slate-600">
              {formatPriorWindow(data.totalEvents24h, data.priorEvents24h)}
            </p>
          ) : (
            <p className="mt-2 text-xs text-slate-600">
              24h comparison starts after 48h of history
              {data.historyStartedAt
                ? ` (first stored: ${formatUtcDateTime(data.historyStartedAt)})`
                : ""}
            </p>
          )}
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
          {data.coverageGapIn24h || (data.hasPriorWindowBaseline && data.coverageGapInPrior24h) ? (
            <p className="mt-2 text-xs font-medium text-amber-800">
              Collection gap in window — totals may undercount actual probes.
            </p>
          ) : null}
        </Panel>

        <Panel className="p-5">
          <div className="flex items-center justify-between gap-2">
            <p className="text-xs font-medium text-slate-500">
              Observed protocols (24h UTC)
            </p>
            <Link
              href="/trends"
              className="rounded text-xs font-medium text-[#632ca6] hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#632ca6]"
            >
              Trends →
            </Link>
          </div>
          <div className="mt-2 flex items-baseline gap-2">
            <p className="font-mono text-3xl font-semibold tracking-tight tabular-nums text-slate-900">
              {formatCount(data.protocolBreakdown.length)}
            </p>
            <span className="text-xs text-slate-500">
              active service protocol{data.protocolBreakdown.length === 1 ? "" : "s"}
            </span>
          </div>
          {topProtocols.length > 0 ? (
            <p className="mt-2 text-xs text-slate-600">
              Led by{" "}
              {topProtocols
                .map((p) => `${p.protocol.toUpperCase()} (${p.sharePct.toFixed(1)}%)`)
                .join(" and ")}
            </p>
          ) : (
            <p className="mt-2 text-xs text-slate-500">No protocol activity recorded in this window.</p>
          )}
        </Panel>
      </section>

      {/* 3. Noteworthy Observations */}
      <Panel ariaLabel="Noteworthy observations">
        <PanelHeader
          title="Noteworthy observations"
          subtitle={
            data.hasPriorWindowBaseline
              ? "Evidence-backed shifts vs. the previous 24 UTC hours"
              : "Current observation summary while 48-hour comparison baseline is building"
          }
        />
        {data.noteworthy.length === 0 ? (
          <p className="px-4 py-6 text-xs text-slate-500">
            No noteworthy observations meet the minimum sample threshold in this window.
          </p>
        ) : (
          <ol className="divide-y divide-slate-100">
            {data.noteworthy.map((note) => (
              <li
                key={note.id}
                className={`px-4 py-3.5 transition-colors hover:bg-slate-50/70 ${
                  note.severity === "primary"
                    ? "border-l-2 border-l-[#632ca6]"
                    : "border-l-2 border-l-transparent"
                }`}
              >
                <div className="flex flex-wrap items-start justify-between gap-2">
                  <Link
                    href={note.href}
                    className={`rounded text-sm hover:text-[#632ca6] hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#632ca6] ${
                      note.severity === "primary"
                        ? "font-semibold text-slate-900"
                        : "font-medium text-slate-800"
                    }`}
                  >
                    {safeDisplayText(note.title)}
                  </Link>
                  <div className="flex items-center gap-2.5">
                    <ProtocolBadge protocol={note.protocol} />
                    <Link
                      href={note.href}
                      className="rounded text-[11px] font-medium text-[#632ca6] hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#632ca6]"
                    >
                      Inspect →
                    </Link>
                  </div>
                </div>
                <p translate="no" className="mt-1 font-mono text-xs text-slate-700">
                  {safeDisplayText(note.detail)}
                </p>
                {note.rationale ? (
                  <p className="mt-1 text-xs text-slate-500">{note.rationale}</p>
                ) : null}
                {note.comparisonReliable ? null : (
                  <p className="mt-1 text-xs font-medium text-amber-800">
                    A coverage gap or incomplete rollup affects this window.
                  </p>
                )}
              </li>
            ))}
          </ol>
        )}
      </Panel>

      {/* 4. Time-series chart */}
      <VolumeChart
        series={data.hourlySeries}
        heading="Hourly Activity (Last 24 UTC Hours)"
        emptyLabel="No stored observations in this window."
        footnote="Buckets are grouped in UTC hours; pre-observation hours are shaded separately from measured zero-event hours. Use the sidebar toggle to switch timestamps between UTC and local time."
      />

      {/* 5. Protocol Distribution */}
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

              <div className="mt-4 grid gap-x-8 divide-y divide-slate-100 sm:grid-cols-2 sm:divide-y-0">
                {data.protocolBreakdown.map((item) => (
                  <div
                    key={item.protocol}
                    className="flex items-center justify-between border-b border-slate-100 py-2 text-xs last:border-b-0"
                  >
                    <Link
                      href={`/events?protocol=${item.protocol}&period=24h`}
                      className="rounded hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#632ca6]"
                    >
                      <ProtocolBadge protocol={item.protocol} />
                    </Link>
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

      {/* 6. Representative HTTP Paths & Observed Categories */}
      <PatternLists
        patterns={data.patterns24h}
        cveContext={data.patternCveContext24h}
        httpPaths={data.httpPaths24h}
        sampledNote={
          data.is24hBreakdownSampled
            ? `HTTP paths use the latest ${formatCount(data.sampled24hCount)} events. Protocol and category totals use the full UTC-hour rollup.`
            : null
        }
      />

      {/* 7. Recent Observations */}
      <Panel>
        <PanelHeader
          title="Recent Observations"
          subtitle="Latest sanitized probes (source IPs and query values excluded)"
          action={
            <Link
              href="/events"
              className="rounded text-xs font-medium text-[#632ca6] transition-colors hover:text-[#4e2185] hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#632ca6]"
            >
              Open Explore →
            </Link>
          }
        />

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead>
              <tr className="border-b border-slate-200 bg-slate-50/80 text-xs font-medium text-slate-500">
                <th className="px-4 py-2.5 font-medium">
                  Observed (<TimezoneLabel />)
                </th>
                <th className="px-3 py-2.5 font-medium">Protocol</th>
                <th className="px-3 py-2.5 font-medium">Port</th>
                <th className="px-3 py-2.5 font-medium">Event</th>
                {hasRegionOrAsn ? (
                  <th className="px-3 py-2.5 font-medium">Region / ASN</th>
                ) : null}
                <th className="px-4 py-2.5 font-medium">Sanitized detail</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {data.recentEvents.length === 0 ? (
                <tr>
                  <td
                    colSpan={hasRegionOrAsn ? 6 : 5}
                    className="px-4 py-8 text-center text-slate-500"
                  >
                    No observations recorded yet.
                  </td>
                </tr>
              ) : (
                data.recentEvents.map((ev) => (
                  <tr key={ev.id} className="transition-colors hover:bg-slate-50/80">
                    <td className="whitespace-nowrap px-4 py-2.5 font-mono tabular-nums text-slate-600">
                      <FormattedTime iso={ev.observed_at} variant="short" />
                    </td>
                    <td className="px-3 py-2.5">
                      <ProtocolBadge protocol={ev.protocol} />
                    </td>
                    <td className="px-3 py-2.5 font-mono tabular-nums text-slate-700">
                      {ev.dst_port}
                    </td>
                    <td className="whitespace-nowrap px-3 py-2.5 font-medium text-slate-800">
                      {formatEventTypeLabel(ev.event_type)}
                    </td>
                    {hasRegionOrAsn ? (
                      <td
                        translate="no"
                        className="whitespace-nowrap px-3 py-2.5 font-mono text-slate-500"
                      >
                        {safeDisplayText(ev.src_country)} / {safeDisplayText(ev.src_asn)}
                      </td>
                    ) : null}
                    <td className="max-w-xs truncate px-4 py-2.5 font-mono">
                      <Link
                        href={`/events/${ev.id}`}
                        translate="no"
                        className="rounded text-[#632ca6] transition-colors hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#632ca6]"
                      >
                        {ev.http_method
                          ? `${ev.http_method} ${safeDisplayHttpPath(ev.http_path_redacted, "/")}`
                          : formatFingerprintLabel(ev.fingerprint)}
                      </Link>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </Panel>

      {/* Optional GeoIP map only when real region data is available */}
      {worldMapData.totalMapped > 0 ? (
        <WorldGeoMap
          data={worldMapData}
          title="Observed Source Regions (24h · GeoIP Estimate)"
          subtitle={
            data.is24hBreakdownSampled
              ? `Secondary view from the latest ${formatCount(data.sampled24hCount)} sampled events (raw IPs excluded)`
              : "Secondary country/region view. Raw IPs and exact locations are excluded."
          }
        />
      ) : null}

      {/* 8. Sensor Status & Observation Coverage */}
      <Panel>
        <PanelHeader
          title="Sensor Status & Coverage"
          action={
            <Link
              href="/sensors"
              className="rounded text-xs font-medium text-[#632ca6] transition-colors hover:text-[#4e2185] hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#632ca6]"
            >
              Open Coverage →
            </Link>
          }
        />
        <div className="divide-y divide-slate-100 p-4">
          {data.sensors.length === 0 ? (
            <p className="text-xs text-slate-500">No registered sensors.</p>
          ) : (
            data.sensors.map((sensor) => (
              <div
                key={sensor.id}
                className="flex flex-col gap-3 py-1.5 first:pt-0 last:pb-0 sm:flex-row sm:items-center sm:justify-between"
              >
                <div className="min-w-0">
                  <div className="flex items-center gap-2">
                    <p className="truncate text-sm font-semibold text-slate-900">
                      {safeDisplayText(sensor.name)}
                    </p>
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
                  <p translate="no" className="mt-0.5 font-mono text-[11px] text-slate-500">
                    {safeDisplayText(sensor.id)} · {safeDisplayText(sensor.region)} · {sensor.type}
                  </p>
                </div>

                <dl className="flex flex-wrap items-center gap-x-6 gap-y-1 text-[11px]">
                  <div>
                    <dt className="text-slate-500">
                      Heartbeat (<TimezoneLabel />)
                    </dt>
                    <dd className="font-mono tabular-nums text-slate-800">
                      <FormattedTime iso={sensor.last_heartbeat_at} variant="short" />
                    </dd>
                  </div>
                  <div>
                    <dt className="text-slate-500">
                      Last Event (<TimezoneLabel />)
                    </dt>
                    <dd className="font-mono tabular-nums text-slate-800">
                      <FormattedTime iso={sensor.last_event_at} variant="short" />
                    </dd>
                  </div>
                </dl>
              </div>
            ))
          )}
        </div>
      </Panel>
    </div>
  );
}
