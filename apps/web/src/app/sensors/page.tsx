import Link from "next/link";
import { MethodologyBanner } from "@/components/methodology-banner";
import { ProtocolBadge } from "@/components/protocol-badge";
import { Callout, PageHeader, Panel, PanelHeader } from "@/components/ui";
import { formatOutageDuration, isCoverageGapStatus } from "@/lib/dashboard-metrics";
import { formatCount, formatJstDateTime, safeDisplayText } from "@/lib/format";
import { getSensorsData } from "@/lib/observatory";
import type { SensorHealthStatus, SensorStatusEventType } from "@/lib/types";

export const dynamic = "force-dynamic";

const HEALTH_STYLE: Record<
  SensorHealthStatus,
  { label: string; textClass: string; dotClass: string }
> = {
  healthy: {
    label: "Healthy",
    textClass: "text-emerald-700",
    dotClass: "bg-emerald-600",
  },
  stale: {
    label: "Stale heartbeat",
    textClass: "text-amber-700",
    dotClass: "bg-amber-500",
  },
  inactive: {
    label: "Offline (inactive)",
    textClass: "text-slate-600",
    dotClass: "bg-slate-400",
  },
};

const EVENT_STATUS_STYLE: Record<
  SensorStatusEventType,
  { label: string; textClass: string; dotClass: string }
> = {
  healthy: {
    label: "Recovered / healthy",
    textClass: "text-emerald-700",
    dotClass: "bg-emerald-600",
  },
  degraded: {
    label: "Degraded collection",
    textClass: "text-amber-800",
    dotClass: "bg-amber-500",
  },
  offline: {
    label: "Sensor offline (gap)",
    textClass: "text-red-700",
    dotClass: "bg-red-600",
  },
  error: {
    label: "Collection error (gap)",
    textClass: "text-red-700",
    dotClass: "bg-red-600",
  },
};

export default async function SensorsPage() {
  const data = await getSensorsData();
  const nowMs = Date.parse(data.evaluatedAt);
  const healthyCount = data.sensors.filter((s) => s.healthStatus === "healthy").length;
  const staleCount = data.sensors.filter((s) => s.healthStatus === "stale").length;
  const offlineCount = data.sensors.filter((s) => s.healthStatus === "inactive").length;
  const gapEvents = data.statusEvents.filter((event) => isCoverageGapStatus(event.status));

  return (
    <div className="space-y-5">
      <PageHeader
        title="Coverage"
        description="Sensor health, heartbeat freshness, monitored services, and collection outage intervals"
        actions={
          <span className="font-mono text-xs tabular-nums text-slate-500">
            Evaluated: {formatJstDateTime(data.evaluatedAt)}
          </span>
        }
      />

      <MethodologyBanner sourceMode={data.sourceMode} sensorCount={data.sensors.length} />

      <Callout
        tone="warning"
        ariaLabel="Zero observation versus outage distinction"
        title="Distinguishing zero observations from collection outages"
      >
        A period with <span className="font-mono font-semibold">0</span> recorded events only
        represents quiet traffic when the sensor heartbeat is healthy and no outage interval
        overlaps that window. Intervals marked as offline, degraded, or error indicate missing or
        partial collection and must not be interpreted as a drop in Internet scanning.
      </Callout>

      <section
        aria-label="Sensor health summary"
        className="grid grid-cols-2 gap-3 sm:grid-cols-4"
      >
        <Panel className="p-4">
          <p className="text-xs font-medium text-slate-500">Healthy</p>
          <p className="mt-1.5 font-mono text-2xl font-semibold tabular-nums text-emerald-700">
            {formatCount(healthyCount)}
          </p>
          <p className="mt-1 text-xs text-slate-500">Heartbeat within 15m</p>
        </Panel>

        <Panel className="p-4">
          <p className="text-xs font-medium text-slate-500">Stale heartbeat</p>
          <p className="mt-1.5 font-mono text-2xl font-semibold tabular-nums text-amber-800">
            {formatCount(staleCount)}
          </p>
          <p className="mt-1 text-xs text-slate-500">No recent delivery (&gt;15m)</p>
        </Panel>

        <Panel className="p-4">
          <p className="text-xs font-medium text-slate-500">Offline / inactive</p>
          <p className="mt-1.5 font-mono text-2xl font-semibold tabular-nums text-slate-700">
            {formatCount(offlineCount)}
          </p>
          <p className="mt-1 text-xs text-slate-500">Disabled or paused sensor</p>
        </Panel>

        <Panel className="p-4">
          <p className="text-xs font-medium text-slate-500">Active outages</p>
          <p className="mt-1.5 font-mono text-2xl font-semibold tabular-nums text-red-700">
            {formatCount(data.activeOutages.length)}
          </p>
          <p className="mt-1 text-xs text-slate-500">
            {formatCount(gapEvents.length)} gap interval(s) in past 30d
          </p>
        </Panel>
      </section>

      <Panel>
        <PanelHeader
          title={`Registered sensors (${formatCount(data.sensors.length)})`}
          action={
            <Link
              href="/trends"
              className="rounded text-xs font-medium text-[#632ca6] transition-colors hover:text-[#4e2185] hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#632ca6]"
            >
              View Trends →
            </Link>
          }
        />

        <div className="divide-y divide-slate-100 p-4">
          {data.sensors.length === 0 ? (
            <p className="text-xs text-slate-500">
              No sensors are registered yet. No observation coverage is active.
            </p>
          ) : (
            data.sensors.map((sensor) => {
              const status = HEALTH_STYLE[sensor.healthStatus];
              return (
                <article key={sensor.id} className="space-y-3 py-3 first:pt-0 last:pb-0">
                  <div className="flex flex-wrap items-start justify-between gap-2">
                    <div className="min-w-0">
                      <h3 className="truncate text-sm font-semibold text-slate-900">
                        {safeDisplayText(sensor.name)}
                      </h3>
                      <p translate="no" className="mt-0.5 font-mono text-xs text-slate-500">
                        {safeDisplayText(sensor.id)} · {safeDisplayText(sensor.region)} ·{" "}
                        {sensor.type}
                      </p>
                    </div>
                    <span
                      className={`inline-flex items-center gap-1.5 text-xs font-medium ${status.textClass}`}
                    >
                      <span
                        aria-hidden="true"
                        className={`h-2 w-2 rounded-full ${status.dotClass}`}
                      />
                      {status.label}
                    </span>
                  </div>

                  <dl className="grid gap-2 rounded-md border border-slate-200/80 bg-slate-50/80 px-3 py-2.5 text-xs sm:grid-cols-3">
                    <div>
                      <dt className="text-slate-500">Last heartbeat</dt>
                      <dd className="mt-0.5 font-mono tabular-nums text-slate-800">
                        {formatJstDateTime(sensor.last_heartbeat_at)}
                      </dd>
                    </div>
                    <div>
                      <dt className="text-slate-500">Last observed event</dt>
                      <dd className="mt-0.5 font-mono tabular-nums text-slate-800">
                        {formatJstDateTime(sensor.last_event_at)}
                      </dd>
                    </div>
                    <div>
                      <dt className="text-slate-500">Last recorded error</dt>
                      <dd className="mt-0.5 font-mono tabular-nums text-slate-800">
                        {sensor.last_error_at ? formatJstDateTime(sensor.last_error_at) : "None"}
                      </dd>
                    </div>
                  </dl>

                  <div>
                    <p className="text-xs font-medium text-slate-500">Monitored services</p>
                    {sensor.monitored_services.length === 0 ? (
                      <p className="mt-1 text-xs text-slate-500">
                        Service list not reported in sensor metadata.
                      </p>
                    ) : (
                      <div className="mt-1.5 flex flex-wrap gap-x-4 gap-y-1.5">
                        {sensor.monitored_services.map((service) => (
                          <ProtocolBadge key={service} protocol={service} />
                        ))}
                      </div>
                    )}
                  </div>
                </article>
              );
            })
          )}
        </div>
      </Panel>

      <Panel>
        <PanelHeader
          title="Coverage & status intervals (past 30 days)"
          subtitle="Internal host logs are excluded from public status records"
        />

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead>
              <tr className="border-b border-slate-200 bg-slate-50/80 text-xs font-medium text-slate-500">
                <th className="px-4 py-2.5 font-medium">Status</th>
                <th className="px-3 py-2.5 font-medium">Sensor</th>
                <th className="px-3 py-2.5 font-medium">Started (JST)</th>
                <th className="px-3 py-2.5 font-medium">Ended (JST)</th>
                <th className="px-4 py-2.5 font-medium">Duration</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {data.statusEvents.length === 0 ? (
                <tr>
                  <td colSpan={5} className="px-4 py-8 text-center text-slate-500">
                    No sensor outage or status transitions recorded in the past 30 days.
                  </td>
                </tr>
              ) : (
                data.statusEvents.map((ev) => {
                  const status = EVENT_STATUS_STYLE[ev.status];
                  return (
                    <tr key={ev.id} className="transition-colors hover:bg-slate-50/80">
                      <td className="whitespace-nowrap px-4 py-2.5">
                        <span
                          className={`inline-flex items-center gap-1.5 font-medium ${status.textClass}`}
                        >
                          <span
                            aria-hidden="true"
                            className={`h-2 w-2 rounded-full ${status.dotClass}`}
                          />
                          {status.label}
                        </span>
                      </td>
                      <td
                        translate="no"
                        className="whitespace-nowrap px-3 py-2.5 font-mono text-slate-800"
                      >
                        {safeDisplayText(ev.sensor_id)}
                      </td>
                      <td className="whitespace-nowrap px-3 py-2.5 font-mono tabular-nums text-slate-600">
                        {formatJstDateTime(ev.started_at)}
                      </td>
                      <td className="whitespace-nowrap px-3 py-2.5 font-mono tabular-nums text-slate-600">
                        {ev.ended_at ? (
                          formatJstDateTime(ev.ended_at)
                        ) : isCoverageGapStatus(ev.status) ? (
                          <span className="font-semibold text-red-700">Ongoing</span>
                        ) : (
                          <span className="font-medium text-emerald-700">Current</span>
                        )}
                      </td>
                      <td className="whitespace-nowrap px-4 py-2.5 font-mono tabular-nums text-slate-700">
                        {formatOutageDuration(ev.started_at, ev.ended_at, nowMs)}
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </Panel>
    </div>
  );
}
