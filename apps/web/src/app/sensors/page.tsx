import Link from "next/link";
import { MethodologyBanner } from "@/components/methodology-banner";
import { ProtocolBadge } from "@/components/protocol-badge";
import { formatOutageDuration, isCoverageGapStatus } from "@/lib/dashboard-metrics";
import { formatCount, formatJstDateTime, safeDisplayText } from "@/lib/format";
import { getSensorsData } from "@/lib/observatory";
import type { SensorHealthStatus, SensorStatusEventType } from "@/lib/types";

export const dynamic = "force-dynamic";

const HEALTH_BADGE: Record<
  SensorHealthStatus,
  { label: string; symbol: string; classes: string }
> = {
  healthy: {
    label: "Healthy",
    symbol: "OK",
    classes: "border-emerald-200 bg-emerald-50 text-emerald-800",
  },
  stale: {
    label: "Stale Heartbeat",
    symbol: "STALE",
    classes: "border-amber-300 bg-amber-50 text-amber-900",
  },
  inactive: {
    label: "Offline (Inactive)",
    symbol: "OFF",
    classes: "border-gray-300 bg-gray-100 text-gray-700",
  },
};

const EVENT_STATUS_BADGE: Record<
  SensorStatusEventType,
  { label: string; symbol: string; classes: string }
> = {
  healthy: {
    label: "Recovered / Healthy",
    symbol: "OK",
    classes: "border-emerald-200 bg-emerald-50 text-emerald-800",
  },
  degraded: {
    label: "Degraded Collection",
    symbol: "DEG",
    classes: "border-amber-300 bg-amber-50 text-amber-900",
  },
  offline: {
    label: "Sensor Offline (Gap)",
    symbol: "GAP",
    classes: "border-red-300 bg-red-50 text-red-800",
  },
  error: {
    label: "Collection Error (Gap)",
    symbol: "ERR",
    classes: "border-red-300 bg-red-50 text-red-800",
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
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="min-w-0">
          <h1 className="text-lg font-semibold tracking-tight text-gray-900">
            Sensors &amp; Coverage
          </h1>
          <p className="mt-0.5 text-xs text-gray-500">
            Sensor health, heartbeat freshness, monitored services, and collection outage intervals
          </p>
        </div>
        <span className="font-mono text-[11px] tabular-nums text-gray-500">
          Evaluated: {formatJstDateTime(data.evaluatedAt)}
        </span>
      </div>

      <MethodologyBanner sourceMode={data.sourceMode} />

      <section
        aria-label="Zero observation versus outage distinction"
        className="rounded border border-amber-200 bg-amber-50/70 px-4 py-3 text-xs text-amber-950"
      >
        <p className="font-semibold">
          Distinguishing Zero Observations From Collection Outages
        </p>
        <p className="mt-1 leading-relaxed text-amber-900">
          A period with <span className="font-mono font-semibold">0</span> recorded events only
          represents quiet traffic when the sensor heartbeat is <span className="font-mono font-semibold">OK</span>{" "}
          and no outage interval overlaps that window. Intervals marked{" "}
          <span className="font-mono font-semibold">[GAP]</span>,{" "}
          <span className="font-mono font-semibold">[DEG]</span>, or{" "}
          <span className="font-mono font-semibold">[ERR]</span> indicate missing or partial
          collection and must not be interpreted as a drop in Internet scanning.
        </p>
      </section>

      <section
        aria-label="Sensor health summary"
        className="grid grid-cols-2 divide-y divide-gray-200 rounded border border-gray-200 bg-white sm:grid-cols-4 sm:divide-x sm:divide-y-0"
      >
        <div className="p-4">
          <p className="text-[11px] font-semibold uppercase tracking-wider text-gray-500">
            Healthy
          </p>
          <p className="mt-1.5 font-mono text-2xl font-semibold tabular-nums text-emerald-700">
            {formatCount(healthyCount)}
          </p>
          <p className="mt-1 text-[11px] text-gray-500">Heartbeat within 15m</p>
        </div>

        <div className="p-4">
          <p className="text-[11px] font-semibold uppercase tracking-wider text-gray-500">
            Stale Heartbeat
          </p>
          <p className="mt-1.5 font-mono text-2xl font-semibold tabular-nums text-amber-800">
            {formatCount(staleCount)}
          </p>
          <p className="mt-1 text-[11px] text-gray-500">No recent delivery (&gt;15m)</p>
        </div>

        <div className="p-4">
          <p className="text-[11px] font-semibold uppercase tracking-wider text-gray-500">
            Offline / Inactive
          </p>
          <p className="mt-1.5 font-mono text-2xl font-semibold tabular-nums text-gray-700">
            {formatCount(offlineCount)}
          </p>
          <p className="mt-1 text-[11px] text-gray-500">Disabled or paused sensor</p>
        </div>

        <div className="p-4">
          <p className="text-[11px] font-semibold uppercase tracking-wider text-gray-500">
            Active Outages
          </p>
          <p className="mt-1.5 font-mono text-2xl font-semibold tabular-nums text-red-700">
            {formatCount(data.activeOutages.length)}
          </p>
          <p className="mt-1 text-[11px] text-gray-500">
            {formatCount(gapEvents.length)} gap interval(s) in past 30d
          </p>
        </div>
      </section>

      <section className="rounded border border-gray-200 bg-white">
        <div className="flex items-center justify-between border-b border-gray-200 px-4 py-3">
          <h2 className="text-xs font-semibold uppercase tracking-wider text-gray-700">
            Registered Sensors ({formatCount(data.sensors.length)})
          </h2>
          <Link
            href="/trends"
            className="rounded text-xs font-medium text-[#632ca6] hover:text-[#4e2185] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#632ca6]"
          >
            View Trends →
          </Link>
        </div>

        <div className="divide-y divide-gray-100 p-4">
          {data.sensors.length === 0 ? (
            <p className="text-xs text-gray-500">
              No sensors are registered yet. No observation coverage is active.
            </p>
          ) : (
            data.sensors.map((sensor) => {
              const badge = HEALTH_BADGE[sensor.healthStatus];
              return (
                <article key={sensor.id} className="space-y-3 py-3 first:pt-0 last:pb-0">
                  <div className="flex flex-wrap items-start justify-between gap-2">
                    <div className="min-w-0">
                      <h3 className="truncate text-sm font-semibold text-gray-900">
                        {safeDisplayText(sensor.name)}
                      </h3>
                      <p translate="no" className="mt-0.5 font-mono text-[11px] text-gray-500">
                        {safeDisplayText(sensor.id)} · {safeDisplayText(sensor.region)} ·{" "}
                        {sensor.type}
                      </p>
                    </div>
                    <span
                      className={`inline-flex items-center gap-1.5 rounded border px-2 py-0.5 text-[11px] font-medium ${badge.classes}`}
                    >
                      <span
                        aria-hidden="true"
                        className="font-mono text-[10px] font-bold"
                      >
                        [{badge.symbol}]
                      </span>
                      {badge.label}
                    </span>
                  </div>

                  <dl className="grid gap-2 rounded border border-gray-100 bg-gray-50 px-3 py-2.5 text-[11px] sm:grid-cols-3">
                    <div>
                      <dt className="text-gray-500">Last Heartbeat</dt>
                      <dd className="mt-0.5 font-mono tabular-nums text-gray-800">
                        {formatJstDateTime(sensor.last_heartbeat_at)}
                      </dd>
                    </div>
                    <div>
                      <dt className="text-gray-500">Last Observed Event</dt>
                      <dd className="mt-0.5 font-mono tabular-nums text-gray-800">
                        {formatJstDateTime(sensor.last_event_at)}
                      </dd>
                    </div>
                    <div>
                      <dt className="text-gray-500">Last Recorded Error</dt>
                      <dd className="mt-0.5 font-mono tabular-nums text-gray-800">
                        {sensor.last_error_at ? formatJstDateTime(sensor.last_error_at) : "None"}
                      </dd>
                    </div>
                  </dl>

                  <div>
                    <p className="text-[11px] font-medium text-gray-500">Monitored Services</p>
                    {sensor.monitored_services.length === 0 ? (
                      <p className="mt-1 text-xs text-gray-500">
                        Service list not reported in sensor metadata.
                      </p>
                    ) : (
                      <div className="mt-1.5 flex flex-wrap gap-1.5">
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
      </section>

      <section className="rounded border border-gray-200 bg-white">
        <div className="flex flex-wrap items-center justify-between gap-2 border-b border-gray-200 px-4 py-3">
          <h2 className="text-xs font-semibold uppercase tracking-wider text-gray-700">
            Coverage &amp; Status Intervals (Past 30 Days)
          </h2>
          <span className="text-[11px] text-gray-500">
            Internal host logs are excluded from public status records
          </span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead>
              <tr className="border-b border-gray-200 bg-gray-50 text-[11px] font-semibold uppercase tracking-wider text-gray-500">
                <th className="px-4 py-2">Status</th>
                <th className="px-3 py-2">Sensor</th>
                <th className="px-3 py-2">Started (JST)</th>
                <th className="px-3 py-2">Ended (JST)</th>
                <th className="px-4 py-2">Duration</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-100">
              {data.statusEvents.length === 0 ? (
                <tr>
                  <td colSpan={5} className="px-4 py-8 text-center text-gray-500">
                    No sensor outage or status transitions recorded in the past 30 days.
                  </td>
                </tr>
              ) : (
                data.statusEvents.map((ev) => {
                  const badge = EVENT_STATUS_BADGE[ev.status];
                  return (
                    <tr key={ev.id} className="hover:bg-gray-50">
                      <td className="whitespace-nowrap px-4 py-2">
                        <span
                          className={`inline-flex items-center gap-1.5 rounded border px-2 py-0.5 text-[11px] font-medium ${badge.classes}`}
                        >
                          <span aria-hidden="true" className="font-mono text-[10px] font-bold">
                            [{badge.symbol}]
                          </span>
                          {badge.label}
                        </span>
                      </td>
                      <td translate="no" className="whitespace-nowrap px-3 py-2 font-mono text-gray-800">
                        {safeDisplayText(ev.sensor_id)}
                      </td>
                      <td className="whitespace-nowrap px-3 py-2 font-mono tabular-nums text-gray-600">
                        {formatJstDateTime(ev.started_at)}
                      </td>
                      <td className="whitespace-nowrap px-3 py-2 font-mono tabular-nums text-gray-600">
                        {ev.ended_at ? (
                          formatJstDateTime(ev.ended_at)
                        ) : isCoverageGapStatus(ev.status) ? (
                          <span className="font-semibold text-red-700">Ongoing</span>
                        ) : (
                          <span className="font-medium text-emerald-700">Current</span>
                        )}
                      </td>
                      <td className="whitespace-nowrap px-4 py-2 font-mono tabular-nums text-gray-700">
                        {formatOutageDuration(ev.started_at, ev.ended_at, nowMs)}
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
}
