import Link from "next/link";
import { notFound } from "next/navigation";
import { MethodologyBanner } from "@/components/methodology-banner";
import { ProtocolBadge } from "@/components/protocol-badge";
import {
  formatConfidence,
  formatEpss,
  formatJstDateTime,
  safeDisplayText,
} from "@/lib/format";
import { getEventDetail } from "@/lib/observatory";

export const dynamic = "force-dynamic";

interface EventDetailPageProps {
  params: Promise<{ id: string }>;
}

export default async function EventDetailPage({ params }: EventDetailPageProps) {
  const { id } = await params;
  const detail = await getEventDetail(id);

  if (!detail.event) {
    notFound();
  }

  const { event, detections, cveMatches } = detail;

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="min-w-0">
          <Link
            href="/events"
            className="rounded text-xs font-medium text-[#632ca6] transition-colors hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#632ca6]"
          >
            ← Back to Event Explorer
          </Link>
          <h1 className="mt-1 text-lg font-semibold tracking-tight text-gray-900">
            Event Detail
          </h1>
          <p translate="no" className="mt-0.5 break-all font-mono text-xs text-gray-500">
            {event.id}
          </p>
        </div>
        <ProtocolBadge protocol={event.protocol} />
      </div>

      <MethodologyBanner sourceMode={detail.sourceMode} />

      {/* Event Attributes */}
      <section className="rounded border border-gray-200 bg-white">
        <div className="border-b border-gray-200 px-4 py-3">
          <h2 className="text-xs font-semibold uppercase tracking-wider text-gray-700">
            Sanitized Event Attributes
          </h2>
        </div>
        <dl className="grid divide-y divide-gray-100 text-xs sm:grid-cols-2 sm:divide-y-0">
          <div className="border-b border-gray-100 px-4 py-3 sm:border-r">
            <dt className="text-[11px] font-medium uppercase tracking-wider text-gray-400">
              Observed At
            </dt>
            <dd className="mt-1 font-mono tabular-nums text-gray-900">
              {formatJstDateTime(event.observed_at)}
            </dd>
          </div>
          <div className="border-b border-gray-100 px-4 py-3">
            <dt className="text-[11px] font-medium uppercase tracking-wider text-gray-400">
              Sensor ID
            </dt>
            <dd translate="no" className="mt-1 font-mono text-gray-900">
              {safeDisplayText(event.sensor_id)}
            </dd>
          </div>
          <div className="border-b border-gray-100 px-4 py-3 sm:border-r">
            <dt className="text-[11px] font-medium uppercase tracking-wider text-gray-400">
              Protocol / Destination Port
            </dt>
            <dd translate="no" className="mt-1 font-mono tabular-nums text-gray-900">
              {event.protocol.toUpperCase()} / {event.dst_port}
            </dd>
          </div>
          <div className="border-b border-gray-100 px-4 py-3">
            <dt className="text-[11px] font-medium uppercase tracking-wider text-gray-400">
              Event Type
            </dt>
            <dd translate="no" className="mt-1 font-mono text-gray-900">
              {safeDisplayText(event.event_type)}
            </dd>
          </div>
          <div className="border-b border-gray-100 px-4 py-3 sm:border-r">
            <dt className="text-[11px] font-medium uppercase tracking-wider text-gray-400">
              Approx. Region / ASN
            </dt>
            <dd translate="no" className="mt-1 font-mono text-gray-900">
              {safeDisplayText(event.src_country)} / {safeDisplayText(event.src_asn)}
            </dd>
          </div>
          <div className="border-b border-gray-100 px-4 py-3">
            <dt className="text-[11px] font-medium uppercase tracking-wider text-gray-400">
              Fingerprint
            </dt>
            <dd translate="no" className="mt-1 font-mono text-gray-900">
              {safeDisplayText(event.fingerprint)}
            </dd>
          </div>
          <div className="px-4 py-3 sm:col-span-2">
            <dt className="text-[11px] font-medium uppercase tracking-wider text-gray-400">
              HTTP Method &amp; Redacted Path
            </dt>
            <dd
              translate="no"
              className="mt-1.5 break-all rounded border border-gray-200 bg-gray-50 px-3 py-2 font-mono text-xs text-gray-800"
            >
              {event.http_method ? `${event.http_method} ` : ""}
              {safeDisplayText(event.http_path_redacted)}
            </dd>
          </div>
        </dl>
      </section>

      {/* Rule Detections */}
      <section className="rounded border border-gray-200 bg-white">
        <div className="border-b border-gray-200 px-4 py-3">
          <h2 className="text-xs font-semibold uppercase tracking-wider text-gray-700">
            Rule Detections &amp; Evidence
          </h2>
        </div>
        <div className="p-4">
          {detections.length === 0 ? (
            <p className="text-xs text-gray-500">
              No additional signature detections recorded (classification:{" "}
              <code translate="no" className="font-mono text-gray-700">
                observed
              </code>{" "}
              only).
            </p>
          ) : (
            <div className="space-y-3">
              {detections.map((d) => (
                <div
                  key={d.id}
                  className="rounded border border-gray-200 bg-gray-50/60 p-3.5 text-xs"
                >
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <span translate="no" className="font-mono font-semibold text-gray-900">
                      {safeDisplayText(d.rule_id)}@{safeDisplayText(d.rule_version)}
                    </span>
                    <div className="flex items-center gap-2">
                      <span
                        translate="no"
                        className="rounded border border-purple-200 bg-purple-50 px-2 py-0.5 font-mono text-[11px] text-[#632ca6]"
                      >
                        {d.classification}
                      </span>
                      <span className="font-mono tabular-nums text-gray-600">
                        Confidence: {formatConfidence(d.confidence)}
                      </span>
                    </div>
                  </div>
                  <pre
                    translate="no"
                    className="mt-2.5 overflow-x-auto rounded border border-gray-200 bg-white p-3 font-mono text-[11px] text-gray-700"
                  >
                    {JSON.stringify(d.evidence_redacted, null, 2)}
                  </pre>
                </div>
              ))}
            </div>
          )}
        </div>
      </section>

      {/* Candidate CVEs */}
      <section className="rounded border border-gray-200 bg-white">
        <div className="flex flex-wrap items-center justify-between gap-2 border-b border-gray-200 px-4 py-3">
          <h2 className="text-xs font-semibold uppercase tracking-wider text-gray-700">
            Suspected Related CVEs (Candidate Hypothesis Only)
          </h2>
          <span className="text-[11px] text-gray-500">
            Not proof of confirmed exploitation
          </span>
        </div>
        <div className="p-4">
          {cveMatches.length === 0 ? (
            <p className="text-xs text-gray-500">
              No evidence-backed candidate CVEs are linked to this event.
            </p>
          ) : (
            <div className="space-y-3">
              {cveMatches.map((m) => (
                <div
                  key={m.id}
                  className="rounded border border-gray-200 border-l-2 border-l-amber-500 bg-white p-3.5 text-xs"
                >
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <span translate="no" className="font-mono text-sm font-semibold text-gray-900">
                      {safeDisplayText(m.cve_id)}
                    </span>
                    <div className="flex flex-wrap items-center gap-1.5 text-[11px]">
                      <span
                        translate="no"
                        className="rounded border border-amber-200 bg-amber-50 px-2 py-0.5 font-mono tabular-nums text-amber-800"
                      >
                        {m.match_type} · {formatConfidence(m.confidence)}
                      </span>
                      <span
                        translate="no"
                        className={`rounded border px-2 py-0.5 font-mono ${
                          m.kev_present
                            ? "border-red-200 bg-red-50 text-red-700"
                            : "border-gray-200 bg-gray-100 text-gray-600"
                        }`}
                      >
                        CISA KEV: {m.kev_present ? "Listed" : "Not Listed"}
                      </span>
                      <span
                        translate="no"
                        className="rounded border border-gray-200 bg-gray-50 px-2 py-0.5 font-mono tabular-nums text-gray-700"
                      >
                        EPSS: {formatEpss(m.epss_score)}
                        {m.epss_date ? ` (${m.epss_date})` : ""}
                      </span>
                    </div>
                  </div>
                  <p className="mt-2 leading-relaxed text-gray-700">
                    {safeDisplayText(m.reason)}
                  </p>
                  <p className="mt-2 font-mono text-[11px] text-gray-500">
                    Rule:{" "}
                    <span translate="no">
                      {safeDisplayText(m.rule_id)}@{safeDisplayText(m.rule_version)}
                    </span>{" "}
                    — EPSS is a vulnerability-level 30-day forecast, not per-request
                    exploit probability.
                  </p>
                </div>
              ))}
            </div>
          )}
        </div>
      </section>
    </div>
  );
}
