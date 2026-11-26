import Link from "next/link";
import { notFound } from "next/navigation";
import { MethodologyBanner } from "@/components/methodology-banner";
import { ProtocolBadge } from "@/components/protocol-badge";
import { FormattedTime, TimezoneLabel } from "@/components/timezone-provider";
import { Panel, PanelHeader } from "@/components/ui";
import { attackCategoryLabel } from "@/lib/dashboard-metrics";
import {
  formatCvss,
  formatEvidenceBasis,
  formatMatchStrength,
  formatEpss,
  formatEpssPercentile,
  formatEventTypeLabel,
  formatFingerprintLabel,
  formatUtcDate,
  resolveDisplayCategory,
  safeDisplayHttpPath,
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
  const displayCategory = resolveDisplayCategory(event.event_type, event.attack_category);
  const hasGeoOrAsn = Boolean(event.src_country) || Boolean(event.src_asn);

  return (
    <div className="space-y-5">
      <header className="flex flex-wrap items-start justify-between gap-3 border-b border-slate-200/90 pb-4">
        <div className="min-w-0">
          <Link
            href="/events"
            className="rounded text-xs font-medium text-[#632ca6] transition-colors hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#632ca6]"
          >
            ← Back to Explore
          </Link>
          <h1 className="mt-1.5 text-xl font-semibold tracking-tight text-slate-900">
            {formatEventTypeLabel(event.event_type)}
          </h1>
          <p translate="no" className="mt-0.5 break-all font-mono text-xs text-slate-500">
            {event.id}
          </p>
        </div>
        <ProtocolBadge protocol={event.protocol} />
      </header>

      <MethodologyBanner sourceMode={detail.sourceMode} />

      {/* Event Attributes */}
      <Panel>
        <PanelHeader title="Sanitized event attributes" />
        <dl className="grid divide-y divide-slate-100 text-xs sm:grid-cols-2 sm:divide-y-0">
          <div className="border-b border-slate-100 px-4 py-3 sm:border-r">
            <dt className="font-medium text-slate-500">
              Observed at (<TimezoneLabel />)
            </dt>
            <dd className="mt-1 font-mono tabular-nums text-slate-900">
              <FormattedTime iso={event.observed_at} />
            </dd>
          </div>
          <div className="border-b border-slate-100 px-4 py-3">
            <dt className="font-medium text-slate-500">Sensor ID</dt>
            <dd translate="no" className="mt-1 font-mono text-slate-900">
              {safeDisplayText(event.sensor_id)}
            </dd>
          </div>
          <div className="border-b border-slate-100 px-4 py-3 sm:border-r">
            <dt className="font-medium text-slate-500">Protocol / destination port</dt>
            <dd translate="no" className="mt-1 font-mono tabular-nums text-slate-900">
              {event.protocol.toUpperCase()} / {event.dst_port}
            </dd>
          </div>
          <div className="border-b border-slate-100 px-4 py-3">
            <dt className="font-medium text-slate-500">Category</dt>
            <dd className="mt-1 text-slate-900">{attackCategoryLabel(displayCategory)}</dd>
            <dd className="mt-1 text-[11px] text-slate-500">
              A category describes the observed request shape. It does not prove that an exploit
              succeeded.
            </dd>
          </div>
          <div className="border-b border-slate-100 px-4 py-3 sm:border-r">
            <dt className="font-medium text-slate-500">Event type</dt>
            <dd className="mt-1 text-slate-900">
              <span>{formatEventTypeLabel(event.event_type)}</span>{" "}
              <span translate="no" className="font-mono text-[11px] text-slate-500">
                ({safeDisplayText(event.event_type)})
              </span>
            </dd>
          </div>
          <div className="border-b border-slate-100 px-4 py-3">
            <dt className="font-medium text-slate-500">Approx. region / ASN</dt>
            <dd translate="no" className="mt-1 font-mono text-slate-900">
              {hasGeoOrAsn
                ? `${safeDisplayText(event.src_country)} / ${safeDisplayText(event.src_asn)}`
                : "Not collected (GeoIP disabled)"}
            </dd>
          </div>
          <div className="border-b border-slate-100 px-4 py-3 sm:col-span-2">
            <dt className="font-medium text-slate-500">Fingerprint</dt>
            <dd translate="no" className="mt-1 font-mono text-slate-900">
              {event.fingerprint ? formatFingerprintLabel(event.fingerprint) : "—"}
            </dd>
          </div>
          <div className="px-4 py-3 sm:col-span-2">
            <dt className="font-medium text-slate-500">HTTP method &amp; redacted path</dt>
            <dd
              translate="no"
              className="mt-1.5 break-all rounded-md border border-slate-200 bg-slate-50 px-3 py-2 font-mono text-xs text-slate-800"
            >
              {event.http_method ? `${safeDisplayText(event.http_method)} ` : ""}
              {safeDisplayHttpPath(event.http_path_redacted)}
            </dd>
          </div>
        </dl>
      </Panel>

      {/* Rule Detections */}
      <Panel>
        <PanelHeader
          title="Rule detections & evidence"
          subtitle="Inference: a versioned rule matched the observed request. Match strength is a rule-defined evidence grade, not a probability of exploitation."
        />
        <div className="p-4">
          {detections.length === 0 ? (
            <p className="text-xs text-slate-500">
              No additional signature detections recorded (classification:{" "}
              <code translate="no" className="font-mono text-slate-700">
                observed
              </code>{" "}
              only).
            </p>
          ) : (
            <div className="space-y-3">
              {detections.map((d) => (
                <div
                  key={d.id}
                  className="rounded-md border border-slate-200 bg-slate-50/70 p-3.5 text-xs"
                >
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <span translate="no" className="font-mono font-semibold text-slate-900">
                      {safeDisplayText(d.rule_id)}@{safeDisplayText(d.rule_version)}
                    </span>
                    <div className="flex items-center gap-3 font-mono text-[11px] tabular-nums text-slate-600">
                      <span translate="no" className="text-[#632ca6]">
                        {d.classification}
                      </span>
                      <span title="Rule-defined evidence grade (not a probability)">
                        Match strength: {formatMatchStrength(stringField(d.evidence_redacted, "match_strength"))}
                      </span>
                    </div>
                  </div>
                  <DetectionBasis evidence={d.evidence_redacted} />
                  <details className="mt-2">
                    <summary className="cursor-pointer text-[11px] text-slate-500 hover:text-slate-700">
                      Redacted evidence (raw)
                    </summary>
                    <pre
                      translate="no"
                      className="mt-2 overflow-x-auto rounded border border-slate-200 bg-white p-3 font-mono text-[11px] text-slate-700"
                    >
                      {safeDisplayText(JSON.stringify(d.evidence_redacted, null, 2))}
                    </pre>
                  </details>
                </div>
              ))}
            </div>
          )}
        </div>
      </Panel>

      {/* Candidate CVEs */}
      <Panel>
        <PanelHeader
          title="Suspected related CVEs (candidate hypothesis only)"
          subtitle="Evidence-backed candidates only — not proof of confirmed exploitation"
        />
        <div className="p-4">
          {cveMatches.length === 0 ? (
            <p className="text-xs text-slate-500">
              No evidence-backed candidate CVEs are linked to this event.
            </p>
          ) : (
            <div className="space-y-3">
              {cveMatches.map((m) => (
                <div
                  key={m.id}
                  className="rounded-md border border-slate-200 border-l-2 border-l-amber-500 bg-white p-3.5 text-xs"
                >
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <div className="flex flex-wrap items-center gap-2">
                      <span translate="no" className="font-mono text-sm font-semibold text-slate-900">
                        {safeDisplayText(m.cve_id)}
                      </span>
                      {m.vendor || m.product ? (
                        <span translate="no" className="font-mono text-[11px] text-slate-500">
                          {safeDisplayText(m.vendor)} / {safeDisplayText(m.product)}
                        </span>
                      ) : null}
                    </div>
                    <div className="flex flex-wrap items-center gap-x-3 gap-y-1 font-mono text-[11px] tabular-nums text-slate-600">
                      <span translate="no" className="text-amber-800">
                        {m.match_type} · {formatMatchStrength(m.match_strength)} match
                      </span>
                      <span
                        translate="no"
                        className={m.kev_present ? "font-medium text-red-700" : "text-slate-600"}
                      >
                        CISA KEV: {m.kev_present ? "Listed" : "Not listed"}
                        {m.kev_present && m.kev_added_at
                          ? ` (added ${formatUtcDate(m.kev_added_at)})`
                          : ""}
                      </span>
                      <span translate="no">
                        FIRST EPSS {formatEpss(m.epss_score)}
                        {m.epss_percentile !== null
                          ? ` (${formatEpssPercentile(m.epss_percentile)})`
                          : ""}
                        {m.epss_date ? ` · ${m.epss_date}` : ""}
                      </span>
                      {m.cvss_score !== null ? (
                        <span translate="no">CVSS {formatCvss(m.cvss_score)}</span>
                      ) : null}
                    </div>
                  </div>
                  <p className="mt-2 leading-relaxed text-slate-700">
                    {safeDisplayText(m.reason)}
                  </p>
                  <Link
                    href={`/events?cve=${encodeURIComponent(m.cve_id)}`}
                    className="mt-1.5 inline-block rounded text-[11px] font-medium text-[#632ca6] hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#632ca6]"
                  >
                    Other observed events with this candidate CVE →
                  </Link>
                  {m.description ? (
                    <p className="mt-2 rounded border border-slate-100 bg-slate-50 px-3 py-2 text-[11px] leading-relaxed text-slate-600">
                      <span className="font-semibold text-slate-700">NVD summary: </span>
                      {safeDisplayText(m.description)}
                    </p>
                  ) : null}
                  <dl className="mt-2.5 grid gap-2 rounded border border-slate-100 bg-slate-50/70 px-3 py-2 text-[11px] sm:grid-cols-2 lg:grid-cols-4">
                    <div>
                      <dt className="text-slate-500">Detection rule</dt>
                      <dd translate="no" className="mt-0.5 font-mono text-slate-800">
                        {safeDisplayText(m.rule_id)}@{safeDisplayText(m.rule_version)}
                      </dd>
                    </div>
                    <div>
                      <dt className="text-slate-500">Evidence basis</dt>
                      <dd translate="no" className="mt-0.5 break-words font-mono text-slate-800">
                        {safeDisplayText(formatEvidenceBasis(m.indicator, m.matched_location), "—")}
                      </dd>
                    </div>
                    <div>
                      <dt className="text-slate-500">Evaluated at</dt>
                      <dd className="mt-0.5 font-mono tabular-nums text-slate-800">
                        <FormattedTime iso={m.evaluated_at ?? m.created_at} />
                      </dd>
                    </div>
                    <div>
                      <dt className="text-slate-500">NVD published / vector</dt>
                      <dd translate="no" className="mt-0.5 truncate font-mono text-slate-800">
                        {formatUtcDate(m.published_at)}
                        {m.cvss_vector ? ` · ${safeDisplayText(m.cvss_vector)}` : ""}
                      </dd>
                    </div>
                    <div>
                      <dt className="text-slate-500">Feed dates (KEV / EPSS)</dt>
                      <dd translate="no" className="mt-0.5 font-mono tabular-nums text-slate-800">
                        KEV {formatUtcDate(m.kev_updated_at)} / EPSS {m.epss_date ?? "—"}
                      </dd>
                    </div>
                  </dl>
                  <p className="mt-2 text-[11px] leading-relaxed text-slate-500">
                    Candidate hypothesis only — not proof of exploitation. EPSS is a
                    vulnerability-level 30-day forecast from FIRST, not per-request exploit
                    probability.
                  </p>
                </div>
              ))}
            </div>
          )}
        </div>
      </Panel>
    </div>
  );
}

function stringField(record: Record<string, unknown>, key: string): string | null {
  const value = record[key];
  return typeof value === "string" ? value : null;
}

/** Why the rule matched, from the redacted evidence (inference, not observation). */
function DetectionBasis({ evidence }: { evidence: Record<string, unknown> }) {
  const basis = formatEvidenceBasis(stringField(evidence, "indicator"), stringField(evidence, "matched_location"));
  const summary = stringField(evidence, "summary");
  if (!basis && !summary) return null;
  return (
    <dl className="mt-2.5 grid gap-1 text-[11px] text-slate-700">
      {basis ? (
        <div className="flex flex-wrap gap-1">
          <dt className="text-slate-500">Evidence basis:</dt>
          <dd translate="no" className="font-mono">
            {safeDisplayText(basis)}
          </dd>
        </div>
      ) : null}
      {summary ? (
        <div className="flex flex-wrap gap-1">
          <dt className="text-slate-500">Rule rationale:</dt>
          <dd>{safeDisplayText(summary)}</dd>
        </div>
      ) : null}
    </dl>
  );
}
