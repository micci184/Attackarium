interface MethodologyBannerProps {
  sourceMode: "mock" | "supabase";
  sensorCount?: number;
}

export function MethodologyBanner({ sourceMode, sensorCount = 1 }: MethodologyBannerProps) {
  const sensorLabel = sensorCount === 1 ? "1 sensor" : `${sensorCount} sensors`;
  return (
    <details className="group rounded-lg border border-slate-200 bg-white px-3.5 py-2 text-xs text-slate-600">
      <summary className="flex cursor-pointer list-none flex-wrap items-center justify-between gap-2 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#632ca6] focus-visible:ring-offset-2 [&::-webkit-details-marker]:hidden">
        <span className="flex flex-wrap items-center gap-x-2 gap-y-0.5">
          <span className="font-medium text-slate-800">Observation scope:</span>
          <span>{sensorLabel} · US East (N. Virginia) · Low-interaction honeypot</span>
          <span className="text-slate-400" aria-hidden="true">·</span>
          <span className="text-slate-500">Not global traffic; CVE tags are not proof of exploitation</span>
        </span>
        <span className="inline-flex items-center gap-2 text-[11px] font-medium text-[#632ca6]">
          {sourceMode === "mock" ? (
            <span className="font-mono text-amber-700">Synthetic preview</span>
          ) : null}
          <span className="group-open:hidden">Methodology</span>
          <span className="hidden group-open:inline">Hide details</span>
        </span>
      </summary>
      <div className="mt-2.5 border-t border-slate-100 pt-2.5 text-xs leading-relaxed text-slate-600">
        <p>
          Metrics reflect unsolicited Internet probes observed on operator-managed
          low-interaction decoys in US East (N. Virginia), not global Internet attack
          volume. Source IPs, HTTP query values, credentials, and raw payloads are
          excluded from public views and are never stored in Supabase. Candidate
          CVE, KEV, and EPSS links provide analytical context and are{" "}
          <strong className="font-medium text-slate-900">
            not proof of successful exploitation
          </strong>
          .
        </p>
        <p className="mt-2 text-slate-500">
          Retention &amp; abuse notices: Raw sensor logs on EC2 are deleted within
          24 hours; sanitized events are retained for at least 30 days and daily
          aggregates for at least 1 year. For security or abuse inquiries, contact
          the operator via the public{" "}
          <a
            href="https://github.com/micci184/Attackarium/security"
            target="_blank"
            rel="noopener noreferrer"
            className="text-[#632ca6] underline hover:text-[#53238d]"
          >
            Attackarium GitHub Security page
          </a>{" "}
          (AWS infrastructure abuse notices are routed to the registered AWS
          account owner).
        </p>
        <p className="mt-2 text-slate-500">
          Site analytics: public pages are counted with cookieless, aggregate-only
          Vercel Web Analytics (page path, country, referrer, browser, and device
          type). Query strings are dropped, and sign-in, consent, and operator pages
          are never counted.
        </p>
      </div>
    </details>
  );
}
