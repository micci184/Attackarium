interface MethodologyBannerProps {
  sourceMode: "mock" | "supabase";
}

export function MethodologyBanner({ sourceMode }: MethodologyBannerProps) {
  return (
    <section
      aria-label="Observation caveats"
      className="flex flex-wrap items-center justify-between gap-3 rounded border border-gray-200 border-l-2 border-l-[#632ca6] bg-white px-3.5 py-2.5 text-xs text-gray-600"
    >
      <p className="min-w-0 flex-1 leading-relaxed">
        <span className="font-semibold text-gray-900">Observation Scope:</span>{" "}
        Metrics reflect unsolicited traffic observed on one low-interaction honeypot
        in US East (N. Virginia), not global Internet attack volume. Candidate CVE links are{" "}
        <span className="font-medium text-gray-900">not proof of successful exploitation</span>.
      </p>
      <span
        translate="no"
        className="inline-flex shrink-0 items-center gap-1.5 rounded border border-gray-200 bg-gray-50 px-2 py-0.5 font-mono text-[11px] text-gray-700"
      >
        <span
          aria-hidden="true"
          className={`h-1.5 w-1.5 rounded-full ${
            sourceMode === "mock" ? "bg-amber-500" : "bg-emerald-600"
          }`}
        />
        {sourceMode === "mock" ? "Synthetic Mock" : "Supabase Public"}
      </span>
    </section>
  );
}
