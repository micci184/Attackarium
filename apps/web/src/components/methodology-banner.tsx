interface MethodologyBannerProps {
  sourceMode: "mock" | "supabase";
}

export function MethodologyBanner({ sourceMode }: MethodologyBannerProps) {
  return (
    <section
      aria-label="Observation caveats"
      className="flex flex-col gap-2 rounded-lg border border-slate-200 border-l-2 border-l-[#632ca6] bg-white px-4 py-2.5 text-xs text-slate-600 sm:flex-row sm:items-center sm:justify-between sm:gap-4"
    >
      <p className="min-w-0 flex-1 leading-relaxed">
        <span className="font-semibold text-slate-900">Observation scope:</span>{" "}
        Metrics reflect unsolicited traffic observed on one low-interaction honeypot
        in US East (N. Virginia), not global Internet attack volume. Candidate CVE links are{" "}
        <span className="font-medium text-slate-900">not proof of successful exploitation</span>.
      </p>
      <span
        translate="no"
        className="inline-flex shrink-0 items-center gap-1.5 font-mono text-[11px] text-slate-600"
      >
        <span
          aria-hidden="true"
          className={`h-1.5 w-1.5 rounded-full ${
            sourceMode === "mock" ? "bg-amber-500" : "bg-emerald-600"
          }`}
        />
        {sourceMode === "mock" ? "Synthetic mock" : "Supabase public"}
      </span>
    </section>
  );
}
