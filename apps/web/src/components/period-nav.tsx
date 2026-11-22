import Link from "next/link";
import { TREND_PERIODS, type TrendPeriod } from "@/lib/types";

const LABELS: Record<TrendPeriod, string> = {
  "24h": "24h",
  "7d": "7d",
  "30d": "30d",
};

export function PeriodNav({ period }: { period: TrendPeriod }) {
  return (
    <nav
      aria-label="Trend window"
      className="inline-flex rounded-lg border border-slate-200 bg-white p-0.5 shadow-[0_1px_2px_rgba(15,23,42,0.03)]"
    >
      {TREND_PERIODS.map((item) => {
        const selected = item === period;
        return (
          <Link
            key={item}
            href={`/trends?period=${item}`}
            aria-current={selected ? "true" : undefined}
            className={`rounded-md px-3 py-1.5 font-mono text-xs transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#632ca6] ${
              selected
                ? "bg-[#f4effa] font-semibold text-[#632ca6] ring-1 ring-inset ring-[#d8c4f0]"
                : "text-slate-600 hover:bg-slate-100 hover:text-slate-900"
            }`}
          >
            {LABELS[item]}
          </Link>
        );
      })}
    </nav>
  );
}
