import Link from "next/link";
import { TREND_PERIODS, type TrendPeriod } from "@/lib/types";

const LABELS: Record<TrendPeriod, string> = {
  "24h": "24h",
  "7d": "7d",
  "30d": "30d",
};

export function PeriodNav({ period }: { period: TrendPeriod }) {
  return (
    <nav aria-label="Trend window" className="inline-flex rounded border border-gray-200 bg-white p-0.5">
      {TREND_PERIODS.map((item) => {
        const selected = item === period;
        return (
          <Link
            key={item}
            href={`/trends?period=${item}`}
            aria-current={selected ? "true" : undefined}
            className={`rounded px-2.5 py-1 font-mono text-xs focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#632ca6] ${
              selected ? "bg-[#f4effa] font-semibold text-[#632ca6]" : "text-gray-600 hover:bg-gray-100"
            }`}
          >
            {LABELS[item]}
          </Link>
        );
      })}
    </nav>
  );
}
