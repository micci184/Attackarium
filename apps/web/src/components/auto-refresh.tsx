"use client";

import { useRouter } from "next/navigation";
import { useEffect, useState, useTransition } from "react";

interface AutoRefreshProps {
  intervalSeconds?: number;
}

export function AutoRefresh({ intervalSeconds = 30 }: AutoRefreshProps) {
  const router = useRouter();
  const [enabled, setEnabled] = useState(false);
  const [isPending, startTransition] = useTransition();

  useEffect(() => {
    if (!enabled) return;
    const id = window.setInterval(() => {
      startTransition(() => {
        router.refresh();
      });
    }, intervalSeconds * 1000);
    return () => window.clearInterval(id);
  }, [enabled, intervalSeconds, router]);

  const handleManualRefresh = () => {
    startTransition(() => {
      router.refresh();
    });
  };

  return (
    <div className="inline-flex items-center overflow-hidden rounded-lg border border-slate-200 bg-white text-xs shadow-[0_1px_2px_rgba(15,23,42,0.03)]">
      <button
        type="button"
        aria-pressed={enabled}
        onClick={() => setEnabled((prev) => !prev)}
        className={`flex items-center gap-1.5 border-r border-slate-200 px-2.5 py-1.5 font-medium transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-[#632ca6] ${
          enabled
            ? "bg-[#f4effa] text-[#632ca6]"
            : "text-slate-600 hover:bg-slate-50 hover:text-slate-900"
        }`}
      >
        <span
          aria-hidden="true"
          className={`h-1.5 w-1.5 rounded-full ${
            enabled ? "bg-[#632ca6]" : "bg-slate-300"
          }`}
        />
        {enabled ? `Live (${intervalSeconds}s)` : "Auto-refresh"}
      </button>
      <button
        type="button"
        disabled={isPending}
        onClick={handleManualRefresh}
        className="px-2.5 py-1.5 font-medium text-slate-700 transition-colors hover:bg-slate-50 hover:text-slate-900 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-[#632ca6] disabled:opacity-50"
      >
        {isPending ? "Updating…" : "Refresh"}
      </button>
      <span className="sr-only" aria-live="polite">
        {isPending
          ? "Updating dashboard data…"
          : enabled
            ? `Auto-refresh enabled every ${intervalSeconds} seconds`
            : "Auto-refresh disabled"}
      </span>
    </div>
  );
}
