import Link from "next/link";
import { ProtocolBadge } from "@/components/protocol-badge";
import { formatCount, safeDisplayText } from "@/lib/format";
import type { HttpPathTotal, PatternTotal } from "@/lib/types";

export function PatternLists({
  patterns,
  httpPaths,
  sampledNote,
}: {
  patterns: PatternTotal[];
  httpPaths: HttpPathTotal[];
  sampledNote: string | null;
}) {
  return (
    <div className="grid gap-4 lg:grid-cols-2">
      <section className="rounded border border-gray-200 bg-white">
        <div className="border-b border-gray-200 px-4 py-3">
          <h2 className="text-xs font-semibold uppercase tracking-wider text-gray-700">
            Observed Patterns
          </h2>
        </div>
        <div className="p-4">
          {patterns.length === 0 ? (
            <p className="text-xs text-gray-500">No attack patterns stored in this window.</p>
          ) : (
            <ol className="divide-y divide-gray-100">
              {patterns.map((pattern) => (
                <li key={pattern.key} className="flex items-center justify-between gap-3 py-2 text-xs">
                  <div className="flex min-w-0 items-center gap-2">
                    <ProtocolBadge protocol={pattern.protocol} />
                    {pattern.eventsHref ? (
                      <Link
                        href={pattern.eventsHref}
                        className="truncate rounded text-gray-800 hover:text-[#632ca6] hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#632ca6]"
                      >
                        {safeDisplayText(pattern.label)}
                      </Link>
                    ) : (
                      <span className="truncate text-gray-800">{safeDisplayText(pattern.label)}</span>
                    )}
                  </div>
                  <span className="font-mono tabular-nums text-gray-900">{formatCount(pattern.count)}</span>
                </li>
              ))}
            </ol>
          )}
        </div>
      </section>

      <section className="rounded border border-gray-200 bg-white">
        <div className="border-b border-gray-200 px-4 py-3">
          <h2 className="text-xs font-semibold uppercase tracking-wider text-gray-700">
            Representative HTTP Paths
          </h2>
        </div>
        <div className="p-4">
          <p className="pb-2 text-[11px] leading-relaxed text-gray-500">
            Paths are sanitized before storage. A repeated path is a probe pattern, not proof that a request succeeded.
          </p>
          {httpPaths.length === 0 ? (
            <p className="text-xs text-gray-500">No sanitized HTTP paths stored in this window.</p>
          ) : (
            <ol className="divide-y divide-gray-100">
              {httpPaths.map((item) => (
                <li
                  key={`${item.method} ${item.path}`}
                  className="flex items-center justify-between gap-3 py-2 text-xs"
                >
                  <span translate="no" className="min-w-0 truncate font-mono text-gray-800">
                    {safeDisplayText(item.method)} {safeDisplayText(item.path)}
                  </span>
                  <span className="font-mono tabular-nums text-gray-900">{formatCount(item.count)}</span>
                </li>
              ))}
            </ol>
          )}
          {sampledNote ? <p className="mt-3 text-[11px] text-gray-500">{sampledNote}</p> : null}
        </div>
      </section>
    </div>
  );
}
