import type { Protocol } from "@/lib/types";

export const PROTOCOL_COLORS: Record<Protocol, string> = {
  ssh: "#2563eb",
  http: "#632ca6",
  https: "#0d9488",
  telnet: "#dc2626",
  ftp: "#d97706",
  mysql: "#0284c7",
  redis: "#ea580c",
  other: "#64748b",
};

const PROTOCOL_BADGE_STYLES: Record<Protocol, string> = {
  ssh: "border-blue-200 bg-blue-50 text-blue-700",
  http: "border-purple-200 bg-purple-50 text-[#632ca6]",
  https: "border-teal-200 bg-teal-50 text-teal-700",
  telnet: "border-red-200 bg-red-50 text-red-700",
  ftp: "border-amber-200 bg-amber-50 text-amber-800",
  mysql: "border-sky-200 bg-sky-50 text-sky-700",
  redis: "border-orange-200 bg-orange-50 text-orange-700",
  other: "border-gray-200 bg-gray-100 text-gray-700",
};

export function ProtocolBadge({ protocol }: { protocol: Protocol }) {
  return (
    <span
      translate="no"
      className={`inline-flex items-center gap-1.5 rounded border px-1.5 py-0.5 font-mono text-[11px] font-medium uppercase leading-none ${PROTOCOL_BADGE_STYLES[protocol]}`}
    >
      <span
        aria-hidden="true"
        className="h-1.5 w-1.5 rounded-full"
        style={{ backgroundColor: PROTOCOL_COLORS[protocol] }}
      />
      {protocol}
    </span>
  );
}
