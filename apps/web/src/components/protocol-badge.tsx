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

const PROTOCOL_LABELS: Record<Protocol, string> = {
  ssh: "SSH",
  http: "HTTP",
  https: "HTTPS",
  telnet: "Telnet",
  ftp: "FTP",
  mysql: "MySQL",
  redis: "Redis",
  other: "Other",
};

export function ProtocolBadge({ protocol }: { protocol: Protocol }) {
  return (
    <span
      translate="no"
      className="inline-flex items-center gap-1.5 font-mono text-xs font-medium text-slate-700"
    >
      <span
        aria-hidden="true"
        className="h-2 w-2 shrink-0 rounded-full"
        style={{ backgroundColor: PROTOCOL_COLORS[protocol] }}
      />
      {PROTOCOL_LABELS[protocol]}
    </span>
  );
}
