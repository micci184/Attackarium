import type { ReactNode } from "react";

export function PageHeader({
  title,
  description,
  meta,
  actions,
}: {
  title: string;
  description: string;
  meta?: ReactNode;
  actions?: ReactNode;
}) {
  return (
    <header className="flex flex-col gap-3 border-b border-slate-200/90 pb-4 sm:flex-row sm:items-start sm:justify-between">
      <div className="min-w-0">
        <h1 className="text-xl font-semibold tracking-tight text-slate-900">
          {title}
        </h1>
        <p className="mt-1 text-sm text-slate-600">{description}</p>
        {meta ? <div className="mt-2.5">{meta}</div> : null}
      </div>
      {actions ? (
        <div className="flex shrink-0 flex-wrap items-center gap-2">{actions}</div>
      ) : null}
    </header>
  );
}

export function Panel({
  children,
  className = "",
  ariaLabel,
}: {
  children: ReactNode;
  className?: string;
  ariaLabel?: string;
}) {
  return (
    <section
      aria-label={ariaLabel}
      className={`overflow-hidden rounded-lg border border-slate-200 bg-white shadow-[0_1px_2px_rgba(15,23,42,0.04)] ${className}`}
    >
      {children}
    </section>
  );
}

export function PanelHeader({
  title,
  subtitle,
  action,
}: {
  title: string;
  subtitle?: string;
  action?: ReactNode;
}) {
  return (
    <div className="flex flex-wrap items-center justify-between gap-2 border-b border-slate-200/90 bg-slate-50/60 px-4 py-3">
      <div className="min-w-0">
        <h2 className="text-xs font-semibold uppercase tracking-wider text-slate-700">
          {title}
        </h2>
        {subtitle ? (
          <p className="mt-0.5 text-xs text-slate-500">{subtitle}</p>
        ) : null}
      </div>
      {action ? <div className="flex shrink-0 items-center gap-2">{action}</div> : null}
    </div>
  );
}

export function Callout({
  tone = "info",
  title,
  children,
  action,
  ariaLabel,
}: {
  tone?: "info" | "warning";
  title?: string;
  children: ReactNode;
  action?: ReactNode;
  ariaLabel?: string;
}) {
  const styles =
    tone === "warning"
      ? "border-amber-300/90 bg-amber-50/90 text-amber-950"
      : "border-slate-200 border-l-2 border-l-[#632ca6] bg-white text-slate-700";

  return (
    <section
      aria-label={ariaLabel}
      className={`flex flex-wrap items-center justify-between gap-3 rounded-lg border px-4 py-3 text-xs shadow-[0_1px_2px_rgba(15,23,42,0.03)] ${styles}`}
    >
      <div className="min-w-0 flex-1 leading-relaxed">
        {title ? <p className="font-semibold">{title}</p> : null}
        <div className={title ? "mt-0.5" : undefined}>{children}</div>
      </div>
      {action ? <div className="shrink-0">{action}</div> : null}
    </section>
  );
}
