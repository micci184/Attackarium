"use client";

import type { ReactNode } from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";

interface NavItem {
  href: string;
  label: string;
  desc: string;
  icon: ReactNode;
}

const NAV_ITEMS: readonly NavItem[] = [
  {
    href: "/",
    label: "Overview",
    desc: "24h summary & signals",
    icon: (
      <svg aria-hidden="true" viewBox="0 0 16 16" fill="none" className="h-4 w-4 shrink-0">
        <rect x="2" y="2" width="5" height="5" rx="1" stroke="currentColor" strokeWidth="1.4" />
        <rect x="9" y="2" width="5" height="5" rx="1" stroke="currentColor" strokeWidth="1.4" />
        <rect x="2" y="9" width="5" height="5" rx="1" stroke="currentColor" strokeWidth="1.4" />
        <rect x="9" y="9" width="5" height="5" rx="1" stroke="currentColor" strokeWidth="1.4" />
      </svg>
    ),
  },
  {
    href: "/trends",
    label: "Trends",
    desc: "Rollups, patterns & CVEs",
    icon: (
      <svg aria-hidden="true" viewBox="0 0 16 16" fill="none" className="h-4 w-4 shrink-0">
        <path d="M2.5 12.5h11" stroke="currentColor" strokeWidth="1.4" strokeLinecap="round" />
        <path d="M3.5 10l3-3 2.5 2 3.5-4.5" stroke="currentColor" strokeWidth="1.4" strokeLinecap="round" strokeLinejoin="round" />
      </svg>
    ),
  },
  {
    href: "/events",
    label: "Events",
    desc: "Sanitized log explorer",
    icon: (
      <svg aria-hidden="true" viewBox="0 0 16 16" fill="none" className="h-4 w-4 shrink-0">
        <path d="M3 4h10M3 8h10M3 12h6" stroke="currentColor" strokeWidth="1.4" strokeLinecap="round" />
      </svg>
    ),
  },
  {
    href: "/sensors",
    label: "Sensors",
    desc: "Health & coverage gaps",
    icon: (
      <svg aria-hidden="true" viewBox="0 0 16 16" fill="none" className="h-4 w-4 shrink-0">
        <circle cx="8" cy="8" r="2" stroke="currentColor" strokeWidth="1.4" />
        <path d="M4.8 11.2a4.5 4.5 0 0 1 0-6.4M11.2 4.8a4.5 4.5 0 0 1 0 6.4" stroke="currentColor" strokeWidth="1.4" strokeLinecap="round" />
      </svg>
    ),
  },
];

export function NavHeader() {
  const pathname = usePathname();

  return (
    <aside className="sticky top-0 z-30 border-b border-slate-200 bg-white/95 backdrop-blur supports-[backdrop-filter]:bg-white/90 lg:flex lg:h-screen lg:w-60 lg:shrink-0 lg:flex-col lg:border-b-0 lg:border-r lg:bg-white">
      <div className="flex flex-col gap-2.5 px-4 py-3 lg:border-b lg:border-slate-200 lg:py-4">
        <div className="flex items-center justify-between gap-3">
          <Link
            href="/"
            className="flex min-w-0 items-center gap-2.5 rounded-md focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#632ca6] focus-visible:ring-offset-2"
          >
            <span
              aria-hidden="true"
              className="flex h-8 w-8 shrink-0 items-center justify-center rounded-md bg-[#632ca6] text-xs font-bold tracking-tight text-white shadow-xs"
            >
              AT
            </span>
            <div className="min-w-0 leading-tight">
              <div
                translate="no"
                className="truncate text-sm font-semibold tracking-tight text-slate-900"
              >
                Attackarium
              </div>
              <div translate="no" className="truncate text-[11px] font-medium text-slate-500">
                Honeypot Observatory
              </div>
            </div>
          </Link>

          <span
            translate="no"
            className="rounded-full border border-slate-200 bg-slate-50 px-2 py-0.5 font-mono text-[10px] font-medium text-slate-600 lg:hidden"
          >
            us-east-1
          </span>
        </div>

        {/* Mobile scrollable pill nav */}
        <nav
          aria-label="Mobile navigation"
          className="-mx-1 flex items-center gap-1 overflow-x-auto px-1 pb-0.5 lg:hidden"
        >
          {NAV_ITEMS.map((item) => {
            const isActive =
              item.href === "/"
                ? pathname === "/"
                : pathname === item.href || pathname.startsWith(`${item.href}/`);
            return (
              <Link
                key={item.href}
                href={item.href}
                aria-current={isActive ? "page" : undefined}
                className={`inline-flex shrink-0 items-center gap-1.5 rounded-md px-2.5 py-1.5 text-xs font-medium transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#632ca6] ${
                  isActive
                    ? "bg-[#f4effa] text-[#632ca6] ring-1 ring-inset ring-[#d8c4f0]"
                    : "text-slate-600 hover:bg-slate-100 hover:text-slate-900"
                }`}
              >
                {item.icon}
                <span>{item.label}</span>
              </Link>
            );
          })}
        </nav>
      </div>

      {/* Desktop sidebar nav */}
      <nav
        aria-label="Main navigation"
        className="hidden flex-1 flex-col justify-between p-3 lg:flex"
      >
        <div className="space-y-4">
          <div>
            <p className="px-2.5 pb-2 text-[11px] font-semibold uppercase tracking-wider text-slate-500">
              Observatory
            </p>
            <ul className="space-y-1">
              {NAV_ITEMS.map((item) => {
                const isActive =
                  item.href === "/"
                    ? pathname === "/"
                    : pathname === item.href || pathname.startsWith(`${item.href}/`);
                return (
                  <li key={item.href}>
                    <Link
                      href={item.href}
                      aria-current={isActive ? "page" : undefined}
                      className={`group flex items-start gap-2.5 rounded-md px-2.5 py-2 transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#632ca6] ${
                        isActive
                          ? "bg-[#f4effa] text-[#632ca6] ring-1 ring-inset ring-[#d8c4f0]"
                          : "text-slate-700 hover:bg-slate-100 hover:text-slate-900"
                      }`}
                    >
                      <span
                        className={`mt-0.5 ${
                          isActive ? "text-[#632ca6]" : "text-slate-400 group-hover:text-slate-600"
                        }`}
                      >
                        {item.icon}
                      </span>
                      <span className="min-w-0">
                        <span className="block text-sm font-medium leading-tight">
                          {item.label}
                        </span>
                        <span
                          className={`mt-0.5 block text-[11px] leading-tight ${
                            isActive ? "text-[#632ca6]/80" : "text-slate-500"
                          }`}
                        >
                          {item.desc}
                        </span>
                      </span>
                    </Link>
                  </li>
                );
              })}
            </ul>
          </div>
        </div>

        <div className="rounded-lg border border-slate-200/90 bg-slate-50/80 p-3 text-[11px] text-slate-600">
          <div className="flex items-center justify-between gap-2">
            <span className="font-medium text-slate-700">Data Policy</span>
            <span className="rounded bg-white px-1.5 py-0.5 font-mono text-[10px] font-medium text-slate-700 ring-1 ring-inset ring-slate-200">
              Redacted Only
            </span>
          </div>
          <p className="mt-1.5 leading-relaxed text-slate-500">
            Source IPs, query values, credentials, and raw payloads are excluded from public views.
          </p>
        </div>
      </nav>
    </aside>
  );
}
