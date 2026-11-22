"use client";

import type { ReactNode } from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { BrandMark } from "@/components/brand-mark";

interface NavItem {
  href: string;
  label: string;
  icon: ReactNode;
}

const NAV_ITEMS: readonly NavItem[] = [
  {
    href: "/",
    label: "Activity",
    icon: (
      <svg aria-hidden="true" viewBox="0 0 16 16" fill="none" className="h-4 w-4 shrink-0">
        <path
          d="M2 9.5h2.5l1.8-4.5 2.4 7 1.8-3.5H14"
          stroke="currentColor"
          strokeWidth="1.5"
          strokeLinecap="round"
          strokeLinejoin="round"
        />
      </svg>
    ),
  },
  {
    href: "/trends",
    label: "Trends",
    icon: (
      <svg aria-hidden="true" viewBox="0 0 16 16" fill="none" className="h-4 w-4 shrink-0">
        <path d="M2.5 12.5h11" stroke="currentColor" strokeWidth="1.4" strokeLinecap="round" />
        <path
          d="M3.5 10l3-3 2.5 2 3.5-4.5"
          stroke="currentColor"
          strokeWidth="1.5"
          strokeLinecap="round"
          strokeLinejoin="round"
        />
      </svg>
    ),
  },
  {
    href: "/events",
    label: "Explore",
    icon: (
      <svg aria-hidden="true" viewBox="0 0 16 16" fill="none" className="h-4 w-4 shrink-0">
        <circle cx="7" cy="7" r="4.2" stroke="currentColor" strokeWidth="1.4" />
        <path d="M10.2 10.2L13.5 13.5" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" />
      </svg>
    ),
  },
  {
    href: "/sensors",
    label: "Coverage",
    icon: (
      <svg aria-hidden="true" viewBox="0 0 16 16" fill="none" className="h-4 w-4 shrink-0">
        <circle cx="8" cy="8" r="2" stroke="currentColor" strokeWidth="1.4" />
        <path
          d="M4.8 11.2a4.5 4.5 0 0 1 0-6.4M11.2 4.8a4.5 4.5 0 0 1 0 6.4"
          stroke="currentColor"
          strokeWidth="1.4"
          strokeLinecap="round"
        />
      </svg>
    ),
  },
];

export function NavHeader() {
  const pathname = usePathname();

  return (
    <aside className="sticky top-0 z-30 border-b border-slate-200 bg-white/95 backdrop-blur supports-[backdrop-filter]:bg-white/90 lg:flex lg:h-screen lg:w-56 lg:shrink-0 lg:flex-col lg:border-b-0 lg:border-r lg:bg-white">
      <div className="flex flex-col gap-2.5 px-4 py-3 lg:border-b lg:border-slate-200 lg:py-4">
        <div className="flex items-center justify-between gap-3">
          <Link
            href="/"
            className="flex min-w-0 items-center gap-2.5 rounded-md pr-1 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#632ca6] focus-visible:ring-offset-2"
          >
            <BrandMark className="h-7 w-7 shrink-0" />
            <div className="min-w-0 leading-tight">
              <div
                translate="no"
                className="text-[15px] font-semibold tracking-tight text-slate-900"
              >
                Attackarium
              </div>
              <div translate="no" className="text-[11px] text-slate-500">
                Threat Observatory
              </div>
            </div>
          </Link>

          <span
            translate="no"
            className="font-mono text-[11px] text-slate-500 lg:hidden"
          >
            us-east-1
          </span>
        </div>

        {/* Mobile navigation */}
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
                    ? "bg-[#f4effa] text-[#632ca6]"
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

      {/* Desktop sidebar navigation */}
      <nav
        aria-label="Main navigation"
        className="hidden flex-1 flex-col justify-between p-3 lg:flex"
      >
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
                  className={`group flex items-center gap-2.5 rounded-md px-2.5 py-2 text-sm font-medium transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#632ca6] ${
                    isActive
                      ? "bg-[#f4effa] text-[#632ca6]"
                      : "text-slate-700 hover:bg-slate-100 hover:text-slate-900"
                  }`}
                >
                  <span
                    className={
                      isActive ? "text-[#632ca6]" : "text-slate-400 group-hover:text-slate-600"
                    }
                  >
                    {item.icon}
                  </span>
                  <span>{item.label}</span>
                </Link>
              </li>
            );
          })}
        </ul>

        <div className="border-t border-slate-200 pt-3 text-xs text-slate-500">
          <div className="flex items-center justify-between gap-2 px-1">
            <span className="font-medium text-slate-700">Public dataset</span>
            <span className="font-mono text-[11px] text-slate-500">Sanitized</span>
          </div>
          <p className="mt-1.5 px-1 text-[11px] leading-relaxed text-slate-500">
            Source IPs, query values, credentials, and raw payloads are excluded.
          </p>
        </div>
      </nav>
    </aside>
  );
}
