"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";

const NAV_ITEMS = [
  { href: "/", label: "Overview", desc: "24h summary & sensors" },
  { href: "/trends", label: "Trends", desc: "Daily rollups & top lists" },
  { href: "/events", label: "Events", desc: "Sanitized log explorer" },
  { href: "/sensors", label: "Sensors", desc: "Health & coverage gaps" },
] as const;

export function NavHeader() {
  const pathname = usePathname();

  return (
    <aside className="border-b border-gray-200 bg-white lg:sticky lg:top-0 lg:flex lg:h-screen lg:w-56 lg:shrink-0 lg:flex-col lg:border-b-0 lg:border-r">
      <div className="flex items-center justify-between gap-3 px-4 py-3.5 lg:border-b lg:border-gray-200">
        <Link
          href="/"
          className="flex min-w-0 items-center gap-2.5 rounded focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#632ca6]"
        >
          <span
            aria-hidden="true"
            className="flex h-7 w-7 shrink-0 items-center justify-center rounded bg-[#632ca6] text-xs font-semibold text-white"
          >
            A
          </span>
          <div className="min-w-0 leading-tight">
            <div
              translate="no"
              className="truncate text-sm font-semibold tracking-tight text-gray-900"
            >
              Attackarium
            </div>
            <div translate="no" className="truncate text-[11px] text-gray-500">
              Observatory
            </div>
          </div>
        </Link>

        {/* Mobile inline nav */}
        <nav
          aria-label="Mobile navigation"
          className="flex items-center gap-1 lg:hidden"
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
                className={`rounded px-2.5 py-1.5 text-xs font-medium transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#632ca6] ${
                  isActive
                    ? "bg-[#f4effa] text-[#632ca6]"
                    : "text-gray-600 hover:bg-gray-100 hover:text-gray-900"
                }`}
              >
                {item.label}
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
            <p className="px-2.5 pb-1.5 text-[11px] font-semibold uppercase tracking-wider text-gray-400">
              Monitoring
            </p>
            <ul className="space-y-0.5">
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
                      className={`group flex flex-col rounded px-2.5 py-2 transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#632ca6] ${
                        isActive
                          ? "border-l-2 border-[#632ca6] bg-[#f4effa] pl-2 text-[#632ca6]"
                          : "text-gray-700 hover:bg-gray-100 hover:text-gray-900"
                      }`}
                    >
                      <span className="text-sm font-medium leading-none">
                        {item.label}
                      </span>
                      <span
                        className={`mt-1 text-[11px] leading-none ${
                          isActive ? "text-[#632ca6]/80" : "text-gray-400"
                        }`}
                      >
                        {item.desc}
                      </span>
                    </Link>
                  </li>
                );
              })}
            </ul>
          </div>
        </div>

        <div className="border-t border-gray-200 pt-3 text-[11px] text-gray-500">
          <div className="flex items-center justify-between px-1">
            <span>Privacy Policy</span>
            <span className="font-mono text-gray-700">Redacted Only</span>
          </div>
          <p className="mt-1.5 px-1 leading-relaxed text-gray-400">
            Raw IPs, credentials, and payloads are excluded from public views.
          </p>
        </div>
      </nav>
    </aside>
  );
}
