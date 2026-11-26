import type { Metadata, Viewport } from "next";
import { NavHeader } from "@/components/nav-header";
import { PrivacyAnalytics } from "@/components/privacy-analytics";
import { TimezoneProvider } from "@/components/timezone-provider";
import "./globals.css";

export const metadata: Metadata = {
  title: "Attackarium — Threat Observatory",
  description:
    "Noncommercial threat observatory publishing sanitized honeypot telemetry and trends.",
};

export const viewport: Viewport = {
  themeColor: "#f5f7fa",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <body className="min-h-screen overflow-x-hidden bg-[#f5f7fa] text-slate-900 antialiased">
        <a
          href="#main-content"
          className="sr-only focus:not-sr-only focus:fixed focus:left-4 focus:top-4 focus:z-50 focus:rounded-md focus:bg-[#632ca6] focus:px-3.5 py-2 focus:text-sm focus:font-medium focus:text-white focus:outline-none focus:ring-2 focus:ring-[#632ca6] focus:ring-offset-2"
        >
          Skip to main content
        </a>

        <TimezoneProvider>
          <div className="flex min-h-screen flex-col lg:flex-row">
            <NavHeader />

            <div className="flex min-w-0 flex-1 flex-col">
              <main
                id="main-content"
                tabIndex={-1}
                className="mx-auto w-full max-w-[1380px] flex-1 px-4 py-6 focus:outline-none sm:px-6 lg:px-8"
              >
                {children}
              </main>

              <footer className="border-t border-slate-200 bg-white px-4 py-4 text-xs text-slate-600 sm:px-6 lg:px-8">
                <div className="mx-auto flex max-w-[1380px] flex-wrap items-center justify-between gap-2">
                  <span>
                    <span translate="no" className="font-semibold text-slate-800">
                      Attackarium
                    </span>{" "}
                    — Noncommercial Threat Observatory
                  </span>
                  <span className="text-slate-500">
                    Observations reflect unsolicited sensor probes only and do not prove
                    successful exploitation.
                  </span>
                </div>
              </footer>
            </div>
          </div>
        </TimezoneProvider>
        <PrivacyAnalytics />
      </body>
    </html>
  );
}
