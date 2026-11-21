import type { Metadata, Viewport } from "next";
import { NavHeader } from "@/components/nav-header";
import "./globals.css";

export const metadata: Metadata = {
  title: "Attackarium — Honeypot Observatory",
  description:
    "Noncommercial attack observatory publishing sanitized honeypot telemetry and trends.",
};

export const viewport: Viewport = {
  themeColor: "#f7f8fa",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <body className="min-h-screen overflow-x-hidden bg-[#f7f8fa] text-gray-900 antialiased">
        <a
          href="#main-content"
          className="sr-only focus:not-sr-only focus:fixed focus:left-4 focus:top-4 focus:z-50 focus:rounded focus:bg-[#632ca6] focus:px-3 py-2 focus:text-sm focus:font-medium focus:text-white focus:outline-none focus:ring-2 focus:ring-[#632ca6] focus:ring-offset-2"
        >
          Skip to main content
        </a>

        <div className="flex min-h-screen flex-col lg:flex-row">
          <NavHeader />

          <div className="flex min-w-0 flex-1 flex-col">
            <main
              id="main-content"
              tabIndex={-1}
              className="mx-auto w-full max-w-[1360px] flex-1 px-4 py-5 focus:outline-none sm:px-6 lg:px-8"
            >
              {children}
            </main>

            <footer className="border-t border-gray-200 bg-white px-4 py-3.5 text-xs text-gray-500 sm:px-6 lg:px-8">
              <div className="mx-auto flex max-w-[1360px] flex-wrap items-center justify-between gap-2">
                <span>
                  <span translate="no" className="font-medium text-gray-700">
                    Attackarium
                  </span>{" "}
                  — Noncommercial Honeypot Observatory
                </span>
                <span>
                  Observations reflect unsolicited sensor probes only and do not prove
                  successful exploitation.
                </span>
              </div>
            </footer>
          </div>
        </div>
      </body>
    </html>
  );
}
