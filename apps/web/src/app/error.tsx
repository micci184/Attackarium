"use client";

export default function DashboardError({
  reset,
}: {
  error: Error & { digest?: string };
  reset: () => void;
}) {
  return (
    <div role="alert" className="rounded border border-red-200 bg-white p-4">
      <h1 className="text-sm font-semibold text-gray-900">Observation data is unavailable</h1>
      <p className="mt-1 text-xs leading-relaxed text-gray-600">
        The public dashboard could not load sanitized observations. Nothing on this page should be read as an attack trend.
      </p>
      <button
        type="button"
        onClick={reset}
        className="mt-3 rounded border border-gray-300 px-3 py-1.5 text-xs font-medium text-gray-800 hover:bg-gray-50 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#632ca6]"
      >
        Try again
      </button>
    </div>
  );
}
