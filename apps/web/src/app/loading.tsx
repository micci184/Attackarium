export default function DashboardLoading() {
  return (
    <div className="space-y-4" aria-busy="true" aria-live="polite">
      <div className="h-8 w-48 animate-pulse rounded bg-gray-200" />
      <div className="h-16 animate-pulse rounded border border-gray-200 bg-white" />
      <div className="grid grid-cols-2 gap-px overflow-hidden rounded border border-gray-200 bg-gray-200 sm:grid-cols-4">
        {Array.from({ length: 4 }, (_, index) => (
          <div key={index} className="h-24 animate-pulse bg-white" />
        ))}
      </div>
      <p className="text-xs text-gray-500">Loading observation data…</p>
    </div>
  );
}
