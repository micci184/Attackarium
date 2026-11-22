export function BrandMark({ className = "h-7 w-7 shrink-0" }: { className?: string }) {
  return (
    <svg
      aria-hidden="true"
      viewBox="0 0 32 32"
      fill="none"
      className={className}
    >
      {/* Observation baseline */}
      <path
        d="M5 25.5H27"
        stroke="#94a3b8"
        strokeWidth="1.75"
        strokeLinecap="round"
      />
      {/* Geometric A-prism (observatory spire / signal beam) */}
      <path
        d="M8.5 25.5L16 7.5L23.5 25.5"
        stroke="#0f172a"
        strokeWidth="2.4"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
      {/* Measurement crossbar */}
      <path
        d="M11.6 19H20.4"
        stroke="#0f172a"
        strokeWidth="2"
        strokeLinecap="round"
      />
      {/* Single observed signal point */}
      <circle cx="16" cy="7.5" r="2.7" fill="#632ca6" />
    </svg>
  );
}
