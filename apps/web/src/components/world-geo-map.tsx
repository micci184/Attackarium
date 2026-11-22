"use client";

import { useState } from "react";
import { Panel, PanelHeader } from "@/components/ui";
import type { WorldMapData } from "@/lib/world-map";

interface WorldGeoMapProps {
  data: WorldMapData;
  title?: string;
  subtitle?: string;
}

const SCALE_COLORS = [
  "#eef0f4", // 0 (no observations)
  "#e4d5f5", // low
  "#c6a4ea", // medium-low
  "#9e6cd8", // medium-high
  "#7c3fc2", // high
  "#632ca6", // peak
] as const;

function getFillColor(count: number, maxCount: number): string {
  if (count <= 0 || maxCount <= 0) return SCALE_COLORS[0];
  const ratio = count / maxCount;
  if (ratio <= 0.2) return SCALE_COLORS[1];
  if (ratio <= 0.4) return SCALE_COLORS[2];
  if (ratio <= 0.65) return SCALE_COLORS[3];
  if (ratio <= 0.85) return SCALE_COLORS[4];
  return SCALE_COLORS[5];
}

interface InspectedRegion {
  code: string;
  name: string;
  count: number;
}

export function WorldGeoMap({
  data,
  title = "Observed Source Regions (GeoIP Estimate)",
  subtitle = "Country/region-level choropleth heatmap (raw IPs and exact coordinates are never exposed)",
}: WorldGeoMapProps) {
  const [hovered, setHovered] = useState<InspectedRegion | null>(null);
  const [pinned, setPinned] = useState<InspectedRegion | null>(null);

  // Avoid dedicating large empty visual real estate when GeoIP enrichment is not
  // populated (e.g., Phase 1 MVP runs without a GeoIP database per DATA_MODEL.md).
  if (data.totalMapped === 0) {
    return (
      <Panel ariaLabel={title}>
        <PanelHeader
          title={title}
          subtitle="Country/region enrichment status"
          action={
            <span className="text-xs text-slate-500">
              Not enabled
            </span>
          }
        />
        <div className="flex flex-col gap-1.5 px-4 py-4 text-xs text-slate-600 sm:flex-row sm:items-center sm:justify-between">
          <p className="leading-relaxed">
            No country/region GeoIP metadata is populated for events in this window. The Phase 1
            observatory intentionally minimizes IP enrichment and never exposes raw source IPs.
          </p>
          <span className="shrink-0 font-mono text-[11px] tabular-nums text-slate-500">
            0 mapped regions
          </span>
        </div>
      </Panel>
    );
  }

  const activeRegion = hovered ?? pinned;

  const togglePinned = (region: InspectedRegion) => {
    setPinned((curr) => (curr?.code === region.code ? null : region));
  };

  const handleRegionKeyDown = (
    event: React.KeyboardEvent<SVGElement>,
    region: InspectedRegion,
  ) => {
    if (event.key === "Enter" || event.key === " ") {
      event.preventDefault();
      togglePinned(region);
    } else if (event.key === "Escape") {
      setHovered(null);
      setPinned(null);
    }
  };

  const sharePct =
    activeRegion && data.totalMapped > 0
      ? ((activeRegion.count / data.totalMapped) * 100).toFixed(1)
      : "0.0";

  return (
    <Panel ariaLabel={title}>
      <PanelHeader
        title={title}
        subtitle={subtitle}
        action={
          <div
            aria-live="polite"
            className="flex h-7 items-center gap-2 rounded-md border border-slate-200 bg-white px-2.5 font-mono text-[11px] tabular-nums text-slate-700"
          >
            {activeRegion ? (
              <>
                <span translate="no" className="font-semibold text-[#632ca6]">
                  {activeRegion.code}
                </span>
                <span className="max-w-[140px] truncate font-sans text-slate-600">
                  {activeRegion.name}
                </span>
                <span className="text-slate-300">|</span>
                <span className="font-semibold text-slate-900">
                  {activeRegion.count.toLocaleString("en-US")}
                </span>
                <span className="text-slate-500">({sharePct}%)</span>
                {pinned && !hovered ? (
                  <button
                    type="button"
                    onClick={() => setPinned(null)}
                    aria-label={`Clear selected region ${pinned.name}`}
                    className="ml-1 rounded px-1 font-sans text-[10px] text-slate-500 transition-colors hover:bg-slate-200 hover:text-slate-800 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#632ca6]"
                  >
                    Clear
                  </button>
                ) : null}
              </>
            ) : (
              <span className="font-sans text-slate-500">
                Hover, click, or focus a region to inspect
              </span>
            )}
          </div>
        }
      />

      <div className="bg-[#fafbfd] p-3 sm:p-4">
        <svg
          viewBox="0 0 880 420"
          role="img"
          aria-label="World choropleth map showing approximate observed source regions"
          className="h-auto w-full select-none"
        >
          <g>
            {data.countries.map((country, index) => {
              const isSelected = activeRegion?.code === country.code;
              const isPinned = pinned?.code === country.code;
              const fill = getFillColor(country.count, data.maxCount);
              const region: InspectedRegion = {
                code: country.code,
                name: country.name,
                count: country.count,
              };
              return (
                <path
                  key={`${country.id}:${index}`}
                  d={country.d}
                  fill={fill}
                  stroke={isSelected ? "#431a75" : "#ffffff"}
                  strokeWidth={isSelected ? 1.2 : 0.6}
                  className="cursor-pointer transition-colors focus-visible:outline-2 focus-visible:outline-[#632ca6]"
                  role={country.count > 0 ? "button" : undefined}
                  aria-pressed={country.count > 0 ? isPinned : undefined}
                  tabIndex={country.count > 0 ? 0 : -1}
                  aria-label={`${country.name} (${country.code}): ${country.count} events`}
                  onClick={() => togglePinned(region)}
                  onKeyDown={(e) => handleRegionKeyDown(e, region)}
                  onMouseEnter={() => setHovered(region)}
                  onMouseLeave={() => setHovered(null)}
                  onFocus={() => setHovered(region)}
                  onBlur={() => setHovered(null)}
                />
              );
            })}
          </g>

          {data.markers.length > 0 ? (
            <g>
              {data.markers.map((marker) => {
                const isSelected = activeRegion?.code === marker.code;
                const isPinned = pinned?.code === marker.code;
                const fill = getFillColor(marker.count, data.maxCount);
                const region: InspectedRegion = {
                  code: marker.code,
                  name: marker.name,
                  count: marker.count,
                };
                return (
                  <circle
                    key={marker.code}
                    cx={marker.cx}
                    cy={marker.cy}
                    r={isSelected ? 5.5 : 4.2}
                    fill={fill}
                    stroke={isSelected ? "#431a75" : "#ffffff"}
                    strokeWidth={1.2}
                    className="cursor-pointer transition-colors focus-visible:outline-2 focus-visible:outline-[#632ca6]"
                    role="button"
                    aria-pressed={isPinned}
                    tabIndex={0}
                    aria-label={`${marker.name} (${marker.code}): ${marker.count} events`}
                    onClick={() => togglePinned(region)}
                    onKeyDown={(e) => handleRegionKeyDown(e, region)}
                    onMouseEnter={() => setHovered(region)}
                    onMouseLeave={() => setHovered(null)}
                    onFocus={() => setHovered(region)}
                    onBlur={() => setHovered(null)}
                  />
                );
              })}
            </g>
          ) : null}
        </svg>
      </div>

      <div className="flex flex-wrap items-center justify-between gap-2 border-t border-slate-200 px-4 py-2.5 text-[11px] text-slate-500">
        <div className="flex items-center gap-2">
          <span>Volume:</span>
          <span className="font-mono tabular-nums text-slate-700">0</span>
          <div className="flex items-center gap-0.5" aria-hidden="true">
            {SCALE_COLORS.map((color) => (
              <span
                key={color}
                className="h-2.5 w-5 first:rounded-l-sm last:rounded-r-sm"
                style={{ backgroundColor: color }}
              />
            ))}
          </div>
          <span className="font-mono tabular-nums text-slate-700">
            {data.maxCount.toLocaleString("en-US")}
          </span>
        </div>
        <span>
          GeoIP approximation only (includes proxies/VPS; does not identify actual attacker origin)
        </span>
      </div>
    </Panel>
  );
}
