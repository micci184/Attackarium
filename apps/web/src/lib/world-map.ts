import { geoNaturalEarth1, geoPath } from "d3-geo";
import type { Feature, FeatureCollection, Geometry } from "geojson";
import { feature } from "topojson-client";
import type { GeometryCollection, Topology } from "topojson-specification";
import countriesAtlas from "world-atlas/countries-110m.json" with { type: "json" };

export interface MapCountryFeature {
  id: string;
  code: string;
  name: string;
  d: string;
  count: number;
}

export interface MapMarkerFeature {
  code: string;
  name: string;
  cx: number;
  cy: number;
  count: number;
}

export interface WorldMapData {
  countries: MapCountryFeature[];
  markers: MapMarkerFeature[];
  maxCount: number;
  totalMapped: number;
}

// ISO 3166-1 numeric -> alpha-2 mapping covering countries in world-atlas 110m
const NUMERIC_TO_ALPHA2: Record<string, string> = {
  "004": "AF", "008": "AL", "012": "DZ", "024": "AO", "031": "AZ",
  "032": "AR", "036": "AU", "040": "AT", "044": "BS", "050": "BD",
  "051": "AM", "056": "BE", "064": "BT", "068": "BO", "070": "BA",
  "072": "BW", "076": "BR", "084": "BZ", "090": "SB", "096": "BN",
  "100": "BG", "104": "MM", "108": "BI", "112": "BY", "116": "KH",
  "120": "CM", "124": "CA", "140": "CF", "144": "LK", "148": "TD",
  "152": "CL", "156": "CN", "158": "TW", "170": "CO", "178": "CG",
  "180": "CD", "188": "CR", "191": "HR", "192": "CU", "196": "CY",
  "203": "CZ", "204": "BJ", "208": "DK", "214": "DO", "218": "EC",
  "222": "SV", "226": "GQ", "231": "ET", "232": "ER", "233": "EE",
  "238": "FK", "242": "FJ", "246": "FI", "250": "FR", "260": "TF",
  "262": "DJ", "266": "GA", "268": "GE", "270": "GM", "275": "PS",
  "276": "DE", "288": "GH", "300": "GR", "304": "GL", "320": "GT",
  "324": "GN", "328": "GY", "332": "HT", "340": "HN", "348": "HU",
  "352": "IS", "356": "IN", "360": "ID", "364": "IR", "368": "IQ",
  "372": "IE", "376": "IL", "380": "IT", "384": "CI", "388": "JM",
  "392": "JP", "398": "KZ", "400": "JO", "404": "KE", "408": "KP",
  "410": "KR", "414": "KW", "417": "KG", "418": "LA", "422": "LB",
  "426": "LS", "428": "LV", "430": "LR", "434": "LY", "440": "LT",
  "442": "LU", "450": "MG", "454": "MW", "458": "MY", "466": "ML",
  "478": "MR", "484": "MX", "496": "MN", "498": "MD", "499": "ME",
  "504": "MA", "508": "MZ", "512": "OM", "516": "NA", "524": "NP",
  "528": "NL", "540": "NC", "548": "VU", "554": "NZ", "558": "NI",
  "562": "NE", "566": "NG", "578": "NO", "586": "PK", "591": "PA",
  "598": "PG", "600": "PY", "604": "PE", "608": "PH", "616": "PL",
  "620": "PT", "624": "GW", "626": "TL", "630": "PR", "634": "QA",
  "642": "RO", "643": "RU", "646": "RW", "682": "SA", "686": "SN",
  "688": "RS", "694": "SL", "703": "SK", "704": "VN", "705": "SI",
  "706": "SO", "710": "ZA", "716": "ZW", "724": "ES", "728": "SS",
  "729": "SD", "732": "EH", "740": "SR", "748": "SZ", "752": "SE",
  "756": "CH", "760": "SY", "762": "TJ", "764": "TH", "768": "TG",
  "780": "TT", "784": "AE", "788": "TN", "792": "TR", "795": "TM",
  "800": "UG", "804": "UA", "807": "MK", "818": "EG", "826": "GB",
  "834": "TZ", "840": "US", "854": "BF", "858": "UY", "860": "UZ",
  "862": "VE", "887": "YE", "894": "ZM",
};

// Small territories/city-states omitted from 110m polygons, rendered as flat dot markers
const SMALL_REGION_COORDS: Record<string, { name: string; lon: number; lat: number }> = {
  SG: { name: "Singapore", lon: 103.8198, lat: 1.3521 },
  HK: { name: "Hong Kong", lon: 114.1694, lat: 22.3193 },
  MO: { name: "Macao", lon: 113.5439, lat: 22.1987 },
  BH: { name: "Bahrain", lon: 50.5577, lat: 26.0667 },
  MT: { name: "Malta", lon: 14.3754, lat: 35.9375 },
  MC: { name: "Monaco", lon: 7.4246, lat: 43.7384 },
};

interface CachedGeometry {
  countries: Array<{ id: string; code: string; name: string; d: string }>;
  markersByCode: Map<string, { code: string; name: string; cx: number; cy: number }>;
}

const NUMBER_ROUND_REGEX = /-?\d+\.\d+/g;

function roundPathPrecision(d: string): string {
  return d.replace(NUMBER_ROUND_REGEX, (match) => Number(match).toFixed(1));
}

let cachedGeometry: CachedGeometry | null = null;

function getWorldGeometry(): CachedGeometry {
  if (cachedGeometry) return cachedGeometry;

  const topology = countriesAtlas as unknown as Topology<{
    countries: GeometryCollection<{ name?: string }>;
  }>;
  const fc = feature(
    topology,
    topology.objects.countries,
  ) as unknown as FeatureCollection<Geometry, { name?: string }>;

  // Exclude Antarctica (010) for balanced observability map framing
  const filteredFeatures: Feature<Geometry, { name?: string }>[] = fc.features.filter(
    (f) => String(f.id ?? "") !== "010",
  );
  const filteredCollection: FeatureCollection<Geometry, { name?: string }> = {
    type: "FeatureCollection",
    features: filteredFeatures,
  };

  const projection = geoNaturalEarth1().fitExtent(
    [
      [12, 12],
      [868, 408],
    ],
    filteredCollection,
  );
  const pathGenerator = geoPath(projection);

  const countries: Array<{ id: string; code: string; name: string; d: string }> = [];
  for (let i = 0; i < filteredFeatures.length; i += 1) {
    const feat = filteredFeatures[i];
    const hasNumericId = feat.id !== undefined && feat.id !== null && String(feat.id).trim() !== "";
    const rawId = hasNumericId ? String(feat.id).padStart(3, "0") : `UNK-${i}`;
    const dRaw = pathGenerator(feat);
    if (!dRaw) continue;
    const code = hasNumericId ? (NUMERIC_TO_ALPHA2[rawId] ?? rawId) : rawId;
    const name = feat.properties?.name ?? code;
    countries.push({
      id: rawId,
      code,
      name,
      d: roundPathPrecision(dRaw),
    });
  }

  const markersByCode = new Map<
    string,
    { code: string; name: string; cx: number; cy: number }
  >();
  for (const [code, info] of Object.entries(SMALL_REGION_COORDS)) {
    const projected = projection([info.lon, info.lat]);
    if (!projected) continue;
    markersByCode.set(code, {
      code,
      name: info.name,
      cx: Number(projected[0].toFixed(1)),
      cy: Number(projected[1].toFixed(1)),
    });
  }

  cachedGeometry = { countries, markersByCode };
  return cachedGeometry;
}

export function buildWorldMapData(
  regionTotals: Array<{ country: string; count: number }>,
): WorldMapData {
  const geom = getWorldGeometry();
  const countsByCode = new Map<string, number>();

  for (const item of regionTotals) {
    const code = item.country.trim().toUpperCase();
    if (!code || code === "UNKNOWN") continue;
    countsByCode.set(code, (countsByCode.get(code) ?? 0) + item.count);
  }

  let maxCount = 0;
  let totalMapped = 0;
  const matchedCodes = new Set<string>();

  const countries: MapCountryFeature[] = geom.countries.map((c) => {
    const count = countsByCode.get(c.code) ?? 0;
    if (count > 0) {
      matchedCodes.add(c.code);
      totalMapped += count;
      if (count > maxCount) maxCount = count;
    }
    return { ...c, count };
  });

  const markers: MapMarkerFeature[] = [];
  for (const [code, count] of countsByCode.entries()) {
    if (matchedCodes.has(code) || count <= 0) continue;
    const marker = geom.markersByCode.get(code);
    if (!marker) continue;
    totalMapped += count;
    if (count > maxCount) maxCount = count;
    markers.push({ ...marker, count });
  }

  return {
    countries,
    markers,
    maxCount,
    totalMapped,
  };
}
