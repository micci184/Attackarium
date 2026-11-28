import type { McpServer } from "@modelcontextprotocol/server";
import { z } from "zod";
import {
  getOverviewData,
  getSensorsData,
  getTrendsData,
} from "./observatory.ts";
import {
  ProtocolSchema,
  TREND_PERIODS,
  type OverviewData,
  type Protocol,
  type SensorsPageData,
  type TrendPeriod,
  type TrendsData,
} from "./types.ts";

export const MCP_TOOL_NAMES = [
  "get_attack_trends",
  "get_attack_patterns",
  "get_observation_summary",
] as const;

export type McpToolName = (typeof MCP_TOOL_NAMES)[number];

const MCP_TOOL_NAME_SET = new Set<string>(MCP_TOOL_NAMES);

export function isMcpToolName(value: string): value is McpToolName {
  return MCP_TOOL_NAME_SET.has(value);
}

const PeriodSchema = z.enum(TREND_PERIODS);

export const SCOPE_CAVEATS = [
  "Observations reflect unsolicited probes received on operator-managed sensors only, not global Internet attack volume.",
  "Candidate CVE/KEV/EPSS context is evidence-backed hypothesis only and does not prove successful exploitation.",
  "matchStrength (high/medium/low) is a rule-defined evidence grade and maxConfidence is the internal rule score; neither is a probability of exploitation. lastObservedAt is when the matched probe was observed.",
  "Periods marked hasCoverageGap indicate sensor downtime or telemetry gaps rather than zero observed probes.",
] as const;

export interface McpObservatorySource {
  getOverviewData: () => Promise<OverviewData>;
  getTrendsData: (period?: TrendPeriod) => Promise<TrendsData>;
  getSensorsData: () => Promise<SensorsPageData>;
}

export const defaultObservatorySource: McpObservatorySource = {
  getOverviewData,
  getTrendsData,
  getSensorsData,
};

export function buildAttackTrendsPayload(
  trends: TrendsData,
  protocol?: Protocol,
) {
  const protocolTotals = protocol
    ? trends.protocolTotals.filter((row) => row.protocol === protocol)
    : trends.protocolTotals;
  const portTotals = protocol
    ? trends.portTotals.filter((row) => row.protocol === protocol)
    : trends.portTotals;

  return {
    period: trends.period,
    protocolFilter: protocol ?? null,
    seriesSource: trends.seriesSource,
    aggregateComplete: trends.aggregateComplete,
    rollupPendingEvents: trends.rollupPendingEvents,
    historyStartedAt: trends.historyStartedAt,
    dataUpdatedAt: trends.dataUpdatedAt,
    registeredSensorCount: trends.registeredSensorCount,
    series: trends.series.map((bucket) => ({
      bucketStart: bucket.bucketStart,
      label: bucket.label,
      eventCount: bucket.totalEvents,
      hasCoverageGap: bucket.hasCoverageGap ?? false,
      isPreHistory: bucket.isPreHistory ?? false,
      isObservationStart: bucket.isObservationStart ?? false,
    })),
    protocolTotals,
    portTotals: portTotals.slice(0, 20),
    coverageGaps: trends.coverageGaps.map((gap) => ({
      sensorId: gap.sensor_id,
      status: gap.status,
      startedAt: gap.started_at,
      endedAt: gap.ended_at,
    })),
    caveats: protocol
      ? [
          ...SCOPE_CAVEATS,
          "Time-series buckets show total sensor volume across all protocols; protocolTotals and portTotals are filtered to the requested protocol.",
        ]
      : [...SCOPE_CAVEATS],
  };
}

export function buildAttackPatternsPayload(
  trends: TrendsData,
  options: { protocol?: Protocol; limit: number },
) {
  const { protocol, limit } = options;
  const patterns = (
    protocol
      ? trends.patterns.filter((item) => item.protocol === protocol)
      : trends.patterns
  ).slice(0, limit);

  const isHttpProtocol =
    protocol === undefined || protocol === "http" || protocol === "https";

  const httpPaths = isHttpProtocol ? trends.httpPaths.slice(0, limit) : [];

  const patternCveContext = (
    isHttpProtocol
      ? trends.patternCveContext
      : trends.patternCveContext.filter((item) => !item.ruleId.startsWith("http-"))
  ).slice(0, limit);

  return {
    period: trends.period,
    protocolFilter: protocol ?? null,
    dataUpdatedAt: trends.dataUpdatedAt,
    aggregateComplete: trends.aggregateComplete,
    patterns,
    httpPaths,
    candidateCveContext: patternCveContext,
    caveats: [...SCOPE_CAVEATS],
  };
}

export function buildObservationSummaryPayload(
  overview: OverviewData,
  sensors: SensorsPageData,
  trends: TrendsData | null,
  options: { period: TrendPeriod; protocol?: Protocol },
) {
  const { period, protocol } = options;
  const protocolBreakdown = protocol
    ? overview.protocolBreakdown.filter((item) => item.protocol === protocol)
    : overview.protocolBreakdown;

  const periodTotalEvents =
    trends !== null
      ? trends.series.reduce((sum, bucket) => sum + bucket.totalEvents, 0)
      : overview.totalEvents24h;

  const periodProtocolTotals =
    trends !== null
      ? protocol
        ? trends.protocolTotals.filter((item) => item.protocol === protocol)
        : trends.protocolTotals
      : protocolBreakdown.map((item) => ({
          protocol: item.protocol,
          count: item.count,
        }));

  return {
    period,
    protocolFilter: protocol ?? null,
    evaluatedAt: sensors.evaluatedAt,
    dataUpdatedAt: overview.dataUpdatedAt,
    historyStartedAt: overview.historyStartedAt,
    hasPriorWindowBaseline: overview.hasPriorWindowBaseline,
    kpis: {
      totalEvents24h: overview.totalEvents24h,
      priorEvents24h: overview.hasPriorWindowBaseline
        ? overview.priorEvents24h
        : null,
      periodTotalEvents,
      rollupPendingEvents24h: overview.rollupPendingEvents24h,
      aggregateComplete: overview.aggregateComplete,
    },
    coverage: {
      activeSensorCount: overview.activeSensorCount,
      healthySensorCount: overview.healthySensorCount,
      coverageGapIn24h: overview.coverageGapIn24h,
      coverageGapInPrior24h: overview.coverageGapInPrior24h,
      activeOutageCount: sensors.activeOutages.length,
      sensors: sensors.sensors.map((sensor) => ({
        id: sensor.id,
        name: sensor.name,
        region: sensor.region,
        health: sensor.healthStatus,
        lastHeartbeatAt: sensor.last_heartbeat_at,
        monitoredServices: sensor.monitored_services,
      })),
    },
    protocolBreakdown: periodProtocolTotals,
    noteworthy: overview.noteworthy,
    caveats: [...SCOPE_CAVEATS],
  };
}

export function registerAttackariumTools(
  server: McpServer,
  source: McpObservatorySource = defaultObservatorySource,
): void {
  server.registerTool(
    "get_attack_trends",
    {
      title: "Get Attack Trends",
      description:
        "Return sanitized time-series observation volume, protocol/port totals, and coverage gaps for 24h, 7d, or 30d.",
      inputSchema: z.object({
        period: PeriodSchema.optional().default("7d"),
        protocol: ProtocolSchema.optional(),
      }),
      annotations: {
        readOnlyHint: true,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: false,
      },
    },
    async ({ period, protocol }) => {
      const trends = await source.getTrendsData(period);
      const payload = buildAttackTrendsPayload(trends, protocol);
      return {
        content: [{ type: "text", text: JSON.stringify(payload) }],
      };
    },
  );

  server.registerTool(
    "get_attack_patterns",
    {
      title: "Get Attack Patterns",
      description:
        "Return observed attack categories, representative sanitized HTTP paths, and evidence-backed candidate CVE/KEV/EPSS context.",
      inputSchema: z.object({
        period: PeriodSchema.optional().default("7d"),
        protocol: ProtocolSchema.optional(),
        limit: z.number().int().min(1).max(50).optional().default(20),
      }),
      annotations: {
        readOnlyHint: true,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: false,
      },
    },
    async ({ period, protocol, limit }) => {
      const trends = await source.getTrendsData(period);
      const payload = buildAttackPatternsPayload(trends, { protocol, limit });
      return {
        content: [{ type: "text", text: JSON.stringify(payload) }],
      };
    },
  );

  server.registerTool(
    "get_observation_summary",
    {
      title: "Get Observation Summary",
      description:
        "Return 24h/window observation KPIs, baseline status, noteworthy shifts, sensor health, and coverage-gap caveats.",
      inputSchema: z.object({
        period: PeriodSchema.optional().default("24h"),
        protocol: ProtocolSchema.optional(),
      }),
      annotations: {
        readOnlyHint: true,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: false,
      },
    },
    async ({ period, protocol }) => {
      const [overview, sensors, trends] = await Promise.all([
        source.getOverviewData(),
        source.getSensorsData(),
        period === "24h" ? Promise.resolve(null) : source.getTrendsData(period),
      ]);
      const payload = buildObservationSummaryPayload(
        overview,
        sensors,
        trends,
        { period, protocol },
      );
      return {
        content: [{ type: "text", text: JSON.stringify(payload) }],
      };
    },
  );
}
