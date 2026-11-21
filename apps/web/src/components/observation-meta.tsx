import { formatCount, formatJstDateTime } from "@/lib/format";

export function ObservationMeta({
  windowLabel,
  updatedAt,
  sensorCount,
}: {
  windowLabel: string;
  updatedAt: string | null;
  sensorCount: number;
}) {
  return (
    <dl className="flex flex-wrap gap-x-4 gap-y-1 text-[11px] text-gray-500">
      <div className="flex gap-1">
        <dt>Window</dt>
        <dd className="font-medium text-gray-700">{windowLabel}</dd>
      </div>
      <div className="flex gap-1">
        <dt>Updated</dt>
        <dd className="font-mono tabular-nums text-gray-700">{formatJstDateTime(updatedAt)}</dd>
      </div>
      <div className="flex gap-1">
        <dt>Sensors</dt>
        <dd className="font-mono tabular-nums text-gray-700">
          {formatCount(sensorCount)} registered
        </dd>
      </div>
    </dl>
  );
}
