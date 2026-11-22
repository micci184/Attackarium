import { FormattedTime } from "@/components/timezone-provider";
import { formatCount } from "@/lib/format";

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
    <dl className="flex flex-wrap items-center gap-x-4 gap-y-1.5 text-xs text-slate-500">
      <div className="inline-flex items-center gap-1.5">
        <dt className="text-slate-500">Window</dt>
        <dd className="font-medium text-slate-800">{windowLabel}</dd>
      </div>
      <span aria-hidden="true" className="hidden text-slate-300 sm:inline">
        ·
      </span>
      <div className="inline-flex items-center gap-1.5">
        <dt className="text-slate-500">Updated</dt>
        <dd className="font-mono tabular-nums text-slate-800">
          <FormattedTime iso={updatedAt} />
        </dd>
      </div>
      <span aria-hidden="true" className="hidden text-slate-300 sm:inline">
        ·
      </span>
      <div className="inline-flex items-center gap-1.5">
        <dt className="text-slate-500">Sensors</dt>
        <dd className="font-mono tabular-nums text-slate-800">
          {formatCount(sensorCount)} registered
        </dd>
      </div>
    </dl>
  );
}
