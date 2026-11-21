-- Harden sync_sensor_coverage_gaps:
-- 1. Serialize concurrent executions with a dedicated advisory lock.
-- 2. Never close an open coverage gap for a sensor marked inactive.

create or replace function public.sync_sensor_coverage_gaps(p_now timestamptz)
returns void
language plpgsql
security invoker
set search_path = ''
as $$
begin
  if p_now is null then
    raise exception 'p_now is required' using errcode = '22023';
  end if;

  perform pg_catalog.pg_advisory_xact_lock(8217002);

  update public.sensor_status_events as gap
  set ended_at = sensor.last_heartbeat_at
  from public.sensors as sensor
  where gap.sensor_id = sensor.id
    and sensor.is_active
    and gap.ended_at is null
    and gap.status in ('offline', 'degraded', 'error')
    and sensor.last_heartbeat_at is not null
    and sensor.last_heartbeat_at >= p_now - interval '15 minutes'
    and sensor.last_heartbeat_at >= gap.started_at;

  insert into public.sensor_status_events (sensor_id, status, started_at, summary)
  select
    sensor.id,
    'offline',
    coalesce(sensor.last_heartbeat_at, sensor.created_at, p_now),
    'No ingest heartbeat within 15 minutes'
  from public.sensors as sensor
  where sensor.is_active
    and (
      sensor.last_heartbeat_at is null
      or sensor.last_heartbeat_at < p_now - interval '15 minutes'
    )
    and not exists (
      select 1
      from public.sensor_status_events as open_gap
      where open_gap.sensor_id = sensor.id
        and open_gap.ended_at is null
        and open_gap.status in ('offline', 'degraded', 'error')
    );
end;
$$;

revoke all on function public.sync_sensor_coverage_gaps(timestamptz) from public, anon, authenticated;
grant execute on function public.sync_sensor_coverage_gaps(timestamptz) to service_role;
