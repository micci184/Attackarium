-- Reclassify OpenCanary Redis commands that were stored as protocol "other",
-- and record a coverage gap when an active sensor's ingest heartbeat is stale.
-- pg_cron is not present in the CI postgres:16-alpine image, so scheduling
-- runs only where the extension is already available.

update public.attack_events
set
  protocol = 'redis',
  event_type = 'redis_command_probe',
  attack_category = 'auth_attempt'
where protocol = 'other'
  and event_type = 'opencanary_17001'
  and dst_port = 6379
  and metadata->>'logtype' = '17001';

-- 15 minutes matches the dashboard stale-heartbeat threshold.
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

  update public.sensor_status_events as gap
  set ended_at = sensor.last_heartbeat_at
  from public.sensors as sensor
  where gap.sensor_id = sensor.id
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

create or replace function public.run_scheduled_observation_maintenance()
returns void
language plpgsql
security invoker
set search_path = ''
as $$
begin
  perform public.sync_sensor_coverage_gaps(pg_catalog.now());
  perform public.run_observation_maintenance(pg_catalog.now(), 90);
end;
$$;

revoke all on function public.sync_sensor_coverage_gaps(timestamptz) from public, anon, authenticated;
revoke all on function public.run_scheduled_observation_maintenance() from public, anon, authenticated;

grant execute on function public.sync_sensor_coverage_gaps(timestamptz) to service_role;
grant execute on function public.run_scheduled_observation_maintenance() to service_role;

-- Rebuild the recent window so corrected Redis rows enter the public aggregates.
select public.rollup_observation_aggregates(pg_catalog.now(), 8);

do $schedule$
declare
  v_jobid bigint;
begin
  if not exists (select 1 from pg_catalog.pg_extension where extname = 'pg_cron') then
    return;
  end if;

  for v_jobid in
    select job.jobid
    from cron.job as job
    where job.jobname = 'observation-maintenance'
  loop
    perform cron.unschedule(v_jobid);
  end loop;

  perform cron.schedule(
    'observation-maintenance',
    '*/15 * * * *',
    'select public.run_scheduled_observation_maintenance()'
  );
end;
$schedule$;
