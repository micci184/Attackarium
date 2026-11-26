-- =============================================================================
-- Attackarium — HTTP collector overload coverage (#95) tests
-- =============================================================================
\set ON_ERROR_STOP on

begin;

insert into public.sensors (id, name, type, region, is_active, last_heartbeat_at)
values ('sensor-ovl-01', 'Synthetic Overload Sensor', 'combined', 'us-east-1', true, now());

do $$
declare
  n integer;
  r record;
begin
  -- Refused connections create one closed degraded interval.
  if not public.record_sensor_overload('sensor-ovl-01', 7, 3, now() - interval '20 minutes', now() - interval '15 minutes') then
    raise exception 'valid overload report was rejected';
  end if;
  select count(*) into n from public.sensor_status_events where sensor_id = 'sensor-ovl-01';
  if n <> 1 then raise exception 'expected 1 degraded interval, got %', n; end if;
  select * into r from public.sensor_status_events where sensor_id = 'sensor-ovl-01';
  if r.status <> 'degraded' or r.ended_at is null then
    raise exception 'interval must be closed and degraded';
  end if;
  if r.summary not like 'HTTP collector at capacity: 7 connection(s) refused, 3%' then
    raise exception 'unexpected summary: %', r.summary;
  end if;

  -- A window within 15 minutes extends the same interval.
  perform public.record_sensor_overload('sensor-ovl-01', 2, 0, now() - interval '10 minutes', now() - interval '5 minutes');
  select count(*) into n from public.sensor_status_events where sensor_id = 'sensor-ovl-01';
  if n <> 1 then raise exception 'nearby windows must merge, got % rows', n; end if;
  select * into r from public.sensor_status_events where sensor_id = 'sensor-ovl-01';
  if r.ended_at < now() - interval '6 minutes' then raise exception 'merge did not extend ended_at'; end if;

  -- A distant window creates a new interval.
  perform public.record_sensor_overload('sensor-ovl-01', 1, 0, now() - interval '3 hours', now() - interval '170 minutes');
  select count(*) into n from public.sensor_status_events where sensor_id = 'sensor-ovl-01';
  if n <> 2 then raise exception 'distant windows must not merge, got % rows', n; end if;

  -- Deadline cuts alone, bad windows, and unknown sensors record nothing.
  if public.record_sensor_overload('sensor-ovl-01', 0, 50, now() - interval '2 minutes', now()) then
    raise exception 'deadline cuts alone must not mark degraded coverage';
  end if;
  if public.record_sensor_overload('sensor-ovl-01', 5, 0, now(), now() - interval '1 minute') then
    raise exception 'inverted window was accepted';
  end if;
  if public.record_sensor_overload('sensor-ovl-01', 5, 0, now(), now() + interval '1 hour') then
    raise exception 'future window was accepted';
  end if;
  if public.record_sensor_overload('sensor-ovl-01', 5, 0, now() - interval '30 days', now() - interval '29 days') then
    raise exception 'too-old window was accepted';
  end if;
  if public.record_sensor_overload('sensor-unknown', 5, 0, now() - interval '1 minute', now()) then
    raise exception 'unknown sensor was accepted';
  end if;
  select count(*) into n from public.sensor_status_events where sensor_id = 'sensor-ovl-01';
  if n <> 2 then raise exception 'rejected reports changed rows: %', n; end if;

  -- The public view shows the degraded interval but never the summary.
  select count(*) into n from public.public_sensor_status_events
  where sensor_id = 'sensor-ovl-01' and status = 'degraded';
  if n <> 2 then raise exception 'degraded intervals missing from public view'; end if;
  if exists (
    select 1 from information_schema.columns
    where table_schema = 'public' and table_name = 'public_sensor_status_events' and column_name = 'summary'
  ) then
    raise exception 'summary leaked into the public view';
  end if;

  -- The coverage sync must not reopen or close these (already closed) rows.
  perform public.sync_sensor_coverage_gaps(now());
  select count(*) into n from public.sensor_status_events
  where sensor_id = 'sensor-ovl-01' and status = 'degraded' and ended_at is null;
  if n <> 0 then raise exception 'coverage sync opened a degraded interval'; end if;
end $$;

set local role anon;
do $$
begin
  perform public.record_sensor_overload('sensor-ovl-01', 1, 0, now() - interval '1 minute', now());
  raise exception 'SECURITY FAILURE: anon executed record_sensor_overload';
exception when insufficient_privilege then null;
end $$;
reset role;
set local role authenticated;
do $$
begin
  perform public.record_sensor_overload('sensor-ovl-01', 1, 0, now() - interval '1 minute', now());
  raise exception 'SECURITY FAILURE: authenticated executed record_sensor_overload';
exception when insufficient_privilege then null;
end $$;
reset role;

rollback;

\echo 'sensor_overload_test: all checks passed'
