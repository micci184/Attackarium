-- =============================================================================
-- Attackarium — sensor patch freshness (#94) boundary tests
-- =============================================================================
\set ON_ERROR_STOP on

begin;

insert into public.sensors (id, name, type, region, is_active, last_heartbeat_at)
values ('sensor-patch-01', 'Synthetic Patch Sensor', 'combined', 'us-east-1', true, now());

-- 1. Accepted report, latest wins (including an older value after a rollback)
do $$
declare
  v timestamptz;
begin
  if not public.record_sensor_patch_status(
    'sensor-patch-01', timestamptz '2026-11-25 07:00:17+00', timestamptz '2026-11-25 07:05:00+00'
  ) then
    raise exception 'valid patch report was rejected';
  end if;
  select last_patch_success_at into v from public.sensors where id = 'sensor-patch-01';
  if v is distinct from timestamptz '2026-11-25 07:00:17+00' then
    raise exception 'patch time not stored, got %', v;
  end if;

  -- Same value again: no-op
  if public.record_sensor_patch_status(
    'sensor-patch-01', timestamptz '2026-11-25 07:00:17+00', timestamptz '2026-11-25 07:10:00+00'
  ) then
    raise exception 'identical report should not rewrite the row';
  end if;

  -- Rollback to an older snapshot: the older report must replace the newer one
  perform public.record_sensor_patch_status(
    'sensor-patch-01', timestamptz '2026-10-01 00:00:00+00', timestamptz '2026-11-26 00:00:00+00'
  );
  select last_patch_success_at into v from public.sensors where id = 'sensor-patch-01';
  if v is distinct from timestamptz '2026-10-01 00:00:00+00' then
    raise exception 'older (rollback) report did not replace the value, got %', v;
  end if;
end $$;

-- 2. Rejected reports leave the value unchanged
do $$
declare
  v timestamptz;
begin
  if public.record_sensor_patch_status(
    'sensor-patch-01', timestamptz '2026-11-26 01:00:00+00', timestamptz '2026-11-26 00:00:00+00'
  ) then
    raise exception 'future patch report (beyond skew) was accepted';
  end if;
  if public.record_sensor_patch_status(
    'sensor-patch-01', timestamptz '2001-01-01 00:00:00+00', timestamptz '2026-11-26 00:00:00+00'
  ) then
    raise exception 'implausibly old patch report was accepted';
  end if;
  if public.record_sensor_patch_status('sensor-patch-01', now(), null) then
    raise exception 'report without a receive time was accepted';
  end if;
  if public.record_sensor_patch_status(
    'sensor-unknown', timestamptz '2026-11-25 00:00:00+00', timestamptz '2026-11-25 00:01:00+00'
  ) then
    raise exception 'report for an unknown sensor updated a row';
  end if;
  select last_patch_success_at into v from public.sensors where id = 'sensor-patch-01';
  if v is distinct from timestamptz '2026-10-01 00:00:00+00' then
    raise exception 'rejected report changed the stored value, got %', v;
  end if;
end $$;

-- 2b. An explicit NULL (no recorded success, e.g. restored pre-patch host) clears it
do $$
declare
  v timestamptz;
begin
  if not public.record_sensor_patch_status('sensor-patch-01', null, timestamptz '2026-11-26 00:00:00+00') then
    raise exception 'null report did not clear the stored value';
  end if;
  select last_patch_success_at into v from public.sensors where id = 'sensor-patch-01';
  if v is not null then
    raise exception 'value not cleared, got %', v;
  end if;
  if public.record_sensor_patch_status('sensor-patch-01', null, timestamptz '2026-11-26 00:05:00+00') then
    raise exception 'repeated null report should be a no-op';
  end if;
end $$;

-- 3. Never exposed publicly
do $$
begin
  if exists (
    select 1 from information_schema.columns
    where table_schema = 'public'
      and table_name like 'public\_%'
      and column_name = 'last_patch_success_at'
  ) then
    raise exception 'last_patch_success_at leaked into a public view';
  end if;
end $$;

-- 4. anon and authenticated cannot call the RPC or read the base table
set local role anon;
do $$
begin
  perform public.record_sensor_patch_status('sensor-patch-01', now(), now());
  raise exception 'SECURITY FAILURE: anon executed record_sensor_patch_status';
exception
  when insufficient_privilege then null;
end $$;
do $$
begin
  perform last_patch_success_at from public.sensors;
  raise exception 'SECURITY FAILURE: anon read sensors.last_patch_success_at';
exception
  when insufficient_privilege then null;
end $$;

reset role;
set local role authenticated;
do $$
begin
  perform public.record_sensor_patch_status('sensor-patch-01', now(), now());
  raise exception 'SECURITY FAILURE: authenticated executed record_sensor_patch_status';
exception
  when insufficient_privilege then null;
end $$;
do $$
begin
  perform last_patch_success_at from public.sensors;
  raise exception 'SECURITY FAILURE: authenticated read sensors.last_patch_success_at';
exception
  when insufficient_privilege then null;
end $$;

reset role;
rollback;

\echo 'sensor_patch_status_test: all checks passed'
