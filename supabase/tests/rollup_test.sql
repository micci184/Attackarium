-- Idempotent rollup, day/week deltas, pattern totals, and retention.
-- Rolls back all fixtures. Session TimeZone is UTC+9 so a UTC day boundary is
-- not the local midnight.
\set ON_ERROR_STOP on

begin;

set local time zone interval '+09:00';

insert into public.sensors (id, name, type, region, is_active)
values ('sensor-rollup-01', 'Rollup Sensor', 'combined', 'us-east-1', true);

-- 14 days ending yesterday, plus events around the 30-day UTC cutoff.
insert into public.attack_events (
  id, sensor_id, observed_at, protocol, dst_port, event_type, attack_category, src_ip_hash
)
select
  (
    substr(md5(i::text), 1, 8) || '-1111-4111-8111-' || substr(md5(i::text), 1, 12)
  )::uuid,
  'sensor-rollup-01',
  timestamptz '2026-11-21 00:00:00+00' - (i || ' days')::interval + interval '3 hours',
  'ssh',
  22,
  'ssh_login_attempt',
  'auth_attempt',
  'hash-a'
from pg_catalog.generate_series(1, 14) as i;

insert into public.attack_events (
  id, sensor_id, observed_at, protocol, dst_port, event_type, attack_category,
  src_ip_hash, http_method, http_path_redacted, fingerprint
) values (
  'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa1',
  'sensor-rollup-01',
  timestamptz '2026-11-20 04:00:00+00',
  'http',
  80,
  'http_probe',
  'http_path_probe',
  'hash-b',
  'GET',
  '/wp-login.php',
  'fp-http-1'
);

insert into public.attack_events (
  id, sensor_id, observed_at, protocol, dst_port, event_type, attack_category, src_ip_hash
) values
(
  'cccccccc-cccc-4ccc-8ccc-ccccccccccc1',
  'sensor-rollup-01',
  timestamptz '2026-11-19 05:00:00+00',
  'ssh', 22, 'ssh_login_attempt', 'auth_attempt', 'hash-a'
),
(
  'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbb1',
  'sensor-rollup-01',
  timestamptz '2026-10-01 10:00:00+00',
  'ssh', 22, 'ssh_login_attempt', 'auth_attempt', 'hash-a'
),
(
  'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbb2',
  'sensor-rollup-01',
  timestamptz '2026-10-01 11:00:00+00',
  'ssh', 22, 'ssh_login_attempt', 'auth_attempt', 'hash-a'
),
(
  'dddddddd-dddd-4ddd-8ddd-ddddddddddd1',
  'sensor-rollup-01',
  timestamptz '2026-10-21 23:30:00+00',
  'ssh', 22, 'ssh_login_attempt', 'auth_attempt', 'hash-a'
),
(
  'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeee1',
  'sensor-rollup-01',
  timestamptz '2026-10-22 00:00:00+00',
  'ssh', 22, 'ssh_login_attempt', 'auth_attempt', 'hash-a'
);

insert into public.ingest_receipts (sensor_id, request_id, received_at, expires_at)
values
(
  'sensor-rollup-01',
  'req-expired',
  timestamptz '2026-10-01 00:00:00+00',
  timestamptz '2026-10-02 00:00:00+00'
),
(
  'sensor-rollup-01',
  'req-fresh',
  timestamptz '2026-11-21 00:00:00+00',
  timestamptz '2026-11-22 00:00:00+00'
);

do $$
begin
  perform public.prune_observation_retention(timestamptz '2026-11-21 15:00:00+00', 29);
  raise exception 'retention floor was not enforced';
exception
  when invalid_parameter_value then
    null;
end $$;

do $$
begin
  perform public.rollup_observation_aggregates(timestamptz '2026-11-21 15:00:00+00', 7);
  raise exception 'rollup window shorter than ingest age was accepted';
exception
  when invalid_parameter_value then
    null;
end $$;

do $$
begin
  perform public.rollup_observation_aggregates(timestamptz '2026-11-21 15:00:00+00', 31);
  raise exception 'rollup window wider than retention was accepted';
exception
  when invalid_parameter_value then
    null;
end $$;

-- The job ran on 2026-10-02 and again today, twice.
select public.rollup_observation_aggregates(timestamptz '2026-10-02 12:00:00+00');
select public.rollup_observation_aggregates(timestamptz '2026-11-21 15:00:00+00');
select public.rollup_observation_aggregates(timestamptz '2026-11-21 15:00:00+00');

do $$
declare
  v_events bigint;
  v_unique bigint;
  v_day bigint;
  v_prev bigint;
  v_week bigint;
  v_week_prev bigint;
  v_pattern bigint;
begin
  select event_count, unique_source_count
  into v_events, v_unique
  from public.event_aggregates
  where granularity = 'hour'
    and bucket_start = timestamptz '2026-10-01 10:00:00+00'
    and attack_category = 'auth_attempt';
  if v_events <> 1 or v_unique <> 1 then
    raise exception 'expected one unique source in the 10:00 hour, got %/%', v_events, v_unique;
  end if;

  select event_count, unique_source_count
  into v_events, v_unique
  from public.event_aggregates
  where granularity = 'day'
    and bucket_start = timestamptz '2026-10-01 00:00:00+00'
    and protocol = 'ssh';
  if v_events <> 2 or v_unique <> 1 then
    raise exception 'duplicate hash inflated the old day, got %/%', v_events, v_unique;
  end if;

  select current_event_count, previous_event_count, event_count_delta
  into v_day, v_prev, v_events
  from public.observation_count_deltas(timestamptz '2026-11-21 15:00:00+00')
  where comparison = 'day';
  -- 2026-11-20: one SSH event plus one HTTP event (count 2).
  -- 2026-11-19: two SSH events with the same hash (count 2, unique sources 1).
  -- A delta of summed unique_source_count would be 1, not 0.
  if v_day <> 2 or v_prev <> 2 or v_events <> 0 then
    raise exception 'day delta mismatch: current % previous % delta %', v_day, v_prev, v_events;
  end if;

  select current_event_count, previous_event_count, event_count_delta
  into v_week, v_week_prev, v_events
  from public.observation_count_deltas(timestamptz '2026-11-21 15:00:00+00')
  where comparison = 'week';
  if v_week <> 9 or v_week_prev <> 7 or v_events <> 2 then
    raise exception 'week delta mismatch: current % previous % delta %', v_week, v_week_prev, v_events;
  end if;

  select total_count into v_pattern
  from public.observed_patterns
  where pattern_type = 'http_path'
    and pattern_key = '/wp-login.php'
    and protocol = 'http';
  if v_pattern <> 1 then
    raise exception 'expected one redacted HTTP path pattern, got %', v_pattern;
  end if;

  select total_count into v_pattern
  from public.observed_patterns
  where pattern_type = 'attack_category'
    and pattern_key = 'auth_attempt'
    and protocol = 'ssh';
  if v_pattern <> 19 then
    raise exception 'expected 19 SSH auth observations, got %', v_pattern;
  end if;
end $$;

do $$
declare
  v_deleted_events bigint;
  v_deleted_receipts bigint;
  v_remaining bigint;
  v_boundary bigint;
  v_fresh_receipts bigint;
begin
  select deleted_events, deleted_receipts
  into v_deleted_events, v_deleted_receipts
  from public.run_observation_maintenance(timestamptz '2026-11-21 15:00:00+00', 30);

  if v_deleted_events <> 3 or v_deleted_receipts <> 1 then
    raise exception 'prune counts mismatch: events % receipts %', v_deleted_events, v_deleted_receipts;
  end if;

  select count(*) into v_remaining from public.attack_events;
  if v_remaining <> 17 then
    raise exception 'retained events changed, got %', v_remaining;
  end if;

  select count(*) into v_boundary
  from public.attack_events
  where id = 'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeee1';
  if v_boundary <> 1 then
    raise exception 'UTC cutoff day was split';
  end if;

  select count(*) into v_fresh_receipts
  from public.ingest_receipts
  where request_id = 'req-fresh';
  if v_fresh_receipts <> 1 then
    raise exception 'unexpired receipt was deleted';
  end if;
end $$;

-- After retention: five new events today, and one stray event on a pruned day.
insert into public.attack_events (
  id, sensor_id, observed_at, protocol, dst_port, event_type, attack_category, src_ip_hash
)
select
  (
    substr(md5('new' || i::text), 1, 8) || '-2222-4222-8222-' || substr(md5('new' || i::text), 1, 12)
  )::uuid,
  'sensor-rollup-01',
  timestamptz '2026-11-21 10:00:00+00' + (i || ' minutes')::interval,
  'ssh',
  22,
  'ssh_login_attempt',
  'auth_attempt',
  'hash-c'
from pg_catalog.generate_series(1, 5) as i;

insert into public.attack_events (
  id, sensor_id, observed_at, protocol, dst_port, event_type, attack_category, src_ip_hash
) values (
  'ffffffff-ffff-4fff-8fff-fffffffffff1',
  'sensor-rollup-01',
  timestamptz '2026-10-01 12:00:00+00',
  'ssh', 22, 'ssh_login_attempt', 'auth_attempt', 'hash-z'
);

set local role service_role;
select public.run_observation_maintenance(timestamptz '2026-11-21 16:00:00+00', 30);
reset role;

do $$
declare
  v_old_aggregate bigint;
  v_daily bigint;
  v_pattern bigint;
  v_first_seen timestamptz;
begin
  select event_count into v_old_aggregate
  from public.event_aggregates
  where granularity = 'day'
    and bucket_start = timestamptz '2026-10-01 00:00:00+00'
    and protocol = 'ssh';
  if v_old_aggregate <> 2 then
    raise exception 'a pruned day bucket was rewritten, got %', v_old_aggregate;
  end if;

  select event_count into v_daily
  from public.daily_stats
  where date_utc = date '2026-10-01'
    and protocol = 'ssh'
    and event_type = 'ssh_login_attempt';
  if v_daily <> 2 then
    raise exception 'daily stat for a pruned day changed, got %', v_daily;
  end if;

  select total_count, first_seen_at into v_pattern, v_first_seen
  from public.observed_patterns
  where pattern_type = 'attack_category'
    and pattern_key = 'auth_attempt'
    and protocol = 'ssh';
  if v_pattern <> 24 then
    raise exception 'pattern lifetime total should be 19 + 5, got %', v_pattern;
  end if;
  if v_first_seen <> timestamptz '2026-10-01 10:00:00+00' then
    raise exception 'pattern first_seen_at moved after retention, got %', v_first_seen;
  end if;
end $$;

-- OpenCanary logtype 17001 is a Redis command, not an unclassified event.
insert into public.attack_events (
  id, sensor_id, observed_at, protocol, dst_port, event_type, attack_category, metadata
) values (
  '17171717-1717-4171-8171-171717171717',
  'sensor-rollup-01',
  timestamptz '2026-11-21 12:00:00+00',
  'other',
  6379,
  'opencanary_17001',
  null,
  '{"logtype": 17001}'::jsonb
);

update public.attack_events
set
  protocol = 'redis',
  event_type = 'redis_command_probe',
  attack_category = 'auth_attempt'
where protocol = 'other'
  and event_type = 'opencanary_17001'
  and dst_port = 6379
  and metadata->>'logtype' = '17001';

do $$
declare
  v_protocol text;
  v_event_type text;
  v_category text;
begin
  select protocol, event_type, attack_category
  into v_protocol, v_event_type, v_category
  from public.attack_events
  where id = '17171717-1717-4171-8171-171717171717';

  if v_protocol <> 'redis'
    or v_event_type <> 'redis_command_probe'
    or v_category <> 'auth_attempt'
  then
    raise exception 'redis reclassification failed: % % %', v_protocol, v_event_type, v_category;
  end if;
end $$;

insert into public.sensors (id, name, type, region, is_active, last_heartbeat_at, created_at)
values (
  'sensor-coverage-01',
  'Coverage Sensor',
  'combined',
  'us-east-1',
  true,
  timestamptz '2026-11-21 15:00:00+00',
  timestamptz '2026-11-01 00:00:00+00'
);

select public.sync_sensor_coverage_gaps(timestamptz '2026-11-21 15:20:00+00');
select public.sync_sensor_coverage_gaps(timestamptz '2026-11-21 15:20:00+00');

do $$
declare
  v_open bigint;
  v_started timestamptz;
begin
  select count(*), min(started_at)
  into v_open, v_started
  from public.sensor_status_events
  where sensor_id = 'sensor-coverage-01'
    and status = 'offline'
    and ended_at is null;

  if v_open <> 1 or v_started <> timestamptz '2026-11-21 15:00:00+00' then
    raise exception 'expected one open coverage gap at the last heartbeat, got % starting %', v_open, v_started;
  end if;
end $$;

update public.sensors
set last_heartbeat_at = timestamptz '2026-11-21 15:30:00+00'
where id = 'sensor-coverage-01';

select public.sync_sensor_coverage_gaps(timestamptz '2026-11-21 15:30:00+00');

do $$
declare
  v_open bigint;
  v_ended timestamptz;
begin
  select count(*) into v_open
  from public.sensor_status_events
  where sensor_id = 'sensor-coverage-01'
    and ended_at is null
    and status in ('offline', 'degraded', 'error');

  select ended_at into v_ended
  from public.sensor_status_events
  where sensor_id = 'sensor-coverage-01'
    and status = 'offline';

  if v_open <> 0 or v_ended <> timestamptz '2026-11-21 15:30:00+00' then
    raise exception 'coverage gap did not close on a fresh heartbeat: open % ended %', v_open, v_ended;
  end if;
end $$;

-- Inactive sensors keep their open gap even if last_heartbeat_at is still recent.
insert into public.sensors (id, name, type, region, is_active, last_heartbeat_at, created_at)
values (
  'sensor-inactive-01',
  'Inactive Sensor',
  'combined',
  'us-east-1',
  false,
  timestamptz '2026-11-21 15:25:00+00',
  timestamptz '2026-11-01 00:00:00+00'
);

insert into public.sensor_status_events (sensor_id, status, started_at, summary)
values (
  'sensor-inactive-01',
  'offline',
  timestamptz '2026-11-21 15:20:00+00',
  'Paused for maintenance'
);

select public.sync_sensor_coverage_gaps(timestamptz '2026-11-21 15:30:00+00');

do $$
declare
  v_open bigint;
begin
  select count(*) into v_open
  from public.sensor_status_events
  where sensor_id = 'sensor-inactive-01'
    and ended_at is null;

  if v_open <> 1 then
    raise exception 'inactive sensor gap should remain open, got %', v_open;
  end if;
end $$;

set local role anon;

do $$
begin
  perform public.rollup_observation_aggregates(now(), 8);
  raise exception 'anon executed rollup';
exception
  when insufficient_privilege then
    null;
end $$;

do $$
begin
  perform public.sync_sensor_coverage_gaps(now());
  raise exception 'anon executed coverage sync';
exception
  when insufficient_privilege then
    null;
end $$;

do $$
begin
  perform public.run_scheduled_observation_maintenance();
  raise exception 'anon executed scheduled maintenance';
exception
  when insufficient_privilege then
    null;
end $$;

reset role;
set local role authenticated;

do $$
begin
  perform count(*) from public.pattern_daily_counts;
  raise exception 'authenticated read pattern_daily_counts';
exception
  when insufficient_privilege then
    null;
end $$;

rollback;
