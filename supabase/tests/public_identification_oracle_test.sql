-- =============================================================================
-- Attackarium — public surfaces are not a sensor-identification oracle (#88)
-- =============================================================================
-- k = 3 distinct sources, hour-precision timestamps, ~1 hour publication delay.
-- Session TimeZone is UTC+9 so UTC truncation is exercised.
\set ON_ERROR_STOP on

begin;

set local time zone interval '+09:00';

insert into public.sensors (id, name, type, region, is_active, last_heartbeat_at, last_error_at, monitored_services)
values ('sensor-oracle-01', 'Oracle Sensor', 'combined', 'us-east-1', true,
        timestamptz '2026-11-28 05:07:42+00', now() - interval '1 day', array['http']::text[]);

-- Old enough to be published (3 hours ago, odd minute/second).
-- /common-path: 3 distinct sources (public). /marker-xyz: 1 source sending it
-- 6 times (withheld). An http-* fingerprint and an oc-* fingerprint.
insert into public.attack_events (id, sensor_id, observed_at, protocol, dst_port, event_type, attack_category,
                                  src_ip_hash, http_method, http_path_redacted, fingerprint)
select
  ('d0000000-0000-4000-8000-' || lpad(i::text, 12, '0'))::uuid,
  'sensor-oracle-01',
  date_trunc('hour', now()) - interval '3 hours' + make_interval(mins => 7 + i, secs => 13),
  'http', 80, 'http_probe', 'http_path_probe',
  case when i <= 3 then 'hash-' || i else 'hash-marker' end,
  'GET',
  case when i <= 3 then '/common-path' else '/marker-xyz' end,
  'http-0123456789abcdef'
from generate_series(1, 9) as i;

insert into public.attack_events (id, sensor_id, observed_at, protocol, dst_port, event_type, attack_category,
                                  src_ip_hash, fingerprint)
values
  ('d0000000-0000-4000-8000-000000000101', 'sensor-oracle-01',
   date_trunc('hour', now()) - interval '3 hours' + interval '41 minutes 5 seconds',
   'ssh', 22, 'ssh_connection', 'port_scan', 'hash-1', 'oc-4000'),
  -- Too recent: inside the publication delay (current hour).
  ('d0000000-0000-4000-8000-000000000102', 'sensor-oracle-01', now(),
   'telnet', 23, 'telnet_login_attempt', 'auth_attempt', 'hash-9', 'oc-6001');

insert into public.sensor_status_events (sensor_id, status, started_at, ended_at, summary)
values ('sensor-oracle-01', 'offline',
        timestamptz '2026-11-27 05:07:05+00', timestamptz '2026-11-27 05:41:44+00', 'drill');

do $$
begin
  perform public.rollup_observation_aggregates(now(), 8);
  perform public.rollup_public_pattern_eligibility(now(), 3);
end $$;

set local role anon;

-- 1. A path from one source never appears; a path from >= 3 sources does.
do $$
declare
  n integer;
begin
  if exists (select 1 from public.public_events where http_path_redacted like '%marker-xyz%') then
    raise exception 'single-source marker path is public in public_events';
  end if;
  if exists (select 1 from public.public_cve_events where http_path_redacted like '%marker-xyz%') then
    raise exception 'single-source marker path is public in public_cve_events';
  end if;
  if exists (select 1 from public.public_observed_patterns where pattern_key like '%marker-xyz%') then
    raise exception 'single-source marker path is public in public_observed_patterns';
  end if;
  select count(*) into n from public.public_events
  where http_path_redacted = '/common-path';
  if n <> 3 then raise exception 'k-source path should be public on 3 events, got %', n; end if;
  -- Withheld paths keep the method so the UI can say "uncommon path".
  select count(*) into n from public.public_events
  where http_method = 'GET' and http_path_redacted is null and protocol = 'http';
  if n <> 6 then raise exception 'expected 6 withheld-path rows, got %', n; end if;
end $$;

-- 2. Ranking input: distinct-source count on the public pattern.
do $$
declare
  r record;
begin
  select * into strict r from public.public_observed_patterns
  where pattern_type = 'http_path' and pattern_key = '/common-path';
  if r.unique_source_count is distinct from 3 then
    raise exception 'unique_source_count should be 3, got %', r.unique_source_count;
  end if;
  -- First seen = when the 3rd source arrived, at hour precision.
  if r.first_seen_at <> date_trunc('hour', r.first_seen_at) then
    raise exception 'pattern first_seen_at not hour precision: %', r.first_seen_at;
  end if;
end $$;

-- 3. No precomputable HTTP fingerprint anywhere; OpenCanary ones stay.
do $$
begin
  if exists (select 1 from public.public_events where fingerprint like 'http-%')
     or exists (select 1 from public.public_observed_patterns where pattern_key like 'http-%') then
    raise exception 'http-* fingerprint is public';
  end if;
  if not exists (select 1 from public.public_events where fingerprint = 'oc-4000') then
    raise exception 'OpenCanary fingerprint should remain public';
  end if;
end $$;

-- 4. Hour precision, publication delay, no per-event country/ASN.
do $$
begin
  if exists (
    select 1 from public.public_events
    where observed_at <> date_trunc('hour', observed_at at time zone 'UTC') at time zone 'UTC'
       or received_at <> date_trunc('hour', received_at at time zone 'UTC') at time zone 'UTC'
  ) then
    raise exception 'public_events timestamps are not hour precision';
  end if;
  if exists (select 1 from public.public_events where id = 'd0000000-0000-4000-8000-000000000102') then
    raise exception 'an event inside the publication delay is public';
  end if;
  if exists (select 1 from public.public_events where src_country is not null or src_asn is not null) then
    raise exception 'per-event country/ASN is public';
  end if;
  if exists (
    select 1 from public.public_event_aggregates
    where granularity = 'hour'
      and bucket_start >= date_trunc('hour', (now() at time zone 'UTC') - interval '1 hour') at time zone 'UTC'
  ) then
    raise exception 'an hourly bucket inside the publication delay is public';
  end if;
end $$;

-- 5. Sensors: no last_event_at / last_error_at; heartbeat floored to 5 min;
--    outage intervals widened to 15 min (still distinguishable from 0 events).
do $$
declare
  r record;
begin
  select * into strict r from public.public_sensors where id = 'sensor-oracle-01';
  if r.last_event_at is not null or r.last_error_at is not null then
    raise exception 'public_sensors exposes last_event_at or last_error_at';
  end if;
  if r.last_heartbeat_at <> timestamptz '2026-11-28 05:05:00+00' then
    raise exception 'heartbeat should floor to 05:05, got %', r.last_heartbeat_at;
  end if;
  if r.heartbeat_stale is distinct from (timestamptz '2026-11-28 05:07:42+00' < now() - interval '15 minutes') then
    raise exception 'heartbeat_stale must use the unrounded heartbeat';
  end if;
  select * into strict r from public.public_sensor_status_events where sensor_id = 'sensor-oracle-01';
  if r.started_at <> timestamptz '2026-11-27 05:00:00+00' or r.ended_at <> timestamptz '2026-11-27 05:45:00+00' then
    raise exception 'outage should widen to 05:00-05:45, got % - %', r.started_at, r.ended_at;
  end if;
end $$;

-- 6. The eligibility table and its rollup are not reachable by API roles.
do $$
begin
  begin
    perform 1 from public.public_pattern_eligibility;
    raise exception 'SECURITY FAILURE: anon read public_pattern_eligibility';
  exception
    when insufficient_privilege then null;
  end;
  begin
    perform public.rollup_public_pattern_eligibility(now(), 3);
    raise exception 'SECURITY FAILURE: anon executed rollup_public_pattern_eligibility';
  exception
    when insufficient_privilege then null;
  end;
end $$;
reset role;

set local role authenticated;
do $$
begin
  if exists (select 1 from public.public_events where http_path_redacted like '%marker-xyz%') then
    raise exception 'authenticated sees the single-source marker path';
  end if;
  begin
    perform 1 from public.public_pattern_eligibility;
    raise exception 'SECURITY FAILURE: authenticated read public_pattern_eligibility';
  exception
    when insufficient_privilege then null;
  end;
end $$;
reset role;

-- 6a. A pattern row built before the cutoff existed (stale) is removed when
--     all of its observations are still inside the publication delay.
do $$
begin
  insert into public.attack_events (id, sensor_id, observed_at, protocol, dst_port, event_type, attack_category, src_ip_hash)
  values ('d0000000-0000-4000-8000-000000000301', 'sensor-oracle-01', now(), 'redis', 6379, 'redis_command', 'web_attack_attempt', 'hash-r');
  insert into public.observed_patterns (pattern_type, pattern_key, protocol, first_seen_at, last_seen_at, total_count)
  values ('attack_category', 'web_attack_attempt', 'redis', now() - interval '1 day', now(), 7);
  perform public.rollup_observation_aggregates(now(), 8);
  if exists (select 1 from public.observed_patterns where pattern_key = 'web_attack_attempt' and protocol = 'redis') then
    raise exception 'stale pattern row survived the rebuild';
  end if;
end $$;

-- 6b. Source counts use only publishable observations, and a path that falls
--     below k keeps eligibility but reports its current count.
do $$
declare
  v bigint;
begin
  -- A 4th source inside the publication delay must not change the public count.
  insert into public.attack_events (id, sensor_id, observed_at, protocol, dst_port, event_type,
                                    src_ip_hash, http_method, http_path_redacted)
  values ('d0000000-0000-4000-8000-000000000201', 'sensor-oracle-01', now(), 'http', 80, 'http_probe',
          'hash-new', 'GET', '/common-path');
  perform public.rollup_public_pattern_eligibility(now(), 3);
  select unique_source_count into strict v from public.public_pattern_eligibility where pattern_key = '/common-path';
  if v <> 3 then raise exception 'count changed before the new event is public: %', v; end if;
  -- Pattern totals and last-seen also ignore the unpublished event.
  perform public.rollup_observation_aggregates(now(), 8);
  select total_count into strict v from public.public_observed_patterns
  where pattern_type = 'http_path' and pattern_key = '/common-path';
  if v <> 3 then raise exception 'public pattern total moved before the event is public: %', v; end if;
  if exists (
    select 1 from public.public_observed_patterns
    where last_seen_at >= date_trunc('hour', (now() at time zone 'UTC') - interval '1 hour') at time zone 'UTC'
  ) then
    raise exception 'public pattern last_seen_at reveals the publication-delay window';
  end if;
  -- 40 days later the window holds no events: still eligible, count 0.
  perform public.rollup_public_pattern_eligibility(now() + interval '40 days', 3);
  select unique_source_count into strict v from public.public_pattern_eligibility where pattern_key = '/common-path';
  if v <> 0 then raise exception 'stale source count kept after falling below k: %', v; end if;
end $$;

-- 7. Eligibility is never revoked once crossed (rerun keeps it).
do $$
begin
  perform public.rollup_public_pattern_eligibility(now() + interval '60 days', 3);
  if not exists (select 1 from public.public_pattern_eligibility where pattern_key = '/common-path') then
    raise exception 'eligibility was revoked';
  end if;
  begin
    perform public.rollup_public_pattern_eligibility(now(), 1);
    raise exception 'k below 2 was accepted';
  exception
    when invalid_parameter_value then null;
  end;
end $$;

rollback;
