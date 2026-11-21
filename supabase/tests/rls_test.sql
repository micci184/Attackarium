-- =============================================================================
-- Attackarium — PostgreSQL Schema, Idempotency & RLS Security Boundary Tests
-- =============================================================================
-- Run against a PostgreSQL instance after applying supabase/migrations/*.sql.
-- Fails fast with RAISE EXCEPTION on any security boundary regression.

\set ON_ERROR_STOP on

begin;

-- 1. Seed synthetic fixtures as privileged role (simulating ingest / jobs)
insert into public.sensors (id, name, type, region, is_active, last_heartbeat_at)
values ('sensor-test-01', 'Synthetic Test Sensor', 'combined', 'ap-northeast-1', true, now());

insert into public.attack_events (
  id,
  sensor_id,
  observed_at,
  protocol,
  dst_port,
  event_type,
  attack_category,
  src_ip_hash,
  src_country,
  src_asn,
  http_method,
  http_path_redacted,
  fingerprint,
  metadata
)
values (
  '11111111-1111-4111-8111-111111111111',
  'sensor-test-01',
  now() - interval '5 minutes',
  'http',
  80,
  'http_probe',
  'http_path_probe',
  'salted-hash-example',
  'JP',
  'AS64512',
  'GET',
  '/wp-login.php?user=[REDACTED]',
  'fp-http-001',
  '{"private_note":"DO_NOT_EXPOSE"}'::jsonb
);

-- Verify idempotent upsert on duplicate event_id
insert into public.attack_events (
  id, sensor_id, observed_at, protocol, dst_port, event_type
)
values (
  '11111111-1111-4111-8111-111111111111',
  'sensor-test-01',
  now(),
  'http',
  80,
  'http_probe_duplicate'
)
on conflict (id) do nothing;

do $$
declare
  v_count integer;
begin
  select count(*) into v_count
  from public.attack_events
  where id = '11111111-1111-4111-8111-111111111111';
  if v_count <> 1 then
    raise exception 'Expected exactly 1 row after duplicate upsert, got %', v_count;
  end if;
end $$;

-- Verify anti-replay primary key rejects duplicate request_id per sensor
insert into public.ingest_receipts (sensor_id, request_id, received_at, expires_at)
values ('sensor-test-01', 'req-unique-0001', now(), now() + interval '10 minutes');

do $$
begin
  insert into public.ingest_receipts (sensor_id, request_id, received_at, expires_at)
  values ('sensor-test-01', 'req-unique-0001', now(), now() + interval '10 minutes');
  raise exception 'Expected duplicate ingest_receipts insert to fail';
exception
  when unique_violation then
    null; -- expected
end $$;

-- Seed detections, vulnerabilities (1 matched, 1 unmatched), event_cve_matches
insert into public.detections (
  id, event_id, rule_id, rule_version, classification, confidence, evidence_redacted
)
values (
  '22222222-2222-4222-8222-222222222222',
  '11111111-1111-4111-8111-111111111111',
  'http-wp-login-probe',
  '1.0.0',
  'candidate_cve',
  0.650,
  '{"field":"http_path_redacted","matched":"/wp-login.php"}'::jsonb
);

insert into public.vulnerabilities (
  cve_id, description, vendor, product, kev_present, epss_score, epss_percentile, epss_date
)
values
  ('CVE-2024-0001', 'Synthetic matched CVE', 'ExampleVendor', 'ExampleCMS', true, 0.42000, 0.91000, date '2026-11-21'),
  ('CVE-2024-9999', 'Unmatched catalog CVE must not appear in public_vulnerabilities', 'Other', 'Other', false, 0.01000, 0.10000, date '2026-11-21');

insert into public.event_cve_matches (
  event_id, cve_id, detection_id, match_type, confidence, reason
)
values (
  '11111111-1111-4111-8111-111111111111',
  'CVE-2024-0001',
  '22222222-2222-4222-8222-222222222222',
  'candidate_cve',
  0.650,
  'Synthetic test rule matched probe path; candidate only, not exploit proof.'
);

insert into public.daily_stats (
  date_utc, sensor_id, protocol, event_type, event_count, unique_source_count
)
values (
  date '2026-11-21', 'sensor-test-01', 'http', 'http_probe', 12, 4
);

-- Seed one draft report (must stay hidden) and one published report (must be visible)
insert into public.daily_reports (
  date_utc, status, summary_md, x_post_draft, model_id, source_window_start, source_window_end, reviewed_at
)
values
  (
    date '2026-11-20',
    'published',
    'Published summary',
    'Draft tweet text that must not appear in public_daily_reports',
    'synthetic-model-v1',
    now() - interval '2 days',
    now() - interval '1 day',
    now() - interval '12 hours'
  ),
  (
    date '2026-11-21',
    'draft',
    'Unreviewed draft must NOT be publicly visible',
    'Unreviewed x post',
    'synthetic-model-v1',
    now() - interval '1 day',
    now(),
    null
  );

-- 2. Verify public_events projection excludes all sensitive columns
--    and all public_* views enforce security_barrier = true
do $$
declare
  v_forbidden_cols text[];
  v_unprotected_views text[];
begin
  select array_agg(column_name)
  into v_forbidden_cols
  from information_schema.columns
  where table_schema = 'public'
    and table_name = 'public_events'
    and column_name in ('src_ip', 'src_ip_hash', 'raw_object_key', 'metadata');

  if v_forbidden_cols is not null then
    raise exception 'Sensitive columns exposed in public_events: %', v_forbidden_cols;
  end if;

  select array_agg(c.relname)
  into v_unprotected_views
  from pg_class c
  join pg_namespace n on n.oid = c.relnamespace
  where n.nspname = 'public'
    and c.relkind = 'v'
    and c.relname like 'public_%'
    and (c.reloptions is null or not ('security_barrier=true' = any(c.reloptions)));

  if v_unprotected_views is not null then
    raise exception 'Public views missing security_barrier=true: %', v_unprotected_views;
  end if;
end $$;

-- 2a. Raw source IP and raw payload pointers are not columns
do $$
declare
  v_raw_cols text[];
begin
  select array_agg(column_name)
  into v_raw_cols
  from information_schema.columns
  where table_schema = 'public'
    and table_name = 'attack_events'
    and column_name in ('src_ip', 'raw_object_key');

  if v_raw_cols is not null then
    raise exception 'Raw IP or payload columns still exist on attack_events: %', v_raw_cols;
  end if;
end $$;

-- 2b. Verify atomic commit_ingest_batch RPC (idempotency, replay, rate limit, unknown sensor)
do $$
declare
  v_status text;
  v_inserted integer;
  v_hash text;
  v_now timestamptz := now();
  v_batch jsonb := jsonb_build_array(
    jsonb_build_object(
      'id', '33333333-3333-4333-8333-333333333333',
      'observed_at', (v_now - interval '1 minute')::text,
      'protocol', 'ssh',
      'dst_port', 22,
      'event_type', 'ssh_login_attempt',
      'src_ip', '198.51.100.42',
      'raw_object_key', 'raw_http_samples/ignored.bin',
      'src_ip_hash', 'deadbeef',
      'src_country', 'JP',
      'src_asn', 'AS64512',
      'metadata', jsonb_build_object('banner', 'OpenSSH')
    )
  );
begin
  -- First batch succeeds and inserts 1 event
  select status, inserted_count into v_status, v_inserted
  from public.commit_ingest_batch(
    'sensor-test-01',
    'req-rpc-0001',
    v_now,
    v_now + interval '10 minutes',
    2,
    v_batch
  );
  if v_status <> 'ok' or v_inserted <> 1 then
    raise exception 'Expected ok/1 from commit_ingest_batch, got %/%', v_status, v_inserted;
  end if;

  select src_ip_hash into v_hash
  from public.attack_events
  where id = '33333333-3333-4333-8333-333333333333';
  if v_hash <> 'deadbeef' then
    raise exception 'Expected keyed hash to be stored and raw IP discarded, got %', v_hash;
  end if;

  -- Replay of same request_id is rejected
  select status, inserted_count into v_status, v_inserted
  from public.commit_ingest_batch(
    'sensor-test-01',
    'req-rpc-0001',
    v_now + interval '1 second',
    v_now + interval '10 minutes',
    2,
    v_batch
  );
  if v_status <> 'replayed' or v_inserted <> 0 then
    raise exception 'Expected replayed/0, got %/%', v_status, v_inserted;
  end if;

  -- Retry with new request_id hits rate_limit (already 2 receipts in window: req-unique-0001 + req-rpc-0001)
  select status, inserted_count into v_status, v_inserted
  from public.commit_ingest_batch(
    'sensor-test-01',
    'req-rpc-0002',
    v_now + interval '2 seconds',
    v_now + interval '10 minutes',
    2,
    v_batch
  );
  if v_status <> 'rate_limited' or v_inserted <> 0 then
    raise exception 'Expected rate_limited/0, got %/%', v_status, v_inserted;
  end if;

  -- Higher limit allows retry and deduplicates event id (0 new rows)
  select status, inserted_count into v_status, v_inserted
  from public.commit_ingest_batch(
    'sensor-test-01',
    'req-rpc-0003',
    v_now + interval '3 seconds',
    v_now + interval '10 minutes',
    10,
    v_batch
  );
  if v_status <> 'ok' or v_inserted <> 0 then
    raise exception 'Expected ok/0 on duplicate event retry, got %/%', v_status, v_inserted;
  end if;

  -- Unregistered sensor returns unknown_sensor without inserting receipts
  select status, inserted_count into v_status, v_inserted
  from public.commit_ingest_batch(
    'sensor-missing-99',
    'req-rpc-0004',
    v_now,
    v_now + interval '10 minutes',
    10,
    v_batch
  );
  if v_status <> 'unknown_sensor' then
    raise exception 'Expected unknown_sensor, got %', v_status;
  end if;
end $$;

update public.sensors
set monitored_services = array['ssh', 'http']::text[]
where id = 'sensor-test-01';

insert into public.event_aggregates (
  bucket_start, granularity, sensor_id, protocol, attack_category, event_count, unique_source_count
) values (
  date_trunc('hour', now()), 'hour', 'sensor-test-01', 'http', 'http_path_probe', 3, 2
);

insert into public.observed_patterns (
  pattern_type, pattern_key, protocol, first_seen_at, last_seen_at, total_count
) values (
  'http_path', '/wp-login.php', 'http', now() - interval '1 day', now(), 4
);

insert into public.sensor_status_events (
  sensor_id, status, started_at, ended_at, summary
) values (
  'sensor-test-01',
  'offline',
  now() - interval '2 hours',
  now() - interval '1 hour',
  'synthetic collection gap'
);

-- 3. Switch to anonymous role and assert strict default-deny on ALL base tables and RPCs
set local role anon;

do $$
declare
  v_table text;
  v_tables text[] := array[
    'sensors',
    'attack_events',
    'detections',
    'vulnerabilities',
    'event_cve_matches',
    'daily_stats',
    'daily_reports',
    'ingest_receipts',
    'event_aggregates',
    'observed_patterns',
    'sensor_status_events'
  ];
  v_cnt integer;
begin
  foreach v_table in array v_tables loop
    begin
      execute format('select count(*) from public.%I', v_table) into v_cnt;
      raise exception 'SECURITY FAILURE: anon was allowed to SELECT from base table %', v_table;
    exception
      when insufficient_privilege then
        null; -- expected
    end;
  end loop;
end $$;

-- Verify anon cannot execute commit_ingest_batch RPC
do $$
begin
  perform * from public.commit_ingest_batch(
    'sensor-test-01',
    'req-anon-evil-1',
    now(),
    now() + interval '10 minutes',
    10,
    '[]'::jsonb
  );
  raise exception 'SECURITY FAILURE: anon was allowed to EXECUTE commit_ingest_batch';
exception
  when insufficient_privilege then
    null; -- expected
end $$;

-- Verify anon cannot write to base tables or public views
do $$
begin
  insert into public.sensors (id, name, type, region)
  values ('sensor-evil-01', 'Evil', 'combined', 'us-east-1');
  raise exception 'SECURITY FAILURE: anon was allowed to INSERT into public.sensors';
exception
  when insufficient_privilege then
    null; -- expected
end $$;

do $$
begin
  delete from public.public_events;
  raise exception 'SECURITY FAILURE: anon was allowed to DELETE from public.public_events';
exception
  when insufficient_privilege then
    null; -- expected
end $$;

-- 4. Verify anon CAN read sanitized public views with expected filtering
do $$
declare
  v_events_count integer;
  v_sensors_count integer;
  v_vuln_count integer;
  v_reports_count integer;
  v_stats_count integer;
begin
  select count(*) into v_sensors_count from public.public_sensors;
  if v_sensors_count <> 1 then
    raise exception 'Expected 1 public_sensors row, got %', v_sensors_count;
  end if;

  select count(*) into v_events_count from public.public_events;
  if v_events_count <> 2 then
    raise exception 'Expected 2 public_events rows, got %', v_events_count;
  end if;

  select count(*) into v_vuln_count from public.public_vulnerabilities;
  if v_vuln_count <> 1 then
    raise exception 'Expected only 1 matched CVE in public_vulnerabilities, got %', v_vuln_count;
  end if;

  select count(*) into v_reports_count from public.public_daily_reports;
  if v_reports_count <> 1 then
    raise exception 'Expected only 1 published report in public_daily_reports, got %', v_reports_count;
  end if;

  select count(*) into v_stats_count from public.public_daily_stats;
  if v_stats_count <> 1 then
    raise exception 'Expected 1 public_daily_stats row, got %', v_stats_count;
  end if;

  if (select count(*) from public.public_event_aggregates) <> 1 then
    raise exception 'Expected 1 public_event_aggregates row';
  end if;
  if (select count(*) from public.public_observed_patterns) <> 1 then
    raise exception 'Expected 1 public_observed_patterns row';
  end if;
  if (select count(*) from public.public_sensor_status_events) <> 1 then
    raise exception 'Expected 1 public_sensor_status_events row';
  end if;
  if not exists (
    select 1 from public.public_events where attack_category = 'http_path_probe'
  ) then
    raise exception 'public_events did not expose attack_category';
  end if;
  if exists (
    select 1
    from information_schema.columns
    where table_schema = 'public'
      and table_name = 'public_sensor_status_events'
      and column_name = 'summary'
  ) then
    raise exception 'sensor status summary leaked into the public view';
  end if;
  if exists (
    select 1
    from information_schema.columns
    where table_schema = 'public'
      and table_name = 'public_sensors'
      and column_name = 'last_error_summary'
  ) then
    raise exception 'last_error_summary leaked into public_sensors';
  end if;
end $$;

-- 5. Verify authenticated role ALSO faces strict default-deny on base tables and ingest RPC
reset role;
set local role authenticated;

do $$
declare
  v_table text;
  v_tables text[] := array[
    'sensors',
    'attack_events',
    'detections',
    'vulnerabilities',
    'event_cve_matches',
    'daily_stats',
    'daily_reports',
    'ingest_receipts',
    'event_aggregates',
    'observed_patterns',
    'sensor_status_events'
  ];
  v_cnt integer;
begin
  foreach v_table in array v_tables loop
    begin
      execute format('select count(*) from public.%I', v_table) into v_cnt;
      raise exception 'SECURITY FAILURE: authenticated was allowed to SELECT from base table %', v_table;
    exception
      when insufficient_privilege then
        null; -- expected
    end;
  end loop;
end $$;

do $$
begin
  perform * from public.commit_ingest_batch(
    'sensor-test-01',
    'req-auth-evil-1',
    now(),
    now() + interval '10 minutes',
    10,
    '[]'::jsonb
  );
  raise exception 'SECURITY FAILURE: authenticated was allowed to EXECUTE commit_ingest_batch';
exception
  when insufficient_privilege then
    null; -- expected
end $$;

do $$
begin
  perform public.sync_sensor_coverage_gaps(now());
  raise exception 'SECURITY FAILURE: authenticated was allowed to EXECUTE sync_sensor_coverage_gaps';
exception
  when insufficient_privilege then
    null; -- expected
end $$;

do $$
begin
  perform public.run_scheduled_observation_maintenance();
  raise exception 'SECURITY FAILURE: authenticated was allowed to EXECUTE run_scheduled_observation_maintenance';
exception
  when insufficient_privilege then
    null; -- expected
end $$;

do $$
begin
  if (select count(*) from public.public_event_aggregates) <> 1
    or (select count(*) from public.public_observed_patterns) <> 1
    or (select count(*) from public.public_sensor_status_events) <> 1
    or (select count(*) from public.public_events where attack_category = 'auth_attempt') <> 1
  then
    raise exception 'authenticated could not read the sanitized observation views';
  end if;
end $$;

rollback;
