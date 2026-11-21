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
  src_ip,
  src_ip_hash,
  src_country,
  src_asn,
  http_method,
  http_path_redacted,
  fingerprint,
  raw_object_key,
  metadata
)
values (
  '11111111-1111-4111-8111-111111111111',
  'sensor-test-01',
  now() - interval '5 minutes',
  'http',
  80,
  'http_probe',
  '198.51.100.42'::inet,
  'salted-hash-example',
  'JP',
  'AS64512',
  'GET',
  '/wp-login.php?user=[REDACTED]',
  'fp-http-001',
  'raw_http_samples/2026-11-21/11111111.bin',
  '{"secret_header":"DO_NOT_EXPOSE","authorization":"Bearer synthetic"}'::jsonb
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
do $$
declare
  v_forbidden_cols text[];
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
end $$;

-- 3. Switch to anonymous role and assert strict default-deny on ALL base tables
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
    'ingest_receipts'
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
  if v_events_count <> 1 then
    raise exception 'Expected 1 public_events row, got %', v_events_count;
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
end $$;

rollback;
