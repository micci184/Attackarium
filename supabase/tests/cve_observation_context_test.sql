-- =============================================================================
-- Attackarium — CVE observation context (#84) tests
-- =============================================================================
\set ON_ERROR_STOP on

begin;

insert into public.sensors (id, name, type, region, is_active, last_heartbeat_at)
values ('sensor-cve-01', 'Synthetic CVE Sensor', 'combined', 'us-east-1', true, now());

insert into public.vulnerabilities (cve_id) values ('CVE-2025-31324'), ('CVE-2021-44228');

-- An event observed 20 days ago whose match is written (re-evaluated) now,
-- and an event observed 1 hour ago.
insert into public.attack_events (id, sensor_id, observed_at, protocol, dst_port, event_type, attack_category, http_method, http_path_redacted)
values
  ('aaaaaaaa-0000-4000-8000-000000000001', 'sensor-cve-01', now() - interval '20 days', 'http', 80, 'http_probe', 'suspected_cve_probe', 'GET', '/developmentserver/metadatauploader'),
  ('aaaaaaaa-0000-4000-8000-000000000002', 'sensor-cve-01', now() - interval '1 hour', 'http', 80, 'http_probe', 'suspected_cve_probe', 'GET', '/developmentserver/metadatauploader'),
  ('aaaaaaaa-0000-4000-8000-000000000003', 'sensor-cve-01', now() - interval '2 hours', 'http', 80, 'http_probe', 'suspected_cve_probe', 'GET', '/');

insert into public.detections (id, event_id, rule_id, rule_version, classification, confidence, evidence_redacted)
values
  ('bbbbbbbb-0000-4000-8000-000000000001', 'aaaaaaaa-0000-4000-8000-000000000001', 'http-sap-netweaver-cve-2025-31324', '1.0.0', 'candidate_cve', 0.7,
   '{"indicator":"sap_visual_composer_metadatauploader_path","matched_location":"url","match_strength":"medium","summary":"x"}'),
  ('bbbbbbbb-0000-4000-8000-000000000002', 'aaaaaaaa-0000-4000-8000-000000000002', 'http-sap-netweaver-cve-2025-31324', '1.0.0', 'candidate_cve', 0.7,
   '{"indicator":"sap_visual_composer_metadatauploader_path","matched_location":"url","match_strength":"medium","summary":"x"}'),
  -- Two detections of the same CVE on one event must collapse in public_cve_events.
  ('bbbbbbbb-0000-4000-8000-000000000003', 'aaaaaaaa-0000-4000-8000-000000000002', 'http-other-rule', '1.0.0', 'candidate_cve', 0.9,
   '{"indicator":"x","matched_location":"header:x-api-key","match_strength":"bogus"}'),
  ('bbbbbbbb-0000-4000-8000-000000000004', 'aaaaaaaa-0000-4000-8000-000000000003', 'http-log4shell', '1.0.0', 'candidate_cve', 0.9,
   '{"indicator":"jndi","matched_location":"<script>","match_strength":"high"}');

insert into public.event_cve_matches (event_id, cve_id, detection_id, match_type, confidence, reason, created_at)
values
  ('aaaaaaaa-0000-4000-8000-000000000001', 'CVE-2025-31324', 'bbbbbbbb-0000-4000-8000-000000000001', 'candidate_cve', 0.7, 'r', now()),
  ('aaaaaaaa-0000-4000-8000-000000000002', 'CVE-2025-31324', 'bbbbbbbb-0000-4000-8000-000000000002', 'candidate_cve', 0.7, 'r', now()),
  ('aaaaaaaa-0000-4000-8000-000000000002', 'CVE-2025-31324', 'bbbbbbbb-0000-4000-8000-000000000003', 'candidate_cve', 0.9, 'r', now()),
  ('aaaaaaaa-0000-4000-8000-000000000003', 'CVE-2021-44228', 'bbbbbbbb-0000-4000-8000-000000000004', 'candidate_cve', 0.9, 'r', now());

do $$
declare
  n integer;
  r record;
begin
  -- observed_at is the event time; created_at stays the write time.
  select count(*) into n from public.public_event_cve_matches
  where cve_id = 'CVE-2025-31324' and observed_at >= now() - interval '24 hours';
  if n <> 2 then raise exception 'expected 2 recent CVE-2025-31324 matches by observed_at, got %', n; end if;
  select count(*) into n from public.public_event_cve_matches
  where cve_id = 'CVE-2025-31324' and created_at >= now() - interval '24 hours';
  if n <> 3 then raise exception 'created_at must remain the write time (3 rows), got %', n; end if;

  -- Strength and evidence basis are exposed only from the controlled vocabulary.
  select * into strict r from public.public_event_cve_matches where detection_id = 'bbbbbbbb-0000-4000-8000-000000000001';
  if r.match_strength is distinct from 'medium' or r.matched_location is distinct from 'url'
     or r.indicator is distinct from 'sap_visual_composer_metadatauploader_path' then
    raise exception 'unexpected strength/evidence: % % %', r.match_strength, r.matched_location, r.indicator;
  end if;
  select * into strict r from public.public_event_cve_matches where detection_id = 'bbbbbbbb-0000-4000-8000-000000000003';
  if r.match_strength is not null or r.matched_location is distinct from 'header:x-api-key' then
    raise exception 'invalid strength must be null; safe header label kept: % %', r.match_strength, r.matched_location;
  end if;
  select * into strict r from public.public_event_cve_matches where detection_id = 'bbbbbbbb-0000-4000-8000-000000000004';
  if r.matched_location is not null then raise exception 'unsafe location leaked: %', r.matched_location; end if;

  -- public_vulnerabilities: last_observed_at is the latest observation.
  select * into strict r from public.public_vulnerabilities where cve_id = 'CVE-2025-31324';
  if r.last_observed_at is null or r.last_observed_at < now() - interval '2 hours' then
    raise exception 'last_observed_at should be ~1 hour ago, got %', r.last_observed_at;
  end if;
  if r.matched_event_count is distinct from 2 then raise exception 'matched_event_count changed: %', r.matched_event_count; end if;

  -- public_cve_events: one row per (event, cve), same columns as public_events plus cve_id.
  select count(*) into n from public.public_cve_events where cve_id = 'CVE-2025-31324';
  if n <> 2 then raise exception 'expected 2 events for CVE-2025-31324, got %', n; end if;
  select count(*) into n from public.public_cve_events where cve_id = 'CVE-2025-31324' and observed_at >= now() - interval '24 hours';
  if n <> 1 then raise exception 'expected 1 recent event, got %', n; end if;
  if exists (
    select 1 from information_schema.columns
    where table_schema = 'public' and table_name = 'public_cve_events'
      and column_name not in (
        select column_name from information_schema.columns
        where table_schema = 'public' and table_name = 'public_events'
      )
      and column_name <> 'cve_id'
  ) then
    raise exception 'public_cve_events exposes a column that public_events does not';
  end if;
end $$;

-- anon and authenticated can read the public views, never the base tables.
set local role anon;
do $$
declare n integer;
begin
  select count(*) into n from public.public_cve_events;
  if n < 1 then raise exception 'anon cannot read public_cve_events'; end if;
  select count(*) into n from public.public_event_cve_matches where observed_at is not null;
  if n < 1 then raise exception 'anon cannot read observed_at on public_event_cve_matches'; end if;
  begin
    perform 1 from public.event_cve_matches limit 1;
    raise exception 'SECURITY FAILURE: anon read event_cve_matches';
  exception when insufficient_privilege then null;
  end;
end $$;
reset role;
set local role authenticated;
do $$
declare n integer;
begin
  select count(*) into n from public.public_cve_events;
  if n < 1 then raise exception 'authenticated cannot read public_cve_events'; end if;
  begin
    perform 1 from public.detections limit 1;
    raise exception 'SECURITY FAILURE: authenticated read detections';
  exception when insufficient_privilege then null;
  end;
end $$;
reset role;

rollback;

\echo 'cve_observation_context_test: all checks passed'
