-- =============================================================================
-- Attackarium — long-term detection / candidate-CVE daily counts (#84)
-- =============================================================================
-- Session TimeZone is UTC+9 so a UTC day boundary is not the local midnight.
\set ON_ERROR_STOP on

begin;

set local time zone interval '+09:00';

insert into public.sensors (id, name, type, region, is_active)
values ('sensor-sighist-01', 'Signature History Sensor', 'combined', 'us-east-1', true);

insert into public.vulnerabilities (cve_id) values ('CVE-2099-0001'), ('CVE-2099-0002')
on conflict do nothing;

-- e1: 2026-11-20 23:30 UTC (local 11-21), http, source A
-- e2: 2026-11-21 01:00 UTC, https, source A
-- e3: 2026-11-21 02:00 UTC, http, source B, matched by two versions of rule-x
-- e4: 2026-11-21 03:00 UTC, http, source B, technique-only rule (no CVE)
-- e5: 2026-11-21 04:00 UTC, http, source C, one detection -> two CVEs
insert into public.attack_events (id, sensor_id, observed_at, protocol, dst_port, event_type, attack_category, src_ip_hash)
values
  ('c0000000-0000-4000-8000-000000000001', 'sensor-sighist-01', timestamptz '2026-11-20 23:30:00+00', 'http', 80, 'http_probe', 'suspected_cve_probe', 'hash-a'),
  ('c0000000-0000-4000-8000-000000000002', 'sensor-sighist-01', timestamptz '2026-11-21 01:00:00+00', 'https', 443, 'http_probe', 'suspected_cve_probe', 'hash-a'),
  ('c0000000-0000-4000-8000-000000000003', 'sensor-sighist-01', timestamptz '2026-11-21 02:00:00+00', 'http', 80, 'http_probe', 'suspected_cve_probe', 'hash-b'),
  ('c0000000-0000-4000-8000-000000000004', 'sensor-sighist-01', timestamptz '2026-11-21 03:00:00+00', 'http', 80, 'http_probe', 'web_attack_attempt', 'hash-b'),
  ('c0000000-0000-4000-8000-000000000005', 'sensor-sighist-01', timestamptz '2026-11-21 04:00:00+00', 'http', 80, 'http_probe', 'suspected_cve_probe', 'hash-c');

insert into public.detections (id, event_id, rule_id, rule_version, classification, confidence)
values
  ('d0000000-0000-4000-8000-000000000001', 'c0000000-0000-4000-8000-000000000001', 'rule-x', '1.0.0', 'candidate_cve', 0.7),
  ('d0000000-0000-4000-8000-000000000002', 'c0000000-0000-4000-8000-000000000002', 'rule-x', '1.0.0', 'candidate_cve', 0.7),
  ('d0000000-0000-4000-8000-000000000003', 'c0000000-0000-4000-8000-000000000003', 'rule-x', '1.0.0', 'candidate_cve', 0.7),
  ('d0000000-0000-4000-8000-000000000004', 'c0000000-0000-4000-8000-000000000003', 'rule-x', '1.1.0', 'candidate_cve', 0.8),
  ('d0000000-0000-4000-8000-000000000005', 'c0000000-0000-4000-8000-000000000004', 'rule-sqli', '1.0.0', 'observed', 0.5),
  ('d0000000-0000-4000-8000-000000000006', 'c0000000-0000-4000-8000-000000000005', 'rule-multi', '1.0.0', 'candidate_cve', 0.6);

-- Matches written "now" (much later than observed): created_at must not matter.
insert into public.event_cve_matches (event_id, cve_id, detection_id, match_type, confidence, reason, created_at)
values
  ('c0000000-0000-4000-8000-000000000001', 'CVE-2099-0001', 'd0000000-0000-4000-8000-000000000001', 'candidate_cve', 0.7, 'r', now()),
  ('c0000000-0000-4000-8000-000000000002', 'CVE-2099-0001', 'd0000000-0000-4000-8000-000000000002', 'candidate_cve', 0.7, 'r', now()),
  ('c0000000-0000-4000-8000-000000000003', 'CVE-2099-0001', 'd0000000-0000-4000-8000-000000000003', 'candidate_cve', 0.7, 'r', now()),
  ('c0000000-0000-4000-8000-000000000003', 'CVE-2099-0001', 'd0000000-0000-4000-8000-000000000004', 'candidate_cve', 0.8, 'r', now()),
  ('c0000000-0000-4000-8000-000000000005', 'CVE-2099-0001', 'd0000000-0000-4000-8000-000000000006', 'candidate_cve', 0.6, 'r', now()),
  ('c0000000-0000-4000-8000-000000000005', 'CVE-2099-0002', 'd0000000-0000-4000-8000-000000000006', 'candidate_cve', 0.6, 'r', now());

-- 1. Rows by observed UTC day, rule version, CVE ('' = technique-only), and
--    protocol; counts and distinct sources; idempotent re-run.
do $$
declare
  v_rows text;
  v_expected text :=
    '2026-11-20|rule-x|1.0.0|CVE-2099-0001|http|1|1;'
    '2026-11-21|rule-multi|1.0.0|CVE-2099-0001|http|1|1;'
    '2026-11-21|rule-multi|1.0.0|CVE-2099-0002|http|1|1;'
    '2026-11-21|rule-sqli|1.0.0||http|1|1;'
    '2026-11-21|rule-x|1.0.0|CVE-2099-0001|http|1|1;'
    '2026-11-21|rule-x|1.0.0|CVE-2099-0001|https|1|1;'
    '2026-11-21|rule-x|1.1.0|CVE-2099-0001|http|1|1';
begin
  perform public.rollup_signature_daily_counts(timestamptz '2026-11-25 00:00:00+00', 8);
  perform public.rollup_signature_daily_counts(timestamptz '2026-11-25 00:00:00+00', 8);
  select string_agg(
    concat_ws('|', date_utc, rule_id, rule_version, cve_id, protocol, event_count, unique_source_count),
    ';' order by date_utc, rule_id, rule_version, cve_id, protocol
  )
  into v_rows
  from public.signature_daily_counts
  where rule_id in ('rule-x', 'rule-sqli', 'rule-multi');
  if v_rows is distinct from v_expected then
    raise exception E'unexpected daily counts:\n%\nexpected:\n%', v_rows, v_expected;
  end if;
end $$;

-- 2. Distinct sources: two events from the same source on one day count once.
do $$
declare
  v_events bigint;
  v_sources bigint;
begin
  insert into public.attack_events (id, sensor_id, observed_at, protocol, dst_port, event_type, attack_category, src_ip_hash)
  values ('c0000000-0000-4000-8000-000000000006', 'sensor-sighist-01', timestamptz '2026-11-21 05:00:00+00', 'http', 80, 'http_probe', 'web_attack_attempt', 'hash-b');
  insert into public.detections (event_id, rule_id, rule_version, classification, confidence)
  values ('c0000000-0000-4000-8000-000000000006', 'rule-sqli', '1.0.0', 'observed', 0.5);
  perform public.rollup_signature_daily_counts(timestamptz '2026-11-25 00:00:00+00', 8);
  select event_count, unique_source_count into strict v_events, v_sources
  from public.signature_daily_counts
  where date_utc = date '2026-11-21' and rule_id = 'rule-sqli';
  if v_events <> 2 or v_sources <> 1 then
    raise exception 'expected 2 events from 1 source, got % / %', v_events, v_sources;
  end if;
end $$;

-- 3. Counts survive retention: pruning the events (and, by cascade, their
--    detections and matches) must not touch days outside the rollup window.
do $$
declare
  v_events bigint;
  v_rows bigint;
begin
  perform public.run_observation_maintenance(timestamptz '2026-12-31 00:00:00+00', 30, 8);
  select count(*) into v_events from public.attack_events where sensor_id = 'sensor-sighist-01';
  if v_events <> 0 then
    raise exception 'fixture events were not pruned (% left)', v_events;
  end if;
  select count(*) into v_rows
  from public.signature_daily_counts
  where rule_id in ('rule-x', 'rule-sqli', 'rule-multi');
  if v_rows <> 7 then
    raise exception 'daily signature counts were lost after retention: % rows', v_rows;
  end if;
end $$;

-- 4. Window bounds are enforced.
do $$
begin
  begin
    perform public.rollup_signature_daily_counts(now(), 7);
    raise exception 'window below 8 days was accepted';
  exception
    when invalid_parameter_value then null;
  end;
  begin
    perform public.rollup_signature_daily_counts(null, 8);
    raise exception 'null p_now was accepted';
  exception
    when invalid_parameter_value then null;
  end;
end $$;

-- 5. Public access: the day-granular view only (cve_id NULL for
--    technique-only rules); no base table, no rollup execution.
set local role anon;
do $$
declare
  v_rows bigint;
  v_technique bigint;
begin
  select count(*), count(*) filter (where cve_id is null)
  into v_rows, v_technique
  from public.public_signature_daily_counts
  where rule_id in ('rule-x', 'rule-sqli', 'rule-multi');
  if v_rows <> 7 or v_technique <> 1 then
    raise exception 'anon view rows % (technique-only %), expected 7 (1)', v_rows, v_technique;
  end if;
  begin
    perform 1 from public.signature_daily_counts;
    raise exception 'SECURITY FAILURE: anon read signature_daily_counts';
  exception
    when insufficient_privilege then null;
  end;
  begin
    perform public.rollup_signature_daily_counts(now(), 8);
    raise exception 'SECURITY FAILURE: anon executed rollup_signature_daily_counts';
  exception
    when insufficient_privilege then null;
  end;
end $$;
reset role;

set local role authenticated;
do $$
begin
  begin
    perform 1 from public.signature_daily_counts;
    raise exception 'SECURITY FAILURE: authenticated read signature_daily_counts';
  exception
    when insufficient_privilege then null;
  end;
end $$;
reset role;

-- 6. The public view exposes no intra-day timestamps and is a barrier view.
do $$
begin
  if exists (
    select 1 from information_schema.columns
    where table_schema = 'public' and table_name = 'public_signature_daily_counts'
      and column_name in ('first_seen_at', 'last_seen_at', 'updated_at')
  ) then
    raise exception 'public_signature_daily_counts exposes intra-day timestamps';
  end if;
  if not exists (
    select 1 from pg_class c
    where c.oid = 'public.public_signature_daily_counts'::regclass
      and c.reloptions @> array['security_barrier=true']
  ) then
    raise exception 'public_signature_daily_counts is not a security_barrier view';
  end if;
end $$;

rollback;
