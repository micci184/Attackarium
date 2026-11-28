-- =============================================================================
-- Stop public surfaces from acting as a sensor-identification oracle (#88)
-- =============================================================================
-- Anyone could send a unique marker (an HTTP path, a precomputable
-- fingerprint, or a single connection at a known second) to a suspected IP and
-- look for it on Attackarium. The public views are what the dashboard, Remote
-- MCP, and any direct anon REST read share, so the controls live here (L6).
--
-- Operator decisions (2026-11-28): k = 3 distinct sources, hour-precision
-- public timestamps, publication about 1 hour after the hour closes, and the
-- Events page keeps per-event rows.
--
--   L1  An HTTP path is public only once at least 3 distinct sources
--       (src_ip_hash) sent it within the 30-day retention window. Otherwise
--       public views return NULL for the path ("uncommon path").
--       Eligibility is recorded in a private table and never revoked, and a
--       path's public "first seen" is when it crossed the threshold.
--   L2  HTTP fingerprints (http-*) are precomputable from method, path, and
--       user agent, so they are never public. Only OpenCanary fingerprints
--       (oc-<logtype>, a fixed set) remain.
--   L3  Public per-event, detection, and match timestamps are truncated to the
--       UTC hour. last_event_at and last_error_at are no longer published
--       (columns kept, always NULL, so existing readers do not break).
--       last_heartbeat_at is floored to 5 minutes (it moves on every delivery)
--       and outage intervals are widened to 15-minute boundaries.
--   L4  Events, detections, matches, and hourly buckets become public about
--       one hour after their hour closes (visible when observed before the
--       start of the previous UTC hour).
--   L5  public_observed_patterns exposes unique_source_count so top paths are
--       ranked by distinct sources rather than by event count.
--
-- Residual risks are documented in docs/SECURITY.md.
-- =============================================================================

-- -----------------------------------------------------------------------------
-- L1: private eligibility table (never pruned, like other aggregates)
-- -----------------------------------------------------------------------------
create table if not exists public.public_pattern_eligibility (
  pattern_type text not null check (pattern_type in ('http_path')),
  pattern_key text not null check (char_length(pattern_key) between 1 and 512),
  protocol text not null check (protocol in ('http', 'https')),
  unique_source_count bigint not null check (unique_source_count >= 0),
  crossed_at timestamptz not null,
  last_seen_at timestamptz not null,
  updated_at timestamptz not null default now(),
  primary key (pattern_type, pattern_key, protocol),
  check (last_seen_at >= crossed_at)
);

comment on table public.public_pattern_eligibility is
  'PRIVATE. HTTP paths seen from at least k distinct sources (#88). crossed_at is when the k-th distinct source first sent the path; only listed paths are published.';

alter table public.public_pattern_eligibility enable row level security;
alter table public.public_pattern_eligibility force row level security;
revoke all on table public.public_pattern_eligibility from public, anon, authenticated;
grant all on table public.public_pattern_eligibility to service_role;

create or replace function public.rollup_public_pattern_eligibility(
  p_now timestamptz,
  p_k integer default 3
)
returns void
language plpgsql
security invoker
set search_path = ''
as $$
declare
  v_cutoff timestamptz;
begin
  if p_now is null then
    raise exception 'p_now is required' using errcode = '22023';
  end if;
  if p_k is null or p_k < 2 or p_k > 100 then
    raise exception 'k must be between 2 and 100' using errcode = '22023';
  end if;

  -- Same lock as the other rollups and retention.
  perform pg_catalog.pg_advisory_xact_lock(8217001);

  v_cutoff := pg_catalog.date_trunc('hour', (p_now at time zone 'UTC') - interval '1 hour') at time zone 'UTC';

  -- Counts use only observations that are already publishable (before the
  -- publication cutoff), so a public count never changes before the events
  -- that changed it become public.
  insert into public.public_pattern_eligibility as t (
    pattern_type,
    pattern_key,
    protocol,
    unique_source_count,
    crossed_at,
    last_seen_at,
    updated_at
  )
  select
    'http_path',
    per_path.path,
    per_path.protocol,
    per_path.sources,
    per_path.crossed_at,
    per_path.last_seen_at,
    p_now
  from (
    select
      per_source.path,
      per_source.protocol,
      pg_catalog.count(*)::bigint as sources,
      -- When the k-th distinct source first sent this path.
      (pg_catalog.array_agg(per_source.first_seen order by per_source.first_seen))[p_k] as crossed_at,
      pg_catalog.max(per_source.last_seen) as last_seen_at
    from (
      select
        ae.http_path_redacted as path,
        ae.protocol,
        ae.src_ip_hash,
        pg_catalog.min(ae.observed_at) as first_seen,
        pg_catalog.max(ae.observed_at) as last_seen
      from public.attack_events ae
      where ae.protocol in ('http', 'https')
        and ae.http_path_redacted is not null
        and ae.src_ip_hash is not null
        and ae.observed_at >= p_now - interval '30 days'
        and ae.observed_at < v_cutoff
      group by 1, 2, 3
    ) as per_source
    group by 1, 2
    having pg_catalog.count(*) >= p_k
  ) as per_path
  on conflict (pattern_type, pattern_key, protocol) do update
    set unique_source_count = excluded.unique_source_count,
        crossed_at = least(t.crossed_at, excluded.crossed_at),
        last_seen_at = greatest(t.last_seen_at, excluded.last_seen_at),
        updated_at = excluded.updated_at;

  -- Eligibility is permanent, but the source count of a path that is now below
  -- k (or absent from the window) must not stay at an old, higher value.
  update public.public_pattern_eligibility t
  set unique_source_count = (
        select pg_catalog.count(distinct ae.src_ip_hash)
        from public.attack_events ae
        where ae.http_path_redacted = t.pattern_key
          and ae.protocol = t.protocol
          and ae.src_ip_hash is not null
          and ae.observed_at >= p_now - interval '30 days'
          and ae.observed_at < v_cutoff
      ),
      updated_at = p_now
  where t.updated_at is distinct from p_now;
end;
$$;

revoke all on function public.rollup_public_pattern_eligibility(timestamptz, integer)
  from public, anon, authenticated;
grant execute on function public.rollup_public_pattern_eligibility(timestamptz, integer) to service_role;

-- Same rollup as 20261122000003, except that the pattern rows
-- (pattern_daily_counts -> observed_patterns) are built only from observations
-- before the publication cutoff. Signature and other outputs unchanged.
create or replace function public.rollup_observation_aggregates(
  p_now timestamptz,
  p_window_days integer default 8
)
returns void
language plpgsql
security invoker
set search_path = ''
as $$
declare
  v_window_start timestamptz;
  v_pattern_cutoff timestamptz;
begin
  if p_now is null then
    raise exception 'p_now is required' using errcode = '22023';
  end if;
  if p_window_days is null or p_window_days < 8 or p_window_days > 30 then
    raise exception 'rollup window must be between 8 and 30 days' using errcode = '22023';
  end if;

  -- Patterns feed only public_observed_patterns, so they are built from
  -- publishable observations (before the #88 publication cutoff). Counts,
  -- first seen, and last seen therefore never move before the events behind
  -- them are public. Event aggregates and daily stats stay current.
  v_pattern_cutoff := pg_catalog.date_trunc('hour', (p_now at time zone 'UTC') - interval '1 hour') at time zone 'UTC';

  -- Serialize rollup and retention runs.
  perform pg_catalog.pg_advisory_xact_lock(8217001);

  v_window_start := pg_catalog.date_trunc(
    'day',
    (p_now - pg_catalog.make_interval(days => p_window_days)) at time zone 'UTC'
  ) at time zone 'UTC';

  delete from public.event_aggregates a
  where a.bucket_start >= v_window_start;

  delete from public.daily_stats d
  where d.date_utc >= (v_window_start at time zone 'UTC')::date;

  delete from public.pattern_daily_counts p
  where p.date_utc >= (v_window_start at time zone 'UTC')::date;

  insert into public.event_aggregates (
    bucket_start,
    granularity,
    sensor_id,
    protocol,
    attack_category,
    event_count,
    unique_source_count,
    updated_at
  )
  select
    pg_catalog.date_trunc('hour', ae.observed_at at time zone 'UTC') at time zone 'UTC',
    'hour',
    ae.sensor_id,
    ae.protocol,
    ae.attack_category,
    pg_catalog.count(*)::bigint,
    pg_catalog.count(distinct ae.src_ip_hash)::bigint,
    p_now
  from public.attack_events ae
  where ae.observed_at >= v_window_start
    and ae.attack_category is not null
  group by 1, 3, 4, 5;

  insert into public.event_aggregates (
    bucket_start,
    granularity,
    sensor_id,
    protocol,
    attack_category,
    event_count,
    unique_source_count,
    updated_at
  )
  select
    pg_catalog.date_trunc('day', ae.observed_at at time zone 'UTC') at time zone 'UTC',
    'day',
    ae.sensor_id,
    ae.protocol,
    ae.attack_category,
    pg_catalog.count(*)::bigint,
    pg_catalog.count(distinct ae.src_ip_hash)::bigint,
    p_now
  from public.attack_events ae
  where ae.observed_at >= v_window_start
    and ae.attack_category is not null
  group by 1, 3, 4, 5;

  insert into public.daily_stats (
    date_utc,
    sensor_id,
    protocol,
    event_type,
    event_count,
    unique_source_count,
    updated_at
  )
  select
    (ae.observed_at at time zone 'UTC')::date,
    ae.sensor_id,
    ae.protocol,
    ae.event_type,
    pg_catalog.count(*)::integer,
    pg_catalog.count(distinct ae.src_ip_hash)::integer,
    p_now
  from public.attack_events ae
  where ae.observed_at >= v_window_start
  group by 1, 2, 3, 4;

  insert into public.pattern_daily_counts (
    date_utc,
    pattern_type,
    pattern_key,
    protocol,
    first_seen_at,
    last_seen_at,
    event_count,
    updated_at
  )
  select
    src.date_utc,
    src.pattern_type,
    src.pattern_key,
    src.protocol,
    pg_catalog.min(src.observed_at),
    pg_catalog.max(src.observed_at),
    pg_catalog.count(*)::bigint,
    p_now
  from (
    select
      (ae.observed_at at time zone 'UTC')::date as date_utc,
      'http_path'::text as pattern_type,
      ae.http_path_redacted as pattern_key,
      ae.protocol,
      ae.observed_at
    from public.attack_events ae
    where ae.observed_at >= v_window_start
      and ae.observed_at < v_pattern_cutoff
      and ae.protocol in ('http', 'https')
      and ae.http_path_redacted is not null
      and pg_catalog.char_length(ae.http_path_redacted) >= 1
    union all
    select
      (ae.observed_at at time zone 'UTC')::date,
      'signature',
      ae.fingerprint,
      ae.protocol,
      ae.observed_at
    from public.attack_events ae
    where ae.observed_at >= v_window_start
      and ae.observed_at < v_pattern_cutoff
      and ae.fingerprint is not null
      and pg_catalog.char_length(ae.fingerprint) >= 1
    union all
    select
      (ae.observed_at at time zone 'UTC')::date,
      'attack_category',
      ae.attack_category,
      ae.protocol,
      ae.observed_at
    from public.attack_events ae
    where ae.observed_at >= v_window_start
      and ae.observed_at < v_pattern_cutoff
      and ae.attack_category is not null
  ) as src
  group by src.date_utc, src.pattern_type, src.pattern_key, src.protocol;

  insert into public.observed_patterns (
    pattern_type,
    pattern_key,
    protocol,
    first_seen_at,
    last_seen_at,
    total_count
  )
  select
    p.pattern_type,
    p.pattern_key,
    p.protocol,
    pg_catalog.min(p.first_seen_at),
    pg_catalog.max(p.last_seen_at),
    pg_catalog.sum(p.event_count)::bigint
  from public.pattern_daily_counts p
  group by p.pattern_type, p.pattern_key, p.protocol
  on conflict (pattern_type, pattern_key, protocol)
  do update set
    first_seen_at = excluded.first_seen_at,
    last_seen_at = excluded.last_seen_at,
    total_count = excluded.total_count;
end;
$$;

-- Maintenance: rollups, then eligibility, then retention. Signature unchanged.
create or replace function public.run_observation_maintenance(
  p_now timestamptz,
  p_event_retention_days integer,
  p_rollup_window_days integer default 8
)
returns table (
  deleted_events bigint,
  deleted_receipts bigint
)
language plpgsql
security invoker
set search_path = ''
as $$
begin
  perform public.rollup_observation_aggregates(p_now, p_rollup_window_days);
  perform public.rollup_signature_daily_counts(p_now, p_rollup_window_days);
  perform public.rollup_public_pattern_eligibility(p_now, 3);
  return query
  select pruned.deleted_events, pruned.deleted_receipts
  from public.prune_observation_retention(p_now, p_event_retention_days) as pruned;
end;
$$;

-- -----------------------------------------------------------------------------
-- Views. CREATE OR REPLACE keeps every column name, type, and order (readers
-- and dependent views keep working) and preserves grants. The publication
-- cutoff is inlined so anon needs no extra function privilege:
--   date_trunc('hour', (now() at time zone 'UTC') - interval '1 hour') at time zone 'UTC'
-- -----------------------------------------------------------------------------

create or replace view public.public_events
with (security_barrier = true) as
select
  ae.id,
  ae.sensor_id,
  pg_catalog.date_trunc('hour', ae.observed_at at time zone 'UTC') at time zone 'UTC' as observed_at,
  pg_catalog.date_trunc('hour', ae.received_at at time zone 'UTC') at time zone 'UTC' as received_at,
  ae.protocol,
  ae.dst_port,
  ae.event_type,
  -- Country / ASN are not published per event (tracking risk, #113).
  null::text as src_country,
  null::text as src_asn,
  ae.http_method,
  case
    when ae.http_path_redacted is null then null
    when exists (
      select 1
      from public.public_pattern_eligibility el
      where el.pattern_type = 'http_path'
        and el.pattern_key = ae.http_path_redacted
        and el.protocol = ae.protocol
        and el.crossed_at < pg_catalog.date_trunc('hour', (pg_catalog.now() at time zone 'UTC') - interval '1 hour') at time zone 'UTC'
    ) then ae.http_path_redacted
    else null
  end as http_path_redacted,
  case
    when ae.fingerprint ~ '^oc-[0-9]{1,6}$' then ae.fingerprint
    else null
  end as fingerprint,
  ae.attack_category
from public.attack_events ae
where ae.observed_at < pg_catalog.date_trunc('hour', (pg_catalog.now() at time zone 'UTC') - interval '1 hour') at time zone 'UTC';

create or replace view public.public_sensors
with (security_barrier = true) as
select
  s.id,
  s.name,
  s.type,
  s.region,
  s.is_active,
  pg_catalog.date_bin('5 minutes', s.last_heartbeat_at, timestamptz '2000-01-01 00:00:00+00') as last_heartbeat_at,
  s.created_at,
  null::timestamptz as last_event_at,
  s.monitored_services,
  null::timestamptz as last_error_at,
  -- Health from the unrounded heartbeat (15-minute threshold), so the 5-minute
  -- floor above never reports a sensor as stale early.
  (s.last_heartbeat_at is null
    or s.last_heartbeat_at < pg_catalog.now() - interval '15 minutes') as heartbeat_stale
from public.sensors s;

create or replace view public.public_detections
with (security_barrier = true) as
select
  d.id,
  d.event_id,
  d.rule_id,
  d.rule_version,
  d.classification,
  d.confidence,
  d.evidence_redacted,
  pg_catalog.date_trunc('hour', d.created_at at time zone 'UTC') at time zone 'UTC' as created_at
from public.detections d
inner join public.attack_events e on e.id = d.event_id
where e.observed_at < pg_catalog.date_trunc('hour', (pg_catalog.now() at time zone 'UTC') - interval '1 hour') at time zone 'UTC';

create or replace view public.public_event_cve_matches
with (security_barrier = true) as
select
  m.id,
  m.event_id,
  m.cve_id,
  m.detection_id,
  m.match_type,
  m.confidence,
  m.reason,
  pg_catalog.date_trunc('hour', m.created_at at time zone 'UTC') at time zone 'UTC' as created_at,
  d.rule_id,
  d.rule_version,
  v.kev_present,
  v.epss_score,
  v.epss_percentile,
  v.epss_date,
  pg_catalog.date_trunc('hour', m.evaluated_at at time zone 'UTC') at time zone 'UTC' as evaluated_at,
  pg_catalog.date_trunc('hour', e.observed_at at time zone 'UTC') at time zone 'UTC' as observed_at,
  case
    when d.evidence_redacted ->> 'match_strength' in ('high', 'medium', 'low')
      then d.evidence_redacted ->> 'match_strength'
    else null
  end as match_strength,
  left(d.evidence_redacted ->> 'indicator', 64) as indicator,
  case
    -- Same vocabulary as the matcher (url, body, header:<safe-name>, redacted).
    when d.evidence_redacted ->> 'matched_location' ~ '^(url|body|redacted|header:[a-z0-9-]{1,48})$'
      then d.evidence_redacted ->> 'matched_location'
    else null
  end as matched_location
from public.event_cve_matches m
inner join public.detections d on d.id = m.detection_id
inner join public.vulnerabilities v on v.cve_id = m.cve_id
inner join public.attack_events e on e.id = m.event_id
where e.observed_at < pg_catalog.date_trunc('hour', (pg_catalog.now() at time zone 'UTC') - interval '1 hour') at time zone 'UTC';

create or replace view public.public_vulnerabilities
with (security_barrier = true) as
select
  v.cve_id,
  v.description,
  v.vendor,
  v.product,
  v.kev_present,
  v.kev_updated_at,
  v.epss_score,
  v.epss_percentile,
  v.epss_date,
  v.source_updated_at,
  count(distinct m.event_id)::integer as matched_event_count,
  max(m.confidence) as max_confidence,
  pg_catalog.date_trunc('hour', max(m.created_at) at time zone 'UTC') at time zone 'UTC' as last_matched_at,
  v.published_at,
  v.cvss_score,
  v.cvss_vector,
  v.kev_added_at,
  pg_catalog.date_trunc('hour', max(e.observed_at) at time zone 'UTC') at time zone 'UTC' as last_observed_at
from public.vulnerabilities v
inner join public.event_cve_matches m on m.cve_id = v.cve_id
inner join public.attack_events e on e.id = m.event_id
where e.observed_at < pg_catalog.date_trunc('hour', (pg_catalog.now() at time zone 'UTC') - interval '1 hour') at time zone 'UTC'
group by
  v.cve_id,
  v.description,
  v.vendor,
  v.product,
  v.kev_present,
  v.kev_updated_at,
  v.epss_score,
  v.epss_percentile,
  v.epss_date,
  v.source_updated_at,
  v.published_at,
  v.cvss_score,
  v.cvss_vector,
  v.kev_added_at;

create or replace view public.public_event_aggregates
with (security_barrier = true) as
select
  bucket_start,
  granularity,
  sensor_id,
  protocol,
  attack_category,
  event_count,
  unique_source_count,
  updated_at
from public.event_aggregates
-- Hourly buckets follow the publication delay. Daily buckets stay (coarse;
-- residual volume-spike risk is documented).
where not (
  granularity = 'hour'
  and bucket_start >= pg_catalog.date_trunc('hour', (pg_catalog.now() at time zone 'UTC') - interval '1 hour') at time zone 'UTC'
);

create or replace view public.public_observed_patterns
with (security_barrier = true) as
select
  o.pattern_type,
  o.pattern_key,
  o.protocol,
  pg_catalog.date_trunc(
    'hour',
    (case when o.pattern_type = 'http_path' then el.crossed_at else o.first_seen_at end) at time zone 'UTC'
  ) at time zone 'UTC' as first_seen_at,
  pg_catalog.date_trunc('hour', o.last_seen_at at time zone 'UTC') at time zone 'UTC' as last_seen_at,
  o.total_count,
  el.unique_source_count
from public.observed_patterns o
left join public.public_pattern_eligibility el
  on o.pattern_type = 'http_path'
  and el.pattern_type = 'http_path'
  and el.pattern_key = o.pattern_key
  and el.protocol = o.protocol
where
  (
    (o.pattern_type = 'http_path'
      and el.crossed_at < pg_catalog.date_trunc('hour', (pg_catalog.now() at time zone 'UTC') - interval '1 hour') at time zone 'UTC')
    or (o.pattern_type = 'signature' and o.pattern_key ~ '^oc-[0-9]{1,6}$')
    or o.pattern_type = 'attack_category'
  )
  and (
    o.pattern_type = 'http_path'
    or o.first_seen_at < pg_catalog.date_trunc('hour', (pg_catalog.now() at time zone 'UTC') - interval '1 hour') at time zone 'UTC'
  );

create or replace view public.public_sensor_status_events
with (security_barrier = true) as
select
  id,
  sensor_id,
  status,
  -- Widen to 15-minute boundaries: still distinguishes outages from quiet
  -- periods without second-precision timing.
  pg_catalog.date_bin('15 minutes', started_at, timestamptz '2000-01-01 00:00:00+00') as started_at,
  case
    when ended_at is null then null
    when ended_at = pg_catalog.date_bin('15 minutes', ended_at, timestamptz '2000-01-01 00:00:00+00') then ended_at
    else pg_catalog.date_bin('15 minutes', ended_at, timestamptz '2000-01-01 00:00:00+00') + interval '15 minutes'
  end as ended_at
from public.sensor_status_events;

-- Every public view stays a security_barrier view (re-asserted).
alter view public.public_events set (security_barrier = true);
alter view public.public_sensors set (security_barrier = true);
alter view public.public_detections set (security_barrier = true);
alter view public.public_event_cve_matches set (security_barrier = true);
alter view public.public_vulnerabilities set (security_barrier = true);
alter view public.public_event_aggregates set (security_barrier = true);
alter view public.public_observed_patterns set (security_barrier = true);
alter view public.public_sensor_status_events set (security_barrier = true);

-- Populate eligibility now so published paths do not disappear until the next
-- maintenance run.
select public.rollup_public_pattern_eligibility(pg_catalog.now(), 3);
