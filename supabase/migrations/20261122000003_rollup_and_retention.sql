-- =============================================================================
-- Attackarium — Idempotent observation rollup and retention
--
-- Each run rebuilds only the recent UTC days, from the attack_events stored in
-- that window. Older buckets are final and are never rewritten, so detail
-- retention cannot erase history and a late or replayed old event cannot
-- overwrite a kept bucket.
--
-- The window must cover the oldest observed_at that ingest accepts. Ingest
-- rejects events older than 7 days, so the default window is 8 UTC days.
-- The window may not exceed 30 days: retention keeps at least 30 whole UTC
-- days of events, so every rebuilt day still has all of its events. Use a
-- wider window to catch up after the job has been down.
--
-- Pattern lifetime totals are the sum of pattern_daily_counts. Daily rows are
-- kept after their events are deleted, so totals stay exact.
--
-- Event retention cannot be set below 30 days. Deletion is aligned to a UTC
-- day so an hour or day bucket is not split. Raw payload objects are not
-- stored, so this job does not prune them. Aggregate rows are not deleted.
--
-- Not applied to any hosted database here.
-- =============================================================================

create table public.pattern_daily_counts (
  date_utc date not null,
  pattern_type text not null check (pattern_type in ('http_path', 'signature', 'attack_category')),
  pattern_key text not null check (char_length(pattern_key) between 1 and 512),
  protocol text not null check (
    protocol in ('ssh', 'telnet', 'ftp', 'mysql', 'redis', 'http', 'https', 'other')
  ),
  first_seen_at timestamptz not null,
  last_seen_at timestamptz not null,
  event_count bigint not null check (event_count >= 0),
  updated_at timestamptz not null default now(),
  primary key (date_utc, pattern_type, pattern_key, protocol),
  check (last_seen_at >= first_seen_at)
);

create index pattern_daily_counts_pattern_idx
  on public.pattern_daily_counts (pattern_type, pattern_key, protocol);

alter table public.pattern_daily_counts enable row level security;
alter table public.pattern_daily_counts force row level security;

revoke all on table public.pattern_daily_counts from public, anon, authenticated;
grant all on table public.pattern_daily_counts to service_role;

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
begin
  if p_now is null then
    raise exception 'p_now is required' using errcode = '22023';
  end if;
  if p_window_days is null or p_window_days < 8 or p_window_days > 30 then
    raise exception 'rollup window must be between 8 and 30 days' using errcode = '22023';
  end if;

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

create or replace function public.prune_observation_retention(
  p_now timestamptz,
  p_event_retention_days integer
)
returns table (
  deleted_events bigint,
  deleted_receipts bigint
)
language plpgsql
security invoker
set search_path = ''
as $$
declare
  v_cutoff timestamptz;
  v_events bigint;
  v_receipts bigint;
begin
  if p_now is null then
    raise exception 'p_now is required' using errcode = '22023';
  end if;
  if p_event_retention_days is null or p_event_retention_days < 30 then
    raise exception 'event retention must be at least 30 days' using errcode = '22023';
  end if;

  perform pg_catalog.pg_advisory_xact_lock(8217001);

  -- Truncate in UTC. date_trunc(timestamptz) follows the session TimeZone.
  v_cutoff := pg_catalog.date_trunc(
    'day',
    (p_now - pg_catalog.make_interval(days => p_event_retention_days)) at time zone 'UTC'
  ) at time zone 'UTC';

  delete from public.attack_events ae
  where ae.observed_at < v_cutoff;
  get diagnostics v_events = row_count;

  delete from public.ingest_receipts r
  where r.expires_at < p_now;
  get diagnostics v_receipts = row_count;

  return query select v_events, v_receipts;
end;
$$;

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
  return query
  select pruned.deleted_events, pruned.deleted_receipts
  from public.prune_observation_retention(p_now, p_event_retention_days) as pruned;
end;
$$;

-- Day and week comparisons use event_count only. unique_source_count is a
-- per-bucket figure and must not be added across protocols or days.
create or replace function public.observation_count_deltas(p_now timestamptz)
returns table (
  comparison text,
  current_start timestamptz,
  previous_start timestamptz,
  current_event_count bigint,
  previous_event_count bigint,
  event_count_delta bigint
)
language plpgsql
security invoker
set search_path = ''
as $$
declare
  v_today timestamptz;
begin
  if p_now is null then
    raise exception 'p_now is required' using errcode = '22023';
  end if;

  v_today := pg_catalog.date_trunc('day', p_now at time zone 'UTC') at time zone 'UTC';

  return query
  with periods (comparison, current_start, previous_start, span) as (
    values
      ('day'::text, v_today - interval '1 day', v_today - interval '2 days', interval '1 day'),
      ('week'::text, v_today - interval '7 days', v_today - interval '14 days', interval '7 days')
  ),
  totals as (
    select
      pr.comparison,
      pr.current_start,
      pr.previous_start,
      coalesce(pg_catalog.sum(a.event_count) filter (
        where a.bucket_start >= pr.current_start
          and a.bucket_start < pr.current_start + pr.span
      ), 0::numeric)::bigint as current_event_count,
      coalesce(pg_catalog.sum(a.event_count) filter (
        where a.bucket_start >= pr.previous_start
          and a.bucket_start < pr.current_start
      ), 0::numeric)::bigint as previous_event_count
    from periods pr
    left join public.event_aggregates a
      on a.granularity = 'day'
      and a.bucket_start >= pr.previous_start
      and a.bucket_start < pr.current_start + pr.span
    group by pr.comparison, pr.current_start, pr.previous_start
  )
  select
    t.comparison,
    t.current_start,
    t.previous_start,
    t.current_event_count,
    t.previous_event_count,
    t.current_event_count - t.previous_event_count
  from totals t
  order by t.comparison;
end;
$$;

revoke all on function public.rollup_observation_aggregates(timestamptz, integer) from public, anon, authenticated;
revoke all on function public.prune_observation_retention(timestamptz, integer) from public, anon, authenticated;
revoke all on function public.run_observation_maintenance(timestamptz, integer, integer) from public, anon, authenticated;
revoke all on function public.observation_count_deltas(timestamptz) from public, anon, authenticated;

grant execute on function public.rollup_observation_aggregates(timestamptz, integer) to service_role;
grant execute on function public.prune_observation_retention(timestamptz, integer) to service_role;
grant execute on function public.run_observation_maintenance(timestamptz, integer, integer) to service_role;
grant execute on function public.observation_count_deltas(timestamptz) to service_role;
