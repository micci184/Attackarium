-- =============================================================================
-- Attackarium — Idempotent observation rollup and retention
--
-- Recomputes buckets from attack_events currently stored. A second run replaces
-- those counts; it does not add them again. Buckets whose events were already
-- deleted are left untouched, so detail retention does not erase history.
--
-- observed_patterns.total_count never shrinks. That keeps a pattern visible
-- after the events that formed it age out of attack_events.
--
-- Event retention cannot be set below 30 days. Deletion is aligned to a UTC
-- day so an hour or day bucket is not split. Raw payload objects are not
-- stored, so this job does not prune them. Aggregate rows are not deleted.
--
-- Not applied to any hosted database here.
-- =============================================================================

create or replace function public.rollup_observation_aggregates(p_now timestamptz)
returns void
language plpgsql
security invoker
set search_path = ''
as $$
begin
  if p_now is null then
    raise exception 'p_now is required' using errcode = '22023';
  end if;

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
  where ae.attack_category is not null
  group by
    pg_catalog.date_trunc('hour', ae.observed_at at time zone 'UTC') at time zone 'UTC',
    ae.sensor_id,
    ae.protocol,
    ae.attack_category
  on conflict (bucket_start, granularity, sensor_id, protocol, attack_category)
  do update set
    event_count = excluded.event_count,
    unique_source_count = excluded.unique_source_count,
    updated_at = excluded.updated_at;

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
  where ae.attack_category is not null
  group by
    pg_catalog.date_trunc('day', ae.observed_at at time zone 'UTC') at time zone 'UTC',
    ae.sensor_id,
    ae.protocol,
    ae.attack_category
  on conflict (bucket_start, granularity, sensor_id, protocol, attack_category)
  do update set
    event_count = excluded.event_count,
    unique_source_count = excluded.unique_source_count,
    updated_at = excluded.updated_at;

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
  group by
    (ae.observed_at at time zone 'UTC')::date,
    ae.sensor_id,
    ae.protocol,
    ae.event_type
  on conflict (date_utc, sensor_id, protocol, event_type)
  do update set
    event_count = excluded.event_count,
    unique_source_count = excluded.unique_source_count,
    updated_at = excluded.updated_at;

  insert into public.observed_patterns (
    pattern_type,
    pattern_key,
    protocol,
    first_seen_at,
    last_seen_at,
    total_count
  )
  select
    'http_path',
    ae.http_path_redacted,
    ae.protocol,
    pg_catalog.min(ae.observed_at),
    pg_catalog.max(ae.observed_at),
    pg_catalog.count(*)::bigint
  from public.attack_events ae
  where ae.protocol in ('http', 'https')
    and ae.http_path_redacted is not null
    and pg_catalog.char_length(ae.http_path_redacted) between 1 and 512
  group by ae.http_path_redacted, ae.protocol
  on conflict (pattern_type, pattern_key, protocol)
  do update set
    first_seen_at = least(public.observed_patterns.first_seen_at, excluded.first_seen_at),
    last_seen_at = greatest(public.observed_patterns.last_seen_at, excluded.last_seen_at),
    total_count = greatest(public.observed_patterns.total_count, excluded.total_count);

  insert into public.observed_patterns (
    pattern_type,
    pattern_key,
    protocol,
    first_seen_at,
    last_seen_at,
    total_count
  )
  select
    'signature',
    ae.fingerprint,
    ae.protocol,
    pg_catalog.min(ae.observed_at),
    pg_catalog.max(ae.observed_at),
    pg_catalog.count(*)::bigint
  from public.attack_events ae
  where ae.fingerprint is not null
    and pg_catalog.char_length(ae.fingerprint) between 1 and 128
  group by ae.fingerprint, ae.protocol
  on conflict (pattern_type, pattern_key, protocol)
  do update set
    first_seen_at = least(public.observed_patterns.first_seen_at, excluded.first_seen_at),
    last_seen_at = greatest(public.observed_patterns.last_seen_at, excluded.last_seen_at),
    total_count = greatest(public.observed_patterns.total_count, excluded.total_count);

  insert into public.observed_patterns (
    pattern_type,
    pattern_key,
    protocol,
    first_seen_at,
    last_seen_at,
    total_count
  )
  select
    'attack_category',
    ae.attack_category,
    ae.protocol,
    pg_catalog.min(ae.observed_at),
    pg_catalog.max(ae.observed_at),
    pg_catalog.count(*)::bigint
  from public.attack_events ae
  where ae.attack_category is not null
  group by ae.attack_category, ae.protocol
  on conflict (pattern_type, pattern_key, protocol)
  do update set
    first_seen_at = least(public.observed_patterns.first_seen_at, excluded.first_seen_at),
    last_seen_at = greatest(public.observed_patterns.last_seen_at, excluded.last_seen_at),
    total_count = greatest(public.observed_patterns.total_count, excluded.total_count);
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
begin
  perform public.rollup_observation_aggregates(p_now);
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
  select
    'day'::text,
    v_today - interval '1 day',
    v_today - interval '2 days',
    coalesce(pg_catalog.sum(a.event_count) filter (
      where a.bucket_start >= v_today - interval '1 day'
        and a.bucket_start < v_today
    ), 0::numeric)::bigint,
    coalesce(pg_catalog.sum(a.event_count) filter (
      where a.bucket_start >= v_today - interval '2 days'
        and a.bucket_start < v_today - interval '1 day'
    ), 0::numeric)::bigint,
    (
      coalesce(pg_catalog.sum(a.event_count) filter (
        where a.bucket_start >= v_today - interval '1 day'
          and a.bucket_start < v_today
      ), 0::numeric)
      - coalesce(pg_catalog.sum(a.event_count) filter (
        where a.bucket_start >= v_today - interval '2 days'
          and a.bucket_start < v_today - interval '1 day'
      ), 0::numeric)
    )::bigint
  from public.event_aggregates a
  where a.granularity = 'day';

  return query
  select
    'week'::text,
    v_today - interval '7 days',
    v_today - interval '14 days',
    coalesce(pg_catalog.sum(a.event_count) filter (
      where a.bucket_start >= v_today - interval '7 days'
        and a.bucket_start < v_today
    ), 0::numeric)::bigint,
    coalesce(pg_catalog.sum(a.event_count) filter (
      where a.bucket_start >= v_today - interval '14 days'
        and a.bucket_start < v_today - interval '7 days'
    ), 0::numeric)::bigint,
    (
      coalesce(pg_catalog.sum(a.event_count) filter (
        where a.bucket_start >= v_today - interval '7 days'
          and a.bucket_start < v_today
      ), 0::numeric)
      - coalesce(pg_catalog.sum(a.event_count) filter (
        where a.bucket_start >= v_today - interval '14 days'
          and a.bucket_start < v_today - interval '7 days'
      ), 0::numeric)
    )::bigint
  from public.event_aggregates a
  where a.granularity = 'day';
end;
$$;

revoke all on function public.rollup_observation_aggregates(timestamptz) from public, anon, authenticated;
revoke all on function public.prune_observation_retention(timestamptz, integer) from public, anon, authenticated;
revoke all on function public.run_observation_maintenance(timestamptz, integer) from public, anon, authenticated;
revoke all on function public.observation_count_deltas(timestamptz) from public, anon, authenticated;

grant execute on function public.rollup_observation_aggregates(timestamptz) to service_role;
grant execute on function public.prune_observation_retention(timestamptz, integer) to service_role;
grant execute on function public.run_observation_maintenance(timestamptz, integer) to service_role;
grant execute on function public.observation_count_deltas(timestamptz) to service_role;
