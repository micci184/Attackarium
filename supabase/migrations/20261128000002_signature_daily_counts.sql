-- =============================================================================
-- Long-term detection and candidate-CVE observation history (#84)
-- =============================================================================
-- Detailed events (and, through ON DELETE CASCADE, their detections and
-- candidate CVE matches) are pruned after the event retention period (>= 30
-- days, ADR-023). The existing aggregates have no rule or CVE dimension, so
-- which rules fired and which candidate CVEs were observed vanished with them.
--
-- signature_daily_counts keeps one row per OBSERVED UTC day x rule x rule
-- version x candidate CVE x protocol:
-- - cve_id is '' for technique-only rules (no CVE), and one row per CVE for
--   multi-CVE rules;
-- - rule_version is part of the key, so a rule change is never mistaken for a
--   trend change;
-- - unique_source_count (distinct src_ip_hash) sits next to event_count,
--   because a single source can dominate a day's volume.
-- It is rebuilt for the same trailing window as the other rollups (8 days by
-- default; same advisory lock), so late matches and re-evaluations are
-- reflected while events exist, and older days are frozen once their events
-- are pruned. Retained like the other daily aggregates (>= 1 year).
-- Rows are rule-based candidate hypotheses, never proof of exploitation.
-- =============================================================================

create table if not exists public.signature_daily_counts (
  date_utc date not null,
  rule_id text not null check (char_length(rule_id) between 1 and 128),
  rule_version text not null check (char_length(rule_version) between 1 and 32),
  classification text not null check (
    classification in ('observed', 'indicator_match', 'candidate_cve')
  ),
  cve_id text not null default '' check (cve_id = '' or cve_id ~ '^CVE-[0-9]{4}-[0-9]{4,}$'),
  protocol text not null check (
    protocol in ('ssh', 'telnet', 'ftp', 'mysql', 'redis', 'http', 'https', 'other')
  ),
  event_count bigint not null check (event_count >= 0),
  unique_source_count bigint not null check (unique_source_count >= 0),
  first_seen_at timestamptz not null,
  last_seen_at timestamptz not null,
  updated_at timestamptz not null default now(),
  primary key (date_utc, rule_id, rule_version, cve_id, protocol),
  check (last_seen_at >= first_seen_at)
);

create index if not exists signature_daily_counts_cve_date_idx
  on public.signature_daily_counts (cve_id, date_utc desc)
  where cve_id <> '';

create index if not exists signature_daily_counts_rule_date_idx
  on public.signature_daily_counts (rule_id, date_utc desc);

comment on table public.signature_daily_counts is
  'Daily detection counts by observed UTC day, rule, rule version, candidate CVE ('''' = technique-only), and protocol. Retained long-term; rule-based candidate hypotheses, not proof of exploitation.';

alter table public.signature_daily_counts enable row level security;
alter table public.signature_daily_counts force row level security;
revoke all on table public.signature_daily_counts from public, anon, authenticated;
grant all on table public.signature_daily_counts to service_role;

create or replace function public.rollup_signature_daily_counts(
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

  -- Same lock as the other rollups and retention: never interleave with pruning.
  perform pg_catalog.pg_advisory_xact_lock(8217001);

  v_window_start := pg_catalog.date_trunc(
    'day',
    (p_now - pg_catalog.make_interval(days => p_window_days)) at time zone 'UTC'
  ) at time zone 'UTC';

  delete from public.signature_daily_counts s
  where s.date_utc >= (v_window_start at time zone 'UTC')::date;

  insert into public.signature_daily_counts (
    date_utc,
    rule_id,
    rule_version,
    classification,
    cve_id,
    protocol,
    event_count,
    unique_source_count,
    first_seen_at,
    last_seen_at,
    updated_at
  )
  select
    (e.observed_at at time zone 'UTC')::date,
    d.rule_id,
    d.rule_version,
    pg_catalog.max(d.classification),
    coalesce(m.cve_id, ''),
    e.protocol,
    pg_catalog.count(distinct e.id)::bigint,
    pg_catalog.count(distinct e.src_ip_hash)::bigint,
    pg_catalog.min(e.observed_at),
    pg_catalog.max(e.observed_at),
    p_now
  from public.detections d
  inner join public.attack_events e on e.id = d.event_id
  left join public.event_cve_matches m on m.detection_id = d.id
  where e.observed_at >= v_window_start
  group by 1, 2, 3, 5, 6;
end;
$$;

revoke all on function public.rollup_signature_daily_counts(timestamptz, integer)
  from public, anon, authenticated;
grant execute on function public.rollup_signature_daily_counts(timestamptz, integer) to service_role;

-- Run it inside the existing maintenance (every 15 minutes), after the other
-- rollups and before retention prunes events. Signature and result unchanged.
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
  return query
  select pruned.deleted_events, pruned.deleted_receipts
  from public.prune_observation_retention(p_now, p_event_retention_days) as pruned;
end;
$$;

-- Public, day-granular view: no intra-day timestamps (first/last seen stay
-- private), no event ids, no rule evidence. cve_id is NULL for
-- technique-only rules.
create or replace view public.public_signature_daily_counts
with (security_barrier = true) as
select
  s.date_utc,
  s.rule_id,
  s.rule_version,
  s.classification,
  nullif(s.cve_id, '') as cve_id,
  s.protocol,
  s.event_count,
  s.unique_source_count
from public.signature_daily_counts s;

revoke all on public.public_signature_daily_counts from public;
grant select on public.public_signature_daily_counts to anon, authenticated, service_role;

-- Backfill every day that still has events (retention keeps at most 30 days
-- plus the current one), so history starts from the first observation.
select public.rollup_signature_daily_counts(pg_catalog.now(), 30);
