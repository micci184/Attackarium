-- =============================================================================
-- Attackarium — Phase 1 observation schema
--
-- Adds the columns and tables needed for 30-day trends, attack patterns, and
-- the difference between zero traffic and a collection gap.
-- Filling event_aggregates and observed_patterns is a later rollup job.
-- This migration does not scan or rewrite existing event rows.
-- It is not applied to any hosted database here.
-- =============================================================================

alter table public.attack_events
  add column attack_category text
  check (
    attack_category is null
    or attack_category in (
      'port_scan',
      'auth_attempt',
      'http_path_probe',
      'web_attack_attempt',
      'suspected_cve_probe'
    )
  );

-- Category lookups skip rows a rollup has not classified yet.
create index attack_events_category_observed_at_idx
  on public.attack_events (attack_category, observed_at desc)
  where attack_category is not null;

alter table public.sensors
  add column monitored_services text[] not null default '{}',
  add column last_error_at timestamptz,
  add column last_error_summary text
  check (last_error_summary is null or char_length(last_error_summary) <= 280);

alter table public.sensors
  add constraint sensors_monitored_services_check
  check (
    monitored_services <@ array['ssh', 'telnet', 'ftp', 'mysql', 'redis', 'http', 'https']::text[]
  );

create table public.event_aggregates (
  bucket_start timestamptz not null,
  granularity text not null check (granularity in ('hour', 'day')),
  sensor_id text not null references public.sensors (id) on delete restrict,
  protocol text not null check (
    protocol in ('ssh', 'telnet', 'ftp', 'mysql', 'redis', 'http', 'https', 'other')
  ),
  attack_category text not null check (
    attack_category in (
      'port_scan',
      'auth_attempt',
      'http_path_probe',
      'web_attack_attempt',
      'suspected_cve_probe'
    )
  ),
  event_count bigint not null check (event_count >= 0),
  unique_source_count bigint not null check (unique_source_count >= 0),
  updated_at timestamptz not null default now(),
  primary key (bucket_start, granularity, sensor_id, protocol, attack_category)
);

create index event_aggregates_granularity_bucket_idx
  on public.event_aggregates (granularity, bucket_start desc);

create index event_aggregates_sensor_id_idx
  on public.event_aggregates (sensor_id);

create table public.observed_patterns (
  pattern_type text not null check (pattern_type in ('http_path', 'signature', 'attack_category')),
  pattern_key text not null check (char_length(pattern_key) between 1 and 512),
  protocol text not null check (
    protocol in ('ssh', 'telnet', 'ftp', 'mysql', 'redis', 'http', 'https', 'other')
  ),
  first_seen_at timestamptz not null,
  last_seen_at timestamptz not null,
  total_count bigint not null check (total_count >= 0),
  primary key (pattern_type, pattern_key, protocol),
  check (last_seen_at >= first_seen_at)
);

create index observed_patterns_type_last_seen_idx
  on public.observed_patterns (pattern_type, last_seen_at desc);

create table public.sensor_status_events (
  id uuid primary key default gen_random_uuid(),
  sensor_id text not null references public.sensors (id) on delete restrict,
  status text not null check (status in ('healthy', 'degraded', 'offline', 'error')),
  started_at timestamptz not null,
  ended_at timestamptz,
  summary text check (summary is null or char_length(summary) <= 280),
  check (ended_at is null or ended_at >= started_at)
);

create index sensor_status_events_sensor_started_idx
  on public.sensor_status_events (sensor_id, started_at desc);

alter table public.event_aggregates enable row level security;
alter table public.event_aggregates force row level security;
alter table public.observed_patterns enable row level security;
alter table public.observed_patterns force row level security;
alter table public.sensor_status_events enable row level security;
alter table public.sensor_status_events force row level security;

revoke all on table
  public.event_aggregates,
  public.observed_patterns,
  public.sensor_status_events
from public, anon, authenticated;

grant all on table
  public.event_aggregates,
  public.observed_patterns,
  public.sensor_status_events
to service_role;

-- Keep the existing column order and append the public category.
create or replace view public.public_events as
select
  ae.id,
  ae.sensor_id,
  ae.observed_at,
  ae.received_at,
  ae.protocol,
  ae.dst_port,
  ae.event_type,
  ae.src_country,
  ae.src_asn,
  ae.http_method,
  ae.http_path_redacted,
  ae.fingerprint,
  ae.attack_category
from public.attack_events ae;

create or replace view public.public_sensors as
select
  s.id,
  s.name,
  s.type,
  s.region,
  s.is_active,
  s.last_heartbeat_at,
  s.created_at,
  (
    select max(ae.observed_at)
    from public.attack_events ae
    where ae.sensor_id = s.id
  ) as last_event_at,
  s.monitored_services,
  s.last_error_at
from public.sensors s;

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
from public.event_aggregates;

create or replace view public.public_observed_patterns
with (security_barrier = true) as
select
  pattern_type,
  pattern_key,
  protocol,
  first_seen_at,
  last_seen_at,
  total_count
from public.observed_patterns;

-- summary can contain host logs. The public signal is the interval and status.
create or replace view public.public_sensor_status_events
with (security_barrier = true) as
select
  id,
  sensor_id,
  status,
  started_at,
  ended_at
from public.sensor_status_events;

alter view public.public_events set (security_barrier = true);
alter view public.public_sensors set (security_barrier = true);

revoke all on table
  public.public_event_aggregates,
  public.public_observed_patterns,
  public.public_sensor_status_events
from public, anon, authenticated;

grant select on table
  public.public_event_aggregates,
  public.public_observed_patterns,
  public.public_sensor_status_events
to anon, authenticated;

create or replace function public.commit_ingest_batch(
  p_sensor_id text,
  p_request_id text,
  p_received_at timestamptz,
  p_expires_at timestamptz,
  p_rate_limit integer,
  p_events jsonb
)
returns table (
  status text,
  inserted_count integer
)
language plpgsql
security invoker
set search_path = ''
as $$
declare
  v_recent_count integer;
  v_inserted integer := 0;
begin
  if p_rate_limit is null or p_rate_limit < 1 then
    raise exception 'p_rate_limit must be >= 1';
  end if;

  if p_events is null or pg_catalog.jsonb_typeof(p_events) <> 'array' then
    raise exception 'p_events must be a JSON array';
  end if;

  perform pg_catalog.pg_advisory_xact_lock(
    pg_catalog.hashtext('attackarium:ingest:' || p_sensor_id)
  );

  if not exists (
    select 1
    from public.sensors s
    where s.id = p_sensor_id
  ) then
    return query select 'unknown_sensor'::text, 0;
    return;
  end if;

  if exists (
    select 1
    from public.ingest_receipts r
    where r.sensor_id = p_sensor_id
      and r.request_id = p_request_id
  ) then
    return query select 'replayed'::text, 0;
    return;
  end if;

  select pg_catalog.count(*)::integer
  into v_recent_count
  from public.ingest_receipts r
  where r.sensor_id = p_sensor_id
    and r.received_at >= (p_received_at - interval '60 seconds');

  if v_recent_count >= p_rate_limit then
    return query select 'rate_limited'::text, 0;
    return;
  end if;

  insert into public.ingest_receipts (
    sensor_id,
    request_id,
    received_at,
    expires_at
  )
  values (
    p_sensor_id,
    p_request_id,
    p_received_at,
    p_expires_at
  );

  -- src_ip and raw_object_key are ignored.
  -- suspected_cve_probe is stored only when the caller sets that exact category.
  -- Login and HTTP defaults never invent a CVE claim.
  insert into public.attack_events (
    id,
    sensor_id,
    observed_at,
    received_at,
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
  select
    (ev->>'id')::uuid,
    p_sensor_id,
    (ev->>'observed_at')::timestamptz,
    p_received_at,
    ev->>'protocol',
    (ev->>'dst_port')::integer,
    ev->>'event_type',
    case
      when ev->>'attack_category' in (
        'port_scan',
        'auth_attempt',
        'http_path_probe',
        'web_attack_attempt',
        'suspected_cve_probe'
      ) then ev->>'attack_category'
      when ev->>'protocol' in ('ssh', 'telnet', 'ftp', 'mysql', 'redis') then 'auth_attempt'
      when ev->>'protocol' in ('http', 'https')
        and ev->>'event_type' = 'http_payload_probe' then 'web_attack_attempt'
      when ev->>'protocol' in ('http', 'https') then 'http_path_probe'
      else null
    end,
    nullif(ev->>'src_ip_hash', ''),
    nullif(ev->>'src_country', ''),
    nullif(ev->>'src_asn', ''),
    nullif(ev->>'http_method', ''),
    nullif(ev->>'http_path_redacted', ''),
    nullif(ev->>'fingerprint', ''),
    coalesce(ev->'metadata', '{}'::jsonb)
  from pg_catalog.jsonb_array_elements(p_events) as ev
  on conflict (id) do nothing;

  get diagnostics v_inserted = row_count;

  update public.sensors
  set last_heartbeat_at = p_received_at
  where id = p_sensor_id;

  return query select 'ok'::text, v_inserted;
end;
$$;

revoke all on function public.commit_ingest_batch(
  text,
  text,
  timestamptz,
  timestamptz,
  integer,
  jsonb
) from public, anon, authenticated;

grant execute on function public.commit_ingest_batch(
  text,
  text,
  timestamptz,
  timestamptz,
  integer,
  jsonb
) to service_role;
