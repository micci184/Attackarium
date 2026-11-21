-- =============================================================================
-- Attackarium — Initial PostgreSQL Schema, Indexes, Default-Deny RLS, and
-- Sanitized Public Read-Only Views
--
-- Reference: docs/DATA_MODEL.md, docs/SECURITY.md, docs/ARCHITECTURE.md
-- All timestamps are stored as timestamptz (UTC). UI converts to JST for display.
-- =============================================================================

create extension if not exists pgcrypto;

-- -----------------------------------------------------------------------------
-- Ensure Supabase standard roles exist when running migrations against vanilla
-- PostgreSQL (e.g. CI test containers). In hosted/local Supabase these roles
-- already exist.
-- -----------------------------------------------------------------------------
do $$
begin
  if not exists (select 1 from pg_roles where rolname = 'anon') then
    create role anon nologin noinherit;
  end if;
  if not exists (select 1 from pg_roles where rolname = 'authenticated') then
    create role authenticated nologin noinherit;
  end if;
  if not exists (select 1 from pg_roles where rolname = 'service_role') then
    create role service_role nologin noinherit bypassrls;
  end if;
end
$$;

-- -----------------------------------------------------------------------------
-- 1. sensors
-- Never store API secrets or HMAC keys in public/database columns exposed to UI.
-- -----------------------------------------------------------------------------
create table public.sensors (
  id text primary key check (id ~ '^[a-z0-9][a-z0-9_-]{1,63}$'),
  name text not null check (char_length(name) between 1 and 120),
  type text not null check (type in ('opencanary', 'http_collector', 'combined')),
  region text not null check (char_length(region) between 1 and 64),
  is_active boolean not null default true,
  last_heartbeat_at timestamptz,
  created_at timestamptz not null default now()
);

-- -----------------------------------------------------------------------------
-- 2. attack_events (PRIVATE base table)
-- Sensitive fields (src_ip, src_ip_hash, raw_object_key, metadata) must never
-- be exposed to anonymous readers.
-- -----------------------------------------------------------------------------
create table public.attack_events (
  id uuid primary key,
  sensor_id text not null references public.sensors(id) on delete restrict,
  observed_at timestamptz not null,
  received_at timestamptz not null default now(),
  protocol text not null check (
    protocol in ('ssh', 'telnet', 'ftp', 'mysql', 'redis', 'http', 'https', 'other')
  ),
  dst_port integer not null check (dst_port between 1 and 65535),
  event_type text not null check (char_length(event_type) between 1 and 100),
  src_ip inet,
  src_ip_hash text,
  src_country text check (src_country is null or src_country ~ '^[A-Z]{2}$'),
  src_asn text check (src_asn is null or char_length(src_asn) <= 32),
  http_method text check (http_method is null or char_length(http_method) <= 16),
  http_path_redacted text check (http_path_redacted is null or char_length(http_path_redacted) <= 512),
  fingerprint text check (fingerprint is null or char_length(fingerprint) <= 128),
  raw_object_key text check (raw_object_key is null or char_length(raw_object_key) <= 512),
  metadata jsonb not null default '{}'::jsonb
);

create index attack_events_observed_at_idx
  on public.attack_events (observed_at desc);

create index attack_events_sensor_observed_at_idx
  on public.attack_events (sensor_id, observed_at desc);

create index attack_events_protocol_observed_at_idx
  on public.attack_events (protocol, observed_at desc);

create index attack_events_dst_port_observed_at_idx
  on public.attack_events (dst_port, observed_at desc);

-- -----------------------------------------------------------------------------
-- 3. detections
-- Evidence must point to actual observed fields (redacted).
-- -----------------------------------------------------------------------------
create table public.detections (
  id uuid primary key default gen_random_uuid(),
  event_id uuid not null references public.attack_events(id) on delete cascade,
  rule_id text not null check (char_length(rule_id) between 1 and 128),
  rule_version text not null check (char_length(rule_version) between 1 and 32),
  classification text not null check (
    classification in ('observed', 'indicator_match', 'candidate_cve')
  ),
  confidence numeric(4,3) not null check (confidence >= 0 and confidence <= 1),
  evidence_redacted jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now(),
  unique (event_id, rule_id, rule_version)
);

create index detections_event_id_idx
  on public.detections (event_id);

create index detections_rule_created_at_idx
  on public.detections (rule_id, created_at desc);

-- -----------------------------------------------------------------------------
-- 4. vulnerabilities
-- EPSS is a vulnerability-level dated forecast, NOT per-event exploit proof.
-- -----------------------------------------------------------------------------
create table public.vulnerabilities (
  cve_id text primary key check (cve_id ~ '^CVE-[0-9]{4}-[0-9]{4,}$'),
  description text,
  vendor text,
  product text,
  kev_present boolean not null default false,
  kev_updated_at timestamptz,
  epss_score numeric(6,5) check (epss_score is null or (epss_score >= 0 and epss_score <= 1)),
  epss_percentile numeric(6,5) check (epss_percentile is null or (epss_percentile >= 0 and epss_percentile <= 1)),
  epss_date date,
  source_updated_at timestamptz not null default now()
);

-- -----------------------------------------------------------------------------
-- 5. event_cve_matches
-- Candidate CVE hypotheses linked to explicit detections.
-- -----------------------------------------------------------------------------
create table public.event_cve_matches (
  id uuid primary key default gen_random_uuid(),
  event_id uuid not null references public.attack_events(id) on delete cascade,
  cve_id text not null references public.vulnerabilities(cve_id) on delete restrict,
  detection_id uuid not null references public.detections(id) on delete cascade,
  match_type text not null check (match_type in ('candidate_cve', 'indicator_match')),
  confidence numeric(4,3) not null check (confidence >= 0 and confidence <= 1),
  reason text not null check (char_length(reason) between 1 and 500),
  created_at timestamptz not null default now(),
  unique (event_id, cve_id, detection_id)
);

create index event_cve_matches_cve_id_idx
  on public.event_cve_matches (cve_id);

create index event_cve_matches_event_id_idx
  on public.event_cve_matches (event_id);

create index event_cve_matches_detection_id_idx
  on public.event_cve_matches (detection_id);

-- -----------------------------------------------------------------------------
-- 6. daily_stats (aggregates only; retained long-term)
-- -----------------------------------------------------------------------------
create table public.daily_stats (
  date_utc date not null,
  sensor_id text not null references public.sensors(id) on delete restrict,
  protocol text not null check (
    protocol in ('ssh', 'telnet', 'ftp', 'mysql', 'redis', 'http', 'https', 'other')
  ),
  event_type text not null check (char_length(event_type) between 1 and 100),
  event_count integer not null default 0 check (event_count >= 0),
  unique_source_count integer not null default 0 check (unique_source_count >= 0),
  updated_at timestamptz not null default now(),
  primary key (date_utc, sensor_id, protocol, event_type)
);

create index daily_stats_date_utc_idx
  on public.daily_stats (date_utc desc);

create index daily_stats_sensor_date_utc_idx
  on public.daily_stats (sensor_id, date_utc desc);

-- -----------------------------------------------------------------------------
-- 7. daily_reports
-- Drafts remain private until explicitly reviewed and published by a human.
-- -----------------------------------------------------------------------------
create table public.daily_reports (
  id uuid primary key default gen_random_uuid(),
  date_utc date not null unique,
  status text not null default 'draft' check (
    status in ('draft', 'reviewed', 'rejected', 'published')
  ),
  summary_md text not null,
  x_post_draft text,
  model_id text not null,
  prompt_version text not null default 'v1',
  source_window_start timestamptz not null,
  source_window_end timestamptz not null,
  reviewed_at timestamptz,
  created_at timestamptz not null default now(),
  check (source_window_end > source_window_start)
);

create index daily_reports_status_date_utc_idx
  on public.daily_reports (status, date_utc desc);

-- -----------------------------------------------------------------------------
-- 8. ingest_receipts (PRIVATE anti-replay nonce & per-sensor rate-limit store)
-- -----------------------------------------------------------------------------
create table public.ingest_receipts (
  sensor_id text not null references public.sensors(id) on delete cascade,
  request_id text not null check (char_length(request_id) between 8 and 128),
  received_at timestamptz not null default now(),
  expires_at timestamptz not null,
  primary key (sensor_id, request_id),
  check (expires_at > received_at)
);

create index ingest_receipts_expires_at_idx
  on public.ingest_receipts (expires_at);

create index ingest_receipts_sensor_received_at_idx
  on public.ingest_receipts (sensor_id, received_at desc);

-- -----------------------------------------------------------------------------
-- Security: Default-Deny RLS + Least-Privilege Grants on all base tables
-- -----------------------------------------------------------------------------
alter table public.sensors enable row level security;
alter table public.sensors force row level security;

alter table public.attack_events enable row level security;
alter table public.attack_events force row level security;

alter table public.detections enable row level security;
alter table public.detections force row level security;

alter table public.vulnerabilities enable row level security;
alter table public.vulnerabilities force row level security;

alter table public.event_cve_matches enable row level security;
alter table public.event_cve_matches force row level security;

alter table public.daily_stats enable row level security;
alter table public.daily_stats force row level security;

alter table public.daily_reports enable row level security;
alter table public.daily_reports force row level security;

alter table public.ingest_receipts enable row level security;
alter table public.ingest_receipts force row level security;

-- Revoke all direct privileges on base tables from PUBLIC, anon, authenticated.
-- No permissive RLS policies are granted on base tables for anon/authenticated,
-- enforcing strict default-deny even if a privilege were accidentally granted.
revoke all on table
  public.sensors,
  public.attack_events,
  public.detections,
  public.vulnerabilities,
  public.event_cve_matches,
  public.daily_stats,
  public.daily_reports,
  public.ingest_receipts
from public, anon, authenticated;

-- Service role (server-side ingest & jobs) retains operational access.
grant usage on schema public to anon, authenticated, service_role;
grant all on table
  public.sensors,
  public.attack_events,
  public.detections,
  public.vulnerabilities,
  public.event_cve_matches,
  public.daily_stats,
  public.daily_reports,
  public.ingest_receipts
to service_role;

-- -----------------------------------------------------------------------------
-- Sanitized Public Read-Only Projection Views
--
-- Design note:
-- Base tables remain strictly unreadable by anon/authenticated (no grants,
-- default-deny RLS). These views intentionally execute with definer privileges
-- to expose ONLY vetted, redacted, non-sensitive columns and published records
-- as read-only projections. Never add src_ip, src_ip_hash, raw_object_key,
-- raw metadata, ingest_receipts, or unpublished reports to any public view.
-- -----------------------------------------------------------------------------

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
  ) as last_event_at
from public.sensors s;

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
  ae.fingerprint
from public.attack_events ae;

create or replace view public.public_detections as
select
  d.id,
  d.event_id,
  d.rule_id,
  d.rule_version,
  d.classification,
  d.confidence,
  d.evidence_redacted,
  d.created_at
from public.detections d;

-- Only expose candidate CVEs that are actually linked to at least one observed event.
create or replace view public.public_vulnerabilities as
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
  max(m.created_at) as last_matched_at
from public.vulnerabilities v
inner join public.event_cve_matches m on m.cve_id = v.cve_id
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
  v.source_updated_at;

create or replace view public.public_event_cve_matches as
select
  m.id,
  m.event_id,
  m.cve_id,
  m.detection_id,
  m.match_type,
  m.confidence,
  m.reason,
  m.created_at,
  d.rule_id,
  d.rule_version,
  v.kev_present,
  v.epss_score,
  v.epss_percentile,
  v.epss_date
from public.event_cve_matches m
inner join public.detections d on d.id = m.detection_id
inner join public.vulnerabilities v on v.cve_id = m.cve_id;

create or replace view public.public_daily_stats as
select
  ds.date_utc,
  ds.sensor_id,
  ds.protocol,
  ds.event_type,
  ds.event_count,
  ds.unique_source_count,
  ds.updated_at
from public.daily_stats ds;

-- Only expose explicitly published reports; drafts/rejected remain private.
create or replace view public.public_daily_reports as
select
  dr.id,
  dr.date_utc,
  dr.summary_md,
  dr.model_id,
  dr.prompt_version,
  dr.source_window_start,
  dr.source_window_end,
  dr.reviewed_at
from public.daily_reports dr
where dr.status = 'published';

revoke all on table
  public.public_sensors,
  public.public_events,
  public.public_detections,
  public.public_vulnerabilities,
  public.public_event_cve_matches,
  public.public_daily_stats,
  public.public_daily_reports
from public, anon, authenticated;

grant select on table
  public.public_sensors,
  public.public_events,
  public.public_detections,
  public.public_vulnerabilities,
  public.public_event_cve_matches,
  public.public_daily_stats,
  public.public_daily_reports
to anon, authenticated, service_role;
