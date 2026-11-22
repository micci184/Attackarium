-- Phase 2 authorization state, admin-only MCP usage aggregates, and an
-- append-only operator audit log.
--
-- These tables store no email, name, prompt, argument, or token. Authenticated
-- users may read only their own entitlement row and record Terms acceptance
-- while not suspended. They cannot grant themselves MCP access or clear a
-- suspension.

-- Local CI has no Supabase Auth. Hosted Supabase already provides auth.uid()
-- under supabase_auth_admin, so touch the auth schema only when missing.
do $$
begin
  if not exists (
    select 1
    from pg_catalog.pg_proc as proc
    join pg_catalog.pg_namespace as namespace on namespace.oid = proc.pronamespace
    where namespace.nspname = 'auth'
      and proc.proname = 'uid'
  ) then
    create schema if not exists auth;
    create function auth.uid()
    returns uuid
    language sql
    stable
    set search_path = ''
    as $uid$
      select nullif(pg_catalog.current_setting('request.jwt.claim.sub', true), '')::uuid
    $uid$;
    grant usage on schema auth to anon, authenticated, service_role;
    grant execute on function auth.uid() to anon, authenticated, service_role;
  end if;
end;
$$;

-- -----------------------------------------------------------------------------
-- user_mcp_entitlements
-- -----------------------------------------------------------------------------
create table public.user_mcp_entitlements (
  user_id uuid primary key,
  terms_accepted_at timestamptz,
  terms_version text,
  mcp_enabled boolean not null default false,
  is_suspended boolean not null default false,
  updated_at timestamptz not null default now(),
  check (
    terms_version is null
    or terms_version ~ '^[A-Za-z0-9._-]{1,32}$'
  ),
  check (
    (terms_accepted_at is null and terms_version is null)
    or (terms_accepted_at is not null and terms_version is not null)
  )
);

alter table public.user_mcp_entitlements enable row level security;
alter table public.user_mcp_entitlements force row level security;

revoke all on table public.user_mcp_entitlements from public, anon, authenticated;
grant select on table public.user_mcp_entitlements to authenticated;
grant select, insert, update on table public.user_mcp_entitlements to service_role;

create policy user_mcp_entitlements_select_own
  on public.user_mcp_entitlements
  for select
  to authenticated
  using (user_id = (select auth.uid()));

-- Terms acceptance is the only user-facing write. Suspended accounts are
-- rejected; mcp_enabled and is_suspended are never modified by this function.
create or replace function public.accept_mcp_terms(p_terms_version text)
returns void
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_uid uuid := (select auth.uid());
  v_suspended boolean;
begin
  if v_uid is null then
    raise exception 'authentication required' using errcode = '42501';
  end if;
  if p_terms_version is null or p_terms_version !~ '^[A-Za-z0-9._-]{1,32}$' then
    raise exception 'invalid terms version' using errcode = '22023';
  end if;

  select e.is_suspended
  into v_suspended
  from public.user_mcp_entitlements as e
  where e.user_id = v_uid;

  if coalesce(v_suspended, false) then
    raise exception 'account is suspended' using errcode = '42501';
  end if;

  insert into public.user_mcp_entitlements (
    user_id,
    terms_accepted_at,
    terms_version,
    updated_at
  )
  values (v_uid, pg_catalog.now(), p_terms_version, pg_catalog.now())
  on conflict (user_id) do update
    set terms_accepted_at = excluded.terms_accepted_at,
        terms_version = excluded.terms_version,
        updated_at = excluded.updated_at;
end;
$$;

revoke all on function public.accept_mcp_terms(text) from public, anon;
grant execute on function public.accept_mcp_terms(text) to authenticated, service_role;

-- -----------------------------------------------------------------------------
-- mcp_usage_buckets
-- Aggregates only. tool_name is empty for initialize and one of the three
-- read-only tools for tool_call. No per-user identity is stored here.
-- -----------------------------------------------------------------------------
create table public.mcp_usage_buckets (
  bucket_start timestamptz not null,
  granularity text not null check (granularity in ('hour', 'day')),
  request_kind text not null check (request_kind in ('initialize', 'tool_call')),
  tool_name text not null default '',
  call_count bigint not null default 0 check (call_count >= 0),
  success_count bigint not null default 0 check (success_count >= 0),
  error_count bigint not null default 0 check (error_count >= 0),
  auth_failure_count bigint not null default 0 check (auth_failure_count >= 0),
  rate_limited_count bigint not null default 0 check (rate_limited_count >= 0),
  total_latency_ms bigint not null default 0 check (total_latency_ms >= 0),
  active_user_count integer not null default 0 check (active_user_count >= 0),
  primary key (bucket_start, granularity, request_kind, tool_name),
  check (
    (
      request_kind = 'initialize'
      and tool_name = ''
    )
    or (
      request_kind = 'tool_call'
      and tool_name in (
        'get_attack_trends',
        'get_attack_patterns',
        'get_observation_summary'
      )
    )
  ),
  check (success_count + error_count <= call_count)
);

create index mcp_usage_buckets_granularity_bucket_start_idx
  on public.mcp_usage_buckets (granularity, bucket_start desc);

alter table public.mcp_usage_buckets enable row level security;
alter table public.mcp_usage_buckets force row level security;

revoke all on table public.mcp_usage_buckets from public, anon, authenticated;
grant select, insert, update on table public.mcp_usage_buckets to service_role;

-- -----------------------------------------------------------------------------
-- mcp_rate_limit_windows
-- Short-lived per-user counters. The user id is the only identifier.
-- -----------------------------------------------------------------------------
create table public.mcp_rate_limit_windows (
  user_id uuid not null,
  window_start timestamptz not null,
  request_count integer not null default 0 check (request_count >= 0),
  expires_at timestamptz not null,
  primary key (user_id, window_start),
  check (expires_at > window_start)
);

create index mcp_rate_limit_windows_expires_at_idx
  on public.mcp_rate_limit_windows (expires_at);

alter table public.mcp_rate_limit_windows enable row level security;
alter table public.mcp_rate_limit_windows force row level security;

revoke all on table public.mcp_rate_limit_windows from public, anon, authenticated;
grant select, insert, update, delete on table public.mcp_rate_limit_windows to service_role;

-- -----------------------------------------------------------------------------
-- admin_audit_logs
-- Append-only. Update, delete, and truncate are rejected for every role,
-- including the table owner, by triggers. Metadata is a short structured note,
-- not a prompt.
-- -----------------------------------------------------------------------------
create table public.admin_audit_logs (
  id bigint generated always as identity primary key,
  actor_user_id uuid not null,
  action text not null check (action ~ '^[a-z0-9._-]{1,64}$'),
  target_type text check (
    target_type is null or target_type ~ '^[a-z0-9._-]{1,64}$'
  ),
  target_id text check (
    target_id is null or char_length(target_id) between 1 and 128
  ),
  metadata jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now(),
  check (octet_length(metadata::text) <= 2048)
);

create index admin_audit_logs_created_at_idx
  on public.admin_audit_logs (created_at desc);

create index admin_audit_logs_actor_created_at_idx
  on public.admin_audit_logs (actor_user_id, created_at desc);

alter table public.admin_audit_logs enable row level security;
alter table public.admin_audit_logs force row level security;

revoke all on table public.admin_audit_logs from public, anon, authenticated;
grant select, insert on table public.admin_audit_logs to service_role;

create or replace function public.reject_audit_log_mutation()
returns trigger
language plpgsql
set search_path = ''
as $$
begin
  raise exception 'admin_audit_logs is append-only' using errcode = '42501';
end;
$$;

revoke all on function public.reject_audit_log_mutation() from public, anon, authenticated;

create trigger admin_audit_logs_reject_mutation
  before update or delete on public.admin_audit_logs
  for each row execute function public.reject_audit_log_mutation();

create trigger admin_audit_logs_reject_truncate
  before truncate on public.admin_audit_logs
  for each statement execute function public.reject_audit_log_mutation();
