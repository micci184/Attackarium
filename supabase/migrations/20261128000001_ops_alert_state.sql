-- =============================================================================
-- Operator alerts (#32): state for Slack notifications and DB size probe
-- =============================================================================
-- The scheduled ops-alerts job (jobs/ops-alerts, GitHub Actions) reads sensor
-- health with the service_role key and notifies Slack on state changes. Both
-- objects below are operator-only: never exposed to anon or authenticated.
-- =============================================================================

-- One row per alert key. Lets a stateless scheduled job notify only when an
-- alert starts or resolves (plus a daily reminder), instead of every run.
create table if not exists public.ops_alert_state (
  alert_key text primary key check (alert_key ~ '^[a-z0-9_:.-]{1,80}$'),
  active boolean not null,
  since timestamptz not null,
  last_notified_at timestamptz,
  updated_at timestamptz not null default now()
);

comment on table public.ops_alert_state is
  'Operator-only. Notification state of the scheduled ops-alerts job (#32). No sensor data, IPs, or secrets.';

alter table public.ops_alert_state enable row level security;
revoke all on table public.ops_alert_state from public, anon, authenticated;
grant select, insert, update, delete on table public.ops_alert_state to service_role;

-- Database size in bytes, for the storage-quota alert. Invoker rights:
-- pg_database_size needs only CONNECT, which service_role has.
create or replace function public.ops_database_size_bytes()
returns bigint
language sql
stable
security invoker
set search_path = ''
as $$
  select pg_catalog.pg_database_size(pg_catalog.current_database());
$$;

revoke all on function public.ops_database_size_bytes() from public, anon, authenticated;
grant execute on function public.ops_database_size_bytes() to service_role;
