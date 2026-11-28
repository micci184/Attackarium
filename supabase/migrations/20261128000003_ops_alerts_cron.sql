-- =============================================================================
-- Operator alerts on a reliable schedule (#32)
-- =============================================================================
-- GitHub Actions schedules run hours late on this repository, so the
-- 15-minute Slack check moves to pg_cron (which already runs the observation
-- maintenance on time) calling the `ops-alerts` Edge Function through pg_net.
--
-- Configuration lives in Supabase Vault, never in this file:
-- - ops_alerts_function_url: https://<project-ref>.supabase.co/functions/v1/ops-alerts
-- - ops_alerts_cron_secret:  shared Bearer secret, also set as the function
--                            secret OPS_ALERTS_CRON_SECRET
-- (scripts/setup_ops_alerts.sh sets both, plus SLACK_WEBHOOK_URL.) Until both
-- exist the dispatcher does nothing, so applying this migration first is safe.
--
-- Environments without pg_cron / pg_net (plain Postgres in CI) skip the
-- extension and the schedule; the dispatcher function is still created.
-- =============================================================================

do $ext$
begin
  if exists (select 1 from pg_catalog.pg_available_extensions where name = 'pg_net') then
    create extension if not exists pg_net;
  end if;
end;
$ext$;

-- Single-runner lease for health-alert runs. pg_cron runs and on-demand
-- dispatches both reach the Edge Function asynchronously; a run that cannot
-- take the lease skips, so two runs never read and post the same transition.
-- The lease expires on its own, so a crashed run cannot block later ones.
create table if not exists public.ops_alerts_lease (
  id smallint primary key default 1 check (id = 1),
  holder text not null check (char_length(holder) between 1 and 64),
  expires_at timestamptz not null
);

alter table public.ops_alerts_lease enable row level security;
alter table public.ops_alerts_lease force row level security;
revoke all on table public.ops_alerts_lease from public, anon, authenticated;
grant select, insert, update, delete on table public.ops_alerts_lease to service_role;

create or replace function public.ops_alerts_acquire_lease(p_holder text, p_ttl_seconds integer default 120)
returns boolean
language plpgsql
security invoker
set search_path = ''
as $$
declare
  v_taken integer;
begin
  if p_holder is null or char_length(p_holder) not between 1 and 64 then
    raise exception 'invalid lease holder' using errcode = '22023';
  end if;
  if p_ttl_seconds is null or p_ttl_seconds < 10 or p_ttl_seconds > 600 then
    raise exception 'lease ttl must be between 10 and 600 seconds' using errcode = '22023';
  end if;
  insert into public.ops_alerts_lease as l (id, holder, expires_at)
  values (1, p_holder, pg_catalog.clock_timestamp() + pg_catalog.make_interval(secs => p_ttl_seconds))
  on conflict (id) do update
    set holder = excluded.holder,
        expires_at = excluded.expires_at
    where l.expires_at <= pg_catalog.clock_timestamp();
  get diagnostics v_taken = row_count;
  return v_taken = 1;
end;
$$;

create or replace function public.ops_alerts_release_lease(p_holder text)
returns void
language sql
security invoker
set search_path = ''
as $$
  delete from public.ops_alerts_lease where id = 1 and holder = p_holder;
$$;

revoke all on function public.ops_alerts_acquire_lease(text, integer) from public, anon, authenticated;
revoke all on function public.ops_alerts_release_lease(text) from public, anon, authenticated;
grant execute on function public.ops_alerts_acquire_lease(text, integer) to service_role;
grant execute on function public.ops_alerts_release_lease(text) to service_role;

-- Returns the pg_net request id, or NULL when not configured. Owner rights so
-- pg_cron can read the two Vault secrets; never callable by API roles.
-- p_send_test = true also posts a Slack test message through the Edge runner
-- (operator verification of the function's own SLACK_WEBHOOK_URL).
create or replace function public.ops_alerts_dispatch(p_send_test boolean default false)
returns bigint
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_url text;
  v_secret text;
begin
  if not exists (select 1 from pg_catalog.pg_extension where extname = 'pg_net')
     or not exists (select 1 from pg_catalog.pg_extension where extname = 'supabase_vault') then
    return null;
  end if;

  select ds.decrypted_secret into v_url
  from vault.decrypted_secrets ds
  where ds.name = 'ops_alerts_function_url';
  select ds.decrypted_secret into v_secret
  from vault.decrypted_secrets ds
  where ds.name = 'ops_alerts_cron_secret';

  if v_url is null or v_secret is null or pg_catalog.length(v_secret) < 32 then
    return null; -- not configured yet: do nothing
  end if;
  -- Only ever send the secret to this project's ops-alerts function.
  if v_url !~ '^https://[a-z0-9]{20}\.supabase\.co/functions/v1/ops-alerts$' then
    raise exception 'ops_alerts_function_url is not an ops-alerts Edge Function URL'
      using errcode = '22023';
  end if;

  return net.http_post(
    url := v_url,
    body := pg_catalog.jsonb_build_object('send_test', coalesce(p_send_test, false)),
    headers := pg_catalog.jsonb_build_object(
      'Authorization', 'Bearer ' || v_secret,
      'Content-Type', 'application/json'
    ),
    timeout_milliseconds := 30000
  );
end;
$$;

revoke all on function public.ops_alerts_dispatch(boolean) from public, anon, authenticated;
grant execute on function public.ops_alerts_dispatch(boolean) to service_role;

do $schedule$
declare
  v_jobid bigint;
begin
  if not exists (select 1 from pg_catalog.pg_extension where extname = 'pg_cron') then
    return;
  end if;

  for v_jobid in
    select job.jobid
    from cron.job as job
    where job.jobname = 'ops-alerts'
  loop
    perform cron.unschedule(v_jobid);
  end loop;

  -- Offset from the maintenance job (also */15) so the check sees fresh state.
  perform cron.schedule(
    'ops-alerts',
    '5,20,35,50 * * * *',
    'select public.ops_alerts_dispatch()'
  );
end;
$schedule$;
