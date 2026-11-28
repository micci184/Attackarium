-- =============================================================================
-- Candidate CVE matching and KEV/EPSS sync on a reliable schedule
-- =============================================================================
-- GitHub Actions schedules run hours late on this repository (the "hourly"
-- CVE matching ran every 6 to 11 hours), so both jobs move to pg_cron calling
-- the `observation-jobs` Edge Function through pg_net, like ops-alerts
-- (20261128000003). The GitHub workflows stay as manual (workflow_dispatch)
-- fallbacks only.
--
-- No new secrets: the dispatcher reuses the Vault secrets set by
-- supabase/scripts/setup_ops_alerts.sh (ops_alerts_cron_secret, and the
-- ops-alerts URL with its function name replaced). The function checks the
-- same OPS_ALERTS_CRON_SECRET. Until those exist the dispatcher does nothing.
-- Both jobs are idempotent (upserts), so an overlapping manual run is harmless.
-- =============================================================================

create or replace function public.observation_jobs_dispatch(p_job text)
returns bigint
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_url text;
  v_secret text;
begin
  if p_job is null or p_job not in ('cve-matching', 'threat-intel') then
    raise exception 'unknown observation job' using errcode = '22023';
  end if;
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
  -- Only ever send the secret to this project's Edge Functions.
  if v_url !~ '^https://[a-z0-9]{20}\.supabase\.co/functions/v1/ops-alerts$' then
    raise exception 'ops_alerts_function_url is not an ops-alerts Edge Function URL'
      using errcode = '22023';
  end if;

  return net.http_post(
    url := pg_catalog.regexp_replace(v_url, '/ops-alerts$', '/observation-jobs'),
    body := pg_catalog.jsonb_build_object('job', p_job),
    headers := pg_catalog.jsonb_build_object(
      'Authorization', 'Bearer ' || v_secret,
      'Content-Type', 'application/json'
    ),
    -- The KEV feed and NVD lookups can take longer than an alert check.
    timeout_milliseconds := 120000
  );
end;
$$;

revoke all on function public.observation_jobs_dispatch(text) from public, anon, authenticated;
grant execute on function public.observation_jobs_dispatch(text) to service_role;

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
    where job.jobname in ('cve-matching', 'threat-intel')
  loop
    perform cron.unschedule(v_jobid);
  end loop;

  -- Hourly, after the :15 maintenance rollup and away from the ops-alerts slots.
  perform cron.schedule(
    'cve-matching',
    '25 * * * *',
    $job$select public.observation_jobs_dispatch('cve-matching')$job$
  );
  -- Daily, same time as the former GitHub schedule (08:15 UTC).
  perform cron.schedule(
    'threat-intel',
    '15 8 * * *',
    $job$select public.observation_jobs_dispatch('threat-intel')$job$
  );
end;
$schedule$;
