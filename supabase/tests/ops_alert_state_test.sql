-- =============================================================================
-- Attackarium — operator alert state (#32) boundary tests
-- =============================================================================
\set ON_ERROR_STOP on

begin;

-- 1. service_role (and the owner) can use both objects
set local role service_role;
do $$
declare
  v bigint;
begin
  v := public.ops_database_size_bytes();
  if v is null or v <= 0 then
    raise exception 'database size probe returned %', v;
  end if;
  insert into public.ops_alert_state (alert_key, active, since, last_notified_at)
  values ('heartbeat_stale', true, now(), now());
  update public.ops_alert_state set active = false where alert_key = 'heartbeat_stale';
end $$;
reset role;

-- 1b. The pg_cron dispatcher is a no-op without pg_net / Vault configuration
--     (plain Postgres in CI), never an error.
do $$
begin
  if public.ops_alerts_dispatch() is not null or public.ops_alerts_dispatch(true) is not null then
    raise exception 'dispatcher sent a request without configuration';
  end if;
end $$;

-- 1c. Single-runner lease: one holder at a time, expiry frees it, only the
--     holder releases it.
set local role service_role;
do $$
begin
  if not public.ops_alerts_acquire_lease('run-a', 60) then
    raise exception 'first lease was not acquired';
  end if;
  if public.ops_alerts_acquire_lease('run-b', 60) then
    raise exception 'second run took a held lease';
  end if;
  perform public.ops_alerts_release_lease('run-b'); -- not the holder: no effect
  if public.ops_alerts_acquire_lease('run-b', 60) then
    raise exception 'a non-holder released the lease';
  end if;
  perform public.ops_alerts_release_lease('run-a');
  if not public.ops_alerts_acquire_lease('run-b', 60) then
    raise exception 'lease was not free after release';
  end if;
  update public.ops_alerts_lease set expires_at = clock_timestamp() - interval '1 second';
  if not public.ops_alerts_acquire_lease('run-c', 60) then
    raise exception 'expired lease was not taken over';
  end if;
  begin
    perform public.ops_alerts_acquire_lease('run-d', 5);
    raise exception 'ttl below 10 s was accepted';
  exception
    when invalid_parameter_value then null;
  end;
end $$;
reset role;

-- 2. Invalid keys are rejected
do $$
begin
  begin
    insert into public.ops_alert_state (alert_key, active, since) values ('Bad Key!', true, now());
    raise exception 'invalid alert key was accepted';
  exception
    when check_violation then null;
  end;
end $$;

-- 3. anon and authenticated can neither read/write the state nor call the probe
set local role anon;
do $$
begin
  begin
    perform 1 from public.ops_alert_state;
    raise exception 'SECURITY FAILURE: anon read ops_alert_state';
  exception
    when insufficient_privilege then null;
  end;
  begin
    perform public.ops_database_size_bytes();
    raise exception 'SECURITY FAILURE: anon executed ops_database_size_bytes';
  exception
    when insufficient_privilege then null;
  end;
  begin
    perform public.ops_alerts_dispatch();
    raise exception 'SECURITY FAILURE: anon executed ops_alerts_dispatch';
  exception
    when insufficient_privilege then null;
  end;
  begin
    perform public.ops_alerts_acquire_lease('x', 60);
    raise exception 'SECURITY FAILURE: anon took the ops alerts lease';
  exception
    when insufficient_privilege then null;
  end;
  begin
    perform 1 from public.ops_alerts_lease;
    raise exception 'SECURITY FAILURE: anon read ops_alerts_lease';
  exception
    when insufficient_privilege then null;
  end;
end $$;
reset role;

set local role authenticated;
do $$
begin
  begin
    insert into public.ops_alert_state (alert_key, active, since) values ('x', true, now());
    raise exception 'SECURITY FAILURE: authenticated wrote ops_alert_state';
  exception
    when insufficient_privilege then null;
  end;
  begin
    perform public.ops_database_size_bytes();
    raise exception 'SECURITY FAILURE: authenticated executed ops_database_size_bytes';
  exception
    when insufficient_privilege then null;
  end;
  begin
    perform public.ops_alerts_dispatch();
    raise exception 'SECURITY FAILURE: authenticated executed ops_alerts_dispatch';
  exception
    when insufficient_privilege then null;
  end;
end $$;
reset role;

rollback;
