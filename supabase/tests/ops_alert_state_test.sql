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
end $$;
reset role;

rollback;
