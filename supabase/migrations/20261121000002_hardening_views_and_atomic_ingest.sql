-- =============================================================================
-- Attackarium — Security Hardening: View Security Barriers & Atomic Ingest RPC
--
-- Fixes:
-- 1. Enable security_barrier = true on all sanitized public projection views
--    to prevent leaky-operator side-channel probing against filtered rows
--    (e.g., draft daily_reports or unmatched vulnerabilities).
-- 2. Provide an atomic, transactionally locked ingest RPC (commit_ingest_batch)
--    so rate-limit checks, anti-replay receipt insertion, idempotent event
--    upserts, and sensor heartbeat updates execute in a single transaction
--    without race conditions or orphaned nonces on write failure.
-- =============================================================================

-- -----------------------------------------------------------------------------
-- 1. Harden public projection views with security_barrier = true
-- -----------------------------------------------------------------------------
alter view public.public_sensors set (security_barrier = true);
alter view public.public_events set (security_barrier = true);
alter view public.public_detections set (security_barrier = true);
alter view public.public_vulnerabilities set (security_barrier = true);
alter view public.public_event_cve_matches set (security_barrier = true);
alter view public.public_daily_stats set (security_barrier = true);
alter view public.public_daily_reports set (security_barrier = true);

-- -----------------------------------------------------------------------------
-- 2. Atomic per-sensor ingest transaction (service_role ONLY)
--
-- Runs as SECURITY INVOKER with an empty search_path. Only service_role is
-- granted EXECUTE; PUBLIC, anon, and authenticated are explicitly revoked.
-- -----------------------------------------------------------------------------
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

  -- Serialize concurrent batches for the same sensor within this transaction
  perform pg_catalog.pg_advisory_xact_lock(
    pg_catalog.hashtext('attackarium:ingest:' || p_sensor_id)
  );

  -- Ensure sensor is registered before consuming rate limits or receipts
  if not exists (
    select 1
    from public.sensors s
    where s.id = p_sensor_id
  ) then
    return query select 'unknown_sensor'::text, 0;
    return;
  end if;

  -- Check anti-replay receipt first so replays return 409 without consuming quota
  if exists (
    select 1
    from public.ingest_receipts r
    where r.sensor_id = p_sensor_id
      and r.request_id = p_request_id
  ) then
    return query select 'replayed'::text, 0;
    return;
  end if;

  -- Atomic sliding-window rate limit (last 60 seconds)
  select pg_catalog.count(*)::integer
  into v_recent_count
  from public.ingest_receipts r
  where r.sensor_id = p_sensor_id
    and r.received_at >= (p_received_at - interval '60 seconds');

  if v_recent_count >= p_rate_limit then
    return query select 'rate_limited'::text, 0;
    return;
  end if;

  -- Record anti-replay receipt in the same transaction as event writes.
  -- If the event insert fails, Postgres rolls back this receipt automatically.
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

  -- Idempotent batch insert (duplicates on event id are ignored)
  insert into public.attack_events (
    id,
    sensor_id,
    observed_at,
    received_at,
    protocol,
    dst_port,
    event_type,
    src_ip,
    src_ip_hash,
    src_country,
    src_asn,
    http_method,
    http_path_redacted,
    fingerprint,
    raw_object_key,
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
    nullif(ev->>'src_ip', '')::inet,
    nullif(ev->>'src_ip_hash', ''),
    nullif(ev->>'src_country', ''),
    nullif(ev->>'src_asn', ''),
    nullif(ev->>'http_method', ''),
    nullif(ev->>'http_path_redacted', ''),
    nullif(ev->>'fingerprint', ''),
    nullif(ev->>'raw_object_key', ''),
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
