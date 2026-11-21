-- =============================================================================
-- Attackarium — Drop raw source IP and raw payload storage
--
-- Phase 0 decision: Supabase stores sanitized observations only.
-- - attack_events.src_ip is removed so plaintext addresses cannot be persisted.
-- - attack_events.raw_object_key is removed. MVP does not use AWS S3 or a
--   Supabase Storage bucket for raw HTTP bodies.
-- - src_ip_hash, src_country, and src_asn stay. The hash is a keyed HMAC.
--   Country and ASN are derived labels, not the address itself.
--
-- commit_ingest_batch ignores src_ip and raw_object_key if a caller still
-- sends them. This migration is not applied to any hosted database here.
-- =============================================================================

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

  perform pg_catalog.pg_advisory_xact_lock(
    pg_catalog.hashtext('attackarium:ingest:' || p_sensor_id)
  );

  if not exists (
    select 1
    from public.sensors s
    where s.id = p_sensor_id
  ) then
    return query select 'unknown_sensor'::text, 0;
    return;
  end if;

  if exists (
    select 1
    from public.ingest_receipts r
    where r.sensor_id = p_sensor_id
      and r.request_id = p_request_id
  ) then
    return query select 'replayed'::text, 0;
    return;
  end if;

  select pg_catalog.count(*)::integer
  into v_recent_count
  from public.ingest_receipts r
  where r.sensor_id = p_sensor_id
    and r.received_at >= (p_received_at - interval '60 seconds');

  if v_recent_count >= p_rate_limit then
    return query select 'rate_limited'::text, 0;
    return;
  end if;

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

  -- src_ip and raw_object_key in p_events are intentionally ignored.
  insert into public.attack_events (
    id,
    sensor_id,
    observed_at,
    received_at,
    protocol,
    dst_port,
    event_type,
    src_ip_hash,
    src_country,
    src_asn,
    http_method,
    http_path_redacted,
    fingerprint,
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
    nullif(ev->>'src_ip_hash', ''),
    nullif(ev->>'src_country', ''),
    nullif(ev->>'src_asn', ''),
    nullif(ev->>'http_method', ''),
    nullif(ev->>'http_path_redacted', ''),
    nullif(ev->>'fingerprint', ''),
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

alter table public.attack_events drop column src_ip;
alter table public.attack_events drop column raw_object_key;

comment on table public.attack_events is
  'Sanitized observation events. Plaintext source IPs and raw HTTP payloads are not stored.';

comment on column public.attack_events.src_ip_hash is
  'Keyed HMAC of the source IP. The plaintext address is not stored.';
