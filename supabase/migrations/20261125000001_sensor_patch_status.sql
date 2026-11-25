-- =============================================================================
-- Sensor OS patch freshness (#94)
-- =============================================================================
-- The sensor reports when its last successful patch window finished
-- (scripts/patch_window.sh -> shipper -> signed ingest). The value is
-- operator-only: it is stored on the private base table and is NOT added to
-- public_sensors (that view lists its columns explicitly). Patch timing is
-- host-hardening information and stays off public surfaces.
-- =============================================================================

alter table public.sensors
  add column if not exists last_patch_success_at timestamptz;

comment on column public.sensors.last_patch_success_at is
  'Operator-only. When the sensor last completed a successful OS patch window, as reported over signed ingest. NULL = never reported, or the sensor reports no recorded success (for example after a restore).';

-- Latest report wins (not greatest): after a rollback to a pre-patch snapshot
-- the sensor reports an older time, or NULL when it has no recorded success,
-- and the console must show that. NULL clears the value. Timestamps later
-- than the receive time (plus skew) or implausibly old are ignored. Returns
-- true when a row was updated.
create or replace function public.record_sensor_patch_status(
  p_sensor_id text,
  p_patch_last_success_at timestamptz,
  p_received_at timestamptz
)
returns boolean
language plpgsql
security definer
set search_path = ''
as $$
begin
  if p_sensor_id is null or p_received_at is null then
    return false;
  end if;
  if p_patch_last_success_at is not null and (
    p_patch_last_success_at > p_received_at + interval '5 minutes'
    or p_patch_last_success_at < timestamptz '2024-01-01 00:00:00+00'
  ) then
    return false;
  end if;

  update public.sensors
  set last_patch_success_at = p_patch_last_success_at
  where id = p_sensor_id
    and last_patch_success_at is distinct from p_patch_last_success_at;

  return found;
end;
$$;

revoke all on function public.record_sensor_patch_status(text, timestamptz, timestamptz)
  from public, anon, authenticated;
grant execute on function public.record_sensor_patch_status(text, timestamptz, timestamptz)
  to service_role;
