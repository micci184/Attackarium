-- =============================================================================
-- HTTP collector overload as degraded coverage (#95)
-- =============================================================================
-- When the HTTP collector refuses connections at capacity, observations are
-- lost even though the sensor is up. The shipper reports the refused count
-- for a time window; this RPC records that window as a closed 'degraded'
-- interval in sensor_status_events, so public coverage shows degraded
-- collection instead of an honest-looking "0 events". Windows closer than 15
-- minutes merge into one interval. The summary (counts) stays private:
-- public_sensor_status_events does not expose it.
--
-- Windows have second precision and can be zero-length (two reads in the same
-- second); every recorded interval spans at least one minute so delivered
-- refusals always appear as visible degraded coverage.
--
-- Slow connections cut at the per-connection deadline are attacker-side
-- connections, not lost observations, so they alone do not mark degradation.
-- =============================================================================

create or replace function public.record_sensor_overload(
  p_sensor_id text,
  p_rejected integer,
  p_deadline_cut integer,
  p_window_start timestamptz,
  p_window_end timestamptz
)
returns boolean
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_keep_id uuid;
  v_start timestamptz;
  v_end timestamptz;
  v_summary text;
begin
  if p_sensor_id is null
    or p_rejected is null or p_rejected <= 0
    or p_window_start is null or p_window_end is null
    or p_window_end < p_window_start
    or p_window_end > now() + interval '5 minutes'
    or p_window_start < now() - interval '7 days'
  then
    return false;
  end if;

  if not exists (select 1 from public.sensors where id = p_sensor_id) then
    return false;
  end if;

  -- Minimum visible duration (see header).
  p_window_end := greatest(p_window_end, p_window_start + interval '1 minute');

  v_summary := format(
    'HTTP collector at capacity: %s connection(s) refused, %s slow connection(s) cut',
    p_rejected,
    coalesce(greatest(p_deadline_cut, 0), 0)
  );

  -- Serialize per sensor so concurrent batches cannot create overlapping rows.
  perform pg_catalog.pg_advisory_xact_lock(8217003, pg_catalog.hashtext(p_sensor_id));

  -- Merge EVERY capacity interval this window connects (within 15 minutes),
  -- so a report that bridges two existing rows leaves exactly one.
  select min(started_at), max(ended_at)
  into v_start, v_end
  from public.sensor_status_events
  where sensor_id = p_sensor_id
    and status = 'degraded'
    and summary like 'HTTP collector at capacity:%'
    and ended_at is not null
    and ended_at >= p_window_start - interval '15 minutes'
    and started_at <= p_window_end + interval '15 minutes';

  if v_start is null then
    insert into public.sensor_status_events (sensor_id, status, started_at, ended_at, summary)
    values (p_sensor_id, 'degraded', p_window_start, p_window_end, v_summary);
    return true;
  end if;

  select id
  into v_keep_id
  from public.sensor_status_events
  where sensor_id = p_sensor_id
    and status = 'degraded'
    and summary like 'HTTP collector at capacity:%'
    and ended_at is not null
    and ended_at >= p_window_start - interval '15 minutes'
    and started_at <= p_window_end + interval '15 minutes'
  order by started_at, id
  limit 1;

  delete from public.sensor_status_events
  where sensor_id = p_sensor_id
    and status = 'degraded'
    and summary like 'HTTP collector at capacity:%'
    and ended_at is not null
    and ended_at >= p_window_start - interval '15 minutes'
    and started_at <= p_window_end + interval '15 minutes'
    and id <> v_keep_id;

  update public.sensor_status_events
  set started_at = least(v_start, p_window_start),
      ended_at = greatest(v_end, p_window_end),
      summary = v_summary
  where id = v_keep_id;

  return true;
end;
$$;

revoke all on function public.record_sensor_overload(text, integer, integer, timestamptz, timestamptz)
  from public, anon, authenticated;
grant execute on function public.record_sensor_overload(text, integer, integer, timestamptz, timestamptz)
  to service_role;
