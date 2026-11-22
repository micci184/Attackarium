-- Atomic server-side RPCs for Remote MCP per-user rate limiting and
-- admin-only aggregate usage recording. Both functions are restricted to
-- service_role; anon and authenticated cannot execute them.

-- -----------------------------------------------------------------------------
-- consume_mcp_rate_limit
-- Atomically increments the caller's fixed-window counter and returns whether
-- the request is allowed plus seconds until the window resets.
-- -----------------------------------------------------------------------------
create or replace function public.consume_mcp_rate_limit(
  p_user_id uuid,
  p_limit integer default 30,
  p_window_seconds integer default 60
)
returns table (
  allowed boolean,
  current_count integer,
  retry_after_seconds integer
)
language plpgsql
security invoker
set search_path = ''
as $$
declare
  v_now timestamptz := pg_catalog.now();
  v_window_start timestamptz;
  v_expires_at timestamptz;
  v_count integer;
begin
  if p_user_id is null then
    raise exception 'p_user_id is required' using errcode = '22023';
  end if;
  if p_limit is null or p_limit < 1 or p_limit > 10000 then
    raise exception 'p_limit out of range' using errcode = '22023';
  end if;
  if p_window_seconds is null or p_window_seconds < 1 or p_window_seconds > 3600 then
    raise exception 'p_window_seconds out of range' using errcode = '22023';
  end if;

  v_window_start := pg_catalog.to_timestamp(
    pg_catalog.floor(extract(epoch from v_now) / p_window_seconds) * p_window_seconds
  );
  v_expires_at := v_window_start + pg_catalog.make_interval(secs => p_window_seconds);

  delete from public.mcp_rate_limit_windows
  where user_id = p_user_id
    and expires_at <= v_now;

  insert into public.mcp_rate_limit_windows (
    user_id,
    window_start,
    request_count,
    expires_at
  )
  values (p_user_id, v_window_start, 1, v_expires_at)
  on conflict (user_id, window_start) do update
    set request_count = public.mcp_rate_limit_windows.request_count + 1
  returning request_count into v_count;

  allowed := v_count <= p_limit;
  current_count := v_count;
  retry_after_seconds := greatest(
    1,
    pg_catalog.ceil(extract(epoch from (v_expires_at - v_now)))::integer
  );
  return next;
end;
$$;

revoke all on function public.consume_mcp_rate_limit(uuid, integer, integer)
  from public, anon, authenticated;
grant execute on function public.consume_mcp_rate_limit(uuid, integer, integer)
  to service_role;

-- -----------------------------------------------------------------------------
-- record_mcp_usage_bucket
-- Atomically increments hourly and daily aggregate counters in mcp_usage_buckets.
-- Stores no prompts, arguments, tokens, or user identifiers.
-- -----------------------------------------------------------------------------
create or replace function public.record_mcp_usage_bucket(
  p_observed_at timestamptz,
  p_request_kind text,
  p_tool_name text,
  p_call_delta bigint default 0,
  p_success_delta bigint default 0,
  p_error_delta bigint default 0,
  p_auth_failure_delta bigint default 0,
  p_rate_limited_delta bigint default 0,
  p_latency_ms bigint default 0
)
returns void
language plpgsql
security invoker
set search_path = ''
as $$
declare
  v_hour_bucket timestamptz := pg_catalog.date_trunc('hour', coalesce(p_observed_at, pg_catalog.now()) at time zone 'UTC') at time zone 'UTC';
  v_day_bucket timestamptz := pg_catalog.date_trunc('day', coalesce(p_observed_at, pg_catalog.now()) at time zone 'UTC') at time zone 'UTC';
  v_tool text := coalesce(p_tool_name, '');
  v_latency bigint := greatest(0, coalesce(p_latency_ms, 0));
begin
  insert into public.mcp_usage_buckets (
    bucket_start,
    granularity,
    request_kind,
    tool_name,
    call_count,
    success_count,
    error_count,
    auth_failure_count,
    rate_limited_count,
    total_latency_ms
  )
  values
    (
      v_hour_bucket,
      'hour',
      p_request_kind,
      v_tool,
      p_call_delta,
      p_success_delta,
      p_error_delta,
      p_auth_failure_delta,
      p_rate_limited_delta,
      v_latency
    ),
    (
      v_day_bucket,
      'day',
      p_request_kind,
      v_tool,
      p_call_delta,
      p_success_delta,
      p_error_delta,
      p_auth_failure_delta,
      p_rate_limited_delta,
      v_latency
    )
  on conflict (bucket_start, granularity, request_kind, tool_name) do update
    set call_count = public.mcp_usage_buckets.call_count + excluded.call_count,
        success_count = public.mcp_usage_buckets.success_count + excluded.success_count,
        error_count = public.mcp_usage_buckets.error_count + excluded.error_count,
        auth_failure_count = public.mcp_usage_buckets.auth_failure_count + excluded.auth_failure_count,
        rate_limited_count = public.mcp_usage_buckets.rate_limited_count + excluded.rate_limited_count,
        total_latency_ms = public.mcp_usage_buckets.total_latency_ms + excluded.total_latency_ms;
end;
$$;

revoke all on function public.record_mcp_usage_bucket(
  timestamptz, text, text, bigint, bigint, bigint, bigint, bigint, bigint
) from public, anon, authenticated;
grant execute on function public.record_mcp_usage_bucket(
  timestamptz, text, text, bigint, bigint, bigint, bigint, bigint, bigint
) to service_role;
