-- =============================================================================
-- Attackarium — Retention alignment (ADR-022 / ADR-023) & MCP rate-limit cleanup
--
-- Aligns scheduled maintenance with the active retention policy:
--   - Sanitized detailed events (attack_events): configurable, at least 30 days
--     (no fixed 90-day assumption; shorten toward 30 days before pruning aggregates).
--   - Daily aggregates (event_aggregates, daily_stats, observed_patterns,
--     pattern_daily_counts): retained >= 1 year (not deleted by maintenance).
--   - Expired ingest_receipts and expired mcp_rate_limit_windows: pruned on
--     every scheduled run so transient state cannot bloat the 500 MB Free DB.
--   - Raw source IPs and raw payloads are never stored in Supabase.
-- =============================================================================

create or replace function public.run_scheduled_observation_maintenance(
  p_event_retention_days integer default 30
)
returns void
language plpgsql
security invoker
set search_path = ''
as $$
declare
  v_now timestamptz := pg_catalog.now();
begin
  if p_event_retention_days is null or p_event_retention_days < 30 then
    raise exception 'event retention must be at least 30 days' using errcode = '22023';
  end if;

  perform public.sync_sensor_coverage_gaps(v_now);
  perform public.run_observation_maintenance(v_now, p_event_retention_days);

  delete from public.mcp_rate_limit_windows
  where expires_at < v_now;
end;
$$;

revoke all on function public.run_scheduled_observation_maintenance(integer)
  from public, anon, authenticated;
grant execute on function public.run_scheduled_observation_maintenance(integer)
  to service_role;

-- Drop the legacy 0-arg overload if present so scheduled callers unambiguously
-- resolve the configurable default-30-day function.
drop function if exists public.run_scheduled_observation_maintenance();
