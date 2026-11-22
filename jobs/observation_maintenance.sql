-- Service-role entrypoint for coverage-gap sync, rollup, and retention.
-- The hosted pg_cron schedule calls the same function every 15 minutes.
-- Rebuilds the last 8 UTC days, enforces >= 30-day sanitized event retention
-- (default 30 days per ADR-022; configurable via p_event_retention_days >= 30),
-- keeps daily aggregates (>= 1 year), and prunes expired ingest_receipts and
-- expired mcp_rate_limit_windows.
-- After the job has been down longer than 8 days, call
-- public.run_observation_maintenance(now(), 30, <days up to 30>) once.
select public.run_scheduled_observation_maintenance();
