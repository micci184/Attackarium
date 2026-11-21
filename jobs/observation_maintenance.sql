-- Service-role entrypoint for coverage-gap sync, rollup, and retention.
-- The hosted schedule calls the same function every 15 minutes.
-- Rebuilds the last 8 UTC days, then deletes events older than 90 days.
-- After the job has been down longer than 8 days, call
-- public.run_observation_maintenance(now(), 90, <days up to 30>) once.
select public.run_scheduled_observation_maintenance();
