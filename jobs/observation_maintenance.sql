-- Service-role entrypoint for the observation rollup and retention job.
-- Rebuilds the last 8 UTC days, then deletes events older than 90 days.
-- After the job has been down longer than 8 days, pass a third argument
-- of up to 30 to rebuild the missed days.
select public.run_observation_maintenance(pg_catalog.now(), 90);
