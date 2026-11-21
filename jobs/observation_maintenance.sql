-- Service-role entrypoint for the observation rollup and retention job.
-- The function rolls aggregates up before it deletes aged detail rows.
-- Event retention below 30 days is rejected. Aggregate rows are not deleted.
-- There is no raw-payload store to prune.
select public.run_observation_maintenance(pg_catalog.now(), 90);
