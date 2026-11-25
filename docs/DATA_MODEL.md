# Data model and lifecycle

PostgreSQL schema specification for Attackarium (initial migrations checked into
`supabase/migrations/`; **not yet applied to a hosted production database**).
All timestamps are `timestamptz` UTC; UI converts to JST for display.
The first operator-managed sensor is planned for AWS **`us-east-1` (N. Virginia)**
(ADR-018). `sensors.region` is the label stored for that sensor.

## Tables

### Phase 1 — Core observation & aggregation tables

| Table | Core fields | Constraints / notes |
| --- | --- | --- |
| `sensors` | `id`, `name`, `type`, `region`, `is_active`, `last_heartbeat_at`, `created_at` (Phase 1 ext: `monitored_services`, `last_error_at`, `last_error_summary`; #94: `last_patch_success_at`, operator-only, written by `record_sensor_patch_status` and not in `public_sensors`) | No API secret stored in any public column |
| `attack_events` | `id`, `sensor_id`, `observed_at`, `received_at`, `protocol`, `dst_port`, `event_type`, `attack_category` (Phase 1 ext), `src_ip_hash`, `src_country`, `src_asn`, `http_method`, `http_path_redacted`, `fingerprint`, `metadata` | `id` stable UUID for idempotent upsert; `sensor_id` FK. No `src_ip` column and no `raw_object_key`. `src_ip_hash` and `metadata` are PRIVATE. OpenCanary commands are stored only as `metadata.cmd_verb` (allowlisted verb or `OTHER`) and `metadata.cmd_length`, never as raw command text. Client IP headers such as `X-Forwarded-For` are never kept in `metadata.headers`. The HTTP `Host` header value is never kept (for IP-direct scans it is the sensor's own public address); only `metadata.host_kind` (`ip_literal`, `hostname`, or `absent`) is stored |
| `daily_stats` | `date_utc`, `sensor_id`, `protocol`, `event_type`, `event_count`, `unique_source_count`, `updated_at` | Composite primary key; long-term aggregates only |
| `event_aggregates` (Phase 1 ext) | `bucket_start`, `granularity` (`hour` / `day`), `sensor_id`, `protocol`, `attack_category`, `event_count`, `unique_source_count` | Supports 24h/7d/30d trends and day-over-day comparison without scanning raw events |
| `observed_patterns` (Phase 1 ext) | `pattern_type` (`http_path` / `signature` / `attack_category`), `pattern_key`, `protocol`, `first_seen_at`, `last_seen_at`, `total_count` | Tracks representative HTTP paths and attack patterns. Lifetime values are derived from `pattern_daily_counts` |
| `pattern_daily_counts` (Phase 1 ext) | `date_utc`, `pattern_type`, `pattern_key`, `protocol`, `first_seen_at`, `last_seen_at`, `event_count` | PRIVATE. Per-day pattern counts kept after detail retention, so pattern totals stay exact |
| `sensor_status_events` (Phase 1 ext) | `id`, `sensor_id`, `status` (`healthy` / `degraded` / `offline` / `error`), `started_at`, `ended_at`, `summary` | Records collection outages so UI separates zero-traffic periods from coverage gaps |
| `ingest_receipts` | `sensor_id`, `request_id`, `received_at`, `expires_at` | Bounded anti-replay nonce & atomic per-sensor sliding-window rate-limit store |

### Phase 2 — Vulnerability context, reports, Remote MCP & Admin tables

| Table | Core fields | Constraints / notes |
| --- | --- | --- |
| `detections` | `id`, `event_id`, `rule_id`, `rule_version`, `classification`, `confidence`, `evidence_redacted`, `created_at` | Evidence must point to an observed indicator and location. `jobs/cve-matching` writes these rows from the collector catalog |
| `vulnerabilities` | `cve_id`, `description`, `vendor`, `product`, `published_at`, `cvss_score`, `cvss_vector`, `kev_present`, `kev_added_at`, `kev_updated_at`, `epss_score`, `epss_percentile`, `epss_date`, `source_updated_at` | Current EPSS is a vulnerability-level dated forecast, not per-event exploit proof. `kev_added_at` is when CISA added the CVE; `kev_updated_at` is the last catalog sync |
| `epss_daily_scores` | `cve_id`, `score_date`, `epss_score`, `epss_percentile` | Primary key `(cve_id, score_date)`. One FIRST EPSS score per tracked CVE per date. Tracked means the KEV catalog plus CVEs already stored, not the full EPSS universe. Public view includes a row only when that CVE has an observation match |
| `event_cve_matches` | `event_id`, `cve_id`, `detection_id`, `match_type`, `confidence`, `reason`, `evaluated_at` | Unique `(event_id, cve_id, detection_id)`; candidate hypothesis only. `evaluated_at` is the last evaluation time; `created_at` stays the insert time |
| `daily_reports` | `id`, `date_utc`, `status`, `summary_md`, `x_post_draft`, `model_id`, `prompt_version`, `source_window_start`, `source_window_end`, `reviewed_at` | `draft` / `reviewed` / `rejected` / `published`; only `published` exposed via public view |
| `user_mcp_entitlements` (Phase 2) | `user_id`, `terms_accepted_at`, `terms_version`, `mcp_enabled`, `is_suspended`, `updated_at` | Minimal authz state ONLY. `accept_mcp_terms` records Terms acceptance and cannot change `mcp_enabled` or `is_suspended`. Never duplicate Supabase Auth emails/profiles or store PII |
| `mcp_usage_buckets` (Phase 2) | `bucket_start`, `granularity`, `request_kind`, `tool_name`, `call_count`, `success_count`, `error_count`, `auth_failure_count`, `rate_limited_count`, `total_latency_ms`, `active_user_count` | Admin-only aggregates. `request_kind` is `initialize` (empty `tool_name`) or `tool_call` (one of the 3 tools). Average latency is `total_latency_ms / call_count`. `auth_failure_count` counts only requests with a verified JWT that fail a later gate (Terms, entitlement, suspension, consent); missing or invalid tokens return 401 without any database write, so anonymous traffic cannot add rows. **Never store prompts, arguments, tokens, or user ids** |
| `mcp_rate_limit_windows` (Phase 2) | `user_id`, `window_start`, `request_count`, `expires_at` | Short-lived per-user counters. Invisible to `anon` and `authenticated` |
| `admin_audit_logs` (Phase 2) | `id`, `actor_user_id`, `action`, `target_type`, `target_id`, `metadata`, `created_at` | Append-only operator audit log. Triggers reject update, delete, and truncate for every role. `metadata` is at most 2 KB. Never publicly readable |

## Data minimization and breach blast-radius reduction

- Do not collect app-specific user profile fields (name, address, phone number).
- Do not duplicate Supabase Auth user attributes (such as email) into application tables.
  Note that Google/GitHub login inherently stores account metadata (e.g., email) inside
  Supabase Auth itself; do not promise "zero personal data".
- Never store MCP user prompts/questions, OAuth access/refresh tokens, raw attack payloads,
  or plaintext credentials in analytics or public-facing tables.
- Protect against both **data leakage** and **data tampering** via default-deny RLS,
  `security_barrier = true` on all public views, atomic `SECURITY INVOKER` ingest RPCs,
  least-privilege server credentials, strict write paths, and append-only audit logs.

Supabase does not store raw source IPs, raw HTTP bodies, passwords, or
`Authorization` / `Cookie` values (ADR-022).

`src_ip_hash` is a keyed HMAC-SHA256 of the source address, using server-side
`IP_HASH_SALT` (at least 16 characters). It exists so unique-source counts and
repeat-source comparisons work after the address is discarded. It is not on any
public view. The salt stays in the ingest secret store, not on the sensor. A
hash without the salt does not reveal the address. A hash **with** the salt can
be checked against a guessed address, so the salt is a secret and the hash is
retained only as long as the sanitized event (at least 30 days). Daily aggregates
store counts, not hashes.

`src_country` and `src_asn` are optional derived labels. MVP does not add a GeoIP
database. When a later approved step derives them, it must discard the address
after derivation.

The sensor spool may still contain `src_ip` until ingest acknowledges the batch
or 24 hours pass, because hashing happens where the salt lives. Credentials and
raw bodies are removed before that spool write. There is no `INGEST_ALLOW_RAW_IP`
switch.

## Indexes

- `attack_events(observed_at DESC)`, `(sensor_id, observed_at DESC)`, `(protocol, observed_at DESC)`, `(dst_port, observed_at DESC)`.
- Unique `attack_events(id)` to support idempotent upsert.
- `detections(event_id)`, `(rule_id, created_at DESC)`, and `event_cve_matches(cve_id)`, `(event_id)`, `(detection_id)`.
- `epss_daily_scores` primary key `(cve_id, score_date)` also indexes the foreign key to `vulnerabilities`; `epss_daily_scores(score_date DESC)` supports date-range and retention queries.
- `daily_stats(date_utc DESC)`, `(sensor_id, date_utc DESC)`.
- `ingest_receipts(expires_at)`, `(sensor_id, received_at DESC)`.
- Phase 1 extension indexes: `attack_events(attack_category, observed_at DESC) WHERE attack_category IS NOT NULL`, `event_aggregates(granularity, bucket_start DESC)` plus `sensor_id`, `observed_patterns(pattern_type, last_seen_at DESC)`, `sensor_status_events(sensor_id, started_at DESC)`.
- Phase 2 indexes: `mcp_usage_buckets(granularity, bucket_start DESC)`, `mcp_rate_limit_windows(expires_at)`, `admin_audit_logs(created_at DESC)`, `admin_audit_logs(actor_user_id, created_at DESC)`. `user_mcp_entitlements(user_id)` is the primary key used by the own-row policy.

## Access model

- Sensor: only per-sensor signed HTTPS ingestion, **no direct database credentials**.
- Ingest Edge Function: server-side `service_role` in managed secrets calling atomic `public.commit_ingest_batch(...)`.
- Background jobs: server-side only, no public write access.
- Anonymous & general authenticated readers: **only** approved `security_barrier` public views/aggregates.
- Default-deny RLS (`ENABLE` + `FORCE` + `REVOKE ALL`) on all base tables, tested for both `anon` and `authenticated` roles.
- Do not create an AWS S3 bucket or a Supabase Storage bucket for raw payloads.

## Retention and backups (configurable by cost and volume)

1. **Daily and hourly aggregates (`daily_stats`, `event_aggregates`, `observed_patterns`, `pattern_daily_counts`, `sensor_status_events`):**
   Keep for **at least 1 year**. Prefer these over raw detail when the database nears its quota.
2. **Sanitized events (`attack_events`, including `src_ip_hash`):**
   Keep for **at least 30 days**. Shorten this window first if storage fills, and do not go below 30 days without a new decision. `prune_observation_retention` rejects a shorter window and deletes only whole UTC days older than the cutoff.
3. **EC2 raw logs:** OpenCanary JSONL and the collector JSONL are deleted within **24 hours**. The SQLite spool keeps undelivered sanitized-plus-transient-IP events only until delivery, the byte cap, or 24 hours.
4. **Anti-replay nonces (`ingest_receipts`):** expire on the existing receipt TTL. The same job deletes receipts whose `expires_at` has passed. They are not an archive.
5. **Rollup job (`run_observation_maintenance`):** rebuilds the most recent UTC days (8 by default, at most 30) from stored events, then prunes. Rerunning it gives the same counts. Days older than the window are never rewritten, so their buckets and pattern totals survive pruning, and a stray old event cannot overwrite them. After an outage longer than the window, run once with a wider window (up to 30 days) to catch up. Rollup and pruning take the same advisory lock. There is no raw-payload sample store to clean up.
6. **Backups:** MVP does not add S3, a second database, or an archive pipeline. Postgres is the durable store. Deferring an independent backup means a Postgres failure can lose observation history; record that risk in the runbook and revisit before treating the history as irreplaceable.
7. **Dashboard totals:** 24h / 7d / 30d counts and time series come from `event_aggregates`, `daily_stats`, `pattern_daily_counts`, and `observed_patterns`. A capped `public_events` read is a sample, not the period total. Production must not substitute mock observations when Supabase configuration is missing.
8. **Quota monitoring:** Alert before the database quota blocks ingest. There is no separate billing product beyond the single AWS Budget. `pattern_daily_counts` grows with the number of distinct redacted paths per day, so watch it first if attackers vary paths heavily.
9. **CVE evidence:** `detections` and `event_cve_matches` cascade-delete with their event. The candidate-matching job accepts that lifetime: sanitized evidence is kept only as long as the event. Keeping a separate CVE-evidence archive past event retention is deferred.
