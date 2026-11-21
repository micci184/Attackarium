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
| `sensors` | `id`, `name`, `type`, `region`, `is_active`, `last_heartbeat_at`, `created_at` (Phase 1 ext: `monitored_services`, `last_error_at`, `last_error_summary`) | No API secret stored in any public column |
| `attack_events` | `id`, `sensor_id`, `observed_at`, `received_at`, `protocol`, `dst_port`, `event_type`, `attack_category` (Phase 1 ext), `src_ip`, `src_ip_hash`, `src_country`, `src_asn`, `http_method`, `http_path_redacted`, `fingerprint`, `raw_object_key`, `metadata` | `id` stable UUID for idempotent upsert; `sensor_id` FK; sensitive fields PRIVATE |
| `daily_stats` | `date_utc`, `sensor_id`, `protocol`, `event_type`, `event_count`, `unique_source_count`, `updated_at` | Composite primary key; long-term aggregates only |
| `event_aggregates` (Phase 1 ext) | `bucket_start`, `granularity` (`hour` / `day`), `sensor_id`, `protocol`, `attack_category`, `event_count`, `unique_source_count` | Supports 24h/7d/30d trends and day-over-day comparison without scanning raw events |
| `observed_patterns` (Phase 1 ext) | `pattern_type` (`http_path` / `signature` / `attack_category`), `pattern_key`, `protocol`, `first_seen_at`, `last_seen_at`, `total_count` | Tracks representative HTTP paths and attack patterns |
| `sensor_status_events` (Phase 1 ext) | `id`, `sensor_id`, `status` (`healthy` / `degraded` / `offline` / `error`), `started_at`, `ended_at`, `summary` | Records collection outages so UI separates zero-traffic periods from coverage gaps |
| `ingest_receipts` | `sensor_id`, `request_id`, `received_at`, `expires_at` | Bounded anti-replay nonce & atomic per-sensor sliding-window rate-limit store |

### Phase 2 — Vulnerability context, reports, Remote MCP & Admin tables

| Table | Core fields | Constraints / notes |
| --- | --- | --- |
| `detections` | `id`, `event_id`, `rule_id`, `rule_version`, `classification`, `confidence`, `evidence_redacted`, `created_at` | Evidence must point to actual observed redacted field |
| `vulnerabilities` | `cve_id`, `description`, `vendor`, `product`, `kev_present`, `kev_updated_at`, `epss_score`, `epss_percentile`, `epss_date`, `source_updated_at` | EPSS is a vulnerability-level dated forecast, not per-event exploit proof |
| `event_cve_matches` | `event_id`, `cve_id`, `detection_id`, `match_type`, `confidence`, `reason` | Unique `(event_id, cve_id, detection_id)`; candidate hypothesis only |
| `daily_reports` | `id`, `date_utc`, `status`, `summary_md`, `x_post_draft`, `model_id`, `prompt_version`, `source_window_start`, `source_window_end`, `reviewed_at` | `draft` / `reviewed` / `rejected` / `published`; only `published` exposed via public view |
| `user_mcp_entitlements` (Phase 2) | `user_id`, `terms_accepted_at`, `terms_version`, `mcp_enabled`, `is_suspended`, `updated_at` | Minimal authz state ONLY; never duplicate Supabase Auth emails/profiles or store PII |
| `mcp_usage_buckets` (Phase 2) | `bucket_start`, `granularity`, `request_kind`, `tool_name`, `call_count`, `success_count`, `error_count`, `auth_failure_count`, `rate_limited_count`, `avg_latency_ms`, `active_user_count` | Admin-only aggregates; distinguish `initialize` vs `tool_call`; **never store prompts or tokens** |
| `admin_audit_logs` (Phase 2) | `id`, `actor_user_id`, `action`, `target_type`, `target_id`, `metadata`, `created_at` | Append-only operator audit log; tamper-resistant, never publicly readable |

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

`src_ip` is optional/private raw data; the ingest function derives a keyed HMAC hash (`src_ip_hash`)
using `IP_HASH_SALT` and clears plaintext `src_ip` by default (`INGEST_ALLOW_RAW_IP=false`).
**Final source IP and raw payload retention rules must be confirmed in Phase 0 before
production database persistence.** Raw `src_ip` is never exposed in anonymous views.

## Indexes

- `attack_events(observed_at DESC)`, `(sensor_id, observed_at DESC)`, `(protocol, observed_at DESC)`, `(dst_port, observed_at DESC)`.
- Unique `attack_events(id)` to support idempotent upsert.
- `detections(event_id)`, `(rule_id, created_at DESC)`, and `event_cve_matches(cve_id)`, `(event_id)`, `(detection_id)`.
- `daily_stats(date_utc DESC)`, `(sensor_id, date_utc DESC)`.
- `ingest_receipts(expires_at)`, `(sensor_id, received_at DESC)`.
- Phase 1 extension indexes: `event_aggregates(granularity, bucket_start DESC)`, `observed_patterns(pattern_type, last_seen_at DESC)`, `sensor_status_events(sensor_id, started_at DESC)`.

## Access model

- Sensor: only per-sensor signed HTTPS ingestion, **no direct database credentials**.
- Ingest Edge Function: server-side `service_role` in managed secrets calling atomic `public.commit_ingest_batch(...)`.
- Background jobs: server-side only, no public write access.
- Anonymous & general authenticated readers: **only** approved `security_barrier` public views/aggregates.
- Default-deny RLS (`ENABLE` + `FORCE` + `REVOKE ALL`) on all base tables, tested for both `anon` and `authenticated` roles.
- Store optional raw HTTP payload samples in a **private** bucket with strict size limits and short configurable retention.

## Retention and backups (configurable by cost and volume)

1. **Long-term aggregates (`daily_stats`, `event_aggregates`, `observed_patterns`, `sensor_status_events`):**
   Retained long-term independent of detailed-event pruning so 30-day+ and multi-month trends remain intact.
2. **Detailed structured events (`attack_events`):**
   Configurable retention window tuned to DB quota and cost (proposed starting default: **90 days**, adjustable via job configuration).
3. **Raw payload samples & anti-replay nonces:**
   Short configurable retention (proposed: **7 days** for raw samples; periodic expiry cleanup for `ingest_receipts`).
4. **Independent backups:**
   Export daily historical aggregates/records and configuration to a separate private backup location and test restore periodically.
5. **Quota monitoring:**
   Alert before free/planned DB or storage quotas impact ingestion or archive jobs.
