# Data model and lifecycle

Design-level specification for the first PostgreSQL migration; **not yet applied**.
All timestamps are `timestamptz` UTC; UI converts to JST for display.

## Tables

| Table | Core fields | Constraints / notes |
| --- | --- | --- |
| `sensors` | `id`, `name`, `type`, `region`, `is_active`, `created_at` | No API secret stored in a public column |
| `attack_events` | `id`, `sensor_id`, `observed_at`, `received_at`, `protocol`, `dst_port`, `event_type`, `src_ip`, `src_country`, `src_asn`, `http_method`, `http_path_redacted`, `fingerprint`, `raw_object_key`, `metadata` | `id` stable UUID; `sensor_id` FK; sensitive data PRIVATE |
| `detections` | `id`, `event_id`, `rule_id`, `rule_version`, `classification`, `confidence`, `evidence_redacted`, `created_at` | Evidence must point to actual observed field |
| `vulnerabilities` | `cve_id`, `description`, `vendor`, `product`, `kev_present`, `kev_updated_at`, `epss_score`, `epss_percentile`, `epss_date`, `source_updated_at` | EPSS is a dated score, not a per-event probability |
| `event_cve_matches` | `event_id`, `cve_id`, `detection_id`, `match_type`, `confidence`, `reason` | Unique `(event_id, cve_id, detection_id)` |
| `daily_stats` | `date_utc`, `sensor_id`, `protocol`, `event_type`, `event_count`, `unique_source_count` | Composite unique key; aggregates only |
| `daily_reports` | `id`, `date_utc`, `status`, `summary_md`, `x_post_draft`, `model_id`, `source_window_start`, `source_window_end`, `reviewed_at` | Draft/reviewed/rejected/published states |
| `ingest_receipts` | `sensor_id`, `request_id`, `received_at`, `expires_at` | Optional bounded anti-replay nonce store |
| `user_mcp_entitlements` | `user_id`, `terms_accepted_at`, `terms_version`, `mcp_enabled`, `is_suspended`, `updated_at` | Minimal authz state ONLY; never duplicate Supabase Auth emails/profiles or store PII |
| `mcp_usage_buckets` | `bucket_start`, `granularity`, `request_kind`, `tool_name`, `call_count`, `success_count`, `error_count`, `auth_failure_count`, `rate_limited_count`, `avg_latency_ms`, `active_user_count` | Admin-only aggregates; distinguish `initialize` vs `tool_call`; **never store prompts or tokens** |
| `admin_audit_logs` | `id`, `actor_user_id`, `action`, `target_type`, `target_id`, `metadata`, `created_at` | Append-only operator audit log; tamper-resistant, never publicly readable |

## Data minimization and breach blast-radius reduction

- Do not collect app-specific user profile fields (name, address, phone number).
- Do not duplicate Supabase Auth user attributes (such as email) into application tables.
  Note that Google/GitHub login inherently stores account metadata (e.g., email) inside
  Supabase Auth itself; do not promise "zero personal data".
- Never store MCP user prompts/questions, OAuth access/refresh tokens, raw attack payloads,
  or plaintext credentials in analytics or public-facing tables.
- Protect against both **data leakage** and **data tampering** via default-deny RLS,
  least-privilege server credentials, strict write paths, and append-only audit logs.

Indexes to start:

- `attack_events(observed_at DESC)`, `(sensor_id, observed_at DESC)`, `(protocol, observed_at DESC)`.
- Unique `attack_events(id)` to support idempotent upsert.
- `detections(event_id)` and `event_cve_matches(cve_id)`.
- `daily_stats(date_utc DESC)`.

`src_ip` is optional/private raw data; the ingest function derives a keyed HMAC hash (`src_ip_hash`)
using `IP_HASH_SALT` and clears plaintext `src_ip` by default (`INGEST_ALLOW_RAW_IP=false`).
Raw `src_ip` is never exposed in anonymous views (`public_*` views enforce `security_barrier = true`).

## Access model

- Sensor: only per-sensor signed HTTPS ingestion, **no direct database credentials**.
- Ingest Edge Function: server-side privileged DB credentials in managed secrets; insert validated events.
- Background jobs: server-side only, no public write access.
- Anonymous readers: **only** approved views/aggregates; authenticated internal reviewers separate.
- Default-deny RLS on all base tables, tested for anonymous user access.
- Store raw HTTP payload samples in a **private** bucket with content limits and short retention.

## Retention and backups

1. Keep daily aggregates long term, independent of detailed-event retention.
2. Keep individual structured events as long as the allocated DB size and retention policy allow;
   start with a proposed **90-day window**, revise after measuring event volume.
3. Keep raw payload samples for a much shorter proposed **7-day window** and limit body size per request.
4. Export daily historical records and configuration to a separate private backup location;
   verify restore periodically. A backup within the same provider alone is not independent.
5. Monitor DB/storage quotas before free-tier limits affect ingestion or archive jobs.
6. Review privacy requirements for retained IP addresses and do not publish credentials.

For historical EPSS trends, an optional later `epss_daily_scores(cve_id, score_date, score, percentile)`
can be used. The MVP may only store the score/date used for a given report or match.
