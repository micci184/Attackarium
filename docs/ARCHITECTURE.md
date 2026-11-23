# Architecture

## 1. Context

Attackarium is a noncommercial **threat-observability service** that collects
real unsolicited probes and attack attempts from operator-managed honeypots,
retains historical observations over time, and publishes sanitized trends.

**Attackarium is not a vulnerability database.** Original observation telemetry
is the primary product; CVE, CISA KEV, and FIRST EPSS provide supporting context
to interpret observed traffic without claiming confirmed exploitation or
representing global Internet attack volume.

Initial deployment: **one isolated operator-managed AWS EC2 sensor host in
US East (N. Virginia), `us-east-1`** (ADR-018; Lightsail evaluation is closed;
sensor application code remains cloud-agnostic),
Supabase (PostgreSQL + Auth OAuth 2.1) for historical storage and authorization,
and Vercel (Next.js + Vercel Functions) for the login-free public dashboard,
read-only Remote MCP server, and operator-only Admin Console. MVP does not use
AWS S3. Durable observations live in Supabase. The EC2 disk holds only temporary
logs and the retry spool.

User-contributed sensors (GreyNoise Project Swarm model) and general-purpose
public REST APIs are explicitly out of scope.

## 2. Component responsibilities

| Component | Responsibility | Placement |
| --- | --- | --- |
| OpenCanary | Low-interaction SSH, Telnet, FTP, MySQL, Redis decoys | AWS EC2 sensor host |
| HTTP collector | Record bounded HTTP/HTTPS request metadata and sanitized payload samples (non-executing, concurrency-capped) | Same EC2 host, separate process |
| Shipper | Read JSONL, normalize, assign stable event IDs, write bounded SQLite spool, retry HTTPS batches with backoff | AWS EC2 sensor host |
| Ingest | Authenticate per-sensor HMAC; stream-bound body; validate schema/timestamps; atomic rate-limit/replay/upsert RPC | Supabase Edge Function |
| PostgreSQL | Store events, hourly/daily aggregates, patterns, sensor health/gaps, detections, CVE context, MCP entitlements/usage, audit logs | Supabase |
| Auth / OAuth 2.1 | Google/GitHub sign-in, OAuth 2.1 Authorization Code + PKCE for Remote MCP, mandatory MFA (`aal2`) for operator admin | Supabase Auth |
| Background jobs | Hourly/daily rollups, configurable retention cleanup, KEV/EPSS/NVD enrichment, deterministic rules, AI draft reports | Scheduled server-side jobs |
| Public dashboard | Login-free sanitized dashboard (24h/30d trends, protocol & pattern breakdowns, representative HTTP paths, sensor health & coverage gaps) | Vercel / Next.js |
| Remote MCP Server | Read-only Streamable HTTP MCP via Vercel `mcp-handler` (3 initial tools, no Cloudflare Workers, no general public REST API) | Vercel Functions |
| Admin Console | Operator-only MCP Usage analytics, entitlement management, report review, audit trail (default-deny, server allowlist, MFA) | Vercel / Next.js |

## 3. Protocol and port assignment

- OpenCanary: **22/SSH, 23/Telnet, 21/FTP, 3306/MySQL, 6379/Redis**.
- HTTP collector: **80/HTTP, 443/HTTPS** after TLS/DNS is configured.
- **Disable OpenCanary's HTTP and HTTPS decoys** when the dedicated collector owns 80/443.
- Actual administrator SSH: separate non-decoy port, key-only, reachable only through an EC2 Instance Connect Endpoint (IAM-authenticated, CloudTrail-logged; no public admin port, no instance IAM role; ADR-025), and isolated from decoy ports.
- Keep sensor application code (`sensors/http-collector`, `sensors/shipper`, `sensors/opencanary`) free of AWS-specific SDK lock-in so it remains portable.

The HTTP collector must never execute captured requests, fetch attacker-supplied
URLs, follow redirects, or pass payloads to a shell.

## 4. Data path

1. Sensor receives unsolicited inbound traffic and emits a structured local JSONL record.
2. Shipper normalizes the record, strips credentials, assigns a stable event UUID,
   and persists it to a disk-capped SQLite WAL spool before transmission.
3. Shipper sends signed HTTPS batches (`sensor_id`, `timestamp`, `request_id`, `raw_body`)
   with exponential backoff and poison-pill isolation on permanent 400 errors.
4. Ingest streams the body within strict byte limits, verifies HMAC with uniform
   anti-enumeration errors, replaces `src_ip` with a keyed HMAC and discards the address, and
   commits rate-limit check + anti-replay receipt + idempotent upsert + sensor
   heartbeat inside a single atomic PostgreSQL transaction (`commit_ingest_batch`).
5. Background jobs roll up hourly/daily aggregates, record observed patterns and
   sensor coverage gaps, enforce configurable retention on detailed records, and
   (Phase 2) enrich events with deterministic rules and CVE/KEV/EPSS context.
6. The public Next.js site reads only `security_barrier` sanitized views/aggregates.
7. AI receives only sanitized, aggregated evidence and generates a draft report
   for mandatory human review before any X publication.

## 5. Attack data taxonomy and external intelligence

Attack observations are classified along **two orthogonal axes** so raw attempts
are never confused with confirmed exploitation:

1. **Observation category (`attack_category`):**
   - `port_scan` — port scanning and service discovery
   - `auth_attempt` — SSH / Telnet / FTP / DB login attempts
   - `http_path_probe` — HTTP path/file/CMS discovery
   - `web_attack_attempt` — web application attack payloads/probes
   - `suspected_cve_probe` — requests resembling patterns linked to a known CVE
2. **Evidence / confidence level (`classification`):**
   - `observed`: literal protocol/action/request metadata directly captured.
   - `indicator_match`: explicit versioned signature matched with recorded evidence.
   - `candidate_cve`: documented hypothesis with rule ID/version, evidence, confidence, and source metadata — **never proof of exploitation**.

See [`docs/HTTP_SIGNATURES.md`](HTTP_SIGNATURES.md) for the versioned HTTP Collector signature rules, evidence definitions, and known blind spots.

| Feed | Usage | Update cadence |
| --- | --- | --- |
| CISA KEV | Whether a CVE is catalogued as known exploited in the wild | Daily |
| FIRST EPSS | Daily 30-day exploitation probability forecast for a published CVE | Daily |
| NVD / CVE source | Description, affected products, and references for *candidate* CVEs only | On demand; cached |

EPSS is a vulnerability-level forecast, not the probability that a specific
observed request succeeded.

The daily job in `jobs/threat-intel` stores the CISA KEV catalog and FIRST EPSS
scores for those CVEs plus any CVE already stored. It does not import the full
EPSS universe. Both feeds are validated before any write, so a feed outage
leaves the last stored flags and scores in place. `kev_updated_at` is the KEV
catalog `dateReleased`, and the job log records `catalogVersion`. GitHub Actions
runs the job at 08:15 UTC when `SUPABASE_URL` and `SUPABASE_SERVICE_ROLE_KEY`
are repository secrets. Without those secrets the workflow skips and does not
call the feeds.

`jobs/cve-matching` reads `attack_events.metadata.signature_detections` from the
last 48 hours and persists only detections whose rule ID, version, and indicator
match the collector catalog. Technique-only matches stay in `detections`.
Catalog CVEs are written to `event_cve_matches` as candidate hypotheses.
NVD is requested only for those catalog CVE IDs, and only the description,
vendor, product, publish time, and CVSS fields are cached. A failed NVD lookup
does not remove the match or existing KEV/EPSS values. GitHub Actions runs this
job hourly at minute 20 and skips it when the Supabase secrets are absent.

## 6. Public web dashboard (no login required)

General users can inspect sanitized observations without logging in:

- **Overview:** Lead with observation status (sensor health, last update, window,
  coverage gaps), then the last 24h count versus the previous 24h, then at most
  three evidence-backed noteworthy changes (or an explicit "no notable change").
  The 24h series follows. 7-day and 30-day series stay on Trends. Patterns and
  recent events link into the existing Event Explorer filters. The map and
  low-signal KPIs (protocol count, approximate regions) are secondary.
  Noteworthy changes use explainable comparisons, not an anomaly model or an AI claim.
- **Trends:** 24h / 7d / 30d volume from complete aggregates. Bucket sums match the
  period total. Sampled latest-N rows are labeled as samples and are not the total.
- **Sensor Health & Coverage Gaps:** Active/healthy sensor count, heartbeat
  freshness, observation scope, and explicit visual distinction between
  **zero observed events** and **collection outage / missing data**.
- **Event Explorer (MVP minimal filter):** Protocol/basic filtering over sanitized
  records and redacted detail view (no raw IPs, credentials, or raw payloads).
- **Methodology & Limitations:** Prominent disclosure that a small number of
  sensors represent a biased sample, not global Internet attack volume.

## 7. Remote MCP architecture (Phase 2 — Vercel Functions + Supabase Auth OAuth 2.1)

Remote MCP runs on **Vercel Functions** via official `mcp-handler` (Streamable
HTTP) and reuses the shared read-only query layer (`apps/web/src/lib/`). No
general-purpose public REST API is exposed; HTTP endpoints are restricted to
MCP, authentication, and sensor ingestion.

- **Discovery:** Publish RFC 9728 OAuth Protected Resource Metadata
  (`/.well-known/oauth-protected-resource`) pointing MCP clients to the Supabase
  Auth OAuth 2.1 Issuer and supported read-only scopes (e.g., `mcp:read`).
  Unauthenticated requests to `/api/mcp` return `401` with `WWW-Authenticate`.
- **OAuth 2.1 Flow:** Authorization Code + PKCE (`S256`) via Supabase Auth
  (Google or GitHub login) plus Terms acceptance and OAuth client consent.
- **Per-Request Verification & Immediate Revocation:** Every MCP request
  verifies JWT signature (JWKS), `iss`, `aud`, `exp`, and `scope`, then performs
  a live server-side DB check of `user_mcp_entitlements` to enforce all 5 gates:
  (1) Google/GitHub login, (2) current Terms accepted, (3) `is_suspended = false`,
  (4) `mcp_enabled = true`, (5) OAuth consent/scope. Account suspension or
  entitlement revocation takes effect immediately on the next call even if a
  short-lived JWT has not yet expired.
- **Initial Read-Only Tool Catalog (strictly 3 tools):**
  - `get_attack_trends` — time-series volume and protocol/category shifts (with period/protocol filters)
  - `get_attack_patterns` — observed attack patterns and representative sanitized HTTP paths (with period/protocol filters)
  - `get_observation_summary` — 24h/window KPIs, recent changes, sensor health, and coverage caveats (with period/protocol filters)
- **Strict Boundaries:** Read-only only; no raw logs, no secrets, no DB writes,
  no admin tools; per-user rate limits; zero prompt/token logging; MCP Usage is
  exclusively visible in the operator-only Admin Console.

## 8. Scalability boundaries

MVP uses **PostgreSQL** with hourly/daily aggregate tables and indexes rather
than TimescaleDB, Kafka, Elasticsearch, or SIEM stacks. Detailed events use
configurable retention while long-term aggregates remain compact.

## 9. Source references (official)

- [OpenCanary service configuration](https://opencanary.readthedocs.io/en/latest/starting/configuration.html)
- [OpenCanary Linux Web Server](https://opencanary.readthedocs.io/en/latest/services/webserver.html)
- [Supabase Cron](https://supabase.com/docs/guides/cron)
- [Vercel MCP Server Deployment (`mcp-handler`)](https://vercel.com/docs/mcp/deploy-mcp-servers-to-vercel)
- [Supabase Auth OAuth 2.1 for MCP](https://supabase.com/docs/guides/auth/oauth-server/mcp-authentication)
- [Supabase Build Your Own MCP](https://supabase.com/docs/guides/ai-tools/byo-mcp)
- [CISA KEV data](https://github.com/cisagov/kev-data)
- [FIRST EPSS](https://www.first.org/epss/)
- [FIRST EPSS data formats](https://www.first.org/epss/data)
