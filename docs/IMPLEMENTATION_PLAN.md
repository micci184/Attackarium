# Implementation plan (MVP)

Last reviewed: 2026-11-21 (JST). Status: **planned, not deployed**.

## 1. Product requirements

**Target:** A small, noncommercial public site showing what the project's own Internet-facing
honeypot sensors observed over time and what that may imply about broader threat trends.

Must-have:

1. OpenCanary observations for SSH/Telnet/FTP/DB services.
2. Lightweight HTTP/HTTPS request telemetry to supplement OpenCanary.
3. Authenticated event ingestion, retry, de-duplication, timestamped historical storage.
4. Public dashboard with live-ish refresh, protocol trends, historical comparisons.
5. Evidence-based signature rules and **candidate** CVE matching; KEV/EPSS enrichment.
6. Daily AI summary with source evidence and human review before an X post.
7. Sensible operational/abuse handling and a documented cost ceiling.

Not in MVP:

- T-Pot, Kibana, Elastic Stack, Kafka, SIEM-grade correlation.
- Full interaction SSH shell emulation (Cowrie can be added later).
- An exploit framework, malware sandbox/execution or active attacker callbacks.
- A full CVE database mirror or automatic claims that a CVE exploit succeeded.
- Multi-region rollout, automatic X publication without human review, commercial billing.

## 2. Implementation phases

### Phase 0 — Policy and operational gate

- [ ] Pick AWS account, EC2 region/instance sizing, DNS/domain strategy, and monthly spend cap.
- [ ] Confirm AWS acceptable-use / policy alignment for the planned *public, responding low-interaction honeypot* on **EC2**.
- [ ] Confirm incident/abuse report contact, credentials rotation, teardown procedure, and log retention.
- [ ] Decide whether IP addresses will be retained privately (and for how long) and document publication policy.

**Done when:** no unresolved platform-policy question remains for public deployment.

### Phase 1 — Data foundation and UI with test traffic

- [ ] Create Next.js TypeScript app at `apps/web` and deploy preview to Vercel.
- [ ] Set up Supabase project and migration scripts (see `DATA_MODEL.md`).
- [ ] Implement `supabase/functions/ingest` with strict HMAC verification, JSON schema bounds,
      per-sensor quotas, timestamps, replay detection, dedupe, private inserts.
- [ ] Add deterministic synthetic fixture generator/tests including malformed and duplicate batches.
- [ ] Build public Overview, Trends and sanitized Event List; implement server-side pagination.
- [ ] Protect all tables with RLS; public role can select only sanitized views/aggregates.
- [ ] Add a migration check, TypeScript lint/typecheck and API tests to CI.

**Done when:** sample events from a simulated client are stored and safely visible on the dashboard;
bad, replayed, or oversized requests are rejected.

### Phase 2 — Isolated honeypot sensors

- [ ] Provision a minimal Linux host through IaC, with cost alerts and maintenance SSH access.
- [ ] Configure OpenCanary services, immutable identifiers and JSON/file logging.
- [ ] Implement minimal HTTP/HTTPS collector: method, bounded path, selected header metadata,
      limited body sampling; reject oversize requests without executing them.
- [ ] Ensure port ownership is exclusive (HTTP collector owns 80/443, OpenCanary's HTTP decoys disabled).
- [ ] Implement shipper with SQLite/bounded disk spool, at-least-once delivery, exponential backoff,
      stable event IDs and retry/queue metrics.
- [ ] Restrict **outbound** communications at the host OS layer; test inability to contact arbitrary IPs.
- [ ] Run controlled localhost/safe approved test traffic before opening to the Internet.

**Done when:** protocol test events appear once in Supabase after retries; loss and queue limits are known.

### Phase 3 — Vulnerability context

- [ ] Import current CISA KEV dataset once daily; record source version/retrieval date.
- [ ] Import EPSS scores daily, using API for matched CVEs or daily CSV for bulk needs.
- [ ] Add curated, versioned signatures; store pattern ID, match confidence and evidence field.
- [ ] Fetch NVD/CVE metadata **only** for candidates, respect provider rate limits and cache results.
- [ ] Show "suspected related CVE" prominently distinct from confirmed exploit execution.
- [ ] Add tests for false positives and unknown patterns.

**Done when:** one known synthetic signature generates a documented candidate match,
and a benign/probing sample does not generate a false confirmed-exploit label.

### Phase 4 — Reporting, review, production readiness

- [ ] Add periodic rollups and anomaly comparisons: 24-hour baseline, prior day/week.
- [ ] Generate a daily AI summary from **redacted aggregates and matched evidence**, with
      explicit observability limitations; save prompt/model/version for reproducibility.
- [ ] Add a draft/review state and exportable X text; **no automated posting** until reviewed.
- [ ] Add backup/export job, retention policy, disk/DB usage alerts and runbook.
- [ ] Perform auth/RLS tests, secret scanning, log redaction tests and failure recovery drill.
- [ ] Publish the dashboard with explanatory methodology and privacy notices.

**Done when:** dashboard shows real observations and historical trends,
the daily report can be reviewed and exported, and sensor/DB failure modes have been tested.

### Phase 5 — Remote MCP, OAuth 2.1 & Operator Admin Console

- [ ] Add minimal DB tables/RLS for MCP entitlements (`user_mcp_entitlements`), aggregated MCP Usage (`mcp_usage_buckets`, separating initialize vs tool calls), and append-only `admin_audit_logs`.
- [ ] Enable Supabase Auth (Google/GitHub) as OAuth 2.1 Authorization Code + PKCE server and publish required OAuth metadata.
- [ ] Build general-user MCP page: connection instructions, available read-only tool catalog, Terms acceptance, and OAuth consent/revocation (**no usage count dashboard for general users**).
- [ ] Implement read-only Remote MCP server on **Vercel Functions** via official `mcp-handler` (Streamable HTTP, no Cloudflare Workers), reusing shared read-only query helpers, enforcing all 5 server-side authz gates + per-user rate limits, and logging zero prompts/tokens.
- [ ] Build operator-only Admin Console & protected admin APIs (default-deny, server-side admin ID allowlist, mandatory MFA, audit logs) including admin-only MCP Usage analytics.

**Done when:** Cursor/MCP clients connect via OAuth 2.1 PKCE, unauthenticated/unentitled/unaccepted/suspended users are blocked, MCP cannot write or administer DB, and MCP Usage + admin APIs are accessible exclusively to the MFA-verified operator.

## 3. Minimal release acceptance checklist

- Live event visible on dashboard within an agreed refresh window (initial goal: 60 seconds).
- Sensor offline/Edge unavailable -> spool retry; **no silent log loss** within defined spool capacity.
- Duplicate or replayed event -> no duplicate DB row.
- Public anonymous user cannot read raw IPs, credentials, payloads, or ingest credentials.
- All CVE associations disclose confidence, matched rule, and source metadata.
- API cost/volume limits and retention are tested with malformed/high-rate input.
- A human can approve or reject an AI-generated daily summary before any X publication.
- Documentation states that one IP/region is a **biased sample**, not a global Internet attack census.

## 4. Initial cost plan

- AWS EC2 sensor: minimal isolated EC2 instance + public IPv4 + EBS (exact instance size & region confirmed in Phase 0 with explicit monthly spend cap and billing alerts).
- Vercel Hobby: free only for eligible personal/noncommercial usage and within limits (hosts Next.js dashboard, Admin Console, and Vercel Functions Remote MCP).
- Supabase Free: 500 MB database, 1 GB Storage, Supabase Auth (at the referenced date); limits require monitoring.
- LLM token usage, domain, backups/archival, traffic overages: **variable, not included**.
- Do not buy paid infrastructure or deploy a public honeypot until the owner approves the concrete plan.

References: [AWS EC2 pricing](https://aws.amazon.com/ec2/pricing/),
[Vercel Hobby](https://vercel.com/docs/plans/hobby),
[Supabase quotas](https://supabase.com/docs/guides/platform/billing-on-supabase).

## 5. Delivery boundaries

This repository currently contains **documentation and placeholders only**.
Deployment needs an AWS account/region, service credentials, domain/DNS if TLS on 443 is desired,
the user's final policy confirmation, and a GitHub remote/visibility decision.
Nothing in this repository requires real credentials for local review.
