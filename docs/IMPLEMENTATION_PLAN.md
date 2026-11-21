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

- [ ] Pick AWS account, region, DNS/domain strategy, and monthly spend cap.
- [ ] Obtain AWS confirmation of the planned *public, responding low-interaction honeypot* on Lightsail,
      OR select the user's previously approved EC2 deployment pattern.
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

- AWS sensor: conditional **Lightsail 2 GiB / 60 GiB / public IPv4, USD 12/month** according
  to published plan pricing; switch to EC2 if AWS approval or operational controls require it.
- Vercel Hobby: free only for eligible personal/noncommercial usage and within limits.
- Supabase Free: 500 MB database, 1 GB Storage (at the referenced date); limits require monitoring.
- LLM token usage, domain, backups/archival, traffic overages: **variable, not included**.
- Do not buy paid infrastructure or deploy a public honeypot until the owner approves the concrete plan.

References: [AWS Lightsail pricing](https://docs.aws.amazon.com/lightsail/latest/userguide/amazon-lightsail-bundles.html),
[Vercel Hobby](https://vercel.com/docs/plans/hobby),
[Supabase quotas](https://supabase.com/docs/guides/platform/billing-on-supabase).

## 5. Delivery boundaries

This repository currently contains **documentation and placeholders only**.
Deployment needs an AWS account/region, service credentials, domain/DNS if TLS on 443 is desired,
the user's final policy confirmation, and a GitHub remote/visibility decision.
Nothing in this repository requires real credentials for local review.
