# Implementation plan (MVP)

Last reviewed: 2026-11-21 (JST). Status: **Phase 1 foundation is on `main` (PR #31). No cloud resources or public honeypot are deployed yet. Initial AWS region is `us-east-1` (N. Virginia).**

## 1. Product definition and primary goal

**Attackarium** is a noncommercial threat-observability service that collects real
unsolicited Internet probes and attack attempts on **operator-managed honeypots**,
stores historical observations over time, and publishes sanitized trends via a
login-free public web dashboard and an authenticated, read-only Remote MCP server.

**Attackarium is not a vulnerability database.** Original observation telemetry is
the primary dataset; CVE, CISA KEV, and FIRST EPSS provide supporting context to
interpret observed patterns without claiming confirmed exploitation.

**Primary MVP goal:** Reliably collect, store, and explain original attack
observations for **at least 30 consecutive days** on an isolated **AWS EC2** sensor
host (`OpenCanary` + minimal HTTP/HTTPS collector + Supabase + Vercel + Remote MCP).

## 2. Implementation phases

### Phase 0 — Policy and pre-deployment gate

Required operational decisions before provisioning AWS resources or exposing a live
sensor (these do not block local development, documentation, or Issue organization;
**IP/payload retention policy must be finalized before production DB persistence**):

- [x] Confirm AWS region: **US East (N. Virginia), `us-east-1`** (ADR-018). AWS EC2 is formally selected; Lightsail evaluation is closed. Use the existing AWS account.
- [x] Confirm host shape in `us-east-1`: `t3a.small` (2 vCPU / 2 GiB), **standard** CPU credits, Ubuntu Server LTS, encrypted gp3 **20 GiB**, one public IPv4, one sensor (ADR-019).
- [x] Confirm monthly budget target **40 USD**, one AWS Budget with email at 50/80/100%, and shared cost-allocation tags (ADR-020). Budgets do not stop spend.
- [x] Confirm abuse handling uses the existing AWS account contact, and emergency response is the manual runbook in `docs/RUNBOOK.md` (ADR-021).
- [x] Finalize retention: no raw IP or raw payload in Supabase; EC2 raw logs within 24 hours; sanitized events at least 30 days; daily aggregates at least 1 year (ADR-022, ADR-023).
- [x] Select MIT for Attackarium source code only (ADR-024).
- [ ] Owner explicitly approves AWS provisioning and public sensor exposure.

**Done when:** the policy items above are documented and the owner explicitly
approves AWS provisioning and public sensor exposure. Policy documentation alone
does not authorize resource creation.

### Phase 1 — Observation Platform MVP (Top Priority: 30-Day Stable Collection)

Implementation scope:

1. OpenCanary multi-protocol decoys (`22/SSH`, `23/Telnet`, `21/FTP`, `3306/MySQL`, `6379/Redis`; HTTP/HTTPS decoys disabled).
2. Minimal, non-executing HTTP/HTTPS collector (`80`/`443` exclusive ownership, strict header/path/body/concurrency/timeout caps).
3. Authenticated (HMAC), streaming-bounded, replay-resistant, rate-limited, idempotent event ingestion (`supabase/functions/ingest` + atomic `commit_ingest_batch` RPC).
4. Bounded local SQLite spool + shipper with retry/backoff, poison-pill isolation, and cloud-agnostic application code.
5. Isolated AWS EC2 sensor provisioning via IaC with layered egress allowlisting (EC2 Security Group + host OS `nftables`/`iptables`).
6. Supabase PostgreSQL historical storage with default-deny RLS, `security_barrier` public views, hourly/daily rollups, observed patterns, sensor outage tracking, and configurable detailed-event retention.
7. Login-free public Next.js dashboard showing:
   - Last 24h event count, recent/day-over-day changes, and 30-day time-series trends
   - Protocol breakdown, observed attack patterns, and representative sanitized HTTP paths
   - Observation window, last updated timestamp, sensor health/freshness, observation caveats, and **explicit distinction between zero observed events and collection outages**
   - Minimal event explorer filtering (advanced search deferred to Post-MVP) and core accessibility/responsive/loading/error/empty states.

**Done when:**
- External events arriving at the sensor are durably stored in Supabase.
- Under normal operation, new observations appear on the public dashboard within ~60 seconds.
- Re-sending the same event never creates duplicate DB rows or inflated counts.
- During temporary ingest outages, no events are silently lost within the configured local spool cap.
- Unauthorized users (`anon` / `authenticated`) cannot read private tables or execute privileged RPCs.
- 30 days of historical telemetry are inspectable as time-series trends.
- Zero-observation periods are clearly distinguishable from sensor outage / collection gaps.

### Phase 2 — Public Service MVP

Implementation scope:

1. **Basic CVE / CISA KEV / FIRST EPSS context:** Daily KEV and EPSS feeds, versioned deterministic detection rules with recorded evidence/confidence/source metadata, on-demand cached NVD lookup for candidate CVEs only, and clear UI disclaimers avoiding confirmed-exploit claims.
2. **Authenticated Read-Only Remote MCP (Vercel Functions + `mcp-handler`, Streamable HTTP):**
   - Supabase Auth OAuth 2.1 Authorization Code + PKCE (Google/GitHub login) + RFC 9728 discovery metadata.
   - Server-side enforcement of all 5 gates on every request (login, current Terms acceptance, active account, explicit MCP entitlement, OAuth consent/scope) with immediate revocation and per-user rate limits.
   - Strictly limited to **3 read-only tools** (with period/protocol filters):
     - `get_attack_trends`
     - `get_attack_patterns`
     - `get_observation_summary`
   - No raw logs, no secrets, no DB writes, no admin actions, and no general-purpose public REST API.
   - General-user `/mcp` page for connection guide, tool catalog, and Terms/consent management (no usage count dashboard).
3. **Operator-Only Admin Console & MCP Usage:**
   - Default-deny, server-side `ADMIN_ALLOWED_USER_IDS` allowlist (never frontend-only hiding or DB `is_admin` alone), mandatory MFA (`aal2`), server-side API authorization, and append-only `admin_audit_logs`.
   - Admin-only `mcp_usage_buckets` analytics separating `initialize` vs `tool_call` with zero prompt or token logging.
4. **AI Daily Analysis & X Post Drafts:**
   - Generate draft daily summaries strictly from sanitized aggregates and redacted evidence with explicit observability caveats.
   - Mandatory human review (`draft` → `reviewed`/`rejected` → `published`) and exportable X draft text; never auto-post.

**Done when:**
- Observations can be explained with explicit evidence and scope caveats.
- Every CVE association displays confidence, matched rule, and source metadata without claiming confirmed exploitation.
- Entitled MCP users can query aggregated data via the 3 read-only tools; unentitled, unaccepted, suspended, or revoked users are immediately denied.
- General users cannot access or view any admin function or MCP Usage analytics.
- AI drafts stay grounded in observed facts and X posts require explicit human approval.

### Evaluation — 30-Day Value Validation

After 30 days of continuous Phase 1 collection (and Phase 2 completion), evaluate honestly:

1. What probe and attack attempts were actually observed?
2. Were there meaningful day-over-day or week-over-week shifts?
3. Did specific attack patterns rise or decline?
4. Could observed events be credibly explained alongside external CVE/KEV/EPSS context?
5. Did the public web dashboard surface useful findings?
6. Did Remote MCP improve the analytical workflow?

If few notable attacks were observed, report that accurately. Do **not** set
arbitrary event-count or finding-count success targets.

## 3. Explicit non-goals (out of MVP scope)

- User-contributed sensors (GreyNoise Project Swarm model)
- General-purpose public REST APIs (only MCP, auth, and sensor ingest endpoints are permitted)
- T-Pot, Elasticsearch, Kibana, Kafka, or full SIEM platforms
- Multi-region sensor rollout
- Executing attacker code or running malware sandboxes
- Mirroring the full CVE database
- Fully automated X posting without human approval
- Commercialization or billing features
- Post-MVP enhancements tracked separately: advanced explorer search, dark mode toggle, statistical anomaly detection, advanced Threat Intelligence comparisons, multi-sensor campaign analysis, additional MCP tools, and authenticated non-public CSV export.

## 4. Initial cost plan

- **AWS EC2 sensor (`us-east-1` list prices, 730 hours, excluding tax and data transfer):** `t3a.small` Linux on-demand about **$0.0188/hour ($13.72)**, encrypted gp3 20 GiB at **$0.08/GB-month ($1.60)** with included 3,000 IOPS and 125 MB/s, one in-use public IPv4 at **$0.005/hour ($3.65)**. Fixed list-price subtotal is about **$19** before egress. Standard CPU credits throttle at a 20% baseline (24 credits/hour) and do not add surplus-credit charges. Recheck the AWS price list before provisioning. The **40 USD** budget leaves room for egress and tax. AWS Budgets emails at 50/80/100% and does not stop the instance.
- **Vercel Hobby:** Free only for eligible personal/noncommercial usage within platform limits (hosts Next.js public dashboard, Admin Console, and Vercel Functions Remote MCP).
- **Supabase Free:** 500 MB database, 1 GB storage, Supabase Auth (monitor quotas and tune configurable retention).
- **Variable / excluded:** LLM API tokens, custom domain, independent offsite backup storage, traffic overages.
- Do not purchase paid infrastructure or deploy a public honeypot until Phase 0 is complete and explicitly approved by the owner.

References: [AWS EC2 pricing](https://aws.amazon.com/ec2/pricing/),
[Vercel Hobby](https://vercel.com/docs/plans/hobby),
[Supabase quotas](https://supabase.com/docs/guides/platform/billing-on-supabase).
