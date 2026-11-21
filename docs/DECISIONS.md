# Architecture decision record

Working decisions (updated 2026-11-21, JST). Existing decisions are preserved
and revised transparently as project requirements evolve.

| ADR | Decision | Rationale | Caveat |
| --- | --- | --- | --- |
| 001 | OpenCanary over T-Pot as baseline | Lightweight multi-protocol decoys; avoids Elasticsearch/Kibana footprint | Does not deeply emulate Web exploits |
| 002 | Separate HTTP collector for 80/443 | Captures actual Web request details beyond decoy login attempts | Strict size/concurrency/time limits and non-executing behavior |
| 003 | Postgres in Supabase | Historical data, joins, rollups, RLS; supports serverless ingestion and cron | Free 500 MB DB; retention and backups need monitoring |
| 004 | Next.js on Vercel | Public dashboard without login; independent sensor security boundary | Hobby only if noncommercial/fair-use eligible |
| 005 | Single operator-managed AWS sensor at MVP | Lowest complexity; prove 30-day pipeline before multi-location expansion | Single IP yields geographically/protocol-biased data |
| 006 | **AWS EC2 formally selected** for sensor host (Lightsail evaluation closed) | Confirmed EC2 terms; VPC Security Group inbound/outbound control combined with host OS firewall provides layered isolation; hosts OpenCanary + HTTP/HTTPS collector on one VM; IaC-friendly for future scaling | Keep sensor application code cloud-agnostic; do not provision or expose AWS resources until Phase 0 operational items are finalized and explicitly approved |
| 007 | HMAC ingest + atomic RPC + local SQLite spool | No DB admin key on hostile sensor; survives ingest outages without silent loss within spool cap | Requires per-sensor key rotation, streaming body caps, and gateway rate limits |
| 008 | Deterministic rules before AI | Makes CVE associations traceable and testable with rule/evidence/confidence | AI explanation is not evidence of exploit success |
| 009 | Human review before X | Limits false alarms, sensitive-data leaks, and unsourced assertions | Automated X posting is permanently out of MVP scope |
| 010 | No Kafka/Timescale/Kibana/SIEM for MVP | Postgres hourly/daily rollups and batched ingestion suffice until measured otherwise | Reevaluate only when real volume requires it |
| 011 | Remote MCP on Vercel Functions (`mcp-handler`) | Official Streamable HTTP support; shares read-only data layer with Next.js without Cloudflare Workers | Strictly read-only with per-user rate limits |
| 012 | Supabase Auth OAuth 2.1 + PKCE for MCP | Avoids building a separate user system; Google/GitHub login + OAuth consent | Authentication != MCP entitlement; enforce all 5 gates server-side on every request for immediate revocation |
| 013 | Operator-only Admin Console & Admin-only MCP Usage | Minimizes blast radius; general users never see usage count dashboards | Default-deny, server-side `ADMIN_ALLOWED_USER_IDS` allowlist (never `is_admin` alone or frontend-only hiding), mandatory MFA (`aal2`), append-only audit logs |
| 014 | Strict data minimization & anti-tampering | Limits impact even if DB leaks: no custom profile PII, no Auth duplication, no plaintext source IP or raw payload in Supabase, no MCP prompt/token logging | Google/GitHub OAuth stores account email inside Supabase Auth; do not promise "zero personal data". `src_ip_hash` is kept only as a secret-salted HMAC (ADR-022) |
| 015 | Operator-managed sensors only (no Swarm/user-contributed sensors) | Keeps trust boundary, abuse accountability, and data quality controllable | Single-operator coverage bias must be clearly disclosed in UI and reports |
| 016 | No general-purpose public REST API; initial Remote MCP limited to 3 read-only tools | Minimizes abuse surface and focuses Phase 2 on core analytical queries (`get_attack_trends`, `get_attack_patterns`, `get_observation_summary` with filters) | Internal endpoints are limited to MCP, auth, and sensor ingest; additional MCP tools or authenticated exports are Post-MVP |
| 017 | Two-phase MVP prioritized on 30-day stable collection + honest value evaluation | Proves real observational value before investing in advanced analytics; avoids arbitrary event-count vanity metrics | If 30 days of data show few notable events, report that accurately |
| 018 | Initial sensor region is **US East (N. Virginia), `us-east-1`** | Owner selected N. Virginia for the first operator-managed EC2 sensor | Single region only at MVP. Price the host with `us-east-1` list prices. Public pages must say the sensor is in N. Virginia and is not a global sample |
| 019 | One existing-account EC2 host: `t3a.small`, standard CPU credits, Ubuntu Server LTS, encrypted gp3 20 GiB, one public IPv4 | Smallest shape that runs OpenCanary, the HTTP collector, and the shipper together without extra AWS services | Standard credits throttle at the 20% baseline instead of billing surplus. Do not attach IAM credentials. No VPC peering to other workloads. Provisioning still needs explicit approval |
| 020 | Monthly budget target **40 USD**, one AWS Budget, email at 50/80/100%, shared cost-allocation tags | Separates Attackarium spend from the rest of the existing account without a second account or a custom billing system | AWS Budgets notifies. It does not stop EC2 or cap the bill. No extra monitoring product and no auto-shutdown Lambda |
| 021 | Abuse contact is the existing AWS account contact. Emergency response is the manual runbook | Avoids a dedicated mailbox, ticketing system, and responder Lambda | Stop the instance. Do not terminate it during investigation. See `docs/RUNBOOK.md` |
| 022 | Supabase stores sanitized events only. No raw source IP, raw HTTP body, password, or `Authorization`/`Cookie` value. No AWS S3 and no raw-payload bucket | Shrinks the data that a database leak can expose while keeping dedup, retries, and pattern analysis | `src_ip_hash` stays so unique-source counts work. The hash is not public. Country/ASN are stored only as derived labels. The sensor spool may hold a source IP until delivery or 24 hours because the hash salt stays off the host |
| 023 | Retention: no raw IP or payload in Supabase; EC2 raw logs ≤ 24 hours; sanitized events ≥ 30 days; daily aggregates ≥ 1 year | Keeps the 30-day observation goal and long trends inside Postgres | If the database nears its quota, shorten detailed events before aggregates, and do not go below 30 days without a new decision. No TimescaleDB or Elasticsearch |
| 024 | MIT License for Attackarium source code. The public GitHub repository stays public | Matches a noncommercial observatory that publishes its own code | MIT does not cover observation data, third-party CVE/KEV/EPSS feeds, credentials, or raw logs. Those follow their own terms and stay out of Git |

## Remaining gate before infrastructure deployment

Phase 0 policy choices above are decided. The remaining gate is **explicit owner
approval to create AWS resources and expose the honeypot**. That approval is not
granted by this decision log. Use the existing AWS account. Do not create a new
one. Do not purchase or apply infrastructure from this change.
