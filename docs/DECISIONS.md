# Architecture decision record

Working decisions (2026-11-21, JST). These can change as implementation evidence emerges.

| ADR | Decision | Rationale | Caveat |
| --- | --- | --- | --- |
| 001 | OpenCanary over T-Pot as baseline | Lightweight multi-protocol decoys; avoids Elasticsearch/Kibana footprint | Does not deeply emulate Web exploits |
| 002 | Separate HTTP collector for 80/443 | Captures actual Web request details beyond decoy login attempts | Strict size/parser/time limits and non-executing behavior |
| 003 | Postgres in Supabase | Historical data, joins and rollups; supports serverless ingestion and cron | Free 500 MB DB; backups/quotas need planning |
| 004 | Next.js on Vercel | Separate public UI, independent sensor security boundary | Hobby only if noncommercial/fair-use eligible |
| 005 | One AWS sensor at MVP | Lowest complexity; prove pipeline before multi-location rollout | Single IP yields geographically/protocol-biased data |
| 006 | AWS EC2 for sensor host | Confirmed deployment pattern with VPC Security Groups + host OS egress controls | Requires explicit spend cap, billing alerts, and AWS policy compliance |
| 007 | HMAC ingest + local spool | No DB admin key on hostile sensor; tolerate connectivity failure | Key rotation and request-rate limiting required |
| 008 | Deterministic rules before AI | Makes CVE associations traceable and testable | AI explanation is not evidence of exploit success |
| 009 | Human review before X | Limits false alarms, sensitive-data leaks and unsourced assertions | Posting automation postponed |
| 010 | No Kafka/Timescale/Kibana for MVP | Postgres aggregates and batched ingestion suffice until measured otherwise | Reevaluate when actual volume requires it |
| 011 | Remote MCP on Vercel Functions (`mcp-handler`) | Official Streamable HTTP support; shares read-only data layer with Next.js without Cloudflare Workers | Must stay strictly read-only with per-user rate limits |
| 012 | Supabase Auth OAuth 2.1 + PKCE for MCP | Avoids building a separate user system; Google/GitHub login + OAuth consent | Authentication != MCP entitlement; enforce 5 gates server-side (Terms, active account, entitlement, consent) |
| 013 | Operator-only Admin Console & Admin-only MCP Usage | Minimizes blast radius; general users do not get usage count dashboards | Default-deny, server-side admin ID allowlist (never `is_admin` alone), mandatory MFA, audit logs; Cloudflare Access optional later |
| 014 | Strict data minimization & anti-tampering | Limits impact even if DB leaks: no custom profile PII, no Auth duplication, no MCP prompt/token logging | Google/GitHub OAuth stores email inside Supabase Auth; zero-PII cannot be guaranteed |

## Open decisions before infrastructure deployment

- Project name and final GitHub organization/user, visibility (private/public), license.
- AWS EC2 region, instance size, spend cap, and abuse-response contact.
- Domains for public website, Remote MCP endpoint, and optional HTTPS sensor hostname.
- Explicit spending cap and paid-tier upgrade threshold.
- Privacy and retention policy for private IP addresses and raw samples.
- Whether to layer Cloudflare Access in front of the operator-only Admin Console.
- X manual workflow vs eventual X API publication permissions and API costs.
