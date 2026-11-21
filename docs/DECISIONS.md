# Architecture decision record

Working decisions (2026-11-21, JST). These can change as implementation evidence emerges.

| ADR | Decision | Rationale | Caveat |
| --- | --- | --- | --- |
| 001 | OpenCanary over T-Pot as baseline | Lightweight multi-protocol decoys; avoids Elasticsearch/Kibana footprint | Does not deeply emulate Web exploits |
| 002 | Separate HTTP collector for 80/443 | Captures actual Web request details beyond decoy login attempts | Strict size/parser/time limits and non-executing behavior |
| 003 | Postgres in Supabase | Historical data, joins and rollups; supports serverless ingestion and cron | Free 500 MB DB; backups/quotas need planning |
| 004 | Next.js on Vercel | Separate public UI, independent sensor security boundary | Hobby only if noncommercial/fair-use eligible |
| 005 | One AWS sensor at MVP | Lowest complexity; prove pipeline before multi-location rollout | Single IP yields geographically/protocol-biased data |
| 006 | Lightsail is conditional | Low fixed-price starting option | Obtain service-use clarification before public OpenCanary; use verified EC2 pattern otherwise |
| 007 | HMAC ingest + local spool | No DB admin key on hostile sensor; tolerate connectivity failure | Key rotation and request-rate limiting required |
| 008 | Deterministic rules before AI | Makes CVE associations traceable and testable | AI explanation is not evidence of exploit success |
| 009 | Human review before X | Limits false alarms, sensitive-data leaks and unsourced assertions | Posting automation postponed |
| 010 | No Kafka/Timescale/Kibana for MVP | Postgres aggregates and batched ingestion suffice until measured otherwise | Reevaluate when actual volume requires it |

## Open decisions before infrastructure deployment

- Project name and final GitHub organization/user, visibility (private/public), license.
- AWS account, region, public honeypot policy confirmation, Lightsail vs already-approved EC2.
- Domains for public website and optional HTTPS sensor hostname.
- Explicit spending cap and paid-tier upgrade threshold.
- Privacy and retention policy for private IP addresses and raw samples.
- X manual workflow vs eventual X API publication permissions and API costs.
