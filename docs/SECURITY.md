# Security and operations

## Threat model

The sensor is deliberately exposed to hostile traffic. Treat all inbound bytes as untrusted,
including JSON, URLs, headers, SQL strings, protocol banners, HTTP bodies, and apparent credentials.
Assume attackers may attempt remote code execution against the decoy itself, denial of service,
outbound pivoting, secret theft, and log-poisoning/prompt injection.

## Hard deployment gates

1. **Provider policy & AWS EC2 host (formally selected):** Sensor hosting uses **AWS EC2**
   (Lightsail evaluation is closed) running OpenCanary + dedicated HTTP/HTTPS collector on one
   isolated VM in **US East (N. Virginia), `us-east-1`** (ADR-018, ADR-019): `t3a.small`,
   standard CPU credits, Ubuntu Server LTS, encrypted gp3 20 GiB, one public IPv4, on the
   existing AWS account. Tag resources so Attackarium spend can be separated. One AWS Budget
   emails at 50/80/100% of the **40 USD** monthly target. **AWS Budgets does not stop the
   instance or enforce the cap.** Abuse mail goes to the existing AWS account contact.
   Emergency action is the manual procedure in `docs/RUNBOOK.md` (stop, do not terminate).
   Obtain explicit owner approval before provisioning or exposing resources.
2. **Layered Egress Isolation:** Enforce strict outbound (egress) allowlisting at **both**
   AWS EC2 Security Group / NACL and host OS firewall (`nftables`/`iptables`) layers; verify
   egress blocking with automated tests before public exposure.
3. **Management:** dedicated non-decoy management path/port, key-based SSH only, no password login,
   management source allowlist, and an emergency teardown procedure that cannot be publicly abused.
4. **Privilege:** run decoys and collectors as unprivileged accounts with only necessary bind-port
   capabilities (`CAP_NET_BIND_SERVICE`); isolate processes, limit filesystem/memory/tasks, and
   do **not** attach IAM roles or mount AWS credentials on the sensor host.
5. **Network isolation:** no private VPC peering/connections to production workloads, home networks,
   or protected services. Block/restrict access to cloud metadata endpoints (`IMDSv2` hop limit / firewall).
6. **Payload handling:** hard limits on headers, path, body size, concurrent connections, request
   timeout, and local spool; never execute, redirect, or dynamically fetch attacker input.
7. **Ingest:** signed HTTPS batches, unique event IDs, streaming body size cap, timestamp/nonce
   anti-replay, atomic per-sensor rate limits, uniform anti-enumeration auth errors, strict schema
   validation, and maximum batch size. Rotate each sensor key independently.
8. **Public data & honest coverage:** database default-deny RLS (`anon` and `authenticated` denied
   on all base tables); only `security_barrier = true` sanitized projections are exposed. Never
   persist plaintext `src_ip` or raw HTTP bodies, redact credentials/Authorization/Cookie/Referer
   query secrets, and distinguish **zero observed events** from **collection outages**.
9. **LLM safety:** summaries only from sanitized aggregates and redacted evidence; attack payloads
   are prompt-injection vectors, not authoritative instructions. Never permit LLM-driven commands,
   network calls, unsupported exploit assertions, or automated X posting.
10. **Incident response:** abuse contact, AWS Budgets/cost alerts, sensor shutdown runbook, and
    log/secret rotation plan; never run real malware or attacker commands on the sensor.
11. **Remote MCP auth & authz (Vercel Functions + `mcp-handler` + Supabase Auth OAuth 2.1):**
    - Use OAuth 2.1 Authorization Code + PKCE and publish RFC 9728 OAuth Protected Resource Metadata.
    - Verify JWT/access token signature (JWKS), issuer (`iss`), audience (`aud`), expiry (`exp`), and scopes.
    - Enforce all 5 gates server-side on every request: (1) Google/GitHub sign-in, (2) current Terms
      acceptance, (3) active account (`is_suspended = false`), (4) explicit MCP entitlement
      (`authenticated != entitled`), (5) OAuth client consent/scope.
    - Reflect account suspension or entitlement revocation immediately on the next MCP call via live
      server-side DB verification (never rely on stale client or JWT state alone).
    - Keep MCP strictly **read-only**, initially limited to 3 tools (`get_attack_trends`,
      `get_attack_patterns`, `get_observation_summary`), with per-user rate limits. Never expose raw
      logs, secrets, DB writes, admin tools, or a general-purpose public REST API.
    - Never log user prompts/questions or auth tokens; store aggregated usage metrics only.
12. **Operator-only Admin Console & APIs:**
    - Default-deny for all non-operator users; never rely on a DB `is_admin` flag alone or
      frontend-only hiding.
    - Require server-side operator user ID allowlist (`ADMIN_ALLOWED_USER_IDS`), mandatory MFA (`aal2`),
      server-side authorization on every admin API route, and append-only audit logs.
    - MCP Usage analytics are strictly admin-only; never expose usage count dashboards to general users.
    - Optional additional edge protection (e.g., Cloudflare Access) may be layered in front of admin routes.
13. **Data minimization & anti-tampering:**
    - Do not collect custom profile PII (name/address/phone) or copy Supabase Auth user tables.
    - Do not store raw source IPs, raw HTTP payloads, passwords, or `Authorization`/`Cookie`
      values in Supabase. Keep `src_ip_hash` as a non-public keyed HMAC (ADR-022).
    - Delete EC2 raw logs within 24 hours. Keep sanitized events at least 30 days and
      daily aggregates at least 1 year (ADR-023).
    - Combine leak prevention (RLS, `security_barrier` views, redaction, minimal storage) with
      anti-tampering (atomic write paths, HMAC/OAuth verification, append-only audit logs).

## Operational monitoring

| Signal | Alert condition (proposed) | Response |
| --- | --- | --- |
| Sensor heartbeat | No heartbeat after 15 minutes | Check EC2 host; mark sensor `stale`/`offline` and show coverage gap |
| Spool utilization | > 70% of local cap | Investigate ingest errors / throttle capture |
| DB disk/quotas | > 70% of intended budget | Tighten configurable detailed-event retention, export, or upgrade |
| AWS monthly spend | AWS Budgets threshold (e.g., 50% / 80% / 100%) | Review traffic/egress; shut down EC2 sensor if cap approached |
| Abnormal egress | Any outbound connection outside allowlist | Block, inspect, rotate sensor credentials |
| Ingest rejects | Sustained 401/413/429/400 failures | Investigate key abuse, gateway throttling, or format regression |
| HTTP body sampling | Max size crossed or concurrency shed (503) | Truncate/shed cleanly; never unbounded buffer |

## Publication ethics

- Do not reveal passwords, session tokens, plaintext source IPs, user identifiers, or raw attack payloads.
- Label origin by approximate region/ASN cautiously; IP-derived country can be inaccurate.
- Clearly state that Attackarium measures **unsolicited attempts observed on operator-managed sensors**,
  not confirmed exploitation or global Internet attack volume.
- Do not automatically name or accuse source IP owners as attackers.
- Explicitly separate zero-observation periods from sensor outages/collection gaps.

## Primary references

- [AWS penetration testing policy](https://aws.amazon.com/security/penetration-testing/)
- [Amazon EC2 security groups](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-security-groups.html)
- [Supabase quotas](https://supabase.com/docs/guides/platform/billing-on-supabase)
- [Supabase production checklist](https://supabase.com/docs/guides/deployment/going-into-prod)
- [Supabase Auth OAuth 2.1 for MCP](https://supabase.com/docs/guides/auth/oauth-server/mcp-authentication)
- [Vercel MCP servers (`mcp-handler`)](https://vercel.com/docs/mcp/deploy-mcp-servers-to-vercel)
