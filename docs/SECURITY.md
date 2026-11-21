# Security and operations

## Threat model

The sensor is deliberately exposed to hostile traffic. Treat all inbound bytes as untrusted,
including JSON, URLs, headers, SQL strings, protocol banners, HTTP bodies and apparent credentials.
Assume attackers may attempt remote code execution against the decoy itself, denial of service,
outbound pivoting, secret theft and log-poisoning/prompt injection.

## Hard deployment gates

1. **Provider policy & EC2 host:** Sensor hosting uses **AWS EC2** (OpenCanary + dedicated HTTP/HTTPS
   collector). Validate AWS acceptable-use / policy compliance, billing alerts, and explicit spend cap
   before public exposure.
2. **Egress:** Enforce strict outbound (egress) allowlisting at **both** AWS EC2 Security Group / NACL
   and host OS layers (`nftables`/`iptables`); verify allowlisting by automated tests.
3. **Management:** dedicated non-decoy management path/port, key-based access, no password login,
   management source allowlist; maintain a recovery procedure that cannot be publicly abused.
4. **Privilege:** run decoys as unprivileged accounts with only necessary bind-port capabilities;
   isolate processes and limit filesystem access; do not mount AWS credentials.
5. **Network isolation:** no private VPC connections to production workloads, home network, or
   protected services. No broad access to cloud metadata endpoints.
6. **Payload handling:** hard limits on headers/body sizes, request timeout and local spool;
   never execute, redirect or dynamically fetch attacker input. Protect against parser bugs.
7. **Ingest:** signed batches, unique event IDs, timestamp/nonce anti-replay, per-sensor rate limits,
   schema validation and maximum batch size. Rotate each sensor key independently.
8. **Public data:** database default-deny RLS; only safe projections are exposed. Redact source IP,
   credentials, Authorization/Cookie headers and raw payload by default.
9. **LLM safety:** summaries only from sanitized text/data; attack payloads are prompt-injection
   vectors, not authoritative instructions. Do not permit LLM-driven commands, network calls or posting.
10. **Incident response:** abuse contact, cost alerts, sensor shutdown, log and secret rotation plan;
    never run real malware or attacker commands on the sensor.
11. **Remote MCP auth & authz (Vercel Functions + `mcp-handler` + Supabase Auth OAuth 2.1):**
    - Use OAuth 2.1 Authorization Code + PKCE and expose required OAuth discovery metadata.
    - Verify JWT/access token signature, issuer (`iss`), audience (`aud`), expiry (`exp`), and scopes.
    - Enforce all 5 gates server-side: (1) Google/GitHub sign-in, (2) Terms acceptance, (3) active account,
      (4) explicit MCP entitlement (`authenticated != entitled`), (5) OAuth client consent.
    - Reflect account suspension or entitlement revocation on subsequent MCP calls without relying on
      stale client state.
    - Keep MCP strictly **read-only** (no DB writes, deletes, or admin tools) and apply per-user rate limits.
    - Never log user prompts/questions or auth tokens; store aggregated usage metrics only.
12. **Operator-only Admin Console & APIs:**
    - Default-deny for all non-operator users; never rely on a DB `is_admin` flag alone.
    - Require server-side operator user ID allowlist (`ADMIN_ALLOWED_USER_IDS`), mandatory MFA (`aal2`),
      server-side authorization on every admin API route, and append-only audit logs.
    - MCP Usage analytics are strictly admin-only; never expose usage count dashboards to general users.
    - Optional additional edge protection (e.g., Cloudflare Access) may be layered in front of admin routes.
13. **Data minimization & anti-tampering:**
    - Do not collect custom profile PII (name/address/phone) or copy Supabase Auth user tables.
    - Combine leak prevention (RLS, redaction, minimal storage) with anti-tampering (strict write paths,
      HMAC/OAuth verification, append-only audit logs).

## Operational monitoring

| Signal | Alert condition (proposed) | Response |
| --- | --- | --- |
| Sensor heartbeat | No heartbeat after configured interval | Check host; label dashboard coverage gap |
| Spool utilization | > 70% of local cap | Investigate ingest errors / throttle capture |
| DB disk/quotas | > 70% of intended budget | Reduce retention, export, or upgrade |
| Abnormal egress | Any outbound connection outside allowlist | Block, inspect, rotate credentials |
| Ingest rejects | Sustained signatures/429/schema failures | Investigate key abuse or format regression |
| HTTP body sampling | Max size crossed | Truncate and mark metadata; never unbounded buffer |

## Publication ethics

- Do not reveal passwords, session tokens, complete private IP/user identifiers or entire attack payloads.
- Label origin by approximate region/ASN cautiously; IP-derived country can be inaccurate.
- Clearly say that a honeypot measures **attempts observed on this sensor**, not successful exploitation.
- Do not automatically name or accuse source IP owners as attackers.
- Show sensor outages/collection gaps to prevent misleading trends.

## Primary references

- [AWS penetration testing policy](https://aws.amazon.com/security/penetration-testing/)
- [Amazon EC2 security groups](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-security-groups.html)
- [Supabase quotas](https://supabase.com/docs/guides/platform/billing-on-supabase)
- [Supabase production checklist](https://supabase.com/docs/guides/deployment/going-into-prod)
- [Supabase Auth OAuth 2.1 for MCP](https://supabase.com/docs/guides/auth/oauth-server/mcp-authentication)
- [Vercel MCP servers (`mcp-handler`)](https://vercel.com/docs/mcp/deploy-mcp-servers-to-vercel)
