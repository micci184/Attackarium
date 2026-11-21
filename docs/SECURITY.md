# Security and operations

## Threat model

The sensor is deliberately exposed to hostile traffic. Treat all inbound bytes as untrusted,
including JSON, URLs, headers, SQL strings, protocol banners, HTTP bodies and apparent credentials.
Assume attackers may attempt remote code execution against the decoy itself, denial of service,
outbound pivoting, secret theft and log-poisoning/prompt injection.

## Hard deployment gates

1. **Provider policy:** AWS lists Lightsail among allowed *penetration testing* resources, but that
   is **not conclusive approval** for a public responding honeypot. Obtain explicit AWS guidance
   for this workload or use a previously verified EC2 configuration and validate its restrictions.
2. **Egress:** Lightsail's instance firewall governs inbound traffic; it does **not** restrict
   outbound traffic. Implement host-level egress rules and verify allowlisting by tests.
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
- [AWS Lightsail firewall behavior](https://docs.aws.amazon.com/lightsail/latest/userguide/understanding-firewall-and-port-mappings-in-amazon-lightsail.html)
- [Supabase quotas](https://supabase.com/docs/guides/platform/billing-on-supabase)
- [Supabase production checklist](https://supabase.com/docs/guides/deployment/going-into-prod)
