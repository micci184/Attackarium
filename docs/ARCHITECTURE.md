# Architecture

## 1. Context

This is an experimental, noncommercial **attack-observability** project. The goal is to publish
well-labeled observations and trends, not to prove that a particular CVE was exploited
successfully or to provide a globally representative view of attack traffic.

Initial deployment: **one isolated AWS sensor host**, Supabase for history, Vercel for UI.
Keep components separable so a second region, IP address, or sensor can be added later.

## 2. Component responsibilities

| Component | Responsibility | Placement |
| --- | --- | --- |
| OpenCanary | Low-interaction SSH, Telnet, FTP, MySQL, Redis decoys (final ports/config TBD) | Sensor host |
| HTTP collector | Record bounded HTTP request metadata and selected sanitized payload samples | Same sensor host, separate process |
| Shipper | Read JSONL, normalize, assign stable event IDs, write bounded local durable spool, retry batches with backoff | Sensor host |
| Ingest | Authenticate per-sensor HMAC; validate size/schema/timestamps; rate-limit and deduplicate; insert private events | Supabase Edge Function |
| PostgreSQL | Store events, detections, vulnerability enrichments, rollups, reports | Supabase |
| Background jobs | Pull external feeds; run deterministic rules; aggregate; request AI summary; create review draft | Scheduled server-side jobs |
| Public dashboard | Show safe rollups and curated redacted observations, never raw untrusted payloads | Vercel / Next.js |

## 3. Protocol and port assignment

- OpenCanary: candidate decoys **22/SSH, 23/Telnet, 21/FTP, 3306/MySQL, 6379/Redis**.
- HTTP collector: **80/HTTP, 443/HTTPS** after TLS/DNS is configured.
- **Disable OpenCanary's HTTP and HTTPS decoys** when the dedicated collector owns 80/443.
- Actual administrator SSH: different non-decoy port, key-only, allowlisted and preferably through a private management path.
- Extra protocols (SNMP, MSSQL, VNC, etc.) are optional; enable only if supported, useful, and operationally safe.

OpenCanary's built-in HTTP/HTTPS mainly emulates login pages; it is **not** a general Web exploit
sensor. The HTTP collector must never execute captured requests, fetch attacker-supplied URLs,
follow redirects, or pass payloads to a shell.

## 4. Data path

1. Sensor receives unsolicited inbound traffic and emits a structured local record.
2. Shipper normalizes the record, removes/isolates secrets, attaches sensor ID and source fingerprint,
   then puts it in a disk-capped spool before HTTP transmission.
3. Sender batches events over HTTPS, signing body + timestamp + sensor ID with a sensor-specific key.
4. Ingest rejects invalid signatures, old timestamps, oversize bodies, unexpected fields and excess requests;
   upserts events by a stable unique ID. Replay protection must also persist seen event IDs.
5. Background jobs enrich events with pattern matches, KEV membership, EPSS and CVE metadata.
6. The public Next.js site reads only RLS-protected aggregate views or a read-only projection.
7. AI receives only redacted, aggregated evidence and writes a draft report, not a final assertion.

## 5. External intelligence

| Feed | Usage | Update cadence |
| --- | --- | --- |
| CISA KEV | Whether a CVE is catalogued as known exploited in the wild | Daily |
| FIRST EPSS | Daily estimate that a published CVE will be exploited in the next 30 days | Daily |
| NVD / CVE source | Description, affected products and references for *candidate* CVEs | As needed; cached |
| Optional MITRE ATT&CK | Contextual technique classification, not a vulnerability ID | Later |

Rule match levels:

- `observed`: literal protocol/action/request metadata directly captured.
- `indicator_match`: an explicit signature matched, with versioned rule and evidence.
- `candidate_cve`: a *hypothesis*, not proof of exploitation.

**Never** label a mere URL scan, banner probe or login attempt as confirmed CVE exploitation.
EPSS is a vulnerability-level forecast, not the likelihood that this particular request succeeded.

## 6. Public-facing product

- Overview: today / last 24 hours event volume, monitored protocols, latest sample events, sensor health.
- Live stream: sanitized recent events, polled/aggregated every 15-60 seconds initially; no per-event paid realtime dependency.
- Trends: hour/day, protocol, target port, broad geo/ASN categories, signature categories.
- Event details: sanitized request fields + match evidence and confidence, with raw payload private.
- Vulnerabilities: only candidate CVEs actually linked by supported evidence; show KEV status and EPSS date.
- Daily report: changed patterns, caveats, citation sources, human-reviewed share text.

## 7. Scalability boundaries

MVP uses **PostgreSQL**, not TimescaleDB/Kafka/Elasticsearch. Apply indexes and daily aggregates.
If event write volume grows, partition by time, move cold events to private compressed object storage,
or later upgrade database compute. Avoid shipping all raw records to the public UI.

## 8. Source references (official)

- [OpenCanary service configuration](https://opencanary.readthedocs.io/en/latest/starting/configuration.html)
- [OpenCanary Linux Web Server](https://opencanary.readthedocs.io/en/latest/services/webserver.html)
- [Supabase Cron](https://supabase.com/docs/guides/cron)
- [CISA KEV data](https://github.com/cisagov/kev-data)
- [FIRST EPSS](https://www.first.org/epss/)
- [FIRST EPSS data formats](https://www.first.org/epss/data)
