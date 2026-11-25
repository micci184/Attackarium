# HTTP Collector Signature Detection Coverage & Limitations

Attackarium inspects bounded HTTP request data inside `sensors/http-collector/signatures.py`
**before** raw bodies and non-allowlisted headers are discarded. Every detection is stored
as structured, sanitized metadata under `attack_events.metadata.signature_detections` and
feeds downstream persistence and on-demand NVD caching in `jobs/cve-matching`.

## Design invariants

- **Separation of fact vs. inference:**
  - *Observed indicator*: `matched_location` + `evidence.indicator`
  - *Attack technique candidate*: `classification = "indicator_match"`, `attack_technique`, `candidate_cves = []`
  - *Candidate CVE*: `classification = "candidate_cve"`, `candidate_cves = [...]`
  - *Exploitation outcome*: **Unknown**. Signature matches never claim confirmed exploitation; `confidence` / `match_strength` express rule match strength, not exploitation probability.
- **Separation from NVD / KEV / EPSS:** Signature rules identify candidates solely from observed request patterns. Vulnerability feeds enrich matched CVEs later and never generate detections on their own.
- **Data minimization:** Raw HTTP bodies are never stored. Attacker JNDI expressions, callback URLs (including command-injection `curl`/`wget` URLs), credentials, and sensitive header names (`header:redacted`) are excluded or redacted from stored records.
- **Inspection bounds:**
  - URL path + query: `2048` chars
  - HTTP headers: up to `64` headers, `2048` chars per value (overall header block capped by `max_header_bytes = 8192`)
  - Request body: `CollectorConfig.max_body_bytes` (default `4096` bytes, hard cap `4096`)
  - Normalization: up to `2` URL-decode passes, up to `4` non-recursive Log4j deobfuscation passes
  - Output cap: up to `10` unique detections per event

## Registered rules

| `signature_id` | Version | Classification | `attack_technique` | `candidate_cves` | Observable indicator | Primary reference |
| --- | --- | --- | --- | --- | --- | --- |
| `http-log4shell-jndi-lookup` | `1.1.0` | `candidate_cve` | `jndi_injection` | `CVE-2021-44228` | `${jndi:<scheme>:...}` or obfuscated `${jndi:...}` after bounded URL/Log4j normalization | [NVD CVE-2021-44228](https://nvd.nist.gov/vuln/detail/CVE-2021-44228) |
| `http-apache-path-traversal-cve-2021-41773` | `1.0.0` | `candidate_cve` | `path_traversal` | `CVE-2021-41773`, `CVE-2021-42013` | `/cgi-bin/` or `/icons/` with Apache-style encoded dot traversal (`.%2e`, `%%32%65`, `%252e`) resolving to `../`, `/bin/sh`, or `/etc/passwd` | [NVD CVE-2021-41773](https://nvd.nist.gov/vuln/detail/CVE-2021-41773), [CVE-2021-42013](https://nvd.nist.gov/vuln/detail/CVE-2021-42013) |
| `http-spring4shell-cve-2022-22965` | `1.0.0` | `candidate_cve` | `rce` | `CVE-2022-22965` | `class.module.classLoader.resources.context.parent.pipeline.first.` or `class.module.classLoader` with access-log properties | [NVD CVE-2022-22965](https://nvd.nist.gov/vuln/detail/CVE-2022-22965) |
| `http-php-cgi-arg-injection-cve-2024-4577` | `1.0.0` | `candidate_cve` | `rce` | `CVE-2024-4577` | Soft-hyphen `%ADd` argument injection combined with `allow_url_include` or `auto_prepend_file` | [NVD CVE-2024-4577](https://nvd.nist.gov/vuln/detail/CVE-2024-4577) |
| `http-sqli-attempt` | `1.0.0` | `indicator_match` | `sql_injection` | *(none)* | `UNION [ALL] SELECT` (incl. `/**/` comments), `SLEEP`/`BENCHMARK`/`WAITFOR DELAY`, `INFORMATION_SCHEMA` tables/columns, or boolean tautology `' OR '1'='1'--` | [OWASP SQL Injection](https://owasp.org/www-community/attacks/SQL_Injection) |
| `http-path-traversal-attempt` | `1.0.0` | `indicator_match` | `path_traversal` | *(none)* | 2+ `../`/`..\` segments targeting common system files (`/etc/passwd`, `win.ini`, `/proc/self/`), or 3+ repeated parent-directory segments | [OWASP Path Traversal](https://owasp.org/www-community/attacks/Path_Traversal) |
| `http-cmd-injection-attempt` | `1.0.0` | `indicator_match` | `command_injection` | *(none)* | Shell metacharacter (`;`, `|`, `&&`, `||`, `` ` ``, `$(`) followed by a delimited OS command token (`id`, `uname`, `whoami`, `wget`, `curl`, `sh`, etc.) | [OWASP Command Injection](https://owasp.org/www-community/attacks/Command_Injection) |
| `http-sap-netweaver-cve-2025-31324` | `1.0.0` | `candidate_cve` | `unauthenticated_file_upload` | `CVE-2025-31324` | **URL path only:** `/developmentserver/metadatauploader` (SAP NetWeaver Visual Composer Metadata Uploader). Path-based, so medium strength / 0.7 confidence | [NVD CVE-2025-31324](https://nvd.nist.gov/vuln/detail/CVE-2025-31324) |
| `http-sensitive-file-probe` | `1.0.0` | `indicator_match` | `sensitive_file_discovery` | *(none)* | **URL path only, category-neutral:** `.env*` files, `.git/` / `.svn/` / `.hg/` metadata, credential/state/backup files (`secrets.*`, `credentials.*`, `terraform.tfstate`, `.aws/credentials`, SSH private key names, `.bash_history`, `wp-config` backups) | [OWASP WSTG](https://owasp.org/www-project-web-security-testing-guide/) |
| `http-mcp-endpoint-probe` | `1.0.0` | `indicator_match` | `ai_agent_endpoint_discovery` | *(none)* | **URL path only, category-neutral:** `/mcp`, `/api/mcp`, `/sse` (Model Context Protocol server discovery) | [MCP specification](https://modelcontextprotocol.io/specification) |
| `http-debug-endpoint-probe` | `1.0.0` | `indicator_match` | `information_disclosure` | *(none)* | **URL path only, category-neutral:** Spring Boot `/actuator/*`, `phpinfo` pages, Apache `/server-status` / `/server-info`, framework debug panels (`/debug/default/view`, `/_profiler`, `/telescope`, `/_debugbar`) | [OWASP WSTG](https://owasp.org/www-project-web-security-testing-guide/) |

### Path-only and category-neutral rules

- `SignatureRule.locations=("url",)` restricts a rule to the request path, after
  bounded URL decoding and dropping the absolute-form scheme/host, query, and
  fragment. A `Referer`, `User-Agent`, or body that merely mentions such a path
  never matches.
- `affects_attack_category=False` marks reconnaissance rules. They are recorded in
  `metadata.signature_detections` and persisted as `detections` rows, but the event
  keeps its existing category (`http_path_probe`), so aggregate semantics do not
  change. Candidate-CVE rules must affect the category (`suspected_cve_probe`).
- These rules come from paths observed from multiple sources on the live sensor
  (2026-11-21 to 11-25): `.env*` / `.git/` probes were the most common recurring
  paths, and `/developmentserver/metadatauploader` and `/mcp` probes arrived from
  several sources.

## Persistence

`jobs/cve-matching` reads events categorized `suspected_cve_probe`, `web_attack_attempt`, or `http_path_probe` that carry `signature_detections`. It does not inspect requests again. It accepts a stored detection
only when `signature_id`, `rule_version`, and `evidence.indicator` match the catalog
above. Confidence, summary, technique, and candidate CVEs are copied from that
catalog, not from the stored object. `indicator_match` rules create a `detections`
row and no CVE match. `candidate_cve` rules also create one `event_cve_matches` row
per catalog CVE. NVD metadata is fetched afterwards, one catalog CVE at a time.

## End-to-end verification

`tests/e2e/signature-pipeline.test.ts` (CI job `e2e-signature-pipeline`) runs the
real collector, shipper (spool, HMAC, HTTP delivery), ingest handler, and
`jobs/cve-matching` against synthetic probes on loopback only. It fails if a rule
ID, `rule_version`, or indicator drifts between `sensors/http-collector/signatures.py`
and `jobs/cve-matching/rules.ts`, if `attack_category` or `signature_detections`
is dropped on the way to the database, or if the matching job's event query no
longer selects those events. PostgREST and NVD are stubbed; no external request
is made.

If production shows HTTP events but no `signature_detections`, first confirm that
the deployed collector includes signature detection (added in commit `aa83524`).
Detections apply only to traffic captured after the updated collector is running.

## Known blind spots and limitations

- **Size limits:** Payloads placed beyond `max_body_bytes` (default `4096` bytes) or inside header blocks rejected with `431` (`> 8192` bytes) are intentionally not buffered or inspected.
- **Encoding / compression:** Payloads compressed with gzip/deflate, encoded in Base64, URL-encoded more than twice, or sent via `Transfer-Encoding: chunked` without `Content-Length` are not decoded.
- **Advanced obfuscation:** Deeply nested Log4j lookups (`> 4` passes), `${base64:...}` obfuscation, polyglot SQL without the targeted keywords, or uncommon shell builtins will not match.
- **Historical events:** Previously stored `body_sha256` hashes are one-way; new rules only apply to traffic captured after deployment.
- **False-positive boundaries:** Benign traffic containing exact attack syntax (e.g., security scanner research strings or documentation snippets sent to the honeypot) can still match `indicator_match` rules; because the host is an unadvertised honeypot, benign traffic is rare, and matches are still labeled only as observed indicators or candidate hypotheses.
