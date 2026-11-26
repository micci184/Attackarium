-- =============================================================================
-- CVE observation context (#84)
-- =============================================================================
-- 1. Time series of candidate CVEs must follow when the probe was OBSERVED,
--    not when the hourly matcher wrote the row (created_at) or last
--    re-evaluated it (evaluated_at). Both stay for their own purposes; the
--    views add the event's observed_at so re-evaluating old events can never
--    inflate "recent" counts.
-- 2. The public match view also exposes the rule-defined match strength
--    (high/medium/low) and the evidence basis (indicator, matched location)
--    already stored in detections.evidence_redacted, so the UI can show a
--    graded strength and its rationale instead of a probability-looking
--    percentage. The numeric confidence stays as the internal rule score.
-- 3. public_cve_events: public_events plus cve_id, for /events?cve=... with
--    the same filters and pagination as /events. It adds no column beyond
--    public_events and cve_id.
--
-- CREATE OR REPLACE VIEW can only append columns; existing columns and their
-- order are unchanged, and grants are preserved.
-- =============================================================================

create or replace view public.public_event_cve_matches
with (security_barrier = true) as
select
  m.id,
  m.event_id,
  m.cve_id,
  m.detection_id,
  m.match_type,
  m.confidence,
  m.reason,
  m.created_at,
  d.rule_id,
  d.rule_version,
  v.kev_present,
  v.epss_score,
  v.epss_percentile,
  v.epss_date,
  m.evaluated_at,
  e.observed_at,
  case
    when d.evidence_redacted ->> 'match_strength' in ('high', 'medium', 'low')
      then d.evidence_redacted ->> 'match_strength'
    else null
  end as match_strength,
  left(d.evidence_redacted ->> 'indicator', 64) as indicator,
  case
    -- Same vocabulary as the matcher (url, body, header:<safe-name>, redacted).
    when d.evidence_redacted ->> 'matched_location' ~ '^(url|body|redacted|header:[a-z0-9-]{1,48})$'
      then d.evidence_redacted ->> 'matched_location'
    else null
  end as matched_location
from public.event_cve_matches m
inner join public.detections d on d.id = m.detection_id
inner join public.vulnerabilities v on v.cve_id = m.cve_id
inner join public.attack_events e on e.id = m.event_id;

create or replace view public.public_vulnerabilities
with (security_barrier = true) as
select
  v.cve_id,
  v.description,
  v.vendor,
  v.product,
  v.kev_present,
  v.kev_updated_at,
  v.epss_score,
  v.epss_percentile,
  v.epss_date,
  v.source_updated_at,
  count(distinct m.event_id)::integer as matched_event_count,
  max(m.confidence) as max_confidence,
  max(m.created_at) as last_matched_at,
  v.published_at,
  v.cvss_score,
  v.cvss_vector,
  v.kev_added_at,
  max(e.observed_at) as last_observed_at
from public.vulnerabilities v
inner join public.event_cve_matches m on m.cve_id = v.cve_id
inner join public.attack_events e on e.id = m.event_id
group by
  v.cve_id,
  v.description,
  v.vendor,
  v.product,
  v.kev_present,
  v.kev_updated_at,
  v.epss_score,
  v.epss_percentile,
  v.epss_date,
  v.source_updated_at,
  v.published_at,
  v.cvss_score,
  v.cvss_vector,
  v.kev_added_at;

-- One row per (event, candidate CVE); several detections of the same CVE on
-- one event collapse, so counts and pagination match /events.
create or replace view public.public_cve_events
with (security_barrier = true) as
select
  c.cve_id,
  pe.id,
  pe.sensor_id,
  pe.observed_at,
  pe.received_at,
  pe.protocol,
  pe.dst_port,
  pe.event_type,
  pe.src_country,
  pe.src_asn,
  pe.http_method,
  pe.http_path_redacted,
  pe.fingerprint,
  pe.attack_category
from public.public_events pe
inner join (
  select distinct m.event_id, m.cve_id
  from public.event_cve_matches m
) c on c.event_id = pe.id;

revoke all on table public.public_cve_events from public, anon, authenticated;
grant select on table public.public_cve_events to anon, authenticated, service_role;
