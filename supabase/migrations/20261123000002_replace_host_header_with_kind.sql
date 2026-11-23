-- Replace stored HTTP Host header values (metadata.headers.host) with a kind
-- label (metadata.host_kind), matching sensors/http-collector/collector.py
-- classify_host_header(). For scanners that connect by IP, Host is the
-- sensor's own public address and would identify the honeypot if it leaked;
-- hostnames are attacker-controlled. Neither value is needed for analysis.
-- Idempotent: rows without metadata.headers.host are left untouched.

update public.attack_events
set metadata = jsonb_set(
  metadata #- '{headers,host}',
  '{host_kind}',
  to_jsonb(
    case
      when coalesce(btrim(metadata->'headers'->>'host'), '') = '' then 'absent'
      when btrim(metadata->'headers'->>'host') like '[%' then 'ip_literal'
      when regexp_replace(btrim(metadata->'headers'->>'host'), ':[0-9]{1,5}$', '')
        ~ '^[0-9]{1,3}(\.[0-9]{1,3}){3}$' then 'ip_literal'
      else 'hostname'
    end
  ),
  true
)
where jsonb_typeof(metadata->'headers') = 'object'
  and metadata->'headers' ? 'host';
