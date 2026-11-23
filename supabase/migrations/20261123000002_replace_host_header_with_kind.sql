-- Replace stored HTTP Host header values (metadata.headers.host) with a kind
-- label (metadata.host_kind), matching sensors/http-collector/collector.py
-- classify_host_header(). For scanners that connect by IP, Host is the
-- sensor's own public address and would identify the honeypot if it leaked;
-- hostnames are attacker-controlled. Neither value is needed for analysis.
-- Idempotent: rows without metadata.headers.host are left untouched.

-- The trim set below must equal HOST_TRIM_CHARS in collector.py (every
-- character Python str.isspace() accepts), so legacy values such as U+00A0 or
-- U+0085 get the same label the collector would assign.

with classified as (
  select
    ae.id,
    btrim(ae.metadata->'headers'->>'host', E'\u0009\u000a\u000b\u000c\u000d\u001c\u001d\u001e\u001f\u0020\u0085\u00a0\u1680\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007\u2008\u2009\u200a\u2028\u2029\u202f\u205f\u3000') as host
  from public.attack_events ae
  where jsonb_typeof(ae.metadata->'headers') = 'object'
    and ae.metadata->'headers' ? 'host'
)
update public.attack_events as ae
set metadata = jsonb_set(
  ae.metadata #- '{headers,host}',
  '{host_kind}',
  to_jsonb(
    case
      when coalesce(c.host, '') = '' then 'absent'
      when c.host like '[%' then 'ip_literal'
      when regexp_replace(c.host, ':[0-9]{1,5}$', '') ~ '^[0-9]{1,3}(\.[0-9]{1,3}){3}$' then 'ip_literal'
      else 'hostname'
    end
  ),
  true
)
from classified as c
where ae.id = c.id;
