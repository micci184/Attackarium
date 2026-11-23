-- Replace raw OpenCanary command strings (metadata.cmd) with an allowlisted
-- verb and its length, matching sensors/shipper/shipper.py sanitize_command().
-- Attacker-supplied command text must never persist in Supabase.
-- Legacy values were truncated to 256 characters by the old shipper, so
-- cmd_length for these rows is capped at 256.
-- Idempotent: rows without metadata.cmd are left untouched.

update public.attack_events
set metadata = (metadata - 'cmd') || jsonb_build_object(
  'cmd_verb',
  case
    when upper((regexp_split_to_array(btrim(metadata->>'cmd', E' \t\r\n'), E'\\s+'))[1]) = any (array[
      'ACL', 'APPEND', 'AUTH', 'BGREWRITEAOF', 'BGSAVE', 'CLIENT', 'CLUSTER',
      'COMMAND', 'CONFIG', 'DBSIZE', 'DEBUG', 'DEL', 'ECHO', 'EVAL', 'EVALSHA',
      'EXEC', 'EXISTS', 'EXPIRE', 'FLUSHALL', 'FLUSHDB', 'GET', 'HELLO',
      'HGETALL', 'HSET', 'INCR', 'INFO', 'KEYS', 'LASTSAVE', 'LPUSH', 'MEMORY',
      'MGET', 'MODULE', 'MONITOR', 'MSET', 'MULTI', 'PING', 'PSYNC', 'PUBLISH',
      'QUIT', 'REPLCONF', 'REPLICAOF', 'RPUSH', 'SAVE', 'SCAN', 'SCRIPT',
      'SELECT', 'SET', 'SETEX', 'SHUTDOWN', 'SLAVEOF', 'SLOWLOG', 'SUBSCRIBE',
      'SYNC', 'TIME', 'TTL', 'TYPE'
    ])
      then upper((regexp_split_to_array(btrim(metadata->>'cmd', E' \t\r\n'), E'\\s+'))[1])
    else 'OTHER'
  end,
  'cmd_length',
  coalesce(char_length(metadata->>'cmd'), 0)
)
where metadata ? 'cmd';
