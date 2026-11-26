#!/usr/bin/env python3
"""Bounded SQLite spool & HMAC-authenticated batch shipper for Attackarium.

Responsibilities:
- Read structured JSONL from OpenCanary and HTTP collector.
- Normalize into the strict schema expected by supabase/functions/ingest.
- Assign deterministic/stable UUID event IDs for idempotent upsert.
- Persist sanitized events in a bounded local SQLite spool to survive ingest outages.
- Keep source IPs only until delivery or 24 hours, whichever comes first.
- Ship signed HTTPS batches with exponential backoff and retry metrics.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import os
import hmac
import json
import re
import sqlite3
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

EVENT_NAMESPACE_UUID = uuid.UUID("7f3d56f8-3d1d-4d0e-942c-0df9b7489f41")
SPOOL_MAX_AGE_SECONDS = 24 * 60 * 60
SPOOL_ALERT_RATIO = 0.70
SPOOL_ALERT_REPEAT_SECONDS = 300.0
PATCH_STATUS_MAX_BYTES = 4096
def _iso_seconds(value: str) -> str:
    """Normalize an ISO UTC timestamp to 'YYYY-MM-DDTHH:MM:SSZ' (ingest format)."""
    parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    return parsed.astimezone(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


PATCH_TIMESTAMP_RE = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z")
HTTP_METHOD_REGEX = re.compile(r"^[A-Z]{2,16}$")
LOCAL_HTTP_HOSTS = frozenset({"127.0.0.1", "localhost", "::1"})

OPENCANARY_LOGTYPE_MAP: dict[int, tuple[str, str]] = {
    2000: ("ftp", "ftp_login_attempt"),
    4000: ("ssh", "ssh_new_connection"),
    4001: ("ssh", "ssh_remote_version"),
    4002: ("ssh", "ssh_login_attempt"),
    6001: ("telnet", "telnet_login_attempt"),
    8001: ("mysql", "mysql_login_attempt"),
    # OpenCanary LoggerBase.LOG_REDIS_COMMAND. 11001 is NTP monlist, not Redis.
    17001: ("redis", "redis_command_probe"),
}

ALLOWED_PROTOCOLS = frozenset(
    {"ssh", "telnet", "ftp", "mysql", "redis", "http", "https", "other"}
)
ALLOWED_ATTACK_CATEGORIES = frozenset(
    {
        "port_scan",
        "auth_attempt",
        "http_path_probe",
        "web_attack_attempt",
        "suspected_cve_probe",
    }
)


@dataclass(frozen=True)
class ShipperConfig:
    sensor_id: str
    hmac_secret: str
    ingest_url: str
    spool_path: Path
    max_spool_bytes: int = 100 * 1024 * 1024  # 100 MiB default cap
    max_batch_events: int = 50
    max_batch_bytes: int = 200 * 1024
    http_timeout_seconds: float = 10.0
    base_backoff_seconds: float = 1.0
    max_backoff_seconds: float = 60.0
    heartbeat_interval_seconds: float = 300.0
    # Written by infra/aws-sensor/scripts/patch_window.sh after a successful
    # patch window (#94). None disables the operator-only patch status report.
    patch_status_path: Path | None = None
    # Cumulative overload counters written by the HTTP collector (#95). The
    # shipper reports the increase since its last delivered report.
    collector_metrics_path: Path | None = None


@dataclass
class ShipperMetrics:
    enqueued: int = 0
    dropped_spool_full: int = 0
    dropped_invalid: int = 0
    batches_sent: int = 0
    batches_failed: int = 0
    events_delivered: int = 0
    last_error: str | None = None
    last_retry_after_seconds: float | None = None
    last_delivery_at: str | None = None


def validate_ingest_url(url: str) -> str:
    parsed = urllib.parse.urlparse(url)
    scheme = parsed.scheme.lower()
    host = (parsed.hostname or "").lower()
    if scheme == "https" and host:
        return url
    if scheme == "http" and host in LOCAL_HTTP_HOSTS:
        return url
    raise ValueError(
        "ingest_url must use https:// (http:// is allowed only for loopback testing)"
    )


def build_signature_payload(
    sensor_id: str,
    timestamp: str,
    request_id: str,
    raw_body: str,
) -> str:
    return f"{sensor_id}\n{timestamp}\n{request_id}\n{raw_body}"


def compute_hmac_sha256_hex(secret: str, message: str) -> str:
    return hmac.new(
        secret.encode("utf-8"),
        message.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


# Known Redis command verbs. Anything else is recorded as "OTHER" so attacker-
# controlled strings never reach the spool or Supabase. Keep in sync with
# supabase/migrations/20261123000001_sanitize_opencanary_cmd_metadata.sql.
KNOWN_COMMAND_VERBS = frozenset(
    {
        "ACL", "APPEND", "AUTH", "BGREWRITEAOF", "BGSAVE", "CLIENT", "CLUSTER",
        "COMMAND", "CONFIG", "DBSIZE", "DEBUG", "DEL", "ECHO", "EVAL", "EVALSHA",
        "EXEC", "EXISTS", "EXPIRE", "FLUSHALL", "FLUSHDB", "GET", "HELLO",
        "HGETALL", "HSET", "INCR", "INFO", "KEYS", "LASTSAVE", "LPUSH", "MEMORY",
        "MGET", "MODULE", "MONITOR", "MSET", "MULTI", "PING", "PSYNC", "PUBLISH",
        "QUIT", "REPLCONF", "REPLICAOF", "RPUSH", "SAVE", "SCAN", "SCRIPT",
        "SELECT", "SET", "SETEX", "SHUTDOWN", "SLAVEOF", "SLOWLOG", "SUBSCRIBE",
        "SYNC", "TIME", "TTL", "TYPE",
    }
)
MAX_COMMAND_LENGTH_RECORDED = 65535


def sanitize_command(value: Any) -> dict[str, Any]:
    """Reduce an OpenCanary CMD value to an allowlisted verb and its length."""
    if not isinstance(value, (str, int, float, bool)):
        return {"cmd_verb": "OTHER", "cmd_length": 0}
    text = str(value)
    parts = text.strip().split(None, 1)
    verb = parts[0].upper() if parts else ""
    return {
        "cmd_verb": verb if verb in KNOWN_COMMAND_VERBS else "OTHER",
        "cmd_length": min(len(text), MAX_COMMAND_LENGTH_RECORDED),
    }


def normalize_record(raw: dict[str, Any], sensor_id: str) -> dict[str, Any] | None:
    """Normalize either an HTTP collector record or an OpenCanary JSONL record."""
    if not isinstance(raw, dict):
        return None

    # Format A: Attackarium HTTP collector record
    if raw.get("source") == "http_collector":
        protocol = str(raw.get("protocol", "http")).lower()
        if protocol not in ALLOWED_PROTOCOLS:
            protocol = "other"
        dst_port = int(raw.get("dst_port", 80))
        if not (1 <= dst_port <= 65535):
            return None

        raw_id = str(raw.get("id") or "")
        try:
            event_id = str(uuid.UUID(raw_id))
        except ValueError:
            event_id = str(uuid.uuid4())
        observed_at = str(
            raw.get("observed_at")
            or dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")
        )
        event: dict[str, Any] = {
            "id": event_id,
            "observed_at": observed_at,
            "protocol": protocol,
            "dst_port": dst_port,
            "event_type": str(raw.get("event_type", "http_probe"))[:100],
        }
        if raw.get("src_ip"):
            event["src_ip"] = str(raw["src_ip"])
        if raw.get("http_method"):
            candidate_method = str(raw["http_method"]).strip().upper()[:16]
            if HTTP_METHOD_REGEX.match(candidate_method):
                event["http_method"] = candidate_method
        if raw.get("http_path"):
            event["http_path"] = str(raw["http_path"])[:512]
        if raw.get("fingerprint"):
            event["fingerprint"] = str(raw["fingerprint"])[:128]
        if raw.get("attack_category") in ALLOWED_ATTACK_CATEGORIES:
            event["attack_category"] = raw["attack_category"]
        if isinstance(raw.get("metadata"), dict):
            event["metadata"] = raw["metadata"]
        return event

    # Format B: OpenCanary JSONL record
    if "logtype" in raw:
        try:
            logtype = int(raw["logtype"])
        except (TypeError, ValueError):
            return None

        protocol, event_type = OPENCANARY_LOGTYPE_MAP.get(
            logtype, ("other", f"opencanary_{logtype}")
        )
        try:
            dst_port = int(raw.get("dst_port", 0))
        except (TypeError, ValueError):
            dst_port = 0
        if not (1 <= dst_port <= 65535):
            return None

        observed_raw = str(raw.get("utc_time") or raw.get("local_time") or "")
        observed_at = _parse_opencanary_timestamp(observed_raw)
        src_ip = str(raw["src_host"]) if raw.get("src_host") else None

        # Strip credentials (USERNAME/PASSWORD) from OpenCanary logdata before spooling
        safe_meta: dict[str, Any] = {"logtype": logtype}
        logdata = raw.get("logdata")
        if isinstance(logdata, dict):
            for key in ("LOCALVERSION", "REMOTEVERSION", "SESSION"):
                if key in logdata and isinstance(logdata[key], (str, int, float, bool)):
                    safe_meta[key.lower()] = str(logdata[key])[:256]
            # Never persist the raw attacker-supplied command string.
            if "CMD" in logdata:
                safe_meta.update(sanitize_command(logdata["CMD"]))

        # Deterministic UUIDv5 so re-reading the same OpenCanary line is idempotent
        dedupe_seed = json.dumps(
            {
                "sensor_id": sensor_id,
                "logtype": logtype,
                "observed_at": observed_at,
                "src_ip": src_ip,
                "src_port": raw.get("src_port"),
                "dst_port": dst_port,
            },
            sort_keys=True,
        )
        event_id = str(uuid.uuid5(EVENT_NAMESPACE_UUID, dedupe_seed))

        event = {
            "id": event_id,
            "observed_at": observed_at,
            "protocol": protocol,
            "dst_port": dst_port,
            "event_type": event_type,
            "fingerprint": f"oc-{logtype}",
            "metadata": safe_meta,
        }
        if src_ip:
            event["src_ip"] = src_ip
        return event

    return None


def _parse_opencanary_timestamp(raw: str) -> str:
    if raw:
        candidate = raw.strip().replace(" ", "T")
        if not candidate.endswith("Z") and "+" not in candidate:
            candidate += "Z"
        try:
            parsed = dt.datetime.fromisoformat(candidate.replace("Z", "+00:00"))
            return parsed.astimezone(dt.timezone.utc).isoformat().replace("+00:00", "Z")
        except ValueError:
            pass
    return dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")


class BoundedSqliteSpool:
    """Durable, size-bounded local queue backed by SQLite."""

    def __init__(self, db_path: Path, max_bytes: int) -> None:
        self.db_path = db_path
        self.max_bytes = max_bytes
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(str(self.db_path))
        self.conn.execute("PRAGMA journal_mode=WAL;")
        self.conn.execute(
            """
            CREATE TABLE IF NOT EXISTS spool_events (
                seq INTEGER PRIMARY KEY AUTOINCREMENT,
                event_id TEXT NOT NULL UNIQUE,
                payload_json TEXT NOT NULL,
                byte_size INTEGER NOT NULL,
                created_at REAL NOT NULL
            )
            """
        )
        self.conn.execute(
            """
            CREATE TABLE IF NOT EXISTS file_cursors (
                path TEXT PRIMARY KEY,
                inode INTEGER NOT NULL,
                offset INTEGER NOT NULL
            )
            """
        )
        self.conn.commit()

    def get_cursor(self, path: Path) -> tuple[int | None, int]:
        row = self.conn.execute(
            "SELECT inode, offset FROM file_cursors WHERE path = ?",
            (str(path),),
        ).fetchone()
        if not row:
            return None, 0
        return int(row[0]), int(row[1])

    def set_cursor(self, path: Path, inode: int, offset: int) -> None:
        self.conn.execute(
            """
            INSERT INTO file_cursors (path, inode, offset)
            VALUES (?, ?, ?)
            ON CONFLICT(path) DO UPDATE SET inode = excluded.inode, offset = excluded.offset
            """,
            (str(path), inode, offset),
        )
        self.conn.commit()

    def close(self) -> None:
        self.conn.close()

    def total_bytes(self) -> int:
        row = self.conn.execute(
            "SELECT COALESCE(SUM(byte_size), 0) FROM spool_events"
        ).fetchone()
        return int(row[0]) if row else 0

    def count(self) -> int:
        row = self.conn.execute("SELECT COUNT(*) FROM spool_events").fetchone()
        return int(row[0]) if row else 0

    def purge_expired(self, now: float | None = None, max_age_seconds: float = SPOOL_MAX_AGE_SECONDS) -> int:
        """Drop undelivered rows, including any transient source IPs, after max_age_seconds."""
        cutoff = (time.time() if now is None else now) - max_age_seconds
        cursor = self.conn.execute(
            "DELETE FROM spool_events WHERE created_at < ?",
            (cutoff,),
        )
        self.conn.commit()
        return int(cursor.rowcount)

    def enqueue(self, event: dict[str, Any]) -> bool | None:
        self.purge_expired()
        payload_json = json.dumps(event, ensure_ascii=True, separators=(",", ":"))
        byte_size = len(payload_json.encode("utf-8"))

        if self.total_bytes() + byte_size > self.max_bytes:
            return None

        try:
            cursor = self.conn.execute(
                """
                INSERT OR IGNORE INTO spool_events (event_id, payload_json, byte_size, created_at)
                VALUES (?, ?, ?, ?)
                """,
                (event["id"], payload_json, byte_size, time.time()),
            )
            self.conn.commit()
            # A repeated JSONL line keeps the existing row. It is not a new event
            # and it is not a capacity drop.
            return cursor.rowcount > 0
        except sqlite3.Error:
            return False

    def peek_batch(self, max_events: int, max_bytes: int) -> list[tuple[int, dict[str, Any]]]:
        rows = self.conn.execute(
            """
            SELECT seq, payload_json, byte_size
            FROM spool_events
            ORDER BY seq ASC
            LIMIT ?
            """,
            (max_events,),
        ).fetchall()

        batch: list[tuple[int, dict[str, Any]]] = []
        acc_bytes = 32  # overhead for {"events":[...]}
        for seq, payload_json, byte_size in rows:
            if batch and acc_bytes + byte_size + 2 > max_bytes:
                break
            batch.append((int(seq), json.loads(payload_json)))
            acc_bytes += int(byte_size) + 2
        return batch

    def delete_seqs(self, seqs: list[int]) -> None:
        if not seqs:
            return
        placeholders = ",".join("?" for _ in seqs)
        self.conn.execute(
            f"DELETE FROM spool_events WHERE seq IN ({placeholders})",
            seqs,
        )
        self.conn.commit()


class EventShipper:
    def __init__(self, config: ShipperConfig) -> None:
        validate_ingest_url(config.ingest_url)
        self.config = config
        self.spool = BoundedSqliteSpool(config.spool_path, config.max_spool_bytes)
        self.metrics = ShipperMetrics()
        self.consecutive_failures = 0
        self._last_heartbeat_sec: float | None = None
        # Set when the ingest rejects the optional sensor_status block (for
        # example an ingest that predates #94), so events are never dropped
        # as poison pills because of it.
        self._patch_status_disabled = False
        # Latest collector counters read (started_at, rejected, deadline_cut),
        # when they were read, and the overload not yet delivered to ingest.
        self._collector_snapshot: tuple[str, int, int] | None = None
        self._collector_snapshot_at: str | None = None
        self._pending_overload: dict[str, Any] | None = None
        self._spool_alert_active = False
        self._spool_notice_at: float | None = None

    def close(self) -> None:
        self.spool.close()

    def ingest_jsonl_lines(self, lines: list[str]) -> int:
        added = 0
        for line in lines:
            text = line.strip()
            if not text:
                continue
            try:
                raw = json.loads(text)
            except json.JSONDecodeError:
                self.metrics.dropped_invalid += 1
                continue
            normalized = normalize_record(raw, self.config.sensor_id)
            if not normalized:
                self.metrics.dropped_invalid += 1
                continue
            queued = self.spool.enqueue(normalized)
            if queued is True:
                self.metrics.enqueued += 1
                added += 1
            elif queued is None:
                self.metrics.dropped_spool_full += 1
        return added

    def next_backoff_seconds(self) -> float:
        if self.consecutive_failures <= 0:
            return 0.0
        delay = self.config.base_backoff_seconds * (2 ** (self.consecutive_failures - 1))
        if self.metrics.last_retry_after_seconds is not None:
            delay = max(delay, self.metrics.last_retry_after_seconds)
        return min(delay, self.config.max_backoff_seconds)

    def _read_patch_last_success_at(self) -> str | None:
        """Return the last successful patch time as 'YYYY-MM-DDTHH:MM:SSZ', or None.

        The file is small, root-written, and parsed strictly; anything else is
        treated as "not reported" so a bad file can never block delivery.
        """
        path = self.config.patch_status_path
        if path is None:
            return None
        try:
            with path.open("rb") as fp:
                raw = fp.read(PATCH_STATUS_MAX_BYTES + 1)
        except OSError:
            return None
        if len(raw) > PATCH_STATUS_MAX_BYTES:
            return None
        values: dict[str, str] = {}
        for line in raw.decode("ascii", errors="replace").splitlines():
            key, sep, value = line.partition("=")
            if sep:
                values[key.strip()] = value.strip()
        if values.get("result") != "success":
            return None
        finished = values.get("finished_at", "")
        if not PATCH_TIMESTAMP_RE.fullmatch(finished):
            return None
        try:
            dt.datetime.strptime(finished, "%Y-%m-%dT%H:%M:%SZ")
        except ValueError:
            return None
        return finished

    def _read_collector_metrics(self) -> tuple[str, int, int, str] | None:
        """Strictly parse the collector's cumulative counters, or None."""
        path = self.config.collector_metrics_path
        if path is None:
            return None
        try:
            with path.open("rb") as fp:
                raw = fp.read(PATCH_STATUS_MAX_BYTES + 1)
            if len(raw) > PATCH_STATUS_MAX_BYTES:
                return None
            data = json.loads(raw.decode("utf-8"))
        except (OSError, ValueError):
            return None
        if not isinstance(data, dict):
            return None
        started = data.get("started_at")
        updated = data.get("updated_at")
        rejected = data.get("rejected_overload")
        cut = data.get("deadline_exceeded")
        if not (isinstance(started, str) and isinstance(updated, str)):
            return None
        if not all(isinstance(v, int) and not isinstance(v, bool) and 0 <= v < 2**31 for v in (rejected, cut)):
            return None
        try:
            return (started, rejected, cut, _iso_seconds(updated))
        except ValueError:
            return None

    def _collector_status(self) -> dict[str, Any] | None:
        """Accumulate collector overload into a pending report; return it.

        Every read advances the snapshot (so quiet periods never widen a
        window). Increases are added to a pending report that is cleared only
        after a successful delivery, so a failed send followed by a collector
        restart loses nothing. A restart (new started_at) resets the counters,
        so the new run's values are the increase.
        """
        now_iso = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        current = self._read_collector_metrics()
        if current is not None:
            started, rejected, cut, observed_at = current
            if self._collector_snapshot is None:
                self._collector_snapshot = (started, rejected, cut)
            else:
                snap_started, snap_rejected, snap_cut = self._collector_snapshot
                if started != snap_started:
                    delta_rejected, delta_cut = rejected, cut
                else:
                    delta_rejected = max(0, rejected - snap_rejected)
                    delta_cut = max(0, cut - snap_cut)
                if delta_rejected > 0 or delta_cut > 0:
                    window_start = self._collector_snapshot_at or now_iso
                    window_end = max(observed_at, window_start)
                    pending = self._pending_overload
                    if pending is None:
                        self._pending_overload = {
                            "rejected": delta_rejected,
                            "deadline_cut": delta_cut,
                            "window_start": window_start,
                            "window_end": window_end,
                        }
                    else:
                        pending["rejected"] += delta_rejected
                        pending["deadline_cut"] += delta_cut
                        pending["window_start"] = min(pending["window_start"], window_start)
                        pending["window_end"] = max(pending["window_end"], window_end)
                self._collector_snapshot = (started, rejected, cut)
            self._collector_snapshot_at = now_iso
        if self._pending_overload is None:
            return None
        report = dict(self._pending_overload)
        # Ingest accepts windows from the last 7 days; never let an old
        # undelivered report become a permanent 400.
        oldest = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=6)).strftime("%Y-%m-%dT%H:%M:%SZ")
        if report["window_start"] < oldest:
            report["window_start"] = oldest
        if report["window_end"] < report["window_start"]:
            report["window_end"] = report["window_start"]
        report["rejected"] = min(report["rejected"], 10_000_000)
        report["deadline_cut"] = min(report["deadline_cut"], 10_000_000)
        return report

    def _send_events(
        self,
        events: list[dict[str, Any]],
        now_sec: int | None = None,
    ) -> tuple[str, int | None, float | None]:
        """Send a signed event batch. Returns (outcome, status_code, retry_after)."""
        status: dict[str, Any] | None = None
        if not self._patch_status_disabled:
            status = {}
            if self.config.patch_status_path is not None:
                # Always sent when enabled, with null when no successful window
                # is recorded (for example after restoring a pre-patch
                # snapshot), so the console never keeps an older success.
                status["patch_last_success_at"] = self._read_patch_last_success_at()
            collector_block = self._collector_status()
            if collector_block is not None:
                status["http_collector"] = collector_block
            if not status:
                status = None
        result = self._send_body(events, status, now_sec)
        if result[0] == "ok" and status is not None and "http_collector" in status:
            self._pending_overload = None  # delivered
        if result[0] == "permanent_400" and status is not None:
            # Never let the optional status block turn real events into poison
            # pills: retry the same events without it.
            retry = self._send_body(events, None, now_sec)
            if retry[0] == "ok":
                # Only the status block was rejected (an ingest without #94).
                self._patch_status_disabled = True
                sys.stderr.write(
                    "ingest rejected sensor_status; patch status reporting disabled\n"
                )
            # Otherwise (an event-level 400, or a transient failure that proves
            # nothing) keep status enabled; poison-pill isolation and the normal
            # retry path handle the events.
            result = retry
        return result

    def _send_body(
        self,
        events: list[dict[str, Any]],
        status: dict[str, Any] | None,
        now_sec: int | None,
    ) -> tuple[str, int | None, float | None]:
        body: dict[str, Any] = {"events": events}
        if status is not None:
            body["sensor_status"] = status
        raw_body = json.dumps(body, ensure_ascii=True, separators=(",", ":"))
        timestamp = str(int(now_sec if now_sec is not None else time.time()))
        request_id = f"req-{uuid.uuid4().hex[:24]}"
        signing_payload = build_signature_payload(
            self.config.sensor_id, timestamp, request_id, raw_body
        )
        sig_hex = compute_hmac_sha256_hex(self.config.hmac_secret, signing_payload)

        req = urllib.request.Request(
            self.config.ingest_url,
            data=raw_body.encode("utf-8"),
            method="POST",
            headers={
                "Content-Type": "application/json",
                "X-Sensor-Id": self.config.sensor_id,
                "X-Timestamp": timestamp,
                "X-Request-Id": request_id,
                "X-Signature": f"sha256={sig_hex}",
            },
        )

        try:
            with urllib.request.urlopen(
                req, timeout=self.config.http_timeout_seconds
            ) as resp:
                if 200 <= resp.status < 300:
                    return ("ok", resp.status, None)
                return ("transient", resp.status, None)
        except urllib.error.HTTPError as exc:
            retry_after: float | None = None
            raw_ra = exc.headers.get("Retry-After") if exc.headers else None
            if raw_ra:
                try:
                    parsed_ra = float(raw_ra)
                    if parsed_ra > 0:
                        retry_after = parsed_ra
                except ValueError:
                    retry_after = None
            if exc.code == 400:
                return ("permanent_400", 400, None)
            return ("transient", exc.code, retry_after)
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            return (f"network:{type(exc).__name__}", None, None)

    def flush_once(self, now_sec: int | None = None) -> bool:
        """Attempt to send one signed batch (or periodic heartbeat when idle)."""
        current_sec = float(now_sec if now_sec is not None else time.time())
        self.spool.purge_expired()
        batch = self.spool.peek_batch(
            self.config.max_batch_events, self.config.max_batch_bytes
        )
        if not batch:
            interval = self.config.heartbeat_interval_seconds
            if interval <= 0:
                return True
            if (
                self._last_heartbeat_sec is not None
                and current_sec - self._last_heartbeat_sec < interval
            ):
                return True
            outcome, status_code, retry_after = self._send_events([], now_sec)
            if outcome == "ok":
                self._last_heartbeat_sec = current_sec
                self.consecutive_failures = 0
                self.metrics.last_error = None
                self.metrics.last_retry_after_seconds = None
                self.metrics.last_delivery_at = dt.datetime.now(
                    dt.timezone.utc
                ).isoformat().replace("+00:00", "Z")
                return True
            err_label = f"http_{status_code}" if status_code is not None else outcome
            self._record_failure(err_label, retry_after)
            return False

        seqs = [seq for seq, _ in batch]
        events = [ev for _, ev in batch]
        outcome, status_code, retry_after = self._send_events(events, now_sec)

        if outcome == "ok":
            self.spool.delete_seqs(seqs)
            self.metrics.batches_sent += 1
            self.metrics.events_delivered += len(events)
            self._last_heartbeat_sec = current_sec
            self.consecutive_failures = 0
            self.metrics.last_error = None
            self.metrics.last_retry_after_seconds = None
            self.metrics.last_delivery_at = dt.datetime.now(dt.timezone.utc).isoformat().replace(
                "+00:00", "Z"
            )
            return True

        # Isolate permanent HTTP 400 poison-pill events so valid events are not blocked
        if outcome == "permanent_400":
            if len(batch) == 1:
                self.spool.delete_seqs(seqs)
                self.metrics.dropped_invalid += 1
                self.metrics.last_error = "http_400_dropped"
                return True

            progressed = False
            for seq, ev in batch:
                sub_outcome, sub_status, sub_ra = self._send_events([ev], now_sec)
                if sub_outcome == "ok":
                    self.spool.delete_seqs([seq])
                    self.metrics.batches_sent += 1
                    self.metrics.events_delivered += 1
                    self.metrics.last_delivery_at = dt.datetime.now(dt.timezone.utc).isoformat().replace(
                        "+00:00", "Z"
                    )
                    progressed = True
                elif sub_outcome == "permanent_400":
                    self.spool.delete_seqs([seq])
                    self.metrics.dropped_invalid += 1
                    progressed = True
                else:
                    self._record_failure(
                        f"http_{sub_status}" if sub_status else sub_outcome, sub_ra
                    )
                    return False

            if progressed:
                self.consecutive_failures = 0
                self.metrics.last_error = None
                self.metrics.last_retry_after_seconds = None
            return progressed

        err_label = f"http_{status_code}" if status_code is not None else outcome
        self._record_failure(err_label, retry_after)
        return False

    def _record_failure(self, err: str, retry_after: float | None = None) -> None:
        self.metrics.batches_failed += 1
        self.metrics.last_error = err
        self.metrics.last_retry_after_seconds = retry_after
        self.consecutive_failures += 1

    def spool_status(self) -> dict[str, Any]:
        used = self.spool.total_bytes()
        cap = self.config.max_spool_bytes
        ratio = 0.0 if cap <= 0 else used / cap
        return {
            "max_spool_bytes": cap,
            "spool_utilization": round(ratio, 4),
            "spool_alert": ratio >= SPOOL_ALERT_RATIO,
        }

    def note_spool_pressure(self, now: float | None = None) -> str | None:
        """Record a local warning when the spool stays at or above 70% of its cap.

        The notice goes to stderr so the existing shipper service journal captures
        it. It repeats at most once per five minutes while the condition holds.
        """
        current = time.time() if now is None else now
        status = self.spool_status()
        alert = bool(status["spool_alert"])
        repeat_due = (
            self._spool_notice_at is None
            or current - self._spool_notice_at >= SPOOL_ALERT_REPEAT_SECONDS
        )
        message: str | None = None
        if alert and (not self._spool_alert_active or repeat_due):
            message = (
                "spool utilization "
                f"{status['spool_utilization'] * 100:.1f}% "
                f"({self.spool.total_bytes()}/{status['max_spool_bytes']} bytes); "
                "investigate ingest before the cap drops events"
            )
        elif self._spool_alert_active and not alert:
            message = "spool utilization returned below 70%"
        self._spool_alert_active = alert
        if message is not None:
            self._spool_notice_at = current
            print(message, file=sys.stderr, flush=True)
        return message

    def metrics_snapshot(self) -> dict[str, Any]:
        """Local counters only. A successful batch is what moves the remote heartbeat."""
        return {
            "queue_depth": self.spool.count(),
            "queue_bytes": self.spool.total_bytes(),
            **self.spool_status(),
            "enqueued": self.metrics.enqueued,
            "dropped_spool_full": self.metrics.dropped_spool_full,
            "dropped_invalid": self.metrics.dropped_invalid,
            "batches_sent": self.metrics.batches_sent,
            "batches_failed": self.metrics.batches_failed,
            "events_delivered": self.metrics.events_delivered,
            "consecutive_failures": self.consecutive_failures,
            "backoff_seconds": self.next_backoff_seconds(),
            "last_error": self.metrics.last_error,
            "last_delivery_at": self.metrics.last_delivery_at,
        }

    def ingest_jsonl_file(self, path: Path, max_bytes: int = 1024 * 1024) -> int:
        """Tail complete JSONL lines from path, persisting the file cursor in SQLite."""
        inode, offset = self.spool.get_cursor(path)
        lines, new_inode, new_offset, skipped_oversize = read_new_jsonl(
            path, offset, inode=inode, max_bytes=max_bytes
        )
        if skipped_oversize:
            self.metrics.dropped_invalid += skipped_oversize
        added = self.ingest_jsonl_lines(lines) if lines else 0
        if new_inode is not None and (new_inode != inode or new_offset != offset):
            self.spool.set_cursor(path, new_inode, new_offset)
        return added

    def write_metrics(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(self.metrics_snapshot(), ensure_ascii=True, indent=2) + "\n",
            encoding="utf-8",
        )


def read_new_jsonl(
    path: Path,
    offset: int,
    inode: int | None = None,
    max_bytes: int = 1024 * 1024,
) -> tuple[list[str], int | None, int, int]:
    """Read complete JSONL lines added after offset.

    Resets to offset 0 when the file was rotated (inode changed) or truncated
    (size < offset). If a single line without a newline fills max_bytes, skip
    the oversized corrupt chunk instead of stalling forever.
    Returns (lines, current_inode, new_offset, skipped_oversize_chunks).
    """
    if not path.exists():
        return [], inode, offset, 0
    st = path.stat()
    current_inode = st.st_ino
    if (inode is not None and current_inode != inode) or st.st_size < offset:
        offset = 0

    with path.open("rb") as fp:
        fp.seek(offset)
        chunk = fp.read(max_bytes)
    if not chunk:
        return [], current_inode, offset, 0
    if chunk.endswith(b"\n"):
        consumed = chunk
        new_offset = offset + len(chunk)
    else:
        last_nl = chunk.rfind(b"\n")
        if last_nl < 0:
            if len(chunk) >= max_bytes:
                # Corrupt or hostile line exceeding max_bytes without newline: skip it.
                return [], current_inode, offset + len(chunk), 1
            return [], current_inode, offset, 0
        consumed = chunk[: last_nl + 1]
        new_offset = offset + last_nl + 1
    lines = consumed.decode("utf-8", errors="replace").splitlines()
    return lines, current_inode, new_offset, 0


def main() -> None:
    sensor_id = os.environ.get("SENSOR_ID", "")
    secret = os.environ.get("INGEST_HMAC_SECRET", "")
    ingest_url = os.environ.get("INGEST_URL", "")
    if not sensor_id or not secret or not ingest_url:
        raise SystemExit("SENSOR_ID, INGEST_HMAC_SECRET, and INGEST_URL are required")
    sources = [
        Path(item)
        for item in os.environ.get(
            "SHIPPER_JSONL_PATHS",
            "/var/log/attackarium/opencanary.jsonl,/var/log/attackarium/http-collector.jsonl",
        ).split(",")
        if item.strip()
    ]
    cfg = ShipperConfig(
        sensor_id=sensor_id,
        hmac_secret=secret,
        ingest_url=ingest_url,
        spool_path=Path(os.environ.get("SHIPPER_SPOOL_PATH", "/var/lib/attackarium/spool.sqlite3")),
        heartbeat_interval_seconds=float(
            os.environ.get("SHIPPER_HEARTBEAT_INTERVAL_SECONDS", "300")
        ),
        patch_status_path=Path(
            os.environ.get(
                "SHIPPER_PATCH_STATUS_PATH", "/var/lib/attackarium-patch/last-success"
            )
        )
        if os.environ.get("SHIPPER_PATCH_STATUS_PATH", "x") != ""
        else None,
        collector_metrics_path=Path(
            os.environ.get(
                "SHIPPER_COLLECTOR_METRICS_PATH",
                "/var/log/attackarium/http-collector-metrics.json",
            )
        )
        if os.environ.get("SHIPPER_COLLECTOR_METRICS_PATH", "x") != ""
        else None,
    )
    metrics_path = Path(
        os.environ.get("SHIPPER_METRICS_PATH", "/var/lib/attackarium/shipper-metrics.json")
    )
    shipper = EventShipper(cfg)
    try:
        while True:
            for path in sources:
                shipper.ingest_jsonl_file(path)
            shipper.flush_once()
            shipper.note_spool_pressure()
            shipper.write_metrics(metrics_path)
            delay = shipper.next_backoff_seconds()
            time.sleep(delay if delay > 0 else 1.0)
    except KeyboardInterrupt:
        pass
    finally:
        shipper.close()


if __name__ == "__main__":
    main()
