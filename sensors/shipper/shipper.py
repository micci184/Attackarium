#!/usr/bin/env python3
"""Bounded SQLite spool & HMAC-authenticated batch shipper for Attackarium.

Responsibilities:
- Read structured JSONL from OpenCanary and HTTP collector.
- Normalize into the strict schema expected by supabase/functions/ingest.
- Assign deterministic/stable UUID event IDs for idempotent upsert.
- Persist events in a bounded local SQLite spool to survive ingest outages.
- Ship signed HTTPS batches with exponential backoff and retry metrics.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import hmac
import json
import re
import sqlite3
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

EVENT_NAMESPACE_UUID = uuid.UUID("7f3d56f8-3d1d-4d0e-942c-0df9b7489f41")
HTTP_METHOD_REGEX = re.compile(r"^[A-Z]{2,16}$")
LOCAL_HTTP_HOSTS = frozenset({"127.0.0.1", "localhost", "::1"})

OPENCANARY_LOGTYPE_MAP: dict[int, tuple[str, str]] = {
    2000: ("ftp", "ftp_login_attempt"),
    4000: ("ssh", "ssh_new_connection"),
    4001: ("ssh", "ssh_remote_version"),
    4002: ("ssh", "ssh_login_attempt"),
    6001: ("telnet", "telnet_login_attempt"),
    8001: ("mysql", "mysql_login_attempt"),
    11001: ("redis", "redis_command_probe"),
}

ALLOWED_PROTOCOLS = frozenset(
    {"ssh", "telnet", "ftp", "mysql", "redis", "http", "https", "other"}
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
            for key in ("LOCALVERSION", "REMOTEVERSION", "SESSION", "CMD"):
                if key in logdata and isinstance(logdata[key], (str, int, float, bool)):
                    safe_meta[key.lower()] = str(logdata[key])[:256]

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

    def enqueue(self, event: dict[str, Any]) -> bool:
        payload_json = json.dumps(event, ensure_ascii=True, separators=(",", ":"))
        byte_size = len(payload_json.encode("utf-8"))

        if self.total_bytes() + byte_size > self.max_bytes:
            return False

        try:
            self.conn.execute(
                """
                INSERT OR IGNORE INTO spool_events (event_id, payload_json, byte_size, created_at)
                VALUES (?, ?, ?, ?)
                """,
                (event["id"], payload_json, byte_size, time.time()),
            )
            self.conn.commit()
            return True
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
                continue
            normalized = normalize_record(raw, self.config.sensor_id)
            if not normalized:
                continue
            if self.spool.enqueue(normalized):
                self.metrics.enqueued += 1
                added += 1
            else:
                self.metrics.dropped_spool_full += 1
        return added

    def next_backoff_seconds(self) -> float:
        if self.consecutive_failures <= 0:
            return 0.0
        delay = self.config.base_backoff_seconds * (2 ** (self.consecutive_failures - 1))
        if self.metrics.last_retry_after_seconds is not None:
            delay = max(delay, self.metrics.last_retry_after_seconds)
        return min(delay, self.config.max_backoff_seconds)

    def _send_events(
        self,
        events: list[dict[str, Any]],
        now_sec: int | None = None,
    ) -> tuple[str, int | None, float | None]:
        """Send a signed event batch. Returns (outcome, status_code, retry_after)."""
        raw_body = json.dumps({"events": events}, ensure_ascii=True, separators=(",", ":"))
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
        """Attempt to send one signed batch. Returns True if delivered or empty."""
        batch = self.spool.peek_batch(
            self.config.max_batch_events, self.config.max_batch_bytes
        )
        if not batch:
            return True

        seqs = [seq for seq, _ in batch]
        events = [ev for _, ev in batch]
        outcome, status_code, retry_after = self._send_events(events, now_sec)

        if outcome == "ok":
            self.spool.delete_seqs(seqs)
            self.metrics.batches_sent += 1
            self.metrics.events_delivered += len(events)
            self.consecutive_failures = 0
            self.metrics.last_error = None
            self.metrics.last_retry_after_seconds = None
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
