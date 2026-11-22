#!/usr/bin/env python3
"""Minimal, non-executing HTTP capture sensor for Attackarium.

Security invariants:
- Strictly bounded headers, path, body sample, and socket timeouts.
- Never executes attacker input, never fetches attacker URLs, never follows redirects.
- Drops Authorization / Cookie / credential headers by default.
- Hashes a bounded body sample and discards the bytes. The JSONL does not contain the payload.
- Prunes the local JSONL so records older than 24 hours are deleted.
- Emits structured JSONL records for the local shipper.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import http.server
import json
import os
import re
import socketserver
import threading
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from signatures import (
    InspectionInput,
    derive_signature_attack_category,
    inspect_http_request,
    redact_attacker_references,
)

TEMP_LOG_MAX_AGE = dt.timedelta(hours=24)


def prune_temp_jsonl(
    path: Path,
    now: dt.datetime | None = None,
    max_age: dt.timedelta = TEMP_LOG_MAX_AGE,
) -> None:
    """Keep only JSONL records whose observed_at is inside max_age."""
    if not path.exists():
        return
    current = now or dt.datetime.now(dt.timezone.utc)
    if current.tzinfo is None:
        current = current.replace(tzinfo=dt.timezone.utc)
    cutoff = current - max_age
    raw = path.read_text(encoding="utf-8")
    kept: list[str] = []
    for line in raw.splitlines():
        if not line.strip():
            continue
        try:
            record = json.loads(line)
            observed_raw = str(record.get("observed_at", ""))
            observed = dt.datetime.fromisoformat(observed_raw.replace("Z", "+00:00"))
            if observed.tzinfo is None:
                observed = observed.replace(tzinfo=dt.timezone.utc)
        except (json.JSONDecodeError, ValueError, TypeError):
            continue
        if observed >= cutoff:
            kept.append(line)
    text = ("\n".join(kept) + "\n") if kept else ""
    if text != raw:
        path.write_text(text, encoding="utf-8")


SAFE_HEADER_ALLOWLIST = frozenset(
    {
        "host",
        "user-agent",
        "accept",
        "accept-language",
        "content-type",
        "content-length",
        "referer",
        "x-forwarded-for",
    }
)

SENSITIVE_QUERY_KEYS = re.compile(
    r"(pass(word|wd|phrase)?|pwd|secret|token|auth(orization)?|cookie|session|api[_-]?key|jwt|cred)",
    re.IGNORECASE,
)
CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f]")


@dataclass(frozen=True)
class CollectorConfig:
    host: str = "127.0.0.1"
    port: int = 8080
    protocol_label: str = "http"
    reported_dst_port: int = 80
    output_jsonl: Path = Path("./logs/http-collector.jsonl")
    max_path_length: int = 512
    max_body_bytes: int = 4096
    max_header_value_length: int = 256
    max_header_bytes: int = 8192
    socket_timeout_seconds: float = 5.0
    max_concurrent_connections: int = 32


def strip_control(value: str) -> str:
    return CONTROL_CHARS.sub("", value)


def redact_path(raw_path: str, max_length: int = 512) -> str:
    cleaned = strip_control(raw_path).strip()
    if not cleaned:
        return "/"
    if "?" not in cleaned:
        return redact_attacker_references(cleaned)[:max_length]

    base, query = cleaned.split("?", 1)
    safe_base = redact_attacker_references(base)
    safe_pairs: list[str] = []
    for part in query.split("&"):
        if not part:
            continue
        if "=" not in part:
            safe_pairs.append(
                "[REDACTED]"
                if SENSITIVE_QUERY_KEYS.search(part)
                else redact_attacker_references(part)
            )
            continue
        k, v = part.split("=", 1)
        if SENSITIVE_QUERY_KEYS.search(k) or len(v) > 128:
            safe_pairs.append(f"{k}=[REDACTED]")
        else:
            safe_pairs.append(f"{k}={redact_attacker_references(v)}")
    return f"{safe_base}?{'&'.join(safe_pairs)}"[:max_length]


def extract_safe_headers(headers: Any, max_len: int) -> dict[str, str]:
    selected: dict[str, str] = {}
    for key, value in headers.items():
        lk = key.lower()
        if lk in SAFE_HEADER_ALLOWLIST:
            raw_val = strip_control(str(value))
            if lk == "referer":
                raw_val = redact_path(raw_val, max_len)
            else:
                raw_val = redact_attacker_references(raw_val)
            selected[lk] = raw_val[:max_len]
    return selected


def classify_http_event(method: str, path: str) -> str:
    lower = path.lower()
    if "/.env" in lower or "/.git" in lower:
        return "http_secret_file_probe"
    if "wp-login" in lower or "xmlrpc.php" in lower:
        return "http_cms_probe"
    if "/cgi-bin/" in lower or "/HNAP1" in path:
        return "http_router_probe"
    if method in ("POST", "PUT", "PATCH"):
        return "http_payload_probe"
    return "http_probe"


class BoundedThreadingHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(
        self,
        server_address: tuple[str, int],
        config: CollectorConfig,
    ) -> None:
        self.config = config
        self.write_lock = threading.Lock()
        self._last_prune = 0.0
        self.connection_semaphore = threading.BoundedSemaphore(
            max(1, config.max_concurrent_connections)
        )
        self.rejected_overload = 0
        self.config.output_jsonl.parent.mkdir(parents=True, exist_ok=True)
        super().__init__(server_address, CaptureRequestHandler)

    def process_request(self, request: Any, client_address: Any) -> None:
        if not self.connection_semaphore.acquire(blocking=False):
            self.rejected_overload += 1
            try:
                request.sendall(
                    b"HTTP/1.1 503 Service Unavailable\r\n"
                    b"Content-Length: 0\r\n"
                    b"Connection: close\r\n\r\n"
                )
            except OSError:
                pass
            self.shutdown_request(request)
            return
        super().process_request(request, client_address)

    def process_request_thread(self, request: Any, client_address: Any) -> None:
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.connection_semaphore.release()

    def write_record(self, record: dict[str, Any]) -> None:
        line = json.dumps(record, ensure_ascii=True, separators=(",", ":")) + "\n"
        with self.write_lock:
            now_mono = time.monotonic()
            if now_mono - self._last_prune >= 60:
                prune_temp_jsonl(self.config.output_jsonl)
                self._last_prune = now_mono
            with self.config.output_jsonl.open("a", encoding="utf-8") as fp:
                fp.write(line)


class _BoundedHeaderReader:
    """Stop reading once the header block exceeds the configured byte cap."""

    def __init__(self, raw: Any, limit: int, on_overflow: Any) -> None:
        self._raw = raw
        self._limit = limit
        self._used = 0
        self._headers_done = False
        self._on_overflow = on_overflow

    def readline(self, limit: int = -1) -> bytes:
        if self._headers_done:
            return self._raw.readline(limit)
        # Never ask the socket for more than the remaining header budget.
        budget = self._limit - self._used + 1
        line = self._raw.readline(budget if limit < 0 else min(limit, budget))
        self._used += len(line)
        if self._used > self._limit:
            self._headers_done = True
            self._on_overflow()
            return b""
        if line in (b"\r\n", b"\n", b""):
            self._headers_done = True
        return line

    def read(self, size: int = -1) -> bytes:
        return self._raw.read(size)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._raw, name)


class CaptureRequestHandler(http.server.BaseHTTPRequestHandler):
    server: BoundedThreadingHTTPServer

    def setup(self) -> None:
        super().setup()
        self.request.settimeout(self.server.config.socket_timeout_seconds)
        self._header_rejected = False
        self.rfile = _BoundedHeaderReader(
            self.rfile,
            self.server.config.max_header_bytes,
            self._reject_headers,
        )

    def _reject_headers(self) -> None:
        if self._header_rejected:
            return
        self._header_rejected = True
        self.server.write_record(
            {
                "source": "http_collector",
                "id": str(uuid.uuid4()),
                "observed_at": dt.datetime.now(dt.timezone.utc)
                .isoformat()
                .replace("+00:00", "Z"),
                "protocol": self.server.config.protocol_label,
                "dst_port": self.server.config.reported_dst_port,
                "event_type": "http_probe",
                "src_ip": self.client_address[0] if self.client_address else None,
                "http_method": "GET",
                "http_path": "/",
                "metadata": {"header_rejected": True},
            }
        )

    def log_message(self, format: str, *args: Any) -> None:
        # Suppress default stderr logging to avoid leaking untrusted input.
        return

    def _handle_any(self) -> None:
        if self._header_rejected:
            self.send_response(431)
            self.send_header("Content-Length", "0")
            self.send_header("Connection", "close")
            self.end_headers()
            self.close_connection = True
            return

        cfg = self.server.config
        method = strip_control(self.command or "GET").upper()[:16]
        redacted_path = redact_path(self.path or "/", cfg.max_path_length)
        safe_headers = extract_safe_headers(self.headers, cfg.max_header_value_length)

        declared_len = 0
        raw_cl = self.headers.get("Content-Length")
        if raw_cl is not None:
            try:
                declared_len = max(0, int(raw_cl))
            except ValueError:
                declared_len = 0

        # Read strictly bounded body sample; never buffer unbounded attacker input.
        to_read = min(declared_len, cfg.max_body_bytes + 1)
        body_bytes = b""
        body_truncated = False
        if to_read > 0:
            body_bytes = self.rfile.read(to_read)
            if len(body_bytes) > cfg.max_body_bytes or declared_len > cfg.max_body_bytes:
                body_bytes = body_bytes[: cfg.max_body_bytes]
                body_truncated = True

        # Inspect bounded raw path, all headers, and bounded body before discarding body bytes.
        raw_headers = tuple((str(k), str(v)) for k, v in self.headers.items())
        detections = inspect_http_request(
            InspectionInput(
                method=method,
                raw_path=self.path or "/",
                headers=raw_headers,
                body_bytes=body_bytes,
                body_truncated=body_truncated,
                max_body_bytes=cfg.max_body_bytes,
            )
        )

        body_sha256 = hashlib.sha256(body_bytes).hexdigest() if body_bytes else None
        fp_seed = f"{method}:{redacted_path.split('?', 1)[0]}:{safe_headers.get('user-agent', '')}"
        fingerprint = "http-" + hashlib.sha256(fp_seed.encode("utf-8")).hexdigest()[:16]

        metadata: dict[str, Any] = {
            "headers": safe_headers,
            "declared_content_length": declared_len,
            "sampled_body_bytes": len(body_bytes),
            "body_truncated": body_truncated,
            "body_sha256": body_sha256,
        }
        if detections:
            metadata["signature_detections"] = [match.to_dict() for match in detections]

        record: dict[str, Any] = {
            "source": "http_collector",
            "id": str(uuid.uuid4()),
            "observed_at": dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z"),
            "protocol": cfg.protocol_label,
            "dst_port": cfg.reported_dst_port,
            "event_type": classify_http_event(method, redacted_path),
            "src_ip": self.client_address[0] if self.client_address else None,
            "http_method": method,
            "http_path": redacted_path,
            "fingerprint": fingerprint,
            "metadata": metadata,
        }
        attack_category = derive_signature_attack_category(detections)
        if attack_category is not None:
            record["attack_category"] = attack_category
        self.server.write_record(record)

        body = b"Not Found\n"
        self.send_response(404)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        if method != "HEAD":
            self.wfile.write(body)

    do_GET = _handle_any
    do_POST = _handle_any
    do_PUT = _handle_any
    do_DELETE = _handle_any
    do_PATCH = _handle_any
    do_HEAD = _handle_any
    do_OPTIONS = _handle_any


def create_server(config: CollectorConfig) -> BoundedThreadingHTTPServer:
    return BoundedThreadingHTTPServer((config.host, config.port), config)


def main() -> None:
    cfg = CollectorConfig(
        host=os.environ.get("HTTP_COLLECTOR_HOST", "127.0.0.1"),
        port=int(os.environ.get("HTTP_COLLECTOR_PORT", "8080")),
        protocol_label=os.environ.get("HTTP_COLLECTOR_PROTOCOL", "http"),
        reported_dst_port=int(os.environ.get("HTTP_COLLECTOR_REPORTED_PORT", "80")),
        output_jsonl=Path(
            os.environ.get("HTTP_COLLECTOR_OUTPUT", "./logs/http-collector.jsonl")
        ),
        max_body_bytes=int(os.environ.get("HTTP_COLLECTOR_MAX_BODY_BYTES", "4096")),
    )
    server = create_server(cfg)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
