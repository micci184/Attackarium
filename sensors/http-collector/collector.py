#!/usr/bin/env python3
"""Minimal, non-executing HTTP capture sensor for Attackarium.

Security invariants:
- Strictly bounded headers, path, body sample, and socket timeouts.
- Never executes attacker input, never fetches attacker URLs, never follows redirects.
- Drops Authorization / Cookie / credential headers by default.
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
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

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
    socket_timeout_seconds: float = 5.0


def strip_control(value: str) -> str:
    return CONTROL_CHARS.sub("", value)


def redact_path(raw_path: str, max_length: int = 512) -> str:
    cleaned = strip_control(raw_path).strip()
    if not cleaned:
        return "/"
    if "?" not in cleaned:
        return cleaned[:max_length]

    base, query = cleaned.split("?", 1)
    safe_pairs: list[str] = []
    for part in query.split("&"):
        if not part:
            continue
        if "=" not in part:
            safe_pairs.append("[REDACTED]" if SENSITIVE_QUERY_KEYS.search(part) else part)
            continue
        k, v = part.split("=", 1)
        if SENSITIVE_QUERY_KEYS.search(k) or len(v) > 128:
            safe_pairs.append(f"{k}=[REDACTED]")
        else:
            safe_pairs.append(f"{k}={v}")
    return f"{base}?{'&'.join(safe_pairs)}"[:max_length]


def extract_safe_headers(headers: Any, max_len: int) -> dict[str, str]:
    selected: dict[str, str] = {}
    for key, value in headers.items():
        lk = key.lower()
        if lk in SAFE_HEADER_ALLOWLIST:
            selected[lk] = strip_control(str(value))[:max_len]
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
        self.config.output_jsonl.parent.mkdir(parents=True, exist_ok=True)
        super().__init__(server_address, CaptureRequestHandler)

    def write_record(self, record: dict[str, Any]) -> None:
        line = json.dumps(record, ensure_ascii=True, separators=(",", ":")) + "\n"
        with self.write_lock:
            with self.config.output_jsonl.open("a", encoding="utf-8") as fp:
                fp.write(line)


class CaptureRequestHandler(http.server.BaseHTTPRequestHandler):
    server: BoundedThreadingHTTPServer

    def setup(self) -> None:
        super().setup()
        self.request.settimeout(self.server.config.socket_timeout_seconds)

    def log_message(self, format: str, *args: Any) -> None:
        # Suppress default stderr logging to avoid leaking untrusted input.
        return

    def _handle_any(self) -> None:
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

        body_sha256 = hashlib.sha256(body_bytes).hexdigest() if body_bytes else None
        fp_seed = f"{method}:{redacted_path.split('?', 1)[0]}:{safe_headers.get('user-agent', '')}"
        fingerprint = "http-" + hashlib.sha256(fp_seed.encode("utf-8")).hexdigest()[:16]

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
            "metadata": {
                "headers": safe_headers,
                "declared_content_length": declared_len,
                "sampled_body_bytes": len(body_bytes),
                "body_truncated": body_truncated,
                "body_sha256": body_sha256,
            },
        }
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
