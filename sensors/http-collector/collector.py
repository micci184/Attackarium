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
import sys
import tempfile
import threading
import time
import urllib.parse
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


def _is_fresh_jsonl_line(line: str, cutoff: dt.datetime) -> bool:
    try:
        record = json.loads(line)
        observed_raw = str(record.get("observed_at", ""))
        observed = dt.datetime.fromisoformat(observed_raw.replace("Z", "+00:00"))
        if observed.tzinfo is None:
            observed = observed.replace(tzinfo=dt.timezone.utc)
    except (json.JSONDecodeError, ValueError, TypeError, AttributeError):
        return False
    return observed >= cutoff


def prune_temp_jsonl(
    path: Path,
    now: dt.datetime | None = None,
    max_age: dt.timedelta = TEMP_LOG_MAX_AGE,
) -> None:
    """Keep only JSONL records whose observed_at is inside max_age.

    A read-only streaming pass first checks whether anything has expired, so an
    unchanged log never needs a temporary copy (or the extra disk space). Only
    then does a second pass stream the kept lines into a sibling temp file and
    atomically replace the original. Memory stays bounded by a single line. The
    shipper treats the inode change like a rotation and relies on idempotent
    event IDs.
    """
    if not path.exists():
        return
    current = now or dt.datetime.now(dt.timezone.utc)
    if current.tzinfo is None:
        current = current.replace(tzinfo=dt.timezone.utc)
    cutoff = current - max_age

    def keep(line: str) -> bool:
        stripped = line.rstrip("\n")
        return bool(stripped.strip()) and _is_fresh_jsonl_line(stripped, cutoff)

    with path.open("r", encoding="utf-8", errors="replace") as src:
        if all(keep(line) for line in src):
            return

    fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".prune", dir=path.parent)
    tmp_path = Path(tmp_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as out, path.open(
            "r", encoding="utf-8", errors="replace"
        ) as src:
            for line in src:
                if keep(line):
                    out.write(line.rstrip("\n") + "\n")
        os.chmod(tmp_path, path.stat().st_mode & 0o777)
        os.replace(tmp_path, path)
    finally:
        if tmp_path.exists():
            tmp_path.unlink()


SAFE_HEADER_ALLOWLIST = frozenset(
    {
        "user-agent",
        "accept",
        "accept-language",
        "content-type",
        "content-length",
        "referer",
    }
)

SENSITIVE_QUERY_KEYS = re.compile(
    r"(pass(word|wd|phrase)?|pwd|secret|token|auth(orization)?|cookie|session|jsessionid|stok|api[_-]?key|private[_-]?key|access[_-]?key|jwt|bearer|cred(ential)?s?|sig(nature)?|otp|pin)",
    re.IGNORECASE,
)
CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f]")
EMBEDDED_URL_CREDS = re.compile(r"([a-zA-Z][a-zA-Z0-9+.-]*://)([^/\s@]+)@")
SENSITIVE_VALUE_PATTERNS = (
    # JWT tokens
    re.compile(r"eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"),
    # AWS access keys
    re.compile(r"\b(?:AKIA|ASIA|AIDA|AROA)[0-9A-Z]{16}\b"),
    # Common API / platform tokens (GitHub, Slack, Stripe/OpenAI-style)
    re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr|github_pat|xox[baprs]|sk|pk|rk)_[A-Za-z0-9_-]{12,}\b"),
    re.compile(r"\bsk-[A-Za-z0-9_-]{16,}\b"),
    # Email addresses
    re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"),
)
PATH_PARAM_SECRET = re.compile(
    r"(;[A-Za-z0-9_.-]*(?:stok|jsessionid|session|token|auth|pass|secret|key|sig)[A-Za-z0-9_.-]*=)([^/;?#]+)",
    re.IGNORECASE,
)
MAX_QUERY_KEY_LENGTH = 64


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


def _safe_unquote(value: str) -> str:
    try:
        return urllib.parse.unquote(value)
    except Exception:
        return value


def _contains_sensitive_value(value: str) -> bool:
    if EMBEDDED_URL_CREDS.search(value):
        return True
    return any(pattern.search(value) for pattern in SENSITIVE_VALUE_PATTERNS)


def _redact_path_segment(segment: str) -> str:
    redacted = EMBEDDED_URL_CREDS.sub(r"\1[REDACTED]@", segment)
    redacted = PATH_PARAM_SECRET.sub(r"\1[REDACTED]", redacted)
    for pattern in SENSITIVE_VALUE_PATTERNS:
        redacted = pattern.sub("[REDACTED]", redacted)
    return redacted


def redact_path(raw_path: str, max_length: int = 512) -> str:
    cleaned = strip_control(raw_path).strip()
    if not cleaned:
        return "/"
    # Redact attacker references on the full path before splitting on '&' so
    # command-injection chains like '&&wget http://...' are not broken apart.
    cleaned = redact_attacker_references(cleaned)
    if "?" not in cleaned:
        return _redact_path_segment(cleaned)[:max_length]

    base, query = cleaned.split("?", 1)
    safe_base = _redact_path_segment(base)
    safe_pairs: list[str] = []
    for part in query.split("&"):
        if not part:
            continue
        if "=" not in part:
            decoded_part = _safe_unquote(part)
            if (
                len(decoded_part) > MAX_QUERY_KEY_LENGTH
                or SENSITIVE_QUERY_KEYS.search(decoded_part)
                or _contains_sensitive_value(decoded_part)
            ):
                safe_pairs.append("[REDACTED]")
            else:
                safe_pairs.append(part)
            continue
        k, _v = part.split("=", 1)
        decoded_key = _safe_unquote(k)
        if (
            not decoded_key
            or len(decoded_key) > MAX_QUERY_KEY_LENGTH
            or _contains_sensitive_value(decoded_key)
        ):
            safe_pairs.append("[REDACTED]=[REDACTED]")
        else:
            # Default-deny query parameter values to prevent leaking tokens,
            # credentials, PII, or arbitrary payloads while retaining parameter keys.
            safe_pairs.append(f"{k}=[REDACTED]")
    return f"{safe_base}?{'&'.join(safe_pairs)}"[:max_length]


# Explicit trim set (every character Python str.isspace() accepts) so the
# collector and the SQL migration classify legacy values identically.
HOST_TRIM_CHARS = "\u0009\u000a\u000b\u000c\u000d\u001c\u001d\u001e\u001f\u0020\u0085\u00a0\u1680\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007\u2008\u2009\u200a\u2028\u2029\u202f\u205f\u3000"
HOST_PORT_SUFFIX = re.compile(r":[0-9]{1,5}$")
IPV4_LITERAL = re.compile(r"^[0-9]{1,3}(\.[0-9]{1,3}){3}$")


def classify_host_header(value: Any) -> str:
    """Reduce the Host header to its kind; never keep the value.

    For scanners that connect by IP, Host is the sensor's own public address,
    which would identify the honeypot if it ever leaked. Hostnames are fully
    attacker-controlled. Keep in sync with
    supabase/migrations/20261123000002_replace_host_header_with_kind.sql.
    """
    text = strip_control(str(value)).strip(HOST_TRIM_CHARS) if value is not None else ""
    if not text:
        return "absent"
    if text.startswith("["):
        return "ip_literal"
    if IPV4_LITERAL.match(HOST_PORT_SUFFIX.sub("", text)):
        return "ip_literal"
    return "hostname"


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
        # -inf so the first write prunes even when the monotonic clock is < 60s
        # (e.g. a freshly booted host or CI runner).
        self._last_prune = float("-inf")
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
                # Advance the schedule first so a failing prune retries at most
                # once per minute, and never let it block the request append.
                self._last_prune = now_mono
                try:
                    prune_temp_jsonl(self.config.output_jsonl)
                except OSError as exc:
                    sys.stderr.write(
                        f"temp JSONL prune failed ({type(exc).__name__}); will retry\n"
                    )
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
            "host_kind": classify_host_header(self.headers.get("host")),
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
