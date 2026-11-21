import http.server
import json
import tempfile
import threading
import time
import unittest
from pathlib import Path

from shipper import (
    SPOOL_MAX_AGE_SECONDS,
    BoundedSqliteSpool,
    EventShipper,
    ShipperConfig,
    build_signature_payload,
    compute_hmac_sha256_hex,
    normalize_record,
    read_new_jsonl,
)

TEST_SECRET = "test-shipper-hmac-secret-at-least-32-chars"


class MockIngestState:
    def __init__(self) -> None:
        self.fail_next = 0
        self.rate_limit_next = 0
        self.reject_event_ids: set[str] = set()
        self.received_event_ids: set[str] = set()
        self.received_request_ids: set[str] = set()
        self.signature_failures = 0


class MockIngestHandler(http.server.BaseHTTPRequestHandler):
    state: MockIngestState

    def log_message(self, format: str, *args) -> None:
        return

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", "0"))
        raw_body = self.rfile.read(length).decode("utf-8")

        sensor_id = self.headers.get("X-Sensor-Id", "")
        timestamp = self.headers.get("X-Timestamp", "")
        request_id = self.headers.get("X-Request-Id", "")
        sig_header = self.headers.get("X-Signature", "")

        expected = "sha256=" + compute_hmac_sha256_hex(
            TEST_SECRET,
            build_signature_payload(sensor_id, timestamp, request_id, raw_body),
        )
        if sig_header != expected:
            self.state.signature_failures += 1
            self.send_response(401)
            self.end_headers()
            return

        if self.state.fail_next > 0:
            self.state.fail_next -= 1
            self.send_response(503)
            self.end_headers()
            return

        if self.state.rate_limit_next > 0:
            self.state.rate_limit_next -= 1
            self.send_response(429)
            self.send_header("Retry-After", "25")
            self.end_headers()
            return

        if request_id in self.state.received_request_ids:
            self.send_response(409)
            self.end_headers()
            return

        payload = json.loads(raw_body)
        if any(ev["id"] in self.state.reject_event_ids for ev in payload.get("events", [])):
            self.send_response(400)
            self.end_headers()
            return

        self.state.received_request_ids.add(request_id)
        for ev in payload.get("events", []):
            self.state.received_event_ids.add(ev["id"])

        body = json.dumps({"ok": True}).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class ShipperIntegrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmpdir = tempfile.TemporaryDirectory()
        self.state = MockIngestState()
        handler_cls = type(
            "BoundMockIngestHandler",
            (MockIngestHandler,),
            {"state": self.state},
        )
        self.server = http.server.HTTPServer(("127.0.0.1", 0), handler_cls)
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        self.tmpdir.cleanup()

    def test_normalizes_opencanary_and_strips_credentials(self) -> None:
        raw_oc = {
            "dst_port": 22,
            "src_host": "198.51.100.20",
            "src_port": 51234,
            "logtype": 4002,
            "utc_time": "2026-11-21 10:00:00.000000",
            "logdata": {
                "USERNAME": "root",
                "PASSWORD": "super-secret-password",
                "REMOTEVERSION": "SSH-2.0-Scanner",
            },
        }
        norm1 = normalize_record(raw_oc, "sensor-dev-01")
        norm2 = normalize_record(raw_oc, "sensor-dev-01")
        self.assertIsNotNone(norm1)
        self.assertEqual(norm1["id"], norm2["id"])  # deterministic UUIDv5
        self.assertEqual(norm1["protocol"], "ssh")
        self.assertEqual(norm1["event_type"], "ssh_login_attempt")
        self.assertNotIn("password", norm1["metadata"])
        self.assertNotIn("username", norm1["metadata"])
        self.assertEqual(norm1["metadata"].get("remoteversion"), "SSH-2.0-Scanner")

    def test_spool_retries_after_ingest_outage_without_loss_or_duplicates(self) -> None:
        spool_path = Path(self.tmpdir.name) / "spool.sqlite3"
        cfg = ShipperConfig(
            sensor_id="sensor-dev-01",
            hmac_secret=TEST_SECRET,
            ingest_url=f"http://127.0.0.1:{self.port}/ingest",
            spool_path=spool_path,
            max_spool_bytes=64 * 1024,
        )
        shipper = EventShipper(cfg)
        try:
            lines = [
                json.dumps(
                    {
                        "source": "http_collector",
                        "id": "11111111-1111-4111-8111-111111111111",
                        "observed_at": "2026-11-21T10:00:00Z",
                        "protocol": "http",
                        "dst_port": 80,
                        "event_type": "http_probe",
                        "http_method": "GET",
                        "http_path": "/wp-login.php",
                    }
                ),
                json.dumps(
                    {
                        "dst_port": 22,
                        "src_host": "198.51.100.21",
                        "src_port": 40000,
                        "logtype": 4002,
                        "utc_time": "2026-11-21 10:01:00.000000",
                        "logdata": {"PASSWORD": "nope"},
                    }
                ),
            ]
            self.assertEqual(shipper.ingest_jsonl_lines(lines), 2)
            self.assertEqual(shipper.spool.count(), 2)

            # Simulate temporary 503 outage
            self.state.fail_next = 1
            self.assertFalse(shipper.flush_once())
            self.assertEqual(shipper.spool.count(), 2)
            self.assertGreater(shipper.next_backoff_seconds(), 0)

            # Recovery: flush succeeds with fresh request_id and valid HMAC
            self.assertTrue(shipper.flush_once())
            self.assertEqual(shipper.spool.count(), 0)
            self.assertEqual(self.state.signature_failures, 0)
            self.assertEqual(len(self.state.received_event_ids), 2)
            self.assertEqual(shipper.metrics.events_delivered, 2)
        finally:
            shipper.close()

    def test_enforces_spool_byte_cap_and_records_drop_metrics(self) -> None:
        spool_path = Path(self.tmpdir.name) / "capped.sqlite3"
        cfg = ShipperConfig(
            sensor_id="sensor-dev-01",
            hmac_secret=TEST_SECRET,
            ingest_url=f"http://127.0.0.1:{self.port}/ingest",
            spool_path=spool_path,
            max_spool_bytes=400,  # tiny cap to trigger bounded drop
        )
        shipper = EventShipper(cfg)
        try:
            lines = [
                json.dumps(
                    {
                        "source": "http_collector",
                        "id": f"22222222-2222-4222-8222-00000000000{i}",
                        "observed_at": "2026-11-21T10:00:00Z",
                        "protocol": "http",
                        "dst_port": 80,
                        "event_type": "http_probe",
                        "http_path": "/probe/" + ("x" * 80),
                    }
                )
                for i in range(5)
            ]
            added = shipper.ingest_jsonl_lines(lines)
            self.assertGreater(added, 0)
            self.assertLess(added, 5)
            self.assertEqual(shipper.metrics.dropped_spool_full, 5 - added)
            self.assertLessEqual(shipper.spool.total_bytes(), 400)
        finally:
            shipper.close()

    def test_rejects_non_https_remote_ingest_url(self) -> None:
        spool_path = Path(self.tmpdir.name) / "badurl.sqlite3"
        for bad_url in ("http://example.com/ingest", "file:///etc/passwd"):
            cfg = ShipperConfig(
                sensor_id="sensor-dev-01",
                hmac_secret=TEST_SECRET,
                ingest_url=bad_url,
                spool_path=spool_path,
            )
            with self.assertRaises(ValueError):
                EventShipper(cfg)

    def test_isolates_http_400_poison_pill_and_honors_429_retry_after(self) -> None:
        spool_path = Path(self.tmpdir.name) / "poison.sqlite3"
        cfg = ShipperConfig(
            sensor_id="sensor-dev-01",
            hmac_secret=TEST_SECRET,
            ingest_url=f"http://127.0.0.1:{self.port}/ingest",
            spool_path=spool_path,
        )
        shipper = EventShipper(cfg)
        try:
            bad_id = "33333333-3333-4333-8333-000000000001"
            good_id = "33333333-3333-4333-8333-000000000002"
            self.state.reject_event_ids.add(bad_id)
            lines = [
                json.dumps(
                    {
                        "source": "http_collector",
                        "id": bad_id,
                        "observed_at": "2026-11-21T10:00:00Z",
                        "protocol": "http",
                        "dst_port": 80,
                        "event_type": "http_probe",
                    }
                ),
                json.dumps(
                    {
                        "source": "http_collector",
                        "id": good_id,
                        "observed_at": "2026-11-21T10:00:01Z",
                        "protocol": "http",
                        "dst_port": 80,
                        "event_type": "http_probe",
                    }
                ),
            ]
            self.assertEqual(shipper.ingest_jsonl_lines(lines), 2)

            # First hit 429 and confirm Retry-After drives backoff
            self.state.rate_limit_next = 1
            self.assertFalse(shipper.flush_once())
            self.assertEqual(shipper.metrics.last_error, "http_429")
            self.assertGreaterEqual(shipper.next_backoff_seconds(), 25.0)

            # Next flush encounters 400 on combined batch, isolates poison pill, delivers good event
            self.assertTrue(shipper.flush_once())
            self.assertEqual(shipper.spool.count(), 0)
            self.assertEqual(shipper.metrics.dropped_invalid, 1)
            self.assertEqual(shipper.metrics.events_delivered, 1)
            self.assertIn(good_id, self.state.received_event_ids)
            self.assertNotIn(bad_id, self.state.received_event_ids)
        finally:
            shipper.close()


    def test_purges_spool_rows_older_than_24h(self) -> None:
        spool = BoundedSqliteSpool(Path(self.tmpdir.name) / "age.sqlite3", 64 * 1024)
        try:
            self.assertTrue(
                spool.enqueue(
                    {
                        "id": "00000000-0000-4000-8000-000000000099",
                        "src_ip": "198.51.100.20",
                    }
                )
            )
            spool.conn.execute(
                "UPDATE spool_events SET created_at = ?",
                (time.time() - SPOOL_MAX_AGE_SECONDS - 10,),
            )
            spool.conn.commit()
            self.assertEqual(spool.purge_expired(), 1)
            self.assertEqual(spool.count(), 0)
        finally:
            spool.close()

    def test_normalizes_each_decoy_protocol_without_keeping_credentials(self) -> None:
        samples = [
            (2000, 21, "ftp", "ftp_login_attempt"),
            (6001, 23, "telnet", "telnet_login_attempt"),
            (8001, 3306, "mysql", "mysql_login_attempt"),
            (11001, 6379, "redis", "redis_command_probe"),
        ]
        for logtype, port, protocol, event_type in samples:
            normalized = normalize_record(
                {
                    "dst_port": port,
                    "src_host": "198.51.100.30",
                    "src_port": 41000,
                    "logtype": logtype,
                    "utc_time": "2026-11-21 11:00:00.000000",
                    "logdata": {"USERNAME": "root", "PASSWORD": "secret", "CMD": "PING"},
                },
                "sensor-dev-01",
            )
            self.assertIsNotNone(normalized)
            self.assertEqual(normalized["protocol"], protocol)
            self.assertEqual(normalized["event_type"], event_type)
            self.assertNotIn("password", normalized["metadata"])
            self.assertNotIn("username", normalized["metadata"])

    def test_counts_invalid_lines_and_writes_metrics_after_delivery(self) -> None:
        spool_path = Path(self.tmpdir.name) / "metrics.sqlite3"
        cfg = ShipperConfig(
            sensor_id="sensor-dev-01",
            hmac_secret=TEST_SECRET,
            ingest_url=f"http://127.0.0.1:{self.port}/ingest",
            spool_path=spool_path,
        )
        shipper = EventShipper(cfg)
        try:
            added = shipper.ingest_jsonl_lines(
                [
                    "not-json",
                    json.dumps({"logtype": 4002, "dst_port": 0}),
                    json.dumps(
                        {
                            "source": "http_collector",
                            "id": "44444444-4444-4444-8444-000000000001",
                            "observed_at": "2026-11-21T12:00:00Z",
                            "protocol": "http",
                            "dst_port": 80,
                            "event_type": "http_probe",
                        }
                    ),
                ]
            )
            self.assertEqual(added, 1)
            self.assertEqual(shipper.metrics.dropped_invalid, 2)
            self.assertTrue(shipper.flush_once())
            snapshot = shipper.metrics_snapshot()
            self.assertEqual(snapshot["queue_depth"], 0)
            self.assertEqual(snapshot["events_delivered"], 1)
            self.assertEqual(snapshot["dropped_invalid"], 2)
            self.assertIsNotNone(snapshot["last_delivery_at"])
            metrics_path = Path(self.tmpdir.name) / "metrics.json"
            shipper.write_metrics(metrics_path)
            written = json.loads(metrics_path.read_text(encoding="utf-8"))
            self.assertEqual(written["events_delivered"], 1)
        finally:
            shipper.close()

    def test_reads_only_complete_new_jsonl_lines(self) -> None:
        path = Path(self.tmpdir.name) / "collector.jsonl"
        path.write_bytes(b'{"id":1}\n{"id":2}\n{"id":')
        lines, offset = read_new_jsonl(path, 0)
        self.assertEqual(lines, ['{"id":1}', '{"id":2}'])
        path.write_bytes(b'{"id":1}\n{"id":2}\n{"id":3}\n')
        lines, offset = read_new_jsonl(path, offset)
        self.assertEqual(lines, ['{"id":3}'])
        self.assertEqual(offset, path.stat().st_size)


if __name__ == "__main__":
    unittest.main()
