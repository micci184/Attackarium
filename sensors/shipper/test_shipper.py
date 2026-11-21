import http.server
import json
import tempfile
import threading
import unittest
from pathlib import Path

from shipper import (
    EventShipper,
    ShipperConfig,
    build_signature_payload,
    compute_hmac_sha256_hex,
    normalize_record,
)

TEST_SECRET = "test-shipper-hmac-secret-at-least-32-chars"


class MockIngestState:
    def __init__(self) -> None:
        self.fail_next = 0
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

        if request_id in self.state.received_request_ids:
            self.send_response(409)
            self.end_headers()
            return

        self.state.received_request_ids.add(request_id)
        payload = json.loads(raw_body)
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


if __name__ == "__main__":
    unittest.main()
