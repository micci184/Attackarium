import datetime as dt
import http.client
import json
import tempfile
import threading
import unittest
from pathlib import Path

from collector import CollectorConfig, create_server, prune_temp_jsonl


class HttpCollectorSecurityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmpdir = tempfile.TemporaryDirectory()
        self.output_path = Path(self.tmpdir.name) / "events.jsonl"
        self.config = CollectorConfig(
            host="127.0.0.1",
            port=0,  # ephemeral localhost port
            protocol_label="http",
            reported_dst_port=80,
            output_jsonl=self.output_path,
            max_body_bytes=64,
            max_path_length=128,
        )
        self.server = create_server(self.config)
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        self.tmpdir.cleanup()

    def _read_records(self) -> list[dict]:
        lines = self.output_path.read_text(encoding="utf-8").strip().splitlines()
        return [json.loads(line) for line in lines]

    def test_strips_sensitive_headers_and_redacts_query_secrets(self) -> None:
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=3)
        conn.request(
            "GET",
            "/wp-login.php?user=admin&password=secret123&token=tok999",
            headers={
                "User-Agent": "SyntheticScanner/1.0",
                "Authorization": "Bearer DO_NOT_STORE",
                "Cookie": "session=DO_NOT_STORE",
            },
        )
        resp = conn.getresponse()
        resp.read()
        self.assertEqual(resp.status, 404)
        conn.close()

        records = self._read_records()
        self.assertEqual(len(records), 1)
        rec = records[0]
        self.assertEqual(rec["event_type"], "http_cms_probe")
        self.assertEqual(
            rec["http_path"],
            "/wp-login.php?user=admin&password=[REDACTED]&token=[REDACTED]",
        )
        headers = rec["metadata"]["headers"]
        self.assertEqual(headers.get("user-agent"), "SyntheticScanner/1.0")
        self.assertNotIn("authorization", headers)
        self.assertNotIn("cookie", headers)

    def test_truncates_oversize_body_without_unbounded_buffering(self) -> None:
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=3)
        oversize_payload = b"A" * 500
        conn.request("POST", "/cgi-bin/luci/test", body=oversize_payload)
        resp = conn.getresponse()
        resp.read()
        self.assertEqual(resp.status, 404)
        conn.close()

        records = self._read_records()
        self.assertEqual(len(records), 1)
        meta = records[0]["metadata"]
        self.assertEqual(records[0]["event_type"], "http_router_probe")
        self.assertTrue(meta["body_truncated"])
        self.assertEqual(meta["sampled_body_bytes"], 64)
        self.assertEqual(meta["declared_content_length"], 500)
        self.assertIsNotNone(meta["body_sha256"])

    def test_bounds_long_paths_and_records_hostile_strings_inertly(self) -> None:
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=3)
        long_path = "/.env?q=" + ("x" * 300)
        conn.request("GET", long_path)
        resp = conn.getresponse()
        resp.read()
        self.assertEqual(resp.status, 404)
        conn.close()

        records = self._read_records()
        self.assertEqual(len(records), 1)
        self.assertLessEqual(len(records[0]["http_path"]), 128)
        self.assertEqual(records[0]["event_type"], "http_secret_file_probe")

    def test_redacts_secrets_in_referer_query_string(self) -> None:
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=3)
        conn.request(
            "GET",
            "/login",
            headers={
                "Referer": "https://example.invalid/auth?session=SECRET_SESS&next=/home",
            },
        )
        resp = conn.getresponse()
        resp.read()
        self.assertEqual(resp.status, 404)
        conn.close()

        records = self._read_records()
        self.assertEqual(len(records), 1)
        self.assertEqual(
            records[0]["metadata"]["headers"].get("referer"),
            "https://example.invalid/auth?session=[REDACTED]&next=/home",
        )

    def test_prunes_jsonl_records_older_than_24h(self) -> None:
        now = dt.datetime(2026, 11, 21, tzinfo=dt.timezone.utc)
        old = (now - dt.timedelta(hours=25)).isoformat().replace("+00:00", "Z")
        fresh = now.isoformat().replace("+00:00", "Z")
        self.output_path.write_text(
            json.dumps({"observed_at": old, "src_ip": "192.0.2.1"})
            + "\n"
            + json.dumps({"observed_at": fresh, "src_ip": "192.0.2.2"})
            + "\n",
            encoding="utf-8",
        )
        prune_temp_jsonl(self.output_path, now=now)
        records = self._read_records()
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["src_ip"], "192.0.2.2")

    def test_rejects_requests_when_concurrency_cap_is_exhausted(self) -> None:
        # Exhaust all permits in the server semaphore to deterministically test 503 shedding
        permits = self.config.max_concurrent_connections
        for _ in range(permits):
            self.assertTrue(self.server.connection_semaphore.acquire(blocking=False))
        try:
            conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=3)
            conn.request("GET", "/overload-check")
            resp = conn.getresponse()
            resp.read()
            self.assertEqual(resp.status, 503)
            conn.close()
            self.assertEqual(self.server.rejected_overload, 1)
        finally:
            for _ in range(permits):
                self.server.connection_semaphore.release()


if __name__ == "__main__":
    unittest.main()
