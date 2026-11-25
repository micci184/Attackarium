"""Tests for patch_window.sh with stubbed nft, getent, apt-get, and unattended-upgrade.

Nothing here touches the real firewall or package manager: every privileged
command is a stub on PATH that records its arguments.
"""

from __future__ import annotations

import os
import shutil
import signal
import stat
import subprocess
import tempfile
import textwrap
import time
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parent / "patch_window.sh"
TAG = "attackarium-patch-window"

STUBS = {
    "id": """
        #!/usr/bin/env bash
        if [[ "$1" == "-u" ]]; then echo "${STUB_UID:-0}"; else /usr/bin/id "$@"; fi
    """,
    "nft": """
        #!/usr/bin/env bash
        echo "nft $*" >> "$STUB_LOG"
        case "$1" in
          insert) echo "rule $* # $TAG" > "$STUB_STATE/rule" ;;
          -f) [[ "${STUB_NFT_RESTORE_BROKEN:-0}" == "1" ]] || rm -f "$STUB_STATE/rule" ;;
          list) [[ -f "$STUB_STATE/rule" ]] && cat "$STUB_STATE/rule"; true ;;
        esac
    """,
    "getent": """
        #!/usr/bin/env bash
        echo "getent $*" >> "$STUB_LOG"
        f="$STUB_STATE/dns-$2"
        [[ -f "$f" ]] && cat "$f"; true
    """,
    "apt-get": """
        #!/usr/bin/env bash
        echo "apt-get $* rule_present=$([[ -f $STUB_STATE/rule ]] && echo yes || echo no)" >> "$STUB_LOG"
        [[ -n "${STUB_APT_SLEEP:-}" ]] && sleep "$STUB_APT_SLEEP"
        exit "${STUB_APT_RC:-0}"
    """,
    "ss": """
        #!/usr/bin/env bash
        echo "ss $*" >> "$STUB_LOG"
        if [[ "$1" == "-Htn" ]]; then
          [[ "${STUB_SS_QUERY_FAIL:-0}" == "1" ]] && exit 1
          [[ "${STUB_SS_LEFTOVER:-0}" == "1" ]] && echo "ESTAB 0 0 10.42.0.10:40000 91.189.91.81:80"
        fi
        true
    """,
    "unattended-upgrade": """
        #!/usr/bin/env bash
        echo "unattended-upgrade $* rule_present=$([[ -f $STUB_STATE/rule ]] && echo yes || echo no)" >> "$STUB_LOG"
        exit "${STUB_UU_RC:-0}"
    """,
}

DEB822 = """\
Types: deb
URIs: http://archive.ubuntu.com/ubuntu
Suites: noble noble-updates noble-backports
Components: main restricted universe multiverse

Types: deb
URIs: http://security.ubuntu.com/ubuntu
Suites: noble-security
"""


def ahostsv4(*addrs: str) -> str:
    return "".join(f"{a}      STREAM host\n{a}      DGRAM\n" for a in addrs)


class PatchWindowTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp())
        self.bin = self.tmp / "bin"
        self.state = self.tmp / "stub"
        self.apt = self.tmp / "apt"
        for d in (self.bin, self.state, self.apt / "sources.list.d"):
            d.mkdir(parents=True)
        for name, body in STUBS.items():
            path = self.bin / name
            path.write_text(textwrap.dedent(body).lstrip())
            path.chmod(path.stat().st_mode | stat.S_IXUSR)
        (self.apt / "sources.list.d" / "ubuntu.sources").write_text(DEB822)
        self.log = self.tmp / "calls.log"
        self.log.touch()
        self.set_dns("archive.ubuntu.com", "91.189.91.81", "185.125.190.82")
        self.set_dns("security.ubuntu.com", "91.189.91.83")

    def tearDown(self) -> None:
        subprocess.run(["rm", "-rf", str(self.tmp)], check=False)

    def set_dns(self, host: str, *addrs: str) -> None:
        (self.state / f"dns-{host}").write_text(ahostsv4(*addrs))

    def env(self, **extra: str) -> dict[str, str]:
        env = {
            "PATH": f"{self.bin}:{os.environ['PATH']}",
            "STUB_LOG": str(self.log),
            "STUB_STATE": str(self.state),
            "TAG": TAG,
            "PATCH_WINDOW_NO_DETACH": "1",
            "PATCH_WINDOW_STATE_DIR": str(self.tmp / "result"),
            "PATCH_WINDOW_NFT_CONF": "/etc/nftables.conf",
            "PATCH_WINDOW_APT_SOURCES_DIR": str(self.apt),
            "PATCH_WINDOW_RESOLVE_ROUNDS": "2",
        }
        env.update(extra)
        return env

    def run_script(self, *args: str, **extra: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["bash", str(SCRIPT), *args],
            env=self.env(**extra),
            capture_output=True,
            text=True,
            timeout=30,
        )

    def calls(self) -> list[str]:
        return self.log.read_text().splitlines()

    def result(self) -> dict[str, str]:
        text = (self.tmp / "result" / "last-result").read_text()
        return dict(line.split("=", 1) for line in text.splitlines())

    def rule_present(self) -> bool:
        return (self.state / "rule").exists()

    # --- resolve -----------------------------------------------------------

    def test_resolve_prints_unique_public_mirror_addresses(self) -> None:
        self.set_dns(
            "archive.ubuntu.com",
            "91.189.91.81",
            "91.189.91.81",
            "169.254.169.254",  # instance metadata
            "10.0.0.5",
            "192.0.0.9",
            "192.0.2.10",
            "198.18.0.1",
            "198.19.255.1",
            "198.51.100.7",
            "203.0.113.7",
            "127.0.0.1",
            "100.64.1.1",
            "172.16.9.9",
            "192.168.1.1",
            "224.0.0.1",
        )
        proc = self.run_script("resolve")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(proc.stdout.split(), ["91.189.91.81/32", "91.189.91.83/32"])
        self.assertIn("skipping non-public mirror address 169.254.169.254", proc.stderr)

    def test_resolve_reads_one_line_sources_and_lowercases_hosts(self) -> None:
        (self.apt / "sources.list.d" / "ubuntu.sources").unlink()
        (self.apt / "sources.list").write_text(
            "# comment http://ignored.example.invalid/\n"
            "deb [arch=amd64 signed-by=/k.gpg] http://Mirror.Example.invalid:80/ubuntu noble main\n"
        )
        self.set_dns("mirror.example.invalid", "45.33.10.7")
        proc = self.run_script("resolve")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(proc.stdout.split(), ["45.33.10.7/32"])
        self.assertNotIn("ignored.example.invalid", self.log.read_text())

    def test_resolve_reads_every_deb822_uri_and_skips_disabled_stanzas(self) -> None:
        (self.apt / "sources.list.d" / "ubuntu.sources").write_text(
            "Types: deb\n"
            "URIs: http://mirror-a.example.invalid/ubuntu http://mirror-b.example.invalid/ubuntu\n"
            "  https://mirror-c.example.invalid/ubuntu\n"
            "Suites: noble\n"
            "\n"
            "# a comment between stanzas\n"
            "Types: deb\n"
            "Enabled: no\n"
            "URIs: http://disabled.example.invalid/ubuntu\n"
            "Suites: noble\n"
        )
        for host, addr in (("mirror-a", "45.33.1.1"), ("mirror-b", "45.33.1.2"), ("mirror-c", "45.33.1.3"), ("disabled", "45.33.1.4")):
            self.set_dns(f"{host}.example.invalid", addr)
        proc = self.run_script("resolve")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(proc.stdout.split(), ["45.33.1.1/32", "45.33.1.2/32", "45.33.1.3/32"])
        self.assertNotIn("disabled.example.invalid", self.log.read_text())

    # --- run: happy path ---------------------------------------------------

    def test_run_opens_only_port_80_to_mirrors_patches_then_restores(self) -> None:
        proc = self.run_script("run")
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        calls = self.calls()
        insert = [c for c in calls if c.startswith("nft insert")]
        self.assertEqual(len(insert), 1)
        self.assertIn(
            "ip daddr { 185.125.190.82, 91.189.91.81, 91.189.91.83 } tcp dport 80 accept",
            insert[0],
        )
        self.assertIn(TAG, insert[0])
        self.assertNotIn("443", insert[0])
        order = [c.split()[0] + (" " + c.split()[1] if c.startswith("nft") else "") for c in calls]
        self.assertLess(order.index("nft insert"), order.index("apt-get"))
        self.assertLess(order.index("apt-get"), order.index("unattended-upgrade"))
        self.assertLess(order.index("unattended-upgrade"), order.index("nft -f"))
        self.assertTrue(any("apt-get" in c and "rule_present=yes" in c for c in calls))
        self.assertFalse(self.rule_present())
        self.assertEqual(self.result()["result"], "success")
        self.assertTrue((self.tmp / "result" / "last-success").exists())
        update = next(c for c in calls if c.startswith("apt-get") and "update" in c)
        self.assertIn("APT::Update::Error-Mode=any", update)
        # Window flows are ended for every window address after the reload.
        for addr in ("185.125.190.82", "91.189.91.81", "91.189.91.83"):
            self.assertIn(f"ss -K -tn dst {addr} dport = :80", calls)
        self.assertLess(order.index("nft -f"), order.index("ss"))
        self.assertFalse((self.tmp / "result" / "window-addrs").exists())

    def test_open_window_flow_after_cleanup_is_a_failure(self) -> None:
        proc = self.run_script("run", STUB_SS_LEFTOVER="1")
        self.assertNotEqual(proc.returncode, 0)
        self.assertEqual(self.result()["result"], "failure")
        self.assertIn("firewall restore failed", self.result()["detail"])
        self.assertIn("TCP/80 connections still open", proc.stderr)
        self.assertTrue((self.tmp / "result" / "window-addrs").exists())

    def test_failed_flow_query_is_a_failure_and_keeps_tracking(self) -> None:
        proc = self.run_script("run", STUB_SS_QUERY_FAIL="1")
        self.assertNotEqual(proc.returncode, 0)
        self.assertEqual(self.result()["result"], "failure")
        self.assertIn("query-failed", proc.stderr)
        self.assertTrue((self.tmp / "result" / "window-addrs").exists())

    def test_unverified_previous_window_blocks_a_new_window(self) -> None:
        (self.tmp / "result").mkdir()
        (self.tmp / "result" / "window-addrs").write_text("45.33.9.9\n")
        proc = self.run_script("run", STUB_SS_LEFTOVER="1")
        self.assertNotEqual(proc.returncode, 0)
        self.assertFalse(any(c.startswith("nft insert") for c in self.calls()))
        self.assertIn("previous window flows not cleaned up", self.result()["detail"])
        self.assertIn("45.33.9.9", (self.tmp / "result" / "window-addrs").read_text())

    def test_verified_previous_window_is_cleared_then_run_proceeds(self) -> None:
        (self.tmp / "result").mkdir()
        (self.tmp / "result" / "window-addrs").write_text("45.33.9.9\n")
        proc = self.run_script("run")
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        calls = self.calls()
        # The persisted ruleset is reloaded before the retained flows are drained.
        self.assertLess(calls.index("nft -f /etc/nftables.conf"), calls.index("ss -K -tn dst 45.33.9.9 dport = :80"))
        self.assertLess(
            calls.index("ss -K -tn dst 45.33.9.9 dport = :80"),
            next(i for i, c in enumerate(calls) if c.startswith("nft insert")),
        )
        self.assertEqual(self.result()["result"], "success")

    def test_leftover_rule_without_address_file_is_restored_first(self) -> None:
        (self.state / "rule").write_text(f"leftover # {TAG}\n")
        proc = self.run_script("run")
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        calls = self.calls()
        first_restore = calls.index("nft -f /etc/nftables.conf")
        first_insert = next(i for i, c in enumerate(calls) if c.startswith("nft insert"))
        self.assertLess(first_restore, first_insert)

    def test_install_mode_pins_packages_inside_the_same_window(self) -> None:
        proc = self.run_script("install", "openssl=3.0.13-0ubuntu3.15", "libssl3t64=3.0.13-0ubuntu3.15")
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        calls = self.calls()
        install = [c for c in calls if c.startswith("apt-get") and " install " in c]
        self.assertEqual(len(install), 1)
        self.assertIn("--allow-downgrades install openssl=3.0.13-0ubuntu3.15 libssl3t64=3.0.13-0ubuntu3.15", install[0])
        self.assertIn("rule_present=yes", install[0])
        self.assertFalse(any(c.startswith("unattended-upgrade") for c in calls))
        self.assertFalse(self.rule_present())
        self.assertEqual(self.result()["result"], "success")

    def test_install_mode_rejects_unpinned_or_option_like_arguments(self) -> None:
        for args in ((), ("openssl",), ("-o=APT::x",), ("openssl=1;reboot",), ("--reinstall",)):
            proc = self.run_script("install", *args)
            self.assertNotEqual(proc.returncode, 0, args)
        self.assertEqual(self.calls(), [])

    # --- run: unhappy paths ------------------------------------------------

    def test_apt_failure_still_restores_firewall_and_records_failure(self) -> None:
        proc = self.run_script("run", STUB_APT_RC="100")
        self.assertNotEqual(proc.returncode, 0)
        self.assertFalse(self.rule_present())
        self.assertIn("nft -f /etc/nftables.conf", self.calls())
        self.assertFalse(any(c.startswith("unattended-upgrade") for c in self.calls()))
        self.assertEqual(self.result()["result"], "failure")
        self.assertEqual(self.result()["detail"], "apt-get update failed")
        self.assertFalse((self.tmp / "result" / "last-success").exists())

    def test_upgrade_failure_is_recorded(self) -> None:
        proc = self.run_script("run", STUB_UU_RC="1")
        self.assertNotEqual(proc.returncode, 0)
        self.assertFalse(self.rule_present())
        self.assertEqual(self.result()["detail"], "unattended-upgrade failed")

    def test_no_public_addresses_opens_nothing(self) -> None:
        self.set_dns("archive.ubuntu.com", "169.254.169.254")
        self.set_dns("security.ubuntu.com", "10.1.2.3")
        proc = self.run_script("run")
        self.assertNotEqual(proc.returncode, 0)
        self.assertFalse(any(c.startswith("nft insert") for c in self.calls()))
        self.assertFalse(any(c.startswith("apt-get") for c in self.calls()))
        self.assertEqual(self.result()["detail"], "no public mirror addresses resolved")

    def test_too_many_addresses_is_refused(self) -> None:
        self.set_dns("archive.ubuntu.com", *[f"185.125.1.{i}" for i in range(1, 34)])
        proc = self.run_script("run")
        self.assertNotEqual(proc.returncode, 0)
        self.assertFalse(any(c.startswith("nft insert") for c in self.calls()))
        self.assertIn("refusing to open egress", self.result()["detail"])

    def test_broken_restore_is_reported_as_failure(self) -> None:
        proc = self.run_script("run", STUB_NFT_RESTORE_BROKEN="1")
        self.assertNotEqual(proc.returncode, 0)
        self.assertEqual(self.result()["result"], "failure")
        self.assertIn("firewall restore failed", self.result()["detail"])

    def test_sigterm_during_apt_restores_firewall(self) -> None:
        proc = subprocess.Popen(
            ["bash", str(SCRIPT), "run"],
            env=self.env(STUB_APT_SLEEP="2"),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        deadline = time.monotonic() + 10
        while not self.rule_present() and time.monotonic() < deadline:
            time.sleep(0.05)
        self.assertTrue(self.rule_present())
        proc.send_signal(signal.SIGTERM)
        proc.communicate(timeout=20)
        self.assertNotEqual(proc.returncode, 0)
        self.assertFalse(self.rule_present())
        self.assertEqual(self.result()["detail"], "interrupted")
        self.assertFalse(any(c.startswith("unattended-upgrade") for c in self.calls()))

    @unittest.skipUnless(shutil.which("flock"), "flock (util-linux) not installed")
    def test_patch_unit_itself_holds_the_lock_while_running(self) -> None:
        proc = subprocess.Popen(
            ["bash", str(SCRIPT), "run"],
            env=self.env(STUB_APT_SLEEP="2"),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        lock = self.tmp / "result" / "run.lock"
        deadline = time.monotonic() + 10
        while not self.rule_present() and time.monotonic() < deadline:
            time.sleep(0.05)
        self.assertTrue(self.rule_present())
        probe = subprocess.run(["flock", "-n", str(lock), "true"])
        self.assertNotEqual(probe.returncode, 0, "run.lock must be held by the patch run itself")
        proc.communicate(timeout=30)
        self.assertEqual(proc.returncode, 0)
        probe = subprocess.run(["flock", "-n", str(lock), "true"])
        self.assertEqual(probe.returncode, 0, "run.lock must be released when the run exits")

    def test_requires_root(self) -> None:
        proc = self.run_script("run", STUB_UID="1000")
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("must run as root", proc.stderr)
        self.assertEqual(self.calls(), [])

    def test_cleanup_restores_persisted_ruleset(self) -> None:
        (self.state / "rule").write_text(f"leftover # {TAG}\n")
        proc = self.run_script("cleanup")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertFalse(self.rule_present())

    def test_unknown_command_shows_usage(self) -> None:
        proc = self.run_script("open-everything")
        self.assertEqual(proc.returncode, 2)
        self.assertIn("usage:", proc.stderr)


if __name__ == "__main__":
    unittest.main()
